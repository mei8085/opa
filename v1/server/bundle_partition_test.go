// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/download"
	"github.com/open-policy-agent/opa/v1/plugins"
	bundlePlugin "github.com/open-policy-agent/opa/v1/plugins/bundle"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/util"
)

const (
	partitionBilling  = "billing"
	partitionShipping = "shipping"
)

// partitionSource serves the bundle currently "published" for one partition
// over HTTP. Swapping the bundle between downloads models a control plane
// publishing a new revision of that partition only.
type partitionSource struct {
	mtx sync.Mutex
	b   *bundle.Bundle
	srv *httptest.Server
}

func (p *partitionSource) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	p.mtx.Lock()
	b := p.b
	p.mtx.Unlock()

	if b == nil {
		http.Error(w, "no bundle published", http.StatusNotFound)
		return
	}

	if err := bundle.NewWriter(w).UseModulePath(true).Write(*b); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (p *partitionSource) publish(b *bundle.Bundle) {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.b = b
}

// partitionFixture wires a real bundle plugin (downloading from per-partition
// HTTP servers), a shared in-memory store and an HTTP server in front of both.
// All reads in these tests go through the server's public API, so what is
// asserted is what a request would see.
type partitionFixture struct {
	t       *testing.T
	ctx     context.Context
	manager *plugins.Manager
	plugin  *bundlePlugin.Plugin
	server  *Server
	sources map[string]*partitionSource
	names   []string
	updates chan bundlePlugin.Status
}

func newPartitionFixture(t *testing.T, names ...string) *partitionFixture {
	t.Helper()

	f := &partitionFixture{
		t:       t,
		ctx:     t.Context(),
		sources: map[string]*partitionSource{},
		names:   names,
		updates: make(chan bundlePlugin.Status, 16),
	}

	services := map[string]any{}
	for _, name := range names {
		src := &partitionSource{}
		src.srv = httptest.NewServer(src)
		t.Cleanup(src.srv.Close)
		f.sources[name] = src
		services["svc-"+name] = map[string]any{"url": src.srv.URL}
	}

	manager, err := plugins.New(util.MustMarshalJSON(map[string]any{"services": services}), "partition-test", inmem.New())
	if err != nil {
		t.Fatalf("failed to create plugin manager: %v", err)
	}
	f.manager = manager

	manual := plugins.TriggerManual
	sources := map[string]*bundlePlugin.Source{}
	for _, name := range names {
		sources[name] = &bundlePlugin.Source{
			Service:        "svc-" + name,
			Resource:       "/" + name,
			SizeLimitBytes: bundle.DefaultSizeLimitBytes,
			Config:         download.Config{Trigger: &manual},
		}
	}

	plugin := bundlePlugin.New(&bundlePlugin.Config{Bundles: sources}, manager)
	manager.Register(bundlePlugin.Name, plugin)

	// Capture the status reported for every activation attempt. Because
	// oneShot notifies listeners synchronously, the statuses for a trigger are
	// already queued when Loader.Trigger returns.
	plugin.Register("partition-test", func(st bundlePlugin.Status) {
		select {
		case f.updates <- st:
		default:
		}
	})
	f.plugin = plugin

	if err := manager.Start(t.Context()); err != nil {
		t.Fatalf("failed to start plugin manager: %v", err)
	}

	s, err := New().WithStore(manager.Store).WithManager(manager).Init(t.Context())
	if err != nil {
		t.Fatalf("failed to initialize server: %v", err)
	}
	f.server = s

	t.Cleanup(func() {
		// The test context is already cancelled when cleanups run, so
		// detach from it before shutting down.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Second)
		defer cancel()
		if err := f.server.Shutdown(ctx); err != nil {
			t.Errorf("failed to shut down server: %v", err)
		}
		f.manager.Stop(ctx)
	})

	return f
}

// publish swaps the payload served for name and triggers a download. The
// returned status is the one reported for this specific activation attempt,
// which is what a control plane would surface to the publisher.
func (f *partitionFixture) publish(name string, b *bundle.Bundle) (bundlePlugin.Status, error) {
	f.t.Helper()

	f.drain()
	f.sources[name].publish(b)

	err := f.plugin.Loaders()[name].Trigger(f.ctx)

	var st bundlePlugin.Status
	found := false
	for range len(f.updates) {
		got := <-f.updates
		if got.Name == name {
			st, found = got, true
		}
	}
	if !found {
		f.t.Fatalf("expected a status update for bundle %q", name)
	}

	return st, err
}

func (f *partitionFixture) drain() {
	for {
		select {
		case <-f.updates:
		default:
			return
		}
	}
}

func (f *partitionFixture) request(method, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}

	rec := httptest.NewRecorder()
	f.server.Handler.ServeHTTP(rec, req)
	return rec
}

func (f *partitionFixture) data(path string) any {
	f.t.Helper()

	rec := f.request(http.MethodGet, path, "")
	if rec.Code != http.StatusOK {
		f.t.Fatalf("GET %s: expected status 200 but got %d: %s", path, rec.Code, rec.Body.String())
	}

	var resp struct {
		Result any `json:"result"`
	}
	if err := util.NewJSONDecoder(rec.Body).Decode(&resp); err != nil {
		f.t.Fatalf("GET %s: failed to decode response: %v", path, err)
	}
	return resp.Result
}

// requireValue asserts the document at path is exactly exp (a JSON literal).
func (f *partitionFixture) requireValue(path, exp string) {
	f.t.Helper()

	want := util.MustUnmarshalJSON([]byte(exp))
	if got := f.data(path); !reflect.DeepEqual(got, want) {
		f.t.Fatalf("unexpected value at %s: want %v but got %v", path, want, got)
	}
}

// requireUndefined asserts the document at path cannot be read, i.e. no
// request can observe data at that location.
func (f *partitionFixture) requireUndefined(path string) {
	f.t.Helper()

	if got := f.data(path); got != nil {
		f.t.Fatalf("expected %s to be undefined but got %v", path, got)
	}
}

// requireDecision evaluates the policy at path with input and asserts the
// decision returned to the caller.
func (f *partitionFixture) requireDecision(path, input, exp string) {
	f.t.Helper()

	rec := f.request(http.MethodPost, path, `{"input":`+input+`}`)
	if rec.Code != http.StatusOK {
		f.t.Fatalf("POST %s: expected status 200 but got %d: %s", path, rec.Code, rec.Body.String())
	}

	var resp struct {
		Result any `json:"result"`
	}
	if err := util.NewJSONDecoder(rec.Body).Decode(&resp); err != nil {
		f.t.Fatalf("POST %s: failed to decode response: %v", path, err)
	}

	want := util.MustUnmarshalJSON([]byte(exp))
	if !reflect.DeepEqual(resp.Result, want) {
		f.t.Fatalf("unexpected decision at %s for input %s: want %v but got %v", path, input, want, resp.Result)
	}
}

func (f *partitionFixture) policyIDs() []string {
	f.t.Helper()

	rec := f.request(http.MethodGet, "/v1/policies", "")
	if rec.Code != http.StatusOK {
		f.t.Fatalf("GET /v1/policies: expected status 200 but got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := util.NewJSONDecoder(rec.Body).Decode(&resp); err != nil {
		f.t.Fatalf("GET /v1/policies: failed to decode response: %v", err)
	}

	ids := make([]string, 0, len(resp.Result))
	for _, p := range resp.Result {
		ids = append(ids, p.ID)
	}
	slices.Sort(ids)
	return ids
}

func (f *partitionFixture) requirePolicyIDs(exp ...string) {
	f.t.Helper()

	want := slices.Clone(exp)
	slices.Sort(want)
	if got := f.policyIDs(); !slices.Equal(got, want) {
		f.t.Fatalf("unexpected policy IDs: want %v but got %v", want, got)
	}
}

func (f *partitionFixture) requirePolicyAbsent(id string) {
	f.t.Helper()

	rec := f.request(http.MethodGet, "/v1/policies/"+id, "")
	if rec.Code != http.StatusNotFound {
		f.t.Fatalf("expected policy %q to be absent but GET /v1/policies/%s returned %d: %s",
			id, id, rec.Code, rec.Body.String())
	}
}

// revisions reads the per-bundle revision from the data API provenance, i.e.
// the version information a caller can observe.
func (f *partitionFixture) revisions() map[string]string {
	f.t.Helper()

	rec := f.request(http.MethodGet, "/v1/data?provenance=true", "")
	if rec.Code != http.StatusOK {
		f.t.Fatalf("GET /v1/data?provenance=true: expected status 200 but got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Provenance *struct {
			Bundles map[string]struct {
				Revision string `json:"revision"`
			} `json:"bundles"`
		} `json:"provenance"`
	}
	if err := util.NewJSONDecoder(rec.Body).Decode(&resp); err != nil {
		f.t.Fatalf("GET /v1/data?provenance=true: failed to decode response: %v", err)
	}

	revs := map[string]string{}
	if resp.Provenance != nil {
		for name, b := range resp.Provenance.Bundles {
			revs[name] = b.Revision
		}
	}
	return revs
}

func (f *partitionFixture) requireRevisions(exp map[string]string) {
	f.t.Helper()

	if got := f.revisions(); !maps.Equal(got, exp) {
		f.t.Fatalf("unexpected bundle revisions: want %v but got %v", exp, got)
	}
}

func (f *partitionFixture) requireRevisionAt(name, exp string) {
	f.t.Helper()

	f.requireValue("/v1/data/system/bundles/"+name+"/manifest/revision", `"`+exp+`"`)
}

// partitionSnapshot captures everything a caller can read: business data (and
// the virtual documents derived from it), policy contents and version
// information.
type partitionSnapshot struct {
	data      map[string]any
	policies  map[string]string
	revisions map[string]string
}

func (f *partitionFixture) snapshot() partitionSnapshot {
	f.t.Helper()

	snap := partitionSnapshot{
		data:      map[string]any{},
		policies:  map[string]string{},
		revisions: f.revisions(),
	}
	for _, name := range f.names {
		snap.data[name] = f.data("/v1/data/" + name)
	}

	rec := f.request(http.MethodGet, "/v1/policies", "")
	if rec.Code != http.StatusOK {
		f.t.Fatalf("GET /v1/policies: expected status 200 but got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Result []struct {
			ID  string `json:"id"`
			Raw string `json:"raw"`
		} `json:"result"`
	}
	if err := util.NewJSONDecoder(rec.Body).Decode(&resp); err != nil {
		f.t.Fatalf("GET /v1/policies: failed to decode response: %v", err)
	}
	for _, p := range resp.Result {
		snap.policies[p.ID] = p.Raw
	}

	return snap
}

// requireSnapshot asserts the readable state is exactly want.
func (f *partitionFixture) requireSnapshot(want partitionSnapshot) {
	f.t.Helper()

	if got := f.snapshot(); !reflect.DeepEqual(got, want) {
		f.t.Fatalf("readable state changed unexpectedly:\nwant: %#v\ngot:  %#v", want, got)
	}
}

// partitionBundle builds a snapshot bundle with the given revision, roots,
// data and Rego modules (path -> source).
func partitionBundle(revision string, roots []string, data map[string]any, modules map[string]string) *bundle.Bundle {
	paths := slices.Sorted(maps.Keys(modules))
	mfs := make([]bundle.ModuleFile, 0, len(paths))
	for _, p := range paths {
		mfs = append(mfs, bundle.ModuleFile{Path: p, URL: p, Raw: []byte(modules[p])})
	}

	roots = slices.Clone(roots)
	return &bundle.Bundle{
		Manifest: bundle.Manifest{Revision: revision, Roots: &roots},
		Data:     data,
		Modules:  mfs,
	}
}

func partitionPolicyModule(pkg, action string) string {
	return "package " + pkg + "\n\nimport rego.v1\n\ndefault allow := false\n\nallow if input.action == \"" + action + "\"\n"
}

// TestMultiBundlePartitionPublishing verifies that independent governance
// partitions sharing one store can be published and updated separately: a
// publish of one partition leaves the other partition's data, policies and
// revision untouched.
func TestMultiBundlePartitionPublishing(t *testing.T) {
	t.Parallel()

	f := newPartitionFixture(t, partitionBilling, partitionShipping)

	// Nothing has been published yet.
	f.requireUndefined("/v1/data/billing")
	f.requireUndefined("/v1/data/shipping")
	f.requirePolicyIDs()
	f.requireRevisions(map[string]string{})

	// Publish the billing partition.
	st, err := f.publish(partitionBilling, partitionBundle("billing-rev-1",
		[]string{"billing"},
		map[string]any{"billing": map[string]any{"rate": 5}},
		map[string]string{"/policy.rego": partitionPolicyModule("billing", "read")},
	))
	if err != nil {
		t.Fatalf("publishing billing failed: %v", err)
	}
	if st.ActiveRevision != "billing-rev-1" {
		t.Fatalf("expected active revision billing-rev-1 but got %q", st.ActiveRevision)
	}
	if st.Message != "" {
		t.Fatalf("expected no error status for billing but got %q", st.Message)
	}

	f.requireValue("/v1/data/billing/rate", `5`)
	f.requireUndefined("/v1/data/shipping")
	f.requirePolicyIDs("billing/policy.rego")
	f.requireRevisions(map[string]string{"billing": "billing-rev-1"})
	f.requireRevisionAt("billing", "billing-rev-1")

	f.requireDecision("/v1/data/billing/allow", `{"action":"read"}`, `true`)
	f.requireDecision("/v1/data/billing/allow", `{"action":"ship"}`, `false`)

	// Publish the shipping partition. Its root is a separate governance
	// boundary, so publishing it must not disturb billing.
	st, err = f.publish(partitionShipping, partitionBundle("shipping-rev-1",
		[]string{"shipping"},
		map[string]any{"shipping": map[string]any{"carrier": "acme"}},
		map[string]string{"/policy.rego": partitionPolicyModule("shipping", "ship")},
	))
	if err != nil {
		t.Fatalf("publishing shipping failed: %v", err)
	}
	if st.ActiveRevision != "shipping-rev-1" {
		t.Fatalf("expected active revision shipping-rev-1 but got %q", st.ActiveRevision)
	}

	f.requireValue("/v1/data/billing/rate", `5`)
	f.requireValue("/v1/data/shipping/carrier", `"acme"`)
	f.requirePolicyIDs("billing/policy.rego", "shipping/policy.rego")
	f.requireRevisions(map[string]string{
		"billing":  "billing-rev-1",
		"shipping": "shipping-rev-1",
	})
	f.requireRevisionAt("billing", "billing-rev-1")
	f.requireRevisionAt("shipping", "shipping-rev-1")

	f.requireDecision("/v1/data/shipping/allow", `{"action":"ship"}`, `true`)
	f.requireDecision("/v1/data/shipping/allow", `{"action":"read"}`, `false`)

	// Update only billing: shipping data, policy and revision stay put.
	if _, err := f.publish(partitionBilling, partitionBundle("billing-rev-2",
		[]string{"billing"},
		map[string]any{"billing": map[string]any{"rate": 7}},
		map[string]string{"/policy.rego": partitionPolicyModule("billing", "read")},
	)); err != nil {
		t.Fatalf("updating billing failed: %v", err)
	}

	f.requireValue("/v1/data/billing/rate", `7`)
	f.requireValue("/v1/data/shipping/carrier", `"acme"`)
	f.requireRevisions(map[string]string{
		"billing":  "billing-rev-2",
		"shipping": "shipping-rev-1",
	})
	f.requireRevisionAt("shipping", "shipping-rev-1")

	// Update only shipping: billing data and revision stay put.
	if _, err := f.publish(partitionShipping, partitionBundle("shipping-rev-2",
		[]string{"shipping"},
		map[string]any{"shipping": map[string]any{"carrier": "globex"}},
		map[string]string{"/policy.rego": partitionPolicyModule("shipping", "ship")},
	)); err != nil {
		t.Fatalf("updating shipping failed: %v", err)
	}

	f.requireValue("/v1/data/billing/rate", `7`)
	f.requireValue("/v1/data/shipping/carrier", `"globex"`)
	f.requirePolicyIDs("billing/policy.rego", "shipping/policy.rego")
	f.requireRevisions(map[string]string{
		"billing":  "billing-rev-2",
		"shipping": "shipping-rev-2",
	})
	f.requireRevisionAt("billing", "billing-rev-2")
	f.requireRevisionAt("shipping", "shipping-rev-2")
}

// TestMultiBundlePartitionFailedUpdateKeepsReadableState verifies that a
// rejected update of one partition leaves the rules, business data and version
// information of every partition in the same readable state they had before
// the attempt.
func TestMultiBundlePartitionFailedUpdateKeepsReadableState(t *testing.T) {
	t.Parallel()

	f := newPartitionFixture(t, partitionBilling, partitionShipping)

	if _, err := f.publish(partitionBilling, partitionBundle("billing-rev-1",
		[]string{"billing"},
		map[string]any{"billing": map[string]any{"rate": 5}},
		map[string]string{"/policy.rego": partitionPolicyModule("billing", "read")},
	)); err != nil {
		t.Fatalf("publishing billing failed: %v", err)
	}
	if _, err := f.publish(partitionShipping, partitionBundle("shipping-rev-1",
		[]string{"shipping"},
		map[string]any{"shipping": map[string]any{"carrier": "acme"}},
		map[string]string{"/policy.rego": partitionPolicyModule("shipping", "ship")},
	)); err != nil {
		t.Fatalf("publishing shipping failed: %v", err)
	}

	baseline := f.snapshot()

	cases := []struct {
		note       string
		bundle     *bundle.Bundle
		expErr     string
		expMessage string
	}{
		{
			note: "policy fails to compile",
			bundle: partitionBundle("billing-rev-bad-compile",
				[]string{"billing"},
				map[string]any{"billing": map[string]any{"rate": 6}},
				map[string]string{"/policy.rego": "package billing\n\nimport rego.v1\n\nrate := 6\n\nrate[x] := 7 if { x := \"a\" }\n"},
			),
			expErr:     "conflicting rules",
			expMessage: "compiling module(s)",
		},
		{
			note: "policy conflicts with business data",
			bundle: partitionBundle("billing-rev-bad-data-conflict",
				[]string{"billing"},
				map[string]any{"billing": map[string]any{"rate": 6}},
				map[string]string{"/policy.rego": "package billing\n\nimport rego.v1\n\nrate := 1\n"},
			),
			expErr:     "conflicting rule for data path billing/rate found",
			expMessage: "compiling module(s)",
		},
		{
			note: "data outside declared roots",
			bundle: partitionBundle("billing-rev-bad-scope",
				[]string{"billing"},
				map[string]any{
					"billing": map[string]any{"rate": 6},
					"leak":    map[string]any{"secret": true},
				},
				map[string]string{"/policy.rego": partitionPolicyModule("billing", "read")},
			),
			expErr:     "do not permit data at path '/leak'",
			expMessage: "do not permit data at path '/leak'",
		},
	}

	for _, tc := range cases {
		t.Run(tc.note, func(t *testing.T) {
			// Report failures against the subtest rather than the parent.
			sub := *f
			sub.t = t

			st, err := sub.publish(partitionBilling, tc.bundle)
			if err == nil {
				t.Fatalf("expected publishing %q to fail", tc.bundle.Manifest.Revision)
			}
			if !strings.Contains(err.Error(), tc.expErr) {
				t.Fatalf("expected error containing %q but got %v", tc.expErr, err)
			}
			if !strings.Contains(st.Message, tc.expMessage) {
				t.Fatalf("expected status message containing %q but got %q", tc.expMessage, st.Message)
			}
			if st.ActiveRevision != "billing-rev-1" {
				t.Fatalf("expected the previously active revision to be reported but got %q", st.ActiveRevision)
			}

			// Rules, business data and version information must still read as
			// the single, consistent state published before the failure.
			sub.requireSnapshot(baseline)

			// In particular, none of the rejected payload is reachable.
			sub.requireUndefined("/v1/data/leak")
			sub.requireValue("/v1/data/billing/rate", `5`)
			sub.requireValue("/v1/data/shipping/carrier", `"acme"`)
			sub.requirePolicyAbsent("billing/policy-bad.rego")
			sub.requireRevisions(map[string]string{
				"billing":  "billing-rev-1",
				"shipping": "shipping-rev-1",
			})
			sub.requireRevisionAt("billing", "billing-rev-1")
		})
	}

	// The partition is still publishable after the rejected attempts.
	st, err := f.publish(partitionBilling, partitionBundle("billing-rev-2",
		[]string{"billing"},
		map[string]any{"billing": map[string]any{"rate": 9}},
		map[string]string{"/policy.rego": partitionPolicyModule("billing", "read")},
	))
	if err != nil {
		t.Fatalf("expected recovery publish to succeed but got %v", err)
	}
	if st.ActiveRevision != "billing-rev-2" {
		t.Fatalf("expected active revision billing-rev-2 but got %q", st.ActiveRevision)
	}
	f.requireValue("/v1/data/billing/rate", `9`)
	f.requireValue("/v1/data/shipping/carrier", `"acme"`)
	f.requireRevisions(map[string]string{
		"billing":  "billing-rev-2",
		"shipping": "shipping-rev-1",
	})
}

// TestMultiBundlePartitionRootConflictLeavesNoPartialBundle verifies that a
// package whose manifest roots intrude on another partition is rejected
// without leaving any of its new policies or data readable.
func TestMultiBundlePartitionRootConflictLeavesNoPartialBundle(t *testing.T) {
	t.Parallel()

	f := newPartitionFixture(t, partitionBilling, partitionShipping)

	if _, err := f.publish(partitionBilling, partitionBundle("billing-rev-1",
		[]string{"billing"},
		map[string]any{"billing": map[string]any{"rate": 5}},
		map[string]string{"/policy.rego": partitionPolicyModule("billing", "read")},
	)); err != nil {
		t.Fatalf("publishing billing failed: %v", err)
	}
	if _, err := f.publish(partitionShipping, partitionBundle("shipping-rev-1",
		[]string{"shipping"},
		map[string]any{"shipping": map[string]any{"carrier": "acme"}},
		map[string]string{"/policy.rego": partitionPolicyModule("shipping", "ship")},
	)); err != nil {
		t.Fatalf("publishing shipping failed: %v", err)
	}

	baseline := f.snapshot()

	// This revision of the shipping partition claims a root inside the billing
	// partition. It is a structurally valid bundle, so the rejection has to be
	// decided by the shared store's root ownership rules at activation time.
	conflict := partitionBundle("shipping-rev-conflict",
		[]string{"billing/reports"},
		map[string]any{"billing": map[string]any{"reports": map[string]any{"generated": true}}},
		map[string]string{"/extra.rego": "package billing.reports\n\nimport rego.v1\n\nquarterly := true\n"},
	)

	st, err := f.publish(partitionShipping, conflict)
	if err == nil {
		t.Fatal("expected the conflicting partition update to be rejected")
	}
	if !strings.Contains(err.Error(), "overlapping roots") || !strings.Contains(err.Error(), "billing/reports") {
		t.Fatalf("expected a roots overlap error mentioning billing/reports but got %v", err)
	}
	if !strings.Contains(st.Message, "overlapping roots") {
		t.Fatalf("expected status message to describe the roots overlap but got %q", st.Message)
	}
	if st.ActiveRevision != "shipping-rev-1" {
		t.Fatalf("expected the previously active revision to be reported but got %q", st.ActiveRevision)
	}

	// Nothing from the rejected revision is readable...
	f.requirePolicyAbsent("shipping/extra.rego")
	f.requireUndefined("/v1/data/billing/reports")
	f.requireUndefined("/v1/data/billing/reports/generated")

	// ...while both partitions keep serving exactly the state they had before.
	f.requireSnapshot(baseline)
	f.requireValue("/v1/data/billing/rate", `5`)
	f.requireValue("/v1/data/shipping/carrier", `"acme"`)
	f.requireRevisions(map[string]string{
		"billing":  "billing-rev-1",
		"shipping": "shipping-rev-1",
	})
	f.requireRevisionAt("shipping", "shipping-rev-1")
	f.requireDecision("/v1/data/shipping/allow", `{"action":"ship"}`, `true`)

	// A subsequent, legal shipping revision is accepted and becomes readable,
	// so the rejected attempt did not wedge the partition.
	st, err = f.publish(partitionShipping, partitionBundle("shipping-rev-2",
		[]string{"shipping"},
		map[string]any{"shipping": map[string]any{"carrier": "globex"}},
		map[string]string{
			"/policy.rego": partitionPolicyModule("shipping", "ship"),
			"/extra.rego":  "package shipping\n\nimport rego.v1\n\nlabel := \"eu\"\n",
		},
	))
	if err != nil {
		t.Fatalf("expected the repaired shipping revision to publish but got %v", err)
	}
	if st.ActiveRevision != "shipping-rev-2" {
		t.Fatalf("expected active revision shipping-rev-2 but got %q", st.ActiveRevision)
	}

	f.requirePolicyIDs("billing/policy.rego", "shipping/extra.rego", "shipping/policy.rego")
	f.requireValue("/v1/data/shipping/carrier", `"globex"`)
	f.requireValue("/v1/data/shipping/label", `"eu"`)
	f.requireValue("/v1/data/billing/rate", `5`)
	f.requireUndefined("/v1/data/billing/reports")
	f.requireRevisions(map[string]string{
		"billing":  "billing-rev-1",
		"shipping": "shipping-rev-2",
	})
}

// TestMultiBundlePartitionPublishIsAtomicForReaders repeatedly republishes one
// partition while requests are in flight and checks that every single response
// is one of the two complete states. A response must never combine the rules,
// business data or version information of different revisions, because a
// request is answered from one storage transaction.
func TestMultiBundlePartitionPublishIsAtomicForReaders(t *testing.T) {
	t.Parallel()

	f := newPartitionFixture(t, partitionBilling)

	// The rule derives from the bundle's own data, so a response mixes data and
	// rules and would expose a half-applied update.
	module := `package billing

import rego.v1

default allow := false

allow if input.action == "read"

summary := {"rate": data.billing.rate, "tier": tier} if {
	data.billing.rate > 5
	tier := "gold"
}

summary := {"rate": data.billing.rate, "tier": tier} if {
	data.billing.rate <= 5
	tier := "silver"
}
`

	oldRev := partitionBundle("billing-rev-old",
		[]string{"billing"},
		map[string]any{"billing": map[string]any{"rate": 5}},
		map[string]string{"/policy.rego": module},
	)
	newRev := partitionBundle("billing-rev-new",
		[]string{"billing"},
		map[string]any{"billing": map[string]any{"rate": 7}},
		map[string]string{"/policy.rego": module},
	)

	if _, err := f.publish(partitionBilling, oldRev); err != nil {
		t.Fatalf("publishing initial billing revision failed: %v", err)
	}

	// errs is buffered so readers never block on reporting.
	errs := make(chan error, 128)
	done := make(chan struct{})

	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}

				rec := f.request(http.MethodGet, "/v1/data/billing?provenance=true", "")
				if rec.Code != http.StatusOK {
					select {
					case errs <- fmt.Errorf("GET billing: status %d: %s", rec.Code, rec.Body.String()):
					default:
					}
					return
				}

				var resp struct {
					Result     map[string]any `json:"result"`
					Provenance *struct {
						Bundles map[string]struct {
							Revision string `json:"revision"`
						} `json:"bundles"`
					} `json:"provenance"`
				}
				if err := util.NewJSONDecoder(rec.Body).Decode(&resp); err != nil {
					select {
					case errs <- fmt.Errorf("GET billing: decode failed: %w", err):
					default:
					}
					return
				}

				rate, _ := resp.Result["rate"].(json.Number)
				summary, _ := resp.Result["summary"].(map[string]any)
				tier, _ := summary["tier"].(string)

				var rev string
				if resp.Provenance != nil {
					rev = resp.Provenance.Bundles[partitionBilling].Revision
				}

				var wantTier string
				switch rev {
				case "billing-rev-old":
					if rate.String() != "5" {
						wantTier = "<rate mismatch>"
					} else {
						wantTier = "silver"
					}
				case "billing-rev-new":
					if rate.String() != "7" {
						wantTier = "<rate mismatch>"
					} else {
						wantTier = "gold"
					}
				default:
					wantTier = "<unknown revision>"
				}

				if tier != wantTier {
					select {
					case errs <- fmt.Errorf("inconsistent response: revision=%q rate=%s tier=%q (want tier %q)",
						rev, rate, tier, wantTier):
					default:
					}
					return
				}
			}
		}()
	}

	for i := range 20 {
		b := oldRev
		if i%2 == 0 {
			b = newRev
		}
		if _, err := f.publish(partitionBilling, b); err != nil {
			close(done)
			readers.Wait()
			t.Fatalf("publishing revision %q failed: %v", b.Manifest.Revision, err)
		}
	}

	close(done)
	readers.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}
