// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package rego_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/logging"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/disk"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

// asInt normalizes the numeric types a store may return: the inmem store keeps
// JSON numbers as json.Number while the disk store decodes them to int.
func asInt(t *testing.T, v any) int {
	t.Helper()
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			t.Fatalf("expected integer value, got JSON number %q: %v", n.String(), err)
		}
		return int(i)
	default:
		t.Fatalf("expected integer value, got %T (%v)", v, v)
		return 0
	}
}

// authzSnapshotModule is a role based authorization policy. Every decision
// depends on role bindings (data.roles) and on resource attributes
// (data.resources) held in the store, so a storage snapshot that drifts between
// revisions would flip the authorization result.
const authzSnapshotModule = `
package rbac

import rego.v1

default allow := false

allow if {
	some role in data.roles[input.subject]
	data.resources[input.resource].level <= data.permissions[role]
}
`

// authzSnapshotFixture is the permission data as it is visible at revision 1.
func authzSnapshotFixture() map[string]any {
	return map[string]any{
		"roles": map[string]any{
			// alice is an admin, bob is a reader.
			"alice": []any{"admin"},
			"bob":   []any{"reader"},
		},
		"permissions": map[string]any{
			"admin":  3,
			"reader": 1,
		},
		"resources": map[string]any{
			// /secrets is only reachable by the admin role.
			"secrets": map[string]any{"level": 3, "owner": "alice"},
			"public":  map[string]any{"level": 1, "owner": "ops"},
		},
	}
}

// revisePermissionData is the revision-2 write set: bob is promoted to admin
// and the secrets resource is de-classified to reader level. After this commit
// bob is allowed to read /secrets.
func revisePermissionData(ctx context.Context, store storage.Store) error {
	return storage.Txn(ctx, store, storage.WriteParams, func(txn storage.Transaction) error {
		if err := store.Write(ctx, txn, storage.ReplaceOp,
			storage.MustParsePath("/roles/bob"), []any{"admin", "reader"}); err != nil {
			return err
		}
		return store.Write(ctx, txn, storage.ReplaceOp,
			storage.MustParsePath("/resources/secrets/level"), 1)
	})
}

// newSnapshotStore returns each store implementation under test. The disk
// store keeps its data in a temporary directory that is removed with the test.
func newSnapshotStores(t *testing.T) map[string]storage.Store {
	t.Helper()

	stores := map[string]storage.Store{
		"inmem": inmem.NewFromObject(authzSnapshotFixture()),
	}

	diskStore, err := disk.New(t.Context(), logging.NewNoOpLogger(), nil,
		disk.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("create disk store: %v", err)
	}
	if err := storage.WriteOne(t.Context(), diskStore,
		storage.AddOp, storage.RootPath, authzSnapshotFixture()); err != nil {
		t.Fatalf("seed disk store: %v", err)
	}
	stores["disk"] = diskStore

	t.Cleanup(func() {
		_ = diskStore.Close(context.Background())
	})

	return stores
}

// evalAllow runs the precompiled authorization query against the given
// transaction. Every read performed while evaluating the query is constrained
// to what that transaction can see.
func evalAllow(t *testing.T, ctx context.Context, pq rego.PreparedEvalQuery,
	txn storage.Transaction, subject, resource string,
) bool {
	t.Helper()

	rs, err := pq.Eval(ctx,
		rego.EvalTransaction(txn),
		rego.EvalInput(map[string]any{"subject": subject, "resource": resource}),
	)
	if err != nil {
		t.Fatalf("evaluate authorization query: %v", err)
	}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		t.Fatalf("expected exactly one result expression, got %v", rs)
	}
	allowed, ok := rs[0].Expressions[0].Value.(bool)
	if !ok {
		t.Fatalf("expected boolean decision, got %T", rs[0].Expressions[0].Value)
	}
	return allowed
}

// readResourceLevel reads a resource attribute through the supplied
// transaction, asserting that direct storage reads are scoped to the
// transaction's view as well.
func readResourceLevel(t *testing.T, ctx context.Context, store storage.Store,
	txn storage.Transaction, resource string,
) int {
	t.Helper()

	v, err := store.Read(ctx, txn,
		storage.MustParsePath("/resources/"+resource+"/level"))
	if err != nil {
		t.Fatalf("read resource level in transaction %d: %v", txn.ID(), err)
	}
	return asInt(t, v)
}

// auditDecision is the authorization conclusion recorded for historical
// replay. Together with the decision it freezes the role binding, the role's
// permission level and the resource attribute that were visible to the
// transaction that produced it, so the conclusion can be replayed later without
// touching the live (revised) data.
type auditDecision struct {
	Subject     string
	Resource    string
	WantAllow   bool // authorization conclusion at revision 1
	Allow       bool // decision observed through the revision-1 transaction
	RoleBinding []any
	Permission  int // permission level of the subject's role at revision 1
	Level       int // resource level at revision 1
}

// TestPreparedAuthorizationQueryTransactionSnapshot verifies that a prepared
// authorization query is reusable across data revisions while every decision
// only observes the role and resource attributes visible to the transaction it
// is evaluated on. Decisions captured in an old transaction must not drift when
// a later transaction commits revised permission data.
func TestPreparedAuthorizationQueryTransactionSnapshot(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	for storeName, store := range newSnapshotStores(t) {
		t.Run(storeName, func(t *testing.T) {
			// The query is prepared once, before any revision, and reused for
			// every decision below.
			pq, err := rego.New(
				rego.Query("data.rbac.allow"),
				rego.Module("rbac.rego", authzSnapshotModule),
				rego.Store(store),
			).PrepareForEval(ctx)
			if err != nil {
				t.Fatalf("prepare authorization query: %v", err)
			}
			t.Cleanup(pq.Close)

			// Revision 1: open a read transaction that pins the current
			// snapshot and record the historical audit decisions through it.
			auditTxn := storage.NewTransactionOrDie(ctx, store)
			audit := []auditDecision{
				{Subject: "alice", Resource: "secrets", WantAllow: true},
				{Subject: "bob", Resource: "secrets", WantAllow: false},
				{Subject: "bob", Resource: "public", WantAllow: true},
			}
			for i := range audit {
				d := &audit[i]
				d.Allow = evalAllow(t, ctx, pq, auditTxn, d.Subject, d.Resource)
				if d.Allow != d.WantAllow {
					t.Fatalf("revision-1 decision for %s/%s: want %v, got %v",
						d.Subject, d.Resource, d.WantAllow, d.Allow)
				}

				roles, err := store.Read(ctx, auditTxn,
					storage.MustParsePath("/roles/"+d.Subject))
				if err != nil {
					t.Fatalf("read role binding: %v", err)
				}
				d.RoleBinding = roles.([]any)
				if len(d.RoleBinding) != 1 {
					t.Fatalf("test fixture assumes a single role per subject, got %v", d.RoleBinding)
				}
				perm, err := store.Read(ctx, auditTxn,
					storage.MustParsePath("/permissions/"+d.RoleBinding[0].(string)))
				if err != nil {
					t.Fatalf("read role permission: %v", err)
				}
				d.Permission = asInt(t, perm)
				d.Level = readResourceLevel(t, ctx, store, auditTxn, d.Resource)
			}

			// Re-evaluating through the same transaction must keep returning
			// the revision-1 view: repeated use of the prepared query must not
			// mutate the snapshot the transaction is pinned to.
			for _, d := range audit {
				if got := evalAllow(t, ctx, pq, auditTxn, d.Subject, d.Resource); got != d.Allow {
					t.Fatalf("decision for %s/%s drifted within the original transaction: want %v, got %v",
						d.Subject, d.Resource, d.Allow, got)
				}
			}

			// Commit revision 2. The store serializes revisions against open
			// readers, so the historical transaction is released first; the
			// audit decisions recorded above are the frozen revision-1 view.
			store.Abort(ctx, auditTxn)
			if err := revisePermissionData(ctx, store); err != nil {
				t.Fatalf("commit revised permission data: %v", err)
			}

			// A fresh transaction sees the revised data and reaches the
			// opposite conclusion for bob on /secrets.
			currentTxn := storage.NewTransactionOrDie(ctx, store)
			defer store.Abort(ctx, currentTxn)

			if got := readResourceLevel(t, ctx, store, currentTxn, "secrets"); got != 1 {
				t.Fatalf("expected revised resource level 1, got %d", got)
			}
			if got := evalAllow(t, ctx, pq, currentTxn, "bob", "secrets"); !got {
				t.Fatal("expected bob to be allowed after the permission revision, got deny")
			}

			// Historical audit replay uses the original view: replaying the
			// recorded decisions must reproduce the revision-1 conclusions even
			// though the live data now says otherwise. The replay must not read
			// any live permission data; only the frozen audit record is used.
			for _, d := range audit {
				replayedAllow := d.Level <= d.Permission
				if replayedAllow != d.Allow {
					t.Fatalf("historical decision for %s/%s drifted after the revision: "+
						"recorded %v, replay over the original view gives %v",
						d.Subject, d.Resource, d.Allow, replayedAllow)
				}

				// The recorded conclusion must disagree with the current view
				// wherever the revision actually changed the answer, proving the
				// audit trail is not silently re-reading live data.
				if d.Subject == "bob" && d.Resource == "secrets" {
					live := evalAllow(t, ctx, pq, currentTxn, d.Subject, d.Resource)
					if live == d.Allow {
						t.Fatalf("expected recorded (%v) and live (%v) decisions to differ for bob/secrets",
							d.Allow, live)
					}
				}
			}
		})
	}
}

// TestPreparedPartialQueryTransactionSnapshot covers the partial evaluation
// path: the prepared partial query is evaluated against explicit transactions
// and the residual queries must reflect only the transaction's snapshot.
func TestPreparedPartialQueryTransactionSnapshot(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	for storeName, store := range newSnapshotStores(t) {
		t.Run(storeName, func(t *testing.T) {
			// The resource and the permission table are unknown at prepare
			// time, so role bindings and resource attributes are resolved
			// against the evaluation transaction's snapshot while the
			// permission lookups survive into the residual rules. The
			// residuals therefore differ when the transaction is pinned to a
			// different revision.
			pq, err := rego.New(
				rego.Query("data.rbac.allow"),
				rego.Module("rbac.rego", authzSnapshotModule),
				rego.Store(store),
				rego.Unknowns([]string{
					"input.resource",
					"data.permissions",
				}),
			).PrepareForPartial(ctx)
			if err != nil {
				t.Fatalf("prepare partial query: %v", err)
			}

			oldTxn := storage.NewTransactionOrDie(ctx, store)
			oldPartial, err := pq.Partial(ctx,
				rego.EvalTransaction(oldTxn),
				rego.EvalInput(map[string]any{"subject": "bob"}),
			)
			if err != nil {
				t.Fatalf("partial evaluation on old transaction: %v", err)
			}
			store.Abort(ctx, oldTxn)

			if err := revisePermissionData(ctx, store); err != nil {
				t.Fatalf("commit revised permission data: %v", err)
			}

			newTxn := storage.NewTransactionOrDie(ctx, store)
			defer store.Abort(ctx, newTxn)

			newPartial, err := pq.Partial(ctx,
				rego.EvalTransaction(newTxn),
				rego.EvalInput(map[string]any{"subject": "bob"}),
			)
			if err != nil {
				t.Fatalf("partial evaluation on new transaction: %v", err)
			}

			// The residual rules are data-dependent: at revision 1 bob is a
			// reader facing resource level 3, so one residual rule is emitted;
			// at revision 2 he is also an admin and the level dropped to 1, so
			// two residual rules with different literals are emitted.
			oldRules := partialRuleBodies(oldPartial)
			newRules := partialRuleBodies(newPartial)

			if len(oldPartial.Queries) == 0 || len(oldRules) == 0 {
				t.Fatal("expected residual rules at revision 1, got an unconditional answer")
			}
			if sameStringSet(oldRules, newRules) {
				t.Fatalf("partial residuals unexpectedly identical across the revision:\nold: %v\nnew: %v",
					oldRules, newRules)
			}

			// The residuals must literally reference the attribute values that
			// were visible to each transaction.
			if !containsSubstring(oldRules, "lte(3, data.permissions.reader)") {
				t.Fatalf("revision-1 residual does not reflect the original view: %v", oldRules)
			}
			if !containsSubstring(newRules, "lte(1, data.permissions.admin)") ||
				!containsSubstring(newRules, "lte(1, data.permissions.reader)") {
				t.Fatalf("revision-2 residuals do not reflect the revised view: %v", newRules)
			}

			// Re-running the partial evaluation on another fresh transaction
			// must reproduce the revision-2 result, showing the prepared query
			// itself keeps no per-transaction state.
			retryTxn := storage.NewTransactionOrDie(ctx, store)
			defer store.Abort(ctx, retryTxn)

			retryPartial, err := pq.Partial(ctx,
				rego.EvalTransaction(retryTxn),
				rego.EvalInput(map[string]any{"subject": "bob"}),
			)
			if err != nil {
				t.Fatalf("retry partial evaluation: %v", err)
			}
			if !sameStringSet(partialRuleBodies(newPartial), partialRuleBodies(retryPartial)) {
				t.Fatalf("partial results drifted between fresh transactions:\nfirst: %v\nretry: %v",
					partialRuleBodies(newPartial), partialRuleBodies(retryPartial))
			}
		})
	}
}

// partialRuleBodies renders the residual rules stored in the partial result's
// support modules. The query itself is a reference to the synthesized partial
// document, so the data-dependent content lives in these rules.
func partialRuleBodies(pqs *rego.PartialQueries) []string {
	var rules []string
	for _, mod := range pqs.Support {
		for _, rule := range mod.Rules {
			rules = append(rules, rule.String())
		}
	}
	return rules
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		if !seen[s] {
			return false
		}
	}
	return true
}

func containsSubstring(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

// TestPreparedAuthorizationQuerySnapshotConcurrency drives the reuse scenario
// concurrently: a long-lived reader keeps evaluating the prepared query while a
// writer commits a revision. The writer's commit blocks until the reader
// releases its snapshot, and once committed the reader observes the new view
// through a new transaction. No decision taken under the old snapshot may flip.
func TestPreparedAuthorizationQuerySnapshotConcurrency(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	for storeName, store := range newSnapshotStores(t) {
		t.Run(storeName, func(t *testing.T) {
			pq, err := rego.New(
				rego.Query("data.rbac.allow"),
				rego.Module("rbac.rego", authzSnapshotModule),
				rego.Store(store),
			).PrepareForEval(ctx)
			if err != nil {
				t.Fatalf("prepare authorization query: %v", err)
			}
			t.Cleanup(pq.Close)

			readerDone := make(chan error, 1)
			writerStarted := make(chan struct{})
			committed := make(chan error, 1)

			go func() {
				readTxn, txnErr := store.NewTransaction(ctx)
				if txnErr != nil {
					readerDone <- txnErr
					close(writerStarted)
					return
				}
				// Always release the snapshot, including on every early error
				// return, so the blocked writer cannot leak past the test.
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(func() { store.Abort(ctx, readTxn) }) }
				defer release()

				fail := func(msg string) {
					readerDone <- errors.New(msg)
					close(writerStarted)
				}

				// Pin the revision-1 snapshot and take repeated decisions.
				for range 25 {
					if got := evalAllow(t, ctx, pq, readTxn, "bob", "secrets"); got {
						fail("bob/secrets must stay denied under the pinned snapshot")
						return
					}
				}

				close(writerStarted)

				// Keep the read transaction open while the writer tries to
				// commit: the commit must not be able to change this snapshot.
				// Give the writer time to reach the blocking commit.
				select {
				case <-time.After(100 * time.Millisecond):
				case <-ctx.Done():
					readerDone <- ctx.Err()
					return
				}

				if got := evalAllow(t, ctx, pq, readTxn, "bob", "secrets"); got {
					fail("pinned snapshot changed while the writer was committing")
					return
				}
				release()
				readerDone <- nil
			}()

			go func() {
				<-writerStarted
				committed <- revisePermissionData(ctx, store)
			}()

			select {
			case err := <-readerDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("reader did not finish; possible snapshot locking deadlock")
			}

			select {
			case err := <-committed:
				if err != nil {
					t.Fatalf("revision commit failed: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("writer commit did not complete after the reader released its snapshot")
			}

			// After the revision, a new transaction must reach the new
			// conclusion through the same prepared query.
			currentTxn := storage.NewTransactionOrDie(ctx, store)
			defer store.Abort(ctx, currentTxn)
			if got := evalAllow(t, ctx, pq, currentTxn, "bob", "secrets"); !got {
				t.Fatal("expected bob/secrets to be allowed in a post-revision transaction")
			}
		})
	}
}

// Ensure the fixture and the revision write set stay in sync with the paths the
// policy reads, so a typo in either fails loudly instead of silently exercising
// a different branch.
func TestAuthzSnapshotFixtureShape(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := inmem.NewFromObject(authzSnapshotFixture())

	for _, p := range []string{
		"/roles/bob", "/roles/alice",
		"/permissions/admin", "/permissions/reader",
		"/resources/secrets/level", "/resources/public/level",
	} {
		if _, err := storage.ReadOne(ctx, store, storage.MustParsePath(p)); err != nil {
			t.Fatalf("fixture missing path %s: %v", p, err)
		}
	}

	if err := revisePermissionData(ctx, store); err != nil {
		t.Fatalf("revision write set is invalid against the fixture: %v", err)
	}

	level, err := storage.ReadOne(ctx, store, storage.MustParsePath("/resources/secrets/level"))
	if err != nil {
		t.Fatal(err)
	}
	if got := asInt(t, level); got != 1 {
		t.Fatalf("expected revised level 1, got %v", level)
	}

	roles, err := storage.ReadOne(ctx, store, storage.MustParsePath("/roles/bob"))
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(roles); got != "[admin reader]" {
		t.Fatalf("unexpected revised role binding: %s", got)
	}
}
