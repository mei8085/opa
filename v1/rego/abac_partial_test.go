// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package rego

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

// These tests pin the authorization semantics of an attribute-based access
// control (ABAC) policy across partial evaluation. The split of information
// mirrors a real deployment:
//
//   - Resource policy (roles, required clearance) lives in the data document and
//     is known when the policy is partially evaluated ("pre-compiled").
//   - Identity attributes of the caller (role, clearance level, revocation) live
//     in the input document and are only supplied at request time, so they are
//     unknown during partial evaluation.
//
// The residual policy produced by partial evaluation must make the same
// authorization decision as the original rule for every request: allow, deny,
// or no decision at all (undefined). In particular, pre-compilation must never
// turn an attribute that is only known at request time into a known permission.

// abacModule is an ABAC rule without a default value. When none of its bodies
// holds, data.abac.allow is undefined, so the three authorization outcomes
// (allow / deny / no decision) are all observable.
const abacModule = `
package abac

import rego.v1

# A request is allowed when the caller's role is permitted on the resource,
# their clearance meets the resource requirement, and the identity has not
# been revoked. Every condition reads an identity attribute from input.
allow if {
	data.resource_roles[input.resource][input.subject.role]
	input.subject.clearance >= data.resource_clearance[input.resource]
	not data.revoked[input.subject.user]
}
`

// abacDefaultDenyModule adds a default-deny fallback to abacModule. With the
// default, the rule is always defined: a failed authorization is an explicit
// false rather than an undefined document.
const abacDefaultDenyModule = `
package abac

import rego.v1

default allow := false

allow if {
	data.resource_roles[input.resource][input.subject.role]
	input.subject.clearance >= data.resource_clearance[input.resource]
	not data.revoked[input.subject.user]
}
`

func abacStoreData() map[string]any {
	return map[string]any{
		"resource_roles": map[string]any{
			"doc_alpha": map[string]any{"editor": true, "viewer": true},
			"doc_beta":  map[string]any{"editor": true},
		},
		"resource_clearance": map[string]any{
			"doc_alpha": 1,
			"doc_beta":  3,
		},
		"revoked": map[string]any{
			"mallory": true,
		},
	}
}

// decision is the authorization outcome of evaluating data.abac.allow against
// one concrete input.
type decision struct {
	// defined reports whether the allow document produced a value at all.
	defined bool
	// allowed is its value when defined. With a default-deny rule an explicit
	// denial shows up as defined=true, allowed=false.
	allowed bool
}

// evalDecision runs the (original or residual) query and reports its
// authorization decision. The outcome is expressed purely in terms of
// authorization semantics, never in terms of how the query was compiled or
// optimized.
func evalDecision(t *testing.T, r *Rego) decision {
	t.Helper()
	rs, err := r.Eval(t.Context())
	if err != nil {
		t.Fatalf("unexpected eval error: %v", err)
	}
	if len(rs) == 0 {
		return decision{defined: false}
	}
	allowed, ok := rs[0].Expressions[0].Value.(bool)
	if !ok {
		t.Fatalf("expected boolean allow decision, got %v", rs[0].Expressions[0].Value)
	}
	return decision{defined: true, allowed: allowed}
}

// TestPartialResultABACResidualEquivalence drives an ABAC policy through
// PartialResult, the pre-compilation entry point that returns a residual query
// to be evaluated once request-time identity attributes are known. For every
// request the residual policy and the original rule must reach the same
// allow/deny/no-decision outcome.
func TestPartialResultABACResidualEquivalence(t *testing.T) {
	tests := []struct {
		note   string
		module string
		input  map[string]any
		want   decision
	}{
		{
			note:   "role permitted and clearance sufficient -> allow",
			module: abacModule,
			input: map[string]any{
				"resource": "doc_alpha",
				"subject": map[string]any{
					"user": "alice", "role": "editor", "clearance": 2,
				},
			},
			want: decision{defined: true, allowed: true},
		},
		{
			note:   "viewer role with exact required clearance -> allow",
			module: abacModule,
			input: map[string]any{
				"resource": "doc_alpha",
				"subject": map[string]any{
					"user": "bob", "role": "viewer", "clearance": 1,
				},
			},
			want: decision{defined: true, allowed: true},
		},
		{
			note:   "role not permitted on resource -> deny (undefined without default)",
			module: abacModule,
			input: map[string]any{
				"resource": "doc_beta",
				"subject": map[string]any{
					"user": "bob", "role": "viewer", "clearance": 5,
				},
			},
			want: decision{defined: false},
		},
		{
			note:   "clearance below requirement -> deny (undefined without default)",
			module: abacModule,
			input: map[string]any{
				"resource": "doc_beta",
				"subject": map[string]any{
					"user": "alice", "role": "editor", "clearance": 2,
				},
			},
			want: decision{defined: false},
		},
		{
			note:   "revoked identity -> deny (undefined without default)",
			module: abacModule,
			input: map[string]any{
				"resource": "doc_alpha",
				"subject": map[string]any{
					"user": "mallory", "role": "editor", "clearance": 5,
				},
			},
			want: decision{defined: false},
		},
		{
			note:   "identity attributes absent at request time -> no decision, never an allow",
			module: abacModule,
			input:  map[string]any{"resource": "doc_alpha"},
			want:   decision{defined: false},
		},
		{
			note:   "empty input -> no decision, never an allow",
			module: abacModule,
			input:  map[string]any{},
			want:   decision{defined: false},
		},
		{
			note:   "default deny: role permitted and clearance sufficient -> allow",
			module: abacDefaultDenyModule,
			input: map[string]any{
				"resource": "doc_alpha",
				"subject": map[string]any{
					"user": "alice", "role": "editor", "clearance": 2,
				},
			},
			want: decision{defined: true, allowed: true},
		},
		{
			note:   "default deny: role not permitted -> explicit false",
			module: abacDefaultDenyModule,
			input: map[string]any{
				"resource": "doc_beta",
				"subject": map[string]any{
					"user": "bob", "role": "viewer", "clearance": 5,
				},
			},
			want: decision{defined: true, allowed: false},
		},
		{
			note:   "default deny: revoked identity -> explicit false",
			module: abacDefaultDenyModule,
			input: map[string]any{
				"resource": "doc_alpha",
				"subject": map[string]any{
					"user": "mallory", "role": "editor", "clearance": 5,
				},
			},
			want: decision{defined: true, allowed: false},
		},
		{
			note:   "default deny: identity attributes absent -> explicit false, never an allow",
			module: abacDefaultDenyModule,
			input:  map[string]any{"resource": "doc_alpha"},
			want:   decision{defined: true, allowed: false},
		},
		{
			note:   "default deny: empty input -> explicit false, never an allow",
			module: abacDefaultDenyModule,
			input:  map[string]any{},
			want:   decision{defined: true, allowed: false},
		},
	}

	for _, tc := range tests {
		t.Run(tc.note, func(t *testing.T) {
			ctx := t.Context()

			// Original rule evaluated directly against the full request.
			original := New(
				Query("data.abac.allow"),
				Module("policy.rego", tc.module),
				Store(inmem.NewFromObject(abacStoreData())),
				Input(tc.input),
			)
			want := evalDecision(t, original)
			if want != tc.want {
				t.Fatalf("sanity check: original rule decided %+v, expected %+v", want, tc.want)
			}

			// Pre-compile with identity attributes unknown. No input is supplied
			// here; the whole input document stays unknown, so request-time
			// attributes cannot be folded into a fixed permission.
			pr, err := New(
				Query("data.abac.allow"),
				Module("policy.rego", tc.module),
				Store(inmem.NewFromObject(abacStoreData())),
			).PartialResult(ctx)
			if err != nil {
				t.Fatalf("unexpected PartialResult error: %v", err)
			}

			// PartialResult packages the residual queries as __result__ rules in
			// the partial namespace and moves the inlined conditions into
			// partial support modules. Walk every generated module: the residual
			// policy as a whole must still gate on an input attribute that is
			// only known at request time. Had partial evaluation resolved such an
			// attribute against the known data document, some residual rule body
			// would be empty (unconditionally true) or free of input refs, and
			// the decision would no longer track the caller's identity.
			assertResidualDependsOnInput(t, pr.compiler.Modules)
			// Residual policy evaluated at request time with the identity now
			// known. Its authorization decision must match the original rule.
			residual := pr.Rego(Input(tc.input))
			if got := evalDecision(t, residual); got != want {
				t.Errorf("residual decision %+v does not match original rule decision %+v", got, want)
			}
		})
	}
}

// residualDependsOnInputError inspects the modules produced by partial
// evaluation. It enforces that (1) partial evaluation emitted at least one
// residual rule, and (2) every non-default residual rule either reads the
// input document directly or delegates to another residual rule that does — no
// residual path may be an unconditional permission or be expressible without
// the request-time identity attributes.
func residualDependsOnInputError(modules map[string]*ast.Module) error {
	var residualModules []*ast.Module
	for id, m := range modules {
		if strings.HasPrefix(id, "__partialresult__") || strings.HasPrefix(id, "__partialsupport__") {
			residualModules = append(residualModules, m)
		}
	}
	if len(residualModules) == 0 {
		return errors.New("partial evaluation produced no residual modules")
	}

	ruleCount := 0
	for _, m := range residualModules {
		for _, rule := range m.Rules {
			ruleCount++
			// Default fallbacks (e.g. default allow := false) carry no body and
			// cannot grant access, so they are not residual permission paths.
			if rule.Default {
				continue
			}
			if len(rule.Body) == 0 {
				return fmt.Errorf("residual rule %v is unconditional; request-time attributes were pre-evaluated into a permission", rule.Head)
			}
			if !referencesInput(rule.Body) && !referencesPartialModule(rule.Body) {
				return fmt.Errorf("residual rule %v neither references request-time input nor delegates to a residual module: %v", rule.Head, rule.Body)
			}
		}
	}
	if ruleCount == 0 {
		return errors.New("expected residual rules, got none")
	}
	return nil
}

func assertResidualDependsOnInput(t *testing.T, modules map[string]*ast.Module) {
	t.Helper()
	if err := residualDependsOnInputError(modules); err != nil {
		t.Fatal(err)
	}
}

// referencesPartialModule reports whether the body delegates to a rule living
// in the partial namespace, i.e. to another residual rule that carries the
// actual input-dependent conditions.
func referencesPartialModule(body ast.Body) bool {
	found := false
	ast.WalkRefs(body, func(r ast.Ref) bool {
		if len(r) > 1 && r[0].Equal(ast.DefaultRootDocument) {
			if s, ok := r[1].Value.(ast.String); ok && strings.HasPrefix(string(s), "partial") {
				found = true
			}
		}
		return false
	})
	return found
}

// referencesInput reports whether any expression in the body reads the input
// document. It is the structural guard backing the semantic requirement that
// request-time identity attributes remain part of the residual decision.
func referencesInput(body ast.Body) bool {
	found := false
	ast.WalkRefs(body, func(r ast.Ref) bool {
		if r.HasPrefix(ast.InputRootRef) {
			found = true
		}
		return false
	})
	return found
}

// TestPartialABACKnownResourceUnknownIdentity covers the mixed case where part
// of the request is known at pre-compilation time (the resource) while the
// caller's identity is still unknown. Partial evaluation may specialize on the
// known resource, but the residual decision must continue to hinge on the
// request-time identity attributes and stay equivalent to the original rule.
func TestPartialABACKnownResourceUnknownIdentity(t *testing.T) {
	ctx := t.Context()
	knownAtCompile := map[string]any{"resource": "doc_alpha"}

	pr, err := New(
		Query("data.abac.allow"),
		Module("policy.rego", abacModule),
		Store(inmem.NewFromObject(abacStoreData())),
		Input(knownAtCompile),
		// Only the identity document is unknown when the policy is pre-compiled.
		Unknowns([]string{"input.subject"}),
	).PartialResult(ctx)
	if err != nil {
		t.Fatalf("unexpected PartialResult error: %v", err)
	}

	// Every residual permission path must still gate on a request-time identity
	// attribute; the known resource alone must never produce an allow.
	if err := residualDependsOnInputError(pr.compiler.Modules); err != nil {
		t.Fatal(err)
	}

	requests := []struct {
		note string
		// subject is what arrives at request time; resource stays the one known
		// at pre-compilation.
		subject map[string]any
		want    decision
	}{
		{
			note:    "editor with sufficient clearance -> allow",
			subject: map[string]any{"user": "alice", "role": "editor", "clearance": 2},
			want:    decision{defined: true, allowed: true},
		},
		{
			note:    "viewer with exact clearance -> allow",
			subject: map[string]any{"user": "bob", "role": "viewer", "clearance": 1},
			want:    decision{defined: true, allowed: true},
		},
		{
			note:    "insufficient clearance -> deny (undefined)",
			subject: map[string]any{"user": "bob", "role": "viewer", "clearance": 0},
			want:    decision{defined: false},
		},
		{
			note:    "revoked identity -> deny (undefined)",
			subject: map[string]any{"user": "mallory", "role": "editor", "clearance": 5},
			want:    decision{defined: false},
		},
		{
			note:    "identity absent at request time -> no decision, never an allow",
			subject: nil,
			want:    decision{defined: false},
		},
	}

	for _, req := range requests {
		t.Run(req.note, func(t *testing.T) {
			input := map[string]any{"resource": "doc_alpha"}
			if req.subject != nil {
				input["subject"] = req.subject
			}

			original := New(
				Query("data.abac.allow"),
				Module("policy.rego", abacModule),
				Store(inmem.NewFromObject(abacStoreData())),
				Input(input),
			)
			want := evalDecision(t, original)
			if want != req.want {
				t.Fatalf("sanity check: original rule decided %+v, expected %+v", want, req.want)
			}

			if got := evalDecision(t, pr.Rego(Input(input))); got != want {
				t.Errorf("residual decision %+v does not match original rule decision %+v", got, want)
			}
		})
	}
}

// TestPartialABACResidualQueries covers the lower-level Partial entry point,
// which returns the residual queries and their support modules rather than a
// packaged PartialResult. The residual is re-assembled into a rule and
// evaluated: its decisions over allow, deny and no-decision requests must equal
// the original rule's.
func TestPartialABACResidualQueries(t *testing.T) {
	ctx := t.Context()

	base := func() *Rego {
		return New(
			Query("data.abac.allow"),
			Module("policy.rego", abacModule),
			Store(inmem.NewFromObject(abacStoreData())),
			// Make the request-time identity document unknown explicitly.
			Unknowns([]string{"input"}),
		)
	}

	pq, err := base().Partial(ctx)
	if err != nil {
		t.Fatalf("unexpected Partial error: %v", err)
	}
	if len(pq.Queries) == 0 {
		t.Fatal("expected at least one residual query, got none")
	}

	// No residual query may be an unconditional allow: every residual path has
	// to keep gating on an input attribute that is only known at request time.
	for i, q := range pq.Queries {
		if len(q) == 0 {
			t.Fatalf("residual query %d is empty (unconditionally true); request-time attributes were pre-evaluated into a permission", i)
		}
		if !referencesInput(q) {
			t.Fatalf("residual query %d does not reference request-time input: %v", i, q)
		}
	}

	requests := []struct {
		note  string
		input map[string]any
		want  decision
	}{
		{
			note: "allow",
			input: map[string]any{
				"resource": "doc_alpha",
				"subject":  map[string]any{"user": "alice", "role": "editor", "clearance": 2},
			},
			want: decision{defined: true, allowed: true},
		},
		{
			note: "deny: insufficient clearance",
			input: map[string]any{
				"resource": "doc_beta",
				"subject":  map[string]any{"user": "alice", "role": "editor", "clearance": 2},
			},
			want: decision{defined: false},
		},
		{
			note: "deny: revoked",
			input: map[string]any{
				"resource": "doc_alpha",
				"subject":  map[string]any{"user": "mallory", "role": "editor", "clearance": 5},
			},
			want: decision{defined: false},
		},
		{
			note:  "no decision: identity missing",
			input: map[string]any{"resource": "doc_alpha"},
			want:  decision{defined: false},
		},
		{
			note:  "no decision: empty input",
			input: map[string]any{},
			want:  decision{defined: false},
		},
	}

	for _, req := range requests {
		t.Run(req.note, func(t *testing.T) {
			original := New(
				Query("data.abac.allow"),
				Module("policy.rego", abacModule),
				Store(inmem.NewFromObject(abacStoreData())),
				Input(req.input),
			)
			want := evalDecision(t, original)
			if want != req.want {
				t.Fatalf("sanity check: original rule decided %+v, expected %+v", want, req.want)
			}

			// Evaluate each residual query as its own rule. Authorization is the
			// OR of the residual paths: any one defined and true means allow.
			got := decision{defined: false}
			for i, q := range pq.Queries {
				idx := strconv.Itoa(i)
				var b strings.Builder
				b.WriteString("package residual\n\nimport rego.v1\n\nr")
				b.WriteString(idx)
				b.WriteString(" if {\n\t")
				b.WriteString(q.String())
				b.WriteString("\n}\n")
				opts := []func(*Rego){
					Module("residual.rego", b.String()),
					Query("data.residual.r" + idx),
					Store(inmem.NewFromObject(abacStoreData())),
					Input(req.input),
				}
				for _, m := range pq.Support {
					opts = append(opts, ParsedModule(m))
				}
				if d := evalDecision(t, New(opts...)); d.defined && d.allowed {
					got = decision{defined: true, allowed: true}
				}
			}

			if got != want {
				t.Errorf("residual decision %+v does not match original rule decision %+v\nresidual queries: %v", got, want, pq.Queries)
			}
		})
	}
}
