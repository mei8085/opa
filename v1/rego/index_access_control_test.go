// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package rego

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown"
)

// The rule index sits between query preparation and evaluation: it decides
// which rules evaluation is offered as candidates. It is an optimisation, so
// whatever it leaves out has to be rules that could not have changed the
// answer -- and access control is where that promise is easiest to break. A
// subject's attributes are composite: groups and permissions are collections,
// or objects inside collections. The rules below read them in several shapes,
// of which some the index splits the trie on and others it can only check per
// candidate, or not at all.
//
// The policy can answer "allow", "deny" or "review", can be undefined when no
// rule applies, and can conflict when two rules disagree -- so every outcome
// the index has to preserve is reachable from one policy. `allowed` is a
// boolean document whose rules agree on their value, which lets evaluation stop
// at the first that holds; that is what turns the index's per-candidate
// collection checks off, and the rules it then cannot exclude still have to
// take part in the answer.
const accessControlPolicy = `package authz

import rego.v1

# Rules that read the subject in different shapes.

decision := "allow" if {
	input.action == "write"
	some group in input.subject.groups
	group == "admins"
}

decision := "allow" if {
	input.subject.role == "owner"
	input.resource.owner == input.subject.name
}

decision := "deny" if {
	some group in input.subject.groups
	group == "blocked"
}

decision := "review" if {
	input.subject.role == "auditor"
	input.action == "read"
	input.subject.perms[_] == "read"
}

# The group lookups the index records as collection membership: it can ask, per
# candidate, whether the subject is a key of the collection the rule reads.
# These share every condition the trie narrows on -- the action and the resource
# are the same for both -- so what tells them apart is the lookup, and whichever
# rule the subject belongs to still has to be evaluated.
decision := "allow" if {
	input.action == "read"
	input.resource.foo == "A"
	data.groups.g1.members[input.subject.name]
}

decision := "deny" if {
	input.action == "read"
	input.resource.foo == "A"
	data.groups.g3.members[input.subject.name]
}

# The same question in the "in" shape, which the index does not narrow on but
# which must still select the same rules.
decision := "allow" if {
	input.action == "delete"
	input.subject.name in data.writers
}

# A boolean document: its rules agree on true, so evaluation may stop at the
# first that holds, and the index does not get to exclude candidates by their
# collection lookups. The rules still have to answer together, whichever the
# subject matches.
allowed if {
	input.action == "write"
	input.subject.name in data.writers
}

allowed if {
	input.action == "write"
	data.groups.g1.members[input.subject.name]
}

allowed if {
	input.action == "write"
	not data.groups.g3.members[input.subject.name]
}
`

// accessControlData holds the collections the group rules consult. g1 and g3
// share a member so that a subject can be in a permitting and the denying group
// at once, which is what a conflict needs, and frank is both a writer and in
// the denying group, so that a document whose rules agree on their value has a
// rule the other rules would exclude him from. The groups are objects so that
// the index can compare the subject's name against their keys; writers is an
// array so that the "in" shape has a collection of values to ask for.
func accessControlData() map[string]any {
	return map[string]any{
		"groups": map[string]any{
			"g1": map[string]any{"members": map[string]any{"alice": true, "carol": true}},
			"g2": map[string]any{"members": map[string]any{"bob": true}},
			"g3": map[string]any{"members": map[string]any{"carol": true, "dave": true, "frank": true}},
		},
		"writers": []any{"alice", "bob", "frank"},
	}
}

func newAccessControlQuery(t *testing.T, query string) PreparedEvalQuery {
	t.Helper()

	pq, err := New(
		Query(query),
		Module("authz.rego", accessControlPolicy),
		Store(inmem.NewFromObject(accessControlData())),
	).PrepareForEval(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return pq
}

// undefined is what an outcome that produces no values is compared as, so that
// it cannot be mistaken for the value "[]" a rule might produce.
const undefined = "<undefined>"

// accessOutcome is what a request produced, in a form two evaluations can be
// compared with: the expression values, or the evaluation error.
type accessOutcome struct {
	values string // fmt.Sprint of the expression values; undefined when there were none
	code   string // topdown error code; empty on success
	msg    string // error message; empty on success
}

func (o accessOutcome) String() string {
	if o.code != "" {
		return o.code + ": " + o.msg
	}
	return o.values
}

// accessRequest is one request, the outcome the policy owes it, and the values
// a conflict must name.
type accessRequest struct {
	note      string
	input     map[string]any
	want      []string // expected expression values; empty means undefined
	code      string   // expected error code; empty means evaluation succeeds
	conflicts []string // values the conflict message must list, when code is set
}

// decisionRequests are requests for `data.authz.decision`, which can be
// undefined and can conflict. Subjects range over the group memberships the
// data holds and over shapes it does not: absent fields, composite values,
// scalars where a collection is expected.
var decisionRequests = []accessRequest{
	{
		note:  "admin writes",
		input: map[string]any{"subject": map[string]any{"name": "alice", "role": "member", "groups": []any{"admins"}}, "action": "write"},
		want:  []string{"allow"},
	},
	{
		// A request no rule covers: the rules the index leaves as candidates
		// have to leave the answer undefined rather than settle on one of them.
		note:  "admin reads an unrelated resource",
		input: map[string]any{"subject": map[string]any{"name": "alice", "role": "member", "groups": []any{"admins"}}, "action": "read", "resource": map[string]any{"foo": "B"}},
		want:  nil,
	},
	{
		// The role and the resource are enough; the subject's groups are absent,
		// and the index must not need them to reach the rule.
		note:  "owner edits their own resource without groups",
		input: map[string]any{"subject": map[string]any{"name": "alice", "role": "owner"}, "action": "modify", "resource": map[string]any{"owner": "alice"}},
		want:  []string{"allow"},
	},
	{
		note:  "owner edits another subject's resource",
		input: map[string]any{"subject": map[string]any{"name": "alice", "role": "owner"}, "action": "modify", "resource": map[string]any{"owner": "bob"}},
		want:  nil,
	},
	{
		note:  "auditor reads with the permission",
		input: map[string]any{"subject": map[string]any{"name": "alice", "role": "auditor", "perms": []any{"read"}}, "action": "read"},
		want:  []string{"review"},
	},
	{
		note:  "auditor reads without the permission",
		input: map[string]any{"subject": map[string]any{"name": "alice", "role": "auditor", "perms": []any{}}, "action": "read"},
		want:  nil,
	},
	{
		// A composite permission: the index must carry the value without
		// mistaking it for the string the rule asks for.
		note:  "auditor holds a composite permission",
		input: map[string]any{"subject": map[string]any{"name": "alice", "role": "auditor", "perms": []any{map[string]any{"action": "read"}}}, "action": "read"},
		want:  nil,
	},
	{
		// The index narrows to the two group rules by action and resource and
		// can do no more; the membership check decides which of them applies.
		note:  "member of a permitting group reads the shared resource",
		input: map[string]any{"subject": map[string]any{"name": "alice", "groups": []any{}}, "action": "read", "resource": map[string]any{"foo": "A"}},
		want:  []string{"allow"},
	},
	{
		note:  "member of a permitting group reads another resource",
		input: map[string]any{"subject": map[string]any{"name": "alice", "groups": []any{}}, "action": "read", "resource": map[string]any{"foo": "B"}},
		want:  nil,
	},
	{
		note:  "member of the denying group reads the shared resource",
		input: map[string]any{"subject": map[string]any{"name": "dave", "groups": []any{}}, "action": "read", "resource": map[string]any{"foo": "A"}},
		want:  []string{"deny"},
	},
	{
		// In a permitting and in the denying group at once: both rules apply, so
		// neither the index nor full evaluation may settle on one of them.
		note:      "member of a permitting and the denying group",
		input:     map[string]any{"subject": map[string]any{"name": "carol", "groups": []any{}}, "action": "read", "resource": map[string]any{"foo": "A"}},
		code:      topdown.ConflictErr,
		conflicts: []string{"allow", "deny"},
	},
	{
		note:  "writer deletes",
		input: map[string]any{"subject": map[string]any{"name": "bob"}, "action": "delete"},
		want:  []string{"allow"},
	},
	{
		note:  "non-writer deletes",
		input: map[string]any{"subject": map[string]any{"name": "erin"}, "action": "delete"},
		want:  nil,
	},
	{
		note:  "blocked subject",
		input: map[string]any{"subject": map[string]any{"name": "erin", "groups": []any{"blocked"}}, "action": "read"},
		want:  []string{"deny"},
	},
	{
		note:  "subject in a composite group",
		input: map[string]any{"subject": map[string]any{"name": "alice", "groups": []any{map[string]any{"id": "admins"}}}, "action": "write"},
		want:  nil,
	},
	{
		note:  "subject absent",
		input: map[string]any{"action": "write"},
		want:  nil,
	},
	{
		note:  "subject has no name",
		input: map[string]any{"subject": map[string]any{"role": "owner"}, "action": "read", "resource": map[string]any{"foo": "A"}},
		want:  nil,
	},
	{
		// Not an object: every reference into it is undefined, and the outcome
		// is the same whether or not the index was involved.
		note:  "subject is not an object",
		input: map[string]any{"subject": "alice", "action": "write"},
		want:  nil,
	},
}

// allowedRequests are requests for `data.authz.allowed`, whose rules agree on
// true: evaluation may stop at the first that holds, and the index cannot cut
// candidates by their collection lookups. The answer still has to be the same
// either way.
var allowedRequests = []accessRequest{
	{
		note:  "writer writes",
		input: map[string]any{"subject": map[string]any{"name": "alice"}, "action": "write"},
		want:  []string{"true"},
	},
	{
		// In a permitting and the denying group: one rule holds by being a
		// writer, another by the g1 lookup, and the last one fails -- the
		// document is still true.
		note:  "member of the permitting group writes",
		input: map[string]any{"subject": map[string]any{"name": "carol"}, "action": "write"},
		want:  []string{"true"},
	},
	{
		// The g1 lookup misses, the writer lookup misses, and only "not in g3"
		// holds.
		note:  "subject outside every group writes",
		input: map[string]any{"subject": map[string]any{"name": "erin"}, "action": "write"},
		want:  []string{"true"},
	},
	{
		// A writer the "not in g3" rule would exclude, and that the writer rule
		// admits: the rules still agree, so the answer is true whichever of
		// them the index leaves as candidates.
		note:  "writer in the denying group writes",
		input: map[string]any{"subject": map[string]any{"name": "frank"}, "action": "write"},
		want:  []string{"true"},
	},
	{
		// Every rule misses or is undefined.
		note:  "member of the denying group writes",
		input: map[string]any{"subject": map[string]any{"name": "dave"}, "action": "write"},
		want:  nil,
	},
	{
		note:  "reader reads",
		input: map[string]any{"subject": map[string]any{"name": "alice"}, "action": "read"},
		want:  nil,
	},
	{
		note:  "subject absent",
		input: map[string]any{"action": "write"},
		want:  nil,
	},
}

func evalAccessControl(t *testing.T, pq PreparedEvalQuery, input map[string]any, indexing bool) accessOutcome {
	t.Helper()

	rs, err := pq.Eval(t.Context(), EvalInput(input), EvalRuleIndexing(indexing))
	if err != nil {
		tdErr, ok := errors.AsType[*topdown.Error](err)
		if !ok {
			t.Fatalf("expected a topdown error, got %T: %v", err, err)
		}
		return accessOutcome{code: tdErr.Code, msg: tdErr.Message}
	}

	values := make([]any, 0, len(rs))
	for _, result := range rs {
		for _, expr := range result.Expressions {
			values = append(values, expr.Value)
		}
	}
	if len(values) == 0 {
		return accessOutcome{values: undefined}
	}
	return accessOutcome{values: fmt.Sprint(values)}
}

// wantValues renders what the policy owes the request, in the form
// evalAccessControl reports it.
func (r accessRequest) wantValues() string {
	if len(r.want) == 0 {
		return undefined
	}
	return fmt.Sprint(r.want)
}

// checkAccessOutcome asserts the outcome the policy owes the request. Matching
// the golden answer, rather than only matching the other indexing setting,
// keeps the test from accepting an index and a full evaluation that are wrong
// in the same way.
func checkAccessOutcome(t *testing.T, got accessOutcome, req accessRequest) {
	t.Helper()

	if req.code == "" {
		if got.code != "" {
			t.Fatalf("expected %s, got error %v", req.wantValues(), got)
		}
		if exp := req.wantValues(); got.values != exp {
			t.Fatalf("expected %s, got %s", exp, got.values)
		}
		return
	}

	if got.code != req.code {
		t.Fatalf("expected %s, got %v", req.code, got)
	}
	for _, v := range req.conflicts {
		if !strings.Contains(got.msg, strconv.Quote(v)) {
			t.Fatalf("expected %q among the conflicting values, got %v", v, got)
		}
	}
}

// accessDocument is one document of the policy under test and the requests run
// against it.
type accessDocument struct {
	query    string
	requests []accessRequest
}

var accessDocuments = []accessDocument{
	{"data.authz.decision", decisionRequests},
	{"data.authz.allowed", allowedRequests},
}

// TestAccessControlIndexMatchesFullEval is the property the index owes its
// callers: the same request against the same prepared query answers the same
// with the index as without it, and both answer what the policy says.
func TestAccessControlIndexMatchesFullEval(t *testing.T) {
	for _, doc := range accessDocuments {
		pq := newAccessControlQuery(t, doc.query)

		for _, req := range doc.requests {
			t.Run(doc.query+"/"+req.note, func(t *testing.T) {
				full := evalAccessControl(t, pq, req.input, false)
				indexed := evalAccessControl(t, pq, req.input, true)

				if full != indexed {
					t.Fatalf("full evaluation %v != indexed %v for input %v", full, indexed, req.input)
				}
				checkAccessOutcome(t, indexed, req)
			})
		}
	}
}

// TestAccessControlSubjectAttributeVariation varies the subject's attributes
// one dimension at a time and combines them with each request shape: which
// groups it has and in which shape, whether the role is present and what it is,
// whether the permissions are there and what they hold, and which collection's
// member its name makes it. Every combination is run with and without the
// index, because what the index reads for a dimension is what it narrows on,
// and a rule it wrongly narrowed away shows up as the two disagreeing on that
// combination alone.
func TestAccessControlSubjectAttributeVariation(t *testing.T) {
	// The names cycle through every collection's members, and through ones no
	// collection holds: what a rule's lookup answers is what the index checks
	// per candidate.
	names := []string{"alice", "bob", "carol", "dave", "erin", "frank"}

	subjects := []struct {
		note   string
		fields map[string]any
		scalar bool // the subject is not an object
	}{
		{note: "no attributes", fields: map[string]any{}},
		{note: "no groups", fields: map[string]any{"groups": []any{}}},
		{note: "admin", fields: map[string]any{"groups": []any{"admins"}}},
		{note: "blocked", fields: map[string]any{"groups": []any{"blocked"}}},
		{note: "admin and blocked", fields: map[string]any{"groups": []any{"admins", "blocked"}}},
		{note: "composite group", fields: map[string]any{"groups": []any{map[string]any{"id": "admins"}}}},
		{note: "groups not a collection", fields: map[string]any{"groups": "admins"}},
		{note: "role and perms", fields: map[string]any{"role": "auditor", "perms": []any{"write", "read"}}},
		{note: "owner", fields: map[string]any{"role": "owner"}},
		{note: "auditor without perms", fields: map[string]any{"role": "auditor"}},
		{note: "not an object", scalar: true},
	}

	requests := []struct {
		note string
		rest map[string]any
	}{
		{note: "write", rest: map[string]any{"action": "write"}},
		{note: "read", rest: map[string]any{"action": "read", "resource": map[string]any{"foo": "A"}}},
		{note: "modify", rest: map[string]any{"action": "modify", "resource": map[string]any{"owner": "alice"}}},
		{note: "delete", rest: map[string]any{"action": "delete"}},
		{note: "no action", rest: map[string]any{}},
	}

	for _, doc := range accessDocuments {
		pq := newAccessControlQuery(t, doc.query)

		for _, s := range subjects {
			for _, r := range requests {
				for _, name := range names {
					t.Run(fmt.Sprintf("%s/%s/%s/%s", doc.query, s.note, r.note, name), func(t *testing.T) {
						input := make(map[string]any, len(r.rest)+1)
						for k, v := range r.rest {
							input[k] = v
						}
						if s.scalar {
							input["subject"] = name
						} else {
							subject := map[string]any{"name": name}
							for k, v := range s.fields {
								subject[k] = v
							}
							input["subject"] = subject
						}

						full := evalAccessControl(t, pq, input, false)
						indexed := evalAccessControl(t, pq, input, true)
						if full != indexed {
							t.Fatalf("full evaluation %v != indexed %v for input %v", full, indexed, input)
						}
					})
				}
			}
		}
	}
}

// TestAccessControlRepeatedRequestsShareOnePreparedQuery feeds one prepared
// query a sequence of requests rather than one. The index is consulted afresh
// on every evaluation, so an answer must not depend on what was asked before
// it -- neither on the candidates a previous lookup selected nor on the indexing
// setting of the request before. The requests are run in both orders, each one
// immediately re-asked under the other indexing setting, and the whole sequence
// is run twice so that a request served first has to give the same answer when
// it is served last.
func TestAccessControlRepeatedRequestsShareOnePreparedQuery(t *testing.T) {
	for _, doc := range accessDocuments {
		pq := newAccessControlQuery(t, doc.query)

		forward := make([]int, len(doc.requests))
		for i := range forward {
			forward[i] = i
		}
		backward := slices.Clone(forward)
		slices.Reverse(backward)

		for round := range 2 {
			for _, order := range [][]int{forward, backward} {
				for pos, i := range order {
					req := doc.requests[i]
					// Alternate which setting serves the request first, so a
					// candidate left behind by an indexed lookup would be
					// visible to a full evaluation that follows it, and the
					// other way around.
					indexing := (pos+round)%2 == 0

					got := evalAccessControl(t, pq, req.input, indexing)
					other := evalAccessControl(t, pq, req.input, !indexing)
					if got != other {
						t.Fatalf("%s round %d request %q: indexing=%v gave %v, indexing=%v gave %v",
							doc.query, round, req.note, indexing, got, !indexing, other)
					}
					checkAccessOutcome(t, got, req)
				}
			}
		}
	}
}
