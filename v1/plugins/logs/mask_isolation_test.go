// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package logs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/util"
)

// ruleSpec is a declarative mask rule used by the helpers below.
type ruleSpec struct {
	op                maskOP
	path              string
	value             any
	failUndefinedPath bool
}

func mustBuildRuleSet(t *testing.T, onRuleError func(*maskRule, error), specs ...ruleSpec) *maskRuleSet {
	t.Helper()

	if onRuleError == nil {
		onRuleError = func(r *maskRule, err error) {
			t.Fatalf("unexpected mask rule error for %s: %v", r.String(), err)
		}
	}

	rs := &maskRuleSet{OnRuleError: onRuleError}

	for _, spec := range specs {
		opts := []maskRuleOption{withOP(spec.op)}
		if spec.value != nil {
			opts = append(opts, withValue(spec.value))
		}
		if spec.failUndefinedPath {
			opts = append(opts, withFailUndefinedPath())
		}

		rule, err := newMaskRule(spec.path, opts...)
		if err != nil {
			t.Fatalf("failed to build mask rule for %q: %v", spec.path, err)
		}

		rs.Rules = append(rs.Rules, rule)
	}

	return rs
}

func mustParseEvent(t *testing.T, raw string) EventV1 {
	t.Helper()

	var event EventV1
	if err := util.UnmarshalJSON([]byte(raw), &event); err != nil {
		t.Fatalf("failed to parse event %q: %v", raw, err)
	}

	return event
}

func mustJSONRoundTrip(t *testing.T, v any) any {
	t.Helper()

	bs, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var out any
	if err := util.UnmarshalJSON(bs, &out); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	return out
}

// assertJSONEqual compares a value against expected JSON text after
// normalizing both sides through a JSON round trip, so the concrete Go types
// used by table inputs (e.g. json.Number vs float64) do not matter.
func assertJSONEqual(t *testing.T, got any, wantJSON string) {
	t.Helper()

	var want any
	if err := util.UnmarshalJSON([]byte(wantJSON), &want); err != nil {
		t.Fatalf("failed to parse expected JSON %q: %v", wantJSON, err)
	}

	gotNormalized := mustJSONRoundTrip(t, got)

	if !reflect.DeepEqual(gotNormalized, want) {
		gotPretty, _ := json.MarshalIndent(gotNormalized, "", "  ")
		wantPretty, _ := json.MarshalIndent(want, "", "  ")
		t.Fatalf("JSON mismatch (-got +want):\ngot:\n%s\nwant:\n%s", gotPretty, wantPretty)
	}
}

// assertNotRecoverable ensures none of the given secret fragments survive in
// the JSON encoding of the event: neither as a value nor as a recoverable key.
func assertNotRecoverable(t *testing.T, event EventV1, secrets ...string) {
	t.Helper()

	bs, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal event: %v", err)
	}

	encoded := string(bs)
	for _, secret := range secrets {
		if strings.Contains(encoded, secret) {
			t.Errorf("sensitive value %q must not be recoverable from the logged event, event: %s", secret, encoded)
		}
	}
}

// assertStringSet asserts the two string slices contain the same elements,
// independent of ordering, and that no duplicates were introduced.
func assertStringSet(t *testing.T, field string, got, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("unexpected %s length: got %v, want %v", field, got, want)
	}

	gotSorted := slices.Clone(got)
	wantSorted := slices.Clone(want)
	slices.Sort(gotSorted)
	slices.Sort(wantSorted)

	if !slices.Equal(gotSorted, wantSorted) {
		t.Fatalf("unexpected %s content: got %v, want %v", field, got, want)
	}

	if len(gotSorted) != len(slices.Compact(gotSorted)) {
		t.Fatalf("%s contains duplicate entries: %v", field, got)
	}
}

// TestMaskRuleSetCombinedEraseAndUpsert exercises several erase (remove) and
// replacement (upsert) rules acting together over nested input and result
// values. The sensitive attributes must be unrecoverable from the resulting
// event while non-sensitive policy explanation information stays intact and
// the erased/masked audit markers record every applied rule.
func TestMaskRuleSetCombinedEraseAndUpsert(t *testing.T) {
	t.Parallel()

	const eventJSON = `{
		"input": {
			"credentials": {
				"password": "hunter2",
				"ssn": "123-45-6789",
				"mfa": ["totp-seed-abc", "recovery-code-xyz"]
			},
			"user": {"name": "alice", "role": "admin"},
			"note": "explain why the request was made"
		},
		"result": {
			"allow": true,
			"reasons": ["role match", "tenant allowed"],
			"downstream_token": "tok.live.9f8e7d",
			"nested": {"keep": "visible", "ssn_backref": "123-45-6789"}
		}
	}`

	// This fixture uses a distinct ssn value so that the rule pair targeting
	// only the input ssn can be checked without an unrelated copy of the same
	// string elsewhere in the event.
	const samePathEventJSON = `{
		"input": {
			"credentials": {
				"password": "hunter2",
				"ssn": "987-65-4321",
				"mfa": ["totp-seed-abc", "recovery-code-xyz"]
			},
			"user": {"name": "alice", "role": "admin"},
			"note": "explain why the request was made"
		},
		"result": {
			"allow": true,
			"reasons": ["role match", "tenant allowed"],
			"downstream_token": "tok.live.9f8e7d"
		}
	}`

	tests := []struct {
		note        string
		eventJSON   string
		rules       []ruleSpec
		wantInput   string
		wantRes     string
		wantErase   []string
		wantMask    []string
		wantSecrets []string
	}{
		{
			note:      "multiple erases and replacements across input and result",
			eventJSON: eventJSON,
			rules: []ruleSpec{
				{op: maskOPRemove, path: "/input/credentials/password"},
				{op: maskOPRemove, path: "/input/credentials/mfa/0"},
				{op: maskOPUpsert, path: "/input/credentials/ssn", value: "**REDACTED**"},
				{op: maskOPRemove, path: "/result/downstream_token"},
				{op: maskOPUpsert, path: "/result/nested/ssn_backref", value: "**REDACTED**"},
			},
			wantInput: `{
				"credentials": {"ssn": "**REDACTED**", "mfa": ["recovery-code-xyz"]},
				"user": {"name": "alice", "role": "admin"},
				"note": "explain why the request was made"
			}`,
			wantRes: `{
				"allow": true,
				"reasons": ["role match", "tenant allowed"],
				"nested": {"keep": "visible", "ssn_backref": "**REDACTED**"}
			}`,
			wantErase: []string{
				"/input/credentials/password",
				"/input/credentials/mfa/0",
				"/result/downstream_token",
			},
			wantMask: []string{
				"/input/credentials/ssn",
				"/result/nested/ssn_backref",
			},
			wantSecrets: []string{"hunter2", "123-45-6789", "totp-seed-abc", "tok.live.9f8e7d"},
		},
		{
			note:      "erase and upsert the same nested path leaves only the replacement",
			eventJSON: samePathEventJSON,
			rules: []ruleSpec{
				{op: maskOPRemove, path: "/input/credentials/ssn"},
				{op: maskOPUpsert, path: "/input/credentials/ssn", value: "**REDACTED**"},
			},
			wantInput: `{
				"credentials": {"password": "hunter2", "ssn": "**REDACTED**", "mfa": ["totp-seed-abc", "recovery-code-xyz"]},
				"user": {"name": "alice", "role": "admin"},
				"note": "explain why the request was made"
			}`,
			wantRes: `{
				"allow": true,
				"reasons": ["role match", "tenant allowed"],
				"downstream_token": "tok.live.9f8e7d"
			}`,
			wantErase: []string{"/input/credentials/ssn"},
			wantMask:  []string{"/input/credentials/ssn"},
			// Only the ssn is addressed by this rule pair; the other secrets in
			// the fixture are intentionally outside its scope.
			wantSecrets: []string{"987-65-4321"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.note, func(t *testing.T) {
			t.Parallel()

			event := mustParseEvent(t, tc.eventJSON)
			rs := mustBuildRuleSet(t, nil, tc.rules...)
			rs.Mask(&event)

			assertJSONEqual(t, *event.Input, tc.wantInput)
			assertJSONEqual(t, *event.Result, tc.wantRes)
			assertStringSet(t, "erased", event.Erased, tc.wantErase)
			assertStringSet(t, "masked", event.Masked, tc.wantMask)

			// The raw secret material addressed by the rules must not be
			// reconstructable from any part of the serialized event, including the
			// explanation fields that are expected to survive masking.
			assertNotRecoverable(t, event, tc.wantSecrets...)

			// Non-sensitive policy explanation data is retained verbatim.
			got := mustJSONRoundTrip(t, event).(map[string]any)
			input := got["input"].(map[string]any)
			if input["note"] != "explain why the request was made" {
				t.Errorf("non-sensitive input note must remain available, got %v", input["note"])
			}
			result := got["result"].(map[string]any)
			reasons, ok := result["reasons"].([]any)
			if !ok || len(reasons) != 2 || reasons[0] != "role match" {
				t.Errorf("non-sensitive result reasons must remain available, got %v", result["reasons"])
			}
			if result["allow"] != true {
				t.Errorf("non-sensitive result decision must remain available, got %v", result["allow"])
			}
		})
	}
}

// TestMaskRuleSetResultIsolation verifies that masking the result never leaks
// back into the result value handed to the decision consumer. Any rule that
// targets the result must operate on a deep copy, and the shared nested
// containers of the caller-visible result must stay untouched.
func TestMaskRuleSetResultIsolation(t *testing.T) {
	t.Parallel()

	event := mustParseEvent(t, `{
		"input": {"credentials": {"password": "hunter2"}, "name": "alice"},
		"result": {
			"allow": true,
			"explanation": "role-based grant",
			"secret": {"token": "tok.live.9f8e7d"},
			"items": ["public", "private"]
		}
	}`)

	callerResult := *event.Result
	callerResultMap := (*event.Result).(map[string]any)
	callerNested := callerResultMap["secret"].(map[string]any)
	callerItems := callerResultMap["items"].([]any)

	rs := mustBuildRuleSet(t, nil,
		ruleSpec{op: maskOPRemove, path: "/input/credentials/password"},
		ruleSpec{op: maskOPRemove, path: "/result/secret"},
		ruleSpec{op: maskOPUpsert, path: "/result/items/1", value: "**REDACTED**"},
	)
	rs.Mask(&event)

	// The result seen by the caller/audit pipeline is fully preserved...
	assertJSONEqual(t, callerResult, `{
		"allow": true,
		"explanation": "role-based grant",
		"secret": {"token": "tok.live.9f8e7d"},
		"items": ["public", "private"]
	}`)

	// ...including through the nested containers captured before masking.
	if callerNested["token"] != "tok.live.9f8e7d" {
		t.Errorf("nested caller result was mutated: %v", callerNested)
	}
	if callerItems[1] != "private" {
		t.Errorf("caller result slice was mutated: %v", callerItems)
	}

	// The logged event carries the masked copy instead.
	assertJSONEqual(t, *event.Result, `{
		"allow": true,
		"explanation": "role-based grant",
		"items": ["public", "**REDACTED**"]
	}`)
	assertNotRecoverable(t, event, "tok.live.9f8e7d", "private")

	// A second masking pass on the already-masked event must not mutate it
	// further: removed paths are now undefined and the replacement is stable.
	rs2 := mustBuildRuleSet(t, nil,
		ruleSpec{op: maskOPRemove, path: "/result/secret"},
		ruleSpec{op: maskOPUpsert, path: "/result/items/1", value: "**REDACTED**"},
	)
	beforeSecond := mustJSONRoundTrip(t, *event.Result)
	rs2.Mask(&event)
	assertJSONEqual(t, *event.Result, mustJSONToRaw(t, beforeSecond))

	// Input-only rules leave the result pointer untouched entirely.
	eventInputOnly := mustParseEvent(t, `{"input":{"password":"hunter2"},"result":{"allow":true}}`)
	originalResultPtr := eventInputOnly.Result
	rsInputOnly := mustBuildRuleSet(t, nil,
		ruleSpec{op: maskOPRemove, path: "/input/password"},
	)
	rsInputOnly.Mask(&eventInputOnly)
	if eventInputOnly.Result != originalResultPtr {
		t.Fatal("result must not be copied when no mask rule targets it")
	}
}

// TestMaskRuleSetRepeatedAndDifferentRules keeps logging the same decision
// with independent rule sets and asserts that every produced event is
// deterministic: identical rule sets yield identical masked events and audit
// markers, and a different rule set changes only the paths it addresses while
// the underlying decision data stays stable across the events.
func TestMaskRuleSetRepeatedAndDifferentRules(t *testing.T) {
	t.Parallel()

	newDecisionEvent := func() EventV1 {
		return mustParseEvent(t, `{
			"input": {
				"credentials": {"password": "hunter2", "ssn": "123-45-6789"},
				"user": {"name": "alice"}
			},
			"result": {
				"allow": true,
				"explanation": "role-based grant",
				"downstream_token": "tok.live.9f8e7d"
			}
		}`)
	}

	baseRules := []ruleSpec{
		{op: maskOPRemove, path: "/input/credentials/password"},
		{op: maskOPUpsert, path: "/input/credentials/ssn", value: "**REDACTED**"},
		{op: maskOPRemove, path: "/result/downstream_token"},
	}

	var firstJSON []byte

	for i := range 3 {
		event := newDecisionEvent()
		rs := mustBuildRuleSet(t, nil, baseRules...)
		rs.Mask(&event)

		assertJSONEqual(t, *event.Input, `{
			"credentials": {"ssn": "**REDACTED**"},
			"user": {"name": "alice"}
		}`)
		assertJSONEqual(t, *event.Result, `{
			"allow": true,
			"explanation": "role-based grant"
		}`)
		assertStringSet(t, "erased", event.Erased,
			[]string{"/input/credentials/password", "/result/downstream_token"})
		assertStringSet(t, "masked", event.Masked, []string{"/input/credentials/ssn"})
		assertNotRecoverable(t, event, "hunter2", "123-45-6789", "tok.live.9f8e7d")

		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}
		if i == 0 {
			firstJSON = encoded
			continue
		}
		if !bytes.Equal(firstJSON, encoded) {
			t.Fatalf("re-logging the same decision with the same rules must be stable:\nfirst: %s\nnow:   %s", firstJSON, encoded)
		}
	}

	// Logging the same decision with a different rule set must produce a
	// different but well-defined event without disturbing the decision itself.
	strictEvent := newDecisionEvent()
	strictRules := mustBuildRuleSet(t, nil,
		ruleSpec{op: maskOPRemove, path: "/input/credentials"},
		ruleSpec{op: maskOPUpsert, path: "/result/downstream_token", value: "**REDACTED**"},
	)
	strictRules.Mask(&strictEvent)

	assertJSONEqual(t, *strictEvent.Input, `{"user": {"name": "alice"}}`)
	assertJSONEqual(t, *strictEvent.Result, `{
		"allow": true,
		"explanation": "role-based grant",
		"downstream_token": "**REDACTED**"
	}`)
	assertStringSet(t, "erased", strictEvent.Erased, []string{"/input/credentials"})
	assertStringSet(t, "masked", strictEvent.Masked, []string{"/result/downstream_token"})

	// Non-sensitive explanation information survives both rule configurations,
	// i.e. the policy rationale remains available to downstream consumers.
	if (*strictEvent.Result).(map[string]any)["explanation"] != "role-based grant" {
		t.Fatalf("explanation lost under the strict rule set: %v", strictEvent.Result)
	}
}

// TestMaskRuleSetRuleMissContract pins the behavior when rules cannot hit
// anything in the event. By default a miss is a silent no-op: the event is
// unchanged and no erased/masked marker is recorded. With failUndefinedPath
// the rule error is reported through OnRuleError while the event still remains
// unmodified by the failing rule, matching the documented contract.
func TestMaskRuleSetRuleMissContract(t *testing.T) {
	t.Parallel()

	t.Run("default: misses are silent no-ops", func(t *testing.T) {
		t.Parallel()

		event := mustParseEvent(t, `{
			"input": {"present": {"kept": "value"}, "items": [1, 2]},
			"result": {"allow": true, "reasons": ["role match"]}
		}`)
		before := mustJSONRoundTrip(t, event)

		var ruleErrors []error
		rs := mustBuildRuleSet(t, func(_ *maskRule, err error) {
			ruleErrors = append(ruleErrors, err)
		},
			ruleSpec{op: maskOPRemove, path: "/input/missing/key"},
			ruleSpec{op: maskOPRemove, path: "/input/items/9"},
			ruleSpec{op: maskOPUpsert, path: "/input/present/kept/deeper", value: "x"},
			ruleSpec{op: maskOPRemove, path: "/result/missing"},
			// Rules targeting an entirely absent top-level part are also no-ops.
			ruleSpec{op: maskOPRemove, path: "/nd_builtin_cache/anything"},
		)
		rs.Mask(&event)

		if len(ruleErrors) != 0 {
			t.Fatalf("rule misses must not be reported by default, got: %v", ruleErrors)
		}
		if len(event.Erased) != 0 || len(event.Masked) != 0 {
			t.Fatalf("misses must not record audit markers, erased=%v masked=%v", event.Erased, event.Masked)
		}
		assertJSONEqual(t, mustJSONRoundTrip(t, event), mustJSONToRaw(t, before))
	})

	t.Run("failUndefinedPath: misses are reported but never mutate the event", func(t *testing.T) {
		t.Parallel()

		event := mustParseEvent(t, `{"input": {"present": 1, "other": {"kept": true}}, "result": {"allow": true}}`)

		var ruleErrors []error
		rs := mustBuildRuleSet(t, func(_ *maskRule, err error) {
			ruleErrors = append(ruleErrors, err)
		},
			ruleSpec{op: maskOPRemove, path: "/input/missing/deep", failUndefinedPath: true},
			ruleSpec{op: maskOPRemove, path: "/input/present/down/a/leaf", failUndefinedPath: true},
			ruleSpec{op: maskOPRemove, path: "/result/missing/deep", failUndefinedPath: true},
			// A hitting rule in the same set must still be applied.
			ruleSpec{op: maskOPRemove, path: "/result/allow"},
		)
		rs.Mask(&event)

		if len(ruleErrors) != 3 {
			t.Fatalf("expected 3 rule errors for undefined paths, got %d: %v", len(ruleErrors), ruleErrors)
		}
		for _, err := range ruleErrors {
			if !errors.Is(err, errMaskInvalidObject) {
				t.Fatalf("expected errMaskInvalidObject, got %v", err)
			}
		}

		// The hitting rule is recorded; the failing rules leave no markers.
		assertStringSet(t, "erased", event.Erased, []string{"/result/allow"})
		if len(event.Masked) != 0 {
			t.Fatalf("no upsert rules were applied, masked must be empty, got %v", event.Masked)
		}

		// Failing rules must leave the addressed data untouched: the input is
		// exactly as submitted and the result only lost the key the hitting
		// rule removed.
		assertJSONEqual(t, *event.Input, `{"present": 1, "other": {"kept": true}}`)
		assertJSONEqual(t, *event.Result, `{}`)
	})

	t.Run("failUndefinedPath on an absent part reports the error without creating it", func(t *testing.T) {
		t.Parallel()

		// When the whole input/result part is absent, a rule without
		// failUndefinedPath silently no-ops, while failUndefinedPath surfaces
		// errMaskInvalidObject. In neither case may the missing part be created.
		event := mustParseEvent(t, `{"path": "some/decision"}`)
		var ruleErrors []error
		rs := mustBuildRuleSet(t, func(_ *maskRule, err error) {
			ruleErrors = append(ruleErrors, err)
		},
			ruleSpec{op: maskOPRemove, path: "/input/missing", failUndefinedPath: true},
			ruleSpec{op: maskOPRemove, path: "/result/missing", failUndefinedPath: true},
			// Default behavior on the same absent part must stay silent.
			ruleSpec{op: maskOPRemove, path: "/input/other-missing"},
		)
		rs.Mask(&event)

		if len(ruleErrors) != 2 {
			t.Fatalf("expected 2 rule errors for absent parts, got %d: %v", len(ruleErrors), ruleErrors)
		}
		for _, err := range ruleErrors {
			if !errors.Is(err, errMaskInvalidObject) {
				t.Fatalf("expected errMaskInvalidObject, got %v", err)
			}
		}
		if len(event.Erased) != 0 || len(event.Masked) != 0 {
			t.Fatalf("failed rules must not record markers, erased=%v masked=%v", event.Erased, event.Masked)
		}
		if event.Input != nil || event.Result != nil {
			t.Fatalf("absent parts must stay absent after a failed rule, input=%v result=%v", event.Input, event.Result)
		}
	})

	t.Run("empty input and result parts stay absent on a miss", func(t *testing.T) {
		t.Parallel()

		event := mustParseEvent(t, `{"path": "some/decision"}`)
		rs := mustBuildRuleSet(t, nil,
			ruleSpec{op: maskOPRemove, path: "/input/anything"},
			ruleSpec{op: maskOPUpsert, path: "/result/anything", value: "x"},
		)
		rs.Mask(&event)

		if event.Input != nil || event.Result != nil {
			t.Fatalf("missing parts must not be created by a mask miss, input=%v result=%v", event.Input, event.Result)
		}
		if len(event.Erased) != 0 || len(event.Masked) != 0 {
			t.Fatalf("no markers expected for a miss on an absent part, erased=%v masked=%v", event.Erased, event.Masked)
		}
	})
}

// TestMaskRuleSetMarkersAccumulatePerEvent ensures a rule set applied to
// several events keeps per-event marker state: markers from one event never
// bleed into another event's audit trail.
func TestMaskRuleSetMarkersAccumulatePerEvent(t *testing.T) {
	t.Parallel()

	rules := []ruleSpec{
		{op: maskOPRemove, path: "/input/password"},
		{op: maskOPUpsert, path: "/result/token", value: "**REDACTED**"},
	}

	for i := range 2 {
		event := mustParseEvent(t, fmt.Sprintf(`{
			"input": {"password": "hunter2-%d", "user": "alice"},
			"result": {"token": "tok-%d", "allow": true}
		}`, i, i))

		rs := mustBuildRuleSet(t, nil, rules...)
		rs.Mask(&event)

		assertStringSet(t, "erased", event.Erased, []string{"/input/password"})
		assertStringSet(t, "masked", event.Masked, []string{"/result/token"})
		assertNotRecoverable(t, event, fmt.Sprintf("hunter2-%d", i), fmt.Sprintf("tok-%d", i))

		assertJSONEqual(t, *event.Input, `{"user": "alice"}`)
		assertJSONEqual(t, *event.Result, `{"token": "**REDACTED**", "allow": true}`)
	}
}

// mustJSONToRaw serializes a value back into compact JSON text for reuse with
// assertJSONEqual, which parses its expected argument as JSON.
func mustJSONToRaw(t *testing.T, v any) string {
	t.Helper()

	bs, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	return string(bs)
}
