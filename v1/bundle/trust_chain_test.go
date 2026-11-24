// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package bundle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/internal/file/archive"
	"github.com/open-policy-agent/opa/v1/util"
)

const trustChainPolicy = `package authz

import rego.v1

default allow := false

allow if input.user == "trusted-publisher"
`

func trustChainVerificationConfig() *VerificationConfig {
	return NewVerificationConfig(map[string]*KeyConfig{
		"publisher": {
			Key:       "publisher-secret",
			Algorithm: "HS256",
			Scope:     "release",
		},
		"staging": {
			Key:       "staging-secret",
			Algorithm: "HS256",
			Scope:     "staging",
		},
	}, "publisher", "release", nil)
}

func newTrustChainBundle() *Bundle {
	roots := []string{"authz", "global"}
	return &Bundle{
		Manifest: Manifest{
			Revision: "trust-chain-revision",
			Roots:    &roots,
		},
		Data: map[string]any{
			"authz": map[string]any{
				"mode":    "enforce",
				"retries": 3,
				"users":   []any{"alice", "bob"},
			},
			"global": map[string]any{
				"enabled": true,
			},
		},
		Modules: []ModuleFile{
			{
				URL:  "/authz/policy.rego",
				Path: "/authz/policy.rego",
				Raw:  []byte(trustChainPolicy),
			},
		},
	}
}

func writeTrustChainClaims(t *testing.T, scope string) string {
	t.Helper()

	claims := map[string]string{}
	if scope != "" {
		claims["scope"] = scope
	}

	claimsPath := filepath.Join(t.TempDir(), "claims.json")
	bs, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	if err := os.WriteFile(claimsPath, bs, 0o600); err != nil {
		t.Fatalf("write claims file: %v", err)
	}
	return claimsPath
}

func signTrustChainBundle(t *testing.T, b *Bundle, keyID, secret, scope string) {
	t.Helper()

	signingConfig := NewSigningConfig(secret, "HS256", writeTrustChainClaims(t, scope))
	if err := b.GenerateSignature(signingConfig, keyID, true); err != nil {
		t.Fatalf("generate signature: %v", err)
	}
}

func writeTrustChainBundle(t *testing.T, b *Bundle) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer
	if err := NewWriter(&buf).
		UseModulePath(true).
		DisableFormat(true).
		Write(*b); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return &buf
}

func readTrustChainBundle(t *testing.T, buf *bytes.Buffer, vc *VerificationConfig) (Bundle, error) {
	t.Helper()
	return NewReader(buf).
		WithLazyLoadingMode(false).
		WithBundleVerificationConfig(vc).
		Read()
}

func assertTrustChainLoadedContent(t *testing.T, b Bundle) {
	t.Helper()

	if b.Manifest.Revision != "trust-chain-revision" {
		t.Fatalf("unexpected manifest revision: %q", b.Manifest.Revision)
	}

	authz, ok := b.Data["authz"].(map[string]any)
	if !ok {
		t.Fatalf("loaded data missing authz object: %#v", b.Data)
	}
	if authz["mode"] != "enforce" {
		t.Fatalf("loaded mode = %v, want enforce", authz["mode"])
	}
	if got := fmt.Sprint(authz["retries"]); got != "3" {
		t.Fatalf("loaded retries = %v, want 3", authz["retries"])
	}

	if len(b.Modules) != 1 {
		t.Fatalf("expected one loaded module, got %d", len(b.Modules))
	}
	module := b.Modules[0]
	if module.Path != "/authz/policy.rego" {
		t.Fatalf("unexpected module path: %q", module.Path)
	}
	if string(module.Raw) != trustChainPolicy {
		t.Fatalf("loaded rule bytes changed:\n%s", module.Raw)
	}
	if module.Parsed == nil {
		t.Fatal("expected rule to be parsed when bundle is loaded")
	}
}

// TestTrustChainConfigSignatureAndContent is the happy-path contract: a trust
// config names the expected key and scope, the JWT manifest is checked against
// that config, and every file loaded into OPA is checked against the JWT.
func TestTrustChainConfigSignatureAndContent(t *testing.T) {
	b := newTrustChainBundle()
	signTrustChainBundle(t, b, "publisher", "publisher-secret", "release")

	loaded, err := readTrustChainBundle(t, writeTrustChainBundle(t, b), trustChainVerificationConfig())
	if err != nil {
		t.Fatalf("expected trusted bundle to load: %v", err)
	}

	assertTrustChainLoadedContent(t, loaded)
}

func TestTrustChainRejectsMissingSignature(t *testing.T) {
	b := newTrustChainBundle()

	if _, err := readTrustChainBundle(t, writeTrustChainBundle(t, b), trustChainVerificationConfig()); err == nil ||
		!strings.Contains(err.Error(), "bundle missing .signatures.json file") {
		t.Fatalf("expected strict trust config to reject missing signature, got %v", err)
	}

	loaded, err := readTrustChainBundle(
		t,
		writeTrustChainBundle(t, b),
		trustChainVerificationConfig().WithOptionalSignature(),
	)
	if err != nil {
		t.Fatalf("explicit optional-signature trust config should accept unsigned bundle: %v", err)
	}
	if len(loaded.Modules) != 1 {
		t.Fatalf("expected unsigned bundle to load only when explicitly optional, got %d modules", len(loaded.Modules))
	}
}

// TestTrustChainAcceptsEquivalentStructuredRepresentation ensures byte-level
// formatting differences do not break trust when the parsed JSON document is
// unchanged. The original signature remains valid because structured files are
// verified by their canonical representation.
func TestTrustChainAcceptsEquivalentStructuredRepresentation(t *testing.T) {
	b := newTrustChainBundle()
	signTrustChainBundle(t, b, "publisher", "publisher-secret", "release")

	signatureBytes, err := json.Marshal(b.Signatures)
	if err != nil {
		t.Fatalf("marshal signatures: %v", err)
	}

	files := [][2]string{
		{".signatures.json", string(signatureBytes)},
		{".manifest", `{
			"roots": ["authz", "global"],
			"revision": "trust-chain-revision"
		}`},
		{"data.json", `{
			"global": {
				"enabled": true
			},
			"authz": {
				"users": ["alice", "bob"],
				"retries": 3,
				"mode": "enforce"
			}
		}`},
		{"authz/policy.rego", trustChainPolicy},
	}

	loaded, err := readTrustChainBundle(t, archive.MustWriteTarGz(files), trustChainVerificationConfig())
	if err != nil {
		t.Fatalf("semantically equivalent representation should verify: %v", err)
	}
	assertTrustChainLoadedContent(t, loaded)
}

// TestTrustChainAcceptsResignedEquivalentRule documents the boundary for Rego
// files: they are hashed as exact bytes, so a reformatted rule needs a fresh
// signature. Once the same trusted identity re-signs it in the same scope, the
// equivalent rule representation is accepted.
func TestTrustChainAcceptsResignedEquivalentRule(t *testing.T) {
	reformattedPolicy := `package authz

import rego.v1

default allow := false

allow if {
	input.user == "trusted-publisher"
}
`

	b := newTrustChainBundle()
	signTrustChainBundle(t, b, "publisher", "publisher-secret", "release")
	b.Modules[0].Raw = []byte(reformattedPolicy)

	_, err := readTrustChainBundle(t, writeTrustChainBundle(t, b), trustChainVerificationConfig())
	if err == nil || !strings.Contains(err.Error(), "authz/policy.rego: digest mismatch") {
		t.Fatalf("expected changed rule bytes to fail old manifest, got %v", err)
	}

	signTrustChainBundle(t, b, "publisher", "publisher-secret", "release")
	loaded, err := readTrustChainBundle(t, writeTrustChainBundle(t, b), trustChainVerificationConfig())
	if err != nil {
		t.Fatalf("expected re-signed equivalent rule to verify: %v", err)
	}
	if len(loaded.Modules) != 1 {
		t.Fatalf("expected one module, got %d", len(loaded.Modules))
	}
	if string(loaded.Modules[0].Raw) != reformattedPolicy {
		t.Fatalf("loaded rule does not match re-signed representation:\n%s", loaded.Modules[0].Raw)
	}
	if loaded.Modules[0].Parsed == nil {
		t.Fatal("expected re-signed rule to be parsed")
	}
}

// TestTrustChainRejectsContentAndManifestDrift mutates the package after it was
// signed. The JWT itself remains valid, but its file hashes must reject changed
// rules, data, manifests, extra files, and files missing from the archive.
func TestTrustChainRejectsContentAndManifestDrift(t *testing.T) {
	modifiedRule := strings.Replace(
		trustChainPolicy,
		`input.user == "trusted-publisher"`,
		`input.user == "anyone"`,
		1,
	)

	tests := map[string]struct {
		mutate  func(*Bundle)
		files   func(*testing.T, *Bundle) *bytes.Buffer
		vc      *VerificationConfig
		wantErr string
	}{
		"substantive rule change": {
			mutate: func(b *Bundle) {
				b.Modules[0].Raw = []byte(modifiedRule)
			},
			wantErr: "authz/policy.rego: digest mismatch",
		},
		"substantive data change": {
			mutate: func(b *Bundle) {
				authz := b.Data["authz"].(map[string]any)
				authz["mode"] = "permissive"
			},
			wantErr: "data.json: digest mismatch",
		},
		"manifest drift": {
			mutate: func(b *Bundle) {
				b.Manifest.Revision = "unapproved-revision"
			},
			wantErr: ".manifest: digest mismatch",
		},
		"extra unsigned rule": {
			mutate: func(b *Bundle) {
				b.Modules = append(b.Modules, ModuleFile{
					URL:  "/authz/extra.rego",
					Path: "/authz/extra.rego",
					Raw:  []byte("package authz\n\nextra if true\n"),
				})
			},
			wantErr: "file authz/extra.rego not included in bundle signature",
		},
		"signed rule absent from archive": {
			mutate: func(b *Bundle) {
				b.Modules = nil
			},
			wantErr: "specified in bundle signatures but not found in the target bundle",
		},
		"signed data absent from archive": {
			files: func(t *testing.T, b *Bundle) *bytes.Buffer {
				t.Helper()
				signatureBytes, err := json.Marshal(b.Signatures)
				if err != nil {
					t.Fatal(err)
				}
				return archive.MustWriteTarGz([][2]string{
					{".signatures.json", string(signatureBytes)},
					{".manifest", `{"revision":"trust-chain-revision","roots":["authz","global"]}`},
					{"authz/policy.rego", trustChainPolicy},
				})
			},
			wantErr: "specified in bundle signatures but not found in the target bundle",
		},
		"explicit data exclusion does not excuse rule drift": {
			mutate: func(b *Bundle) {
				authz := b.Data["authz"].(map[string]any)
				authz["mode"] = "permissive"
				b.Modules[0].Raw = []byte(modifiedRule)
			},
			vc: NewVerificationConfig(map[string]*KeyConfig{
				"publisher": {Key: "publisher-secret", Algorithm: "HS256", Scope: "release"},
			}, "publisher", "release", []string{"data.json"}),
			wantErr: "authz/policy.rego: digest mismatch",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			b := newTrustChainBundle()
			signTrustChainBundle(t, b, "publisher", "publisher-secret", "release")

			if tc.mutate != nil {
				tc.mutate(b)
			}

			var buf *bytes.Buffer
			if tc.files != nil {
				buf = tc.files(t, b)
			} else {
				buf = writeTrustChainBundle(t, b)
			}

			vc := tc.vc
			if vc == nil {
				vc = trustChainVerificationConfig()
			}

			_, err := readTrustChainBundle(t, buf, vc)
			if err == nil {
				t.Fatal("expected untrusted bundle to be rejected")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestTrustChainSigningIdentityAndScope checks that a valid JWT is not enough:
// the key that produced it and the scope embedded in it must agree with the
// deployment's trust configuration.
func TestTrustChainSigningIdentityAndScope(t *testing.T) {
	keys := map[string]*KeyConfig{
		"publisher":   {Key: "publisher-secret", Algorithm: "HS256", Scope: "release"},
		"publisher-2": {Key: "publisher-two-secret", Algorithm: "HS256", Scope: "release"},
		"staging":     {Key: "staging-secret", Algorithm: "HS256", Scope: "staging"},
	}

	signedBundle := func(t *testing.T, keyID, secret, scope string) *bytes.Buffer {
		t.Helper()
		b := newTrustChainBundle()
		signTrustChainBundle(t, b, keyID, secret, scope)
		return writeTrustChainBundle(t, b)
	}

	tests := map[string]struct {
		signKeyID  string
		signSecret string
		signScope  string
		vc         *VerificationConfig
		wantErr    string
	}{
		"matching pinned identity and scope": {
			signKeyID:  "publisher",
			signSecret: "publisher-secret",
			signScope:  "release",
			vc:         NewVerificationConfig(keys, "publisher", "release", nil),
		},
		"kid selects key and key scope is trusted": {
			signKeyID:  "publisher",
			signSecret: "publisher-secret",
			signScope:  "release",
			vc:         NewVerificationConfig(keys, "", "", nil),
		},
		"rotated publisher identity in same scope": {
			signKeyID:  "publisher-2",
			signSecret: "publisher-two-secret",
			signScope:  "release",
			vc:         NewVerificationConfig(keys, "", "", nil),
		},
		"token scope below expected release scope": {
			signKeyID:  "publisher",
			signSecret: "publisher-secret",
			signScope:  "staging",
			vc:         NewVerificationConfig(keys, "publisher", "release", nil),
			wantErr:    "scope mismatch",
		},
		"configured scope disagrees with token": {
			signKeyID:  "publisher",
			signSecret: "publisher-secret",
			signScope:  "release",
			vc:         NewVerificationConfig(keys, "publisher", "canary", nil),
			wantErr:    "scope mismatch",
		},
		"pinned publisher key rejects foreign signer": {
			signKeyID:  "attacker",
			signSecret: "attacker-secret",
			signScope:  "release",
			vc:         NewVerificationConfig(keys, "publisher", "release", nil),
			wantErr:    "failed to verify JWT signature",
		},
		"unknown signing identity": {
			signKeyID:  "unknown",
			signSecret: "unknown-secret",
			signScope:  "release",
			vc:         NewVerificationConfig(keys, "", "release", nil),
			wantErr:    "verification key corresponding to ID unknown not found",
		},
		"known staging identity does not satisfy release scope": {
			signKeyID:  "staging",
			signSecret: "staging-secret",
			signScope:  "staging",
			vc:         NewVerificationConfig(keys, "", "release", nil),
			wantErr:    "scope mismatch",
		},
		"staging identity is trusted only in staging scope": {
			signKeyID:  "staging",
			signSecret: "staging-secret",
			signScope:  "staging",
			vc:         NewVerificationConfig(keys, "", "", nil),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			buf := signedBundle(t, tc.signKeyID, tc.signSecret, tc.signScope)
			_, err := readTrustChainBundle(t, buf, tc.vc)

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected trusted identity/scope to pass, got %v", err)
				}
				return
			}

			if err == nil {
				t.Fatal("expected identity/scope mismatch to be rejected")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestTrustChainPartialVerificationLeavesEvidenceGap verifies the evidence
// ledger itself. Verifying one file consumes only that file; a failed digest
// check does not consume its evidence. A non-empty ledger is the condition the
// reader rejects before exposing the bundle as completely verified.
func TestTrustChainPartialVerificationLeavesEvidenceGap(t *testing.T) {
	b := newTrustChainBundle()
	signTrustChainBundle(t, b, "publisher", "publisher-secret", "release")
	vc := trustChainVerificationConfig()

	files, err := VerifyBundleSignature(b.Signatures, vc)
	if err != nil {
		t.Fatalf("verify signed manifest: %v", err)
	}

	expectedClaims := []string{"data.json", ".manifest", "authz/policy.rego"}
	if len(files) != len(expectedClaims) {
		t.Fatalf("expected %d signed file claims, got %d: %v", len(expectedClaims), len(files), files)
	}

	dataValue, err := json.Marshal(b.Data)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundleFile("data.json", *bytes.NewBuffer(dataValue), files); err != nil {
		t.Fatalf("verify data.json: %v", err)
	}
	if _, ok := files["data.json"]; ok {
		t.Fatal("successful verification should consume data.json evidence")
	}
	if len(files) != 2 {
		t.Fatalf("one file verified, expected two remaining evidence entries, got %d", len(files))
	}

	tamperedPolicy := strings.Replace(
		trustChainPolicy,
		`input.user == "trusted-publisher"`,
		`input.user == "anyone"`,
		1,
	)
	err = VerifyBundleFile(
		"authz/policy.rego",
		*bytes.NewBufferString(tamperedPolicy),
		files,
	)
	if err == nil || !strings.Contains(err.Error(), "authz/policy.rego: digest mismatch") {
		t.Fatalf("expected policy digest mismatch, got %v", err)
	}
	if _, ok := files["authz/policy.rego"]; !ok {
		t.Fatal("a failed verification must not consume the file's evidence")
	}
	if len(files) != 2 {
		t.Fatalf("failed verification changed evidence ledger size to %d", len(files))
	}

	if err := VerifyBundleFile(
		"authz/policy.rego",
		*bytes.NewBufferString(trustChainPolicy),
		files,
	); err != nil {
		t.Fatalf("verify original policy: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected only manifest evidence to remain, got %d", len(files))
	}

	equivalentManifest := []byte(`{
		"roots": ["authz", "global"],
		"revision": "trust-chain-revision"
	}`)
	if err := VerifyBundleFile(".manifest", *bytes.NewBuffer(equivalentManifest), files); err != nil {
		t.Fatalf("verify equivalent manifest: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("evidence gap remains after all files verified: %v", files)
	}
}

// TestTrustChainYAMLEquivalenceAndTampering exercises canonical YAML hashing
// through the reader: comments, key order, and flow style are immaterial, but a
// substantive value change must not match the signed file manifest.
func TestTrustChainYAMLEquivalenceAndTampering(t *testing.T) {
	originalYAML := `
authz:
  mode: enforce
  users:
    - alice
    - bob
`
	hasher, err := NewSignatureHasher(SHA256)
	if err != nil {
		t.Fatal(err)
	}

	var doc any
	if err := util.Unmarshal([]byte(originalYAML), &doc); err != nil {
		t.Fatal(err)
	}
	digest, err := hasher.HashFile(doc)
	if err != nil {
		t.Fatal(err)
	}

	fileInfo := NewFile("data.yaml", hex.EncodeToString(digest), SHA256.String())
	signingConfig := NewSigningConfig(
		"publisher-secret",
		"HS256",
		writeTrustChainClaims(t, "release"),
	)
	token, err := GenerateSignedToken([]FileInfo{fileInfo}, signingConfig, "publisher")
	if err != nil {
		t.Fatal(err)
	}
	signatureBytes, err := json.Marshal(SignaturesConfig{Signatures: []string{token}})
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		content string
		wantErr string
	}{
		"original yaml": {},
		"equivalent reordered flow yaml": {
			content: `
# Formatting and comments are not part of the canonical structured digest.
authz:
  users: [alice, bob]
  mode: enforce
`,
		},
		"substantive yaml change": {
			content: `
authz:
  mode: permissive
  users:
    - alice
    - bob
`,
			wantErr: "data.yaml: digest mismatch",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			content := tc.content
			if content == "" {
				content = originalYAML
			}

			buf := archive.MustWriteTarGz([][2]string{
				{".signatures.json", string(signatureBytes)},
				{"data.yaml", content},
			})

			loaded, err := NewReader(buf).
				WithLazyLoadingMode(false).
				WithBundleVerificationConfig(trustChainVerificationConfig()).
				Read()

			if tc.wantErr != "" {
				if err == nil {
					t.Fatal("expected substantive YAML change to be rejected")
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("expected equivalent YAML to verify: %v", err)
			}
			authz, ok := loaded.Data["authz"].(map[string]any)
			if !ok || authz["mode"] != "enforce" {
				t.Fatalf("unexpected loaded YAML data: %#v", loaded.Data)
			}
		})
	}
}
