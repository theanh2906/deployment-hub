package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestVaultEncryptDecryptRoundTrip(t *testing.T) {
	v1, err := New("deploymenthub-master-secret")
	if err != nil {
		t.Fatalf("New with masterKey failed: %v", err)
	}
	v2, err := New("deploymenthub-master-secret")
	if err != nil {
		t.Fatalf("New second instance failed: %v", err)
	}

	cases := []string{
		"",
		"ghp_DeploymentHubDemo9821aBcDeFgHiJk",
		"postgres://app:p@ssw0rd@postgres:5432/prod?sslmode=require",
		"unicode-secret-việt-nam-🔐",
	}

	for _, plain := range cases {
		tok1, err := v1.Encrypt(plain)
		if err != nil {
			t.Fatalf("Encrypt(%q) failed: %v", plain, err)
		}
		tok2, err := v1.Encrypt(plain)
		if err != nil {
			t.Fatalf("Encrypt(%q) second call failed: %v", plain, err)
		}
		if !strings.HasPrefix(tok1, "enc:v1:") {
			t.Fatalf("expected enc:v1: prefix, got %q", tok1)
		}
		if tok1 == tok2 {
			t.Fatalf("expected distinct nonces/ciphertexts across encryptions, got identical %q", tok1)
		}
		if plain != "" && strings.Contains(tok1, plain) {
			t.Fatalf("ciphertext unexpectedly contains plaintext")
		}

		got, err := v2.Decrypt(tok1)
		if err != nil {
			t.Fatalf("Decrypt(%q) failed: %v", tok1, err)
		}
		if got != plain {
			t.Fatalf("Decrypt mismatch: got %q, want %q", got, plain)
		}
	}
}

func TestVaultRandomKeyAndTamperRejection(t *testing.T) {
	vRand1, err := New("")
	if err != nil {
		t.Fatalf("New(\"\") failed: %v", err)
	}
	vRand2, err := New("")
	if err != nil {
		t.Fatalf("New(\"\") second failed: %v", err)
	}

	tok, err := vRand1.Encrypt("super-secret-value")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if got, err := vRand1.Decrypt(tok); err != nil || got != "super-secret-value" {
		t.Fatalf("same vault decrypt failed: got %q, err=%v", got, err)
	}
	if _, err := vRand2.Decrypt(tok); err == nil {
		t.Fatalf("expected decrypt with different random key to fail")
	}

	badTokens := []string{
		"",
		"plain-text",
		"enc:v2:abc:def",
		"enc:v1:onlyonepart",
		"enc:v1:not-base64!:def",
		"enc:v1:AAAA:AAAA",
		tok[:len(tok)-2] + "XX",
	}
	for _, bad := range badTokens {
		if _, err := vRand1.Decrypt(bad); err == nil {
			t.Errorf("expected error for malformed/tampered token %q", bad)
		}
	}

	var nilVault *Vault
	if _, err := nilVault.Encrypt("x"); err == nil {
		t.Error("expected error from nil Vault.Encrypt")
	}
	if _, err := nilVault.Decrypt(tok); err == nil {
		t.Error("expected error from nil Vault.Decrypt")
	}
}

func TestVerifyGitHubSignature(t *testing.T) {
	secret := "whsec_deploymenthub_test_secret"
	payload := []byte(`{"ref":"refs/heads/main","repository":{"full_name":"example-org/sample-app"}}`)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	validSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	upperSig := "sha256=" + strings.ToUpper(hex.EncodeToString(mac.Sum(nil)))

	if !VerifyGitHubSignature(secret, payload, validSig) {
		t.Fatal("expected valid signature to pass")
	}
	if !VerifyGitHubSignature(secret, payload, upperSig) {
		t.Fatal("expected valid uppercase hex signature to pass")
	}
	if VerifyGitHubSignature("", payload, validSig) {
		t.Fatal("expected empty secret to fail")
	}
	if VerifyGitHubSignature(secret, []byte(`{"tampered":true}`), validSig) {
		t.Fatal("expected modified payload to fail")
	}
	if VerifyGitHubSignature(secret, payload, "sha1=deadbeef") {
		t.Fatal("expected non-sha256 header to fail")
	}
	if VerifyGitHubSignature(secret, payload, "sha256=zzzz") {
		t.Fatal("expected invalid hex to fail")
	}
	if VerifyGitHubSignature(secret, payload, "sha256=deadbeef") {
		t.Fatal("expected short digest to fail")
	}
}

func TestRedactSecrets(t *testing.T) {
	line := "Cloning https://x-access-token:ghp_DeploymentHubDemo9821aBc@github.com/org/repo.git with pat github_pat_11AA22BB_secretXYZ and dbpass=my_db_pass_1234 short=abc"
	redacted := RedactSecrets(line, []string{"my_db_pass_1234", "my_db", "abc"})

	if strings.Contains(redacted, "ghp_DeploymentHubDemo9821aBc") {
		t.Fatalf("ghp token was not redacted: %s", redacted)
	}
	if strings.Contains(redacted, "github_pat_11AA22BB_secretXYZ") {
		t.Fatalf("github_pat token was not redacted: %s", redacted)
	}
	if strings.Contains(redacted, "my_db_pass_1234") {
		t.Fatalf("explicit secret was not redacted: %s", redacted)
	}
	if !strings.Contains(redacted, "short=abc") {
		t.Fatalf("short secret (<4 chars) should not be redacted: %s", redacted)
	}
	if strings.Count(redacted, "[REDACTED]") != 3 {
		t.Fatalf("expected 3 redactions, got %d in %q", strings.Count(redacted, "[REDACTED]"), redacted)
	}
}
