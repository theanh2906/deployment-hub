// Package vault provides authenticated encryption (AES-256-GCM),
// GitHub webhook HMAC-SHA256 verification, and secret redaction for logs.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

const tokenPrefix = "enc:v1:"

var githubTokenPattern = regexp.MustCompile(`(?:github_pat_[A-Za-z0-9_]+|ghp_[A-Za-z0-9_]+)`)

// Vault encrypts and decrypts sensitive tokens and environment variables using AES-256-GCM.
type Vault struct {
	key [32]byte
}

// New initializes a Vault. If masterKey is non-empty, a 32-byte key is derived
// via SHA-256; otherwise a random 32-byte CSPRNG key is generated.
func New(masterKey string) (*Vault, error) {
	v := &Vault{}
	if masterKey != "" {
		v.key = sha256.Sum256([]byte(masterKey))
		return v, nil
	}
	if _, err := io.ReadFull(rand.Reader, v.key[:]); err != nil {
		return nil, fmt.Errorf("vault: generate random key: %w", err)
	}
	return v, nil
}

// Encrypt seals plaintext using AES-256-GCM and returns
// "enc:v1:<base64_nonce_12b>:<base64_ciphertext_and_tag>".
func (v *Vault) Encrypt(plaintext string) (string, error) {
	if v == nil {
		return "", errors.New("vault: nil instance")
	}
	block, err := aes.NewCipher(v.key[:])
	if err != nil {
		return "", fmt.Errorf("vault: init cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("vault: init gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("vault: generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return fmt.Sprintf(
		"%s%s:%s",
		tokenPrefix,
		base64.StdEncoding.EncodeToString(nonce),
		base64.StdEncoding.EncodeToString(ciphertext),
	), nil
}

// Decrypt authenticates and decrypts a token produced by Encrypt.
func (v *Vault) Decrypt(token string) (string, error) {
	if v == nil {
		return "", errors.New("vault: nil instance")
	}
	if !strings.HasPrefix(token, tokenPrefix) {
		return "", errors.New("vault: invalid token prefix")
	}
	rest := strings.TrimPrefix(token, tokenPrefix)
	parts := strings.Split(rest, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", errors.New("vault: malformed encrypted token")
	}

	nonce, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("vault: decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("vault: decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(v.key[:])
	if err != nil {
		return "", fmt.Errorf("vault: init cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("vault: init gcm: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return "", fmt.Errorf("vault: invalid nonce length %d", len(nonce))
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("vault: decrypt failed: %w", err)
	}
	return string(plaintext), nil
}

// VerifyGitHubSignature validates a GitHub X-Hub-Signature-256 header ("sha256=<hex>")
// against payload using HMAC-SHA256 and constant-time comparison.
func VerifyGitHubSignature(secret string, payload []byte, sigHeader string) bool {
	if secret == "" {
		return false
	}
	hexSig, ok := strings.CutPrefix(strings.TrimSpace(sigHeader), "sha256=")
	if !ok || hexSig == "" {
		return false
	}
	provided, err := hex.DecodeString(hexSig)
	if err != nil || len(provided) != sha256.Size {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := mac.Sum(nil)
	return hmac.Equal(provided, expected)
}

// RedactSecrets masks explicit secret values (length >= 4) and GitHub PAT tokens
// (ghp_... and github_pat_...) with "[REDACTED]".
func RedactSecrets(line string, secrets []string) string {
	out := line
	if len(secrets) > 0 {
		filtered := make([]string, 0, len(secrets))
		seen := make(map[string]struct{}, len(secrets))
		for _, s := range secrets {
			if len(s) < 4 {
				continue
			}
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			filtered = append(filtered, s)
		}
		// Replace longer secrets first so overlapping prefixes do not leave partial tails.
		sort.Slice(filtered, func(i, j int) bool {
			return len(filtered[i]) > len(filtered[j])
		})
		for _, s := range filtered {
			out = strings.ReplaceAll(out, s, "[REDACTED]")
		}
	}
	return githubTokenPattern.ReplaceAllString(out, "[REDACTED]")
}
