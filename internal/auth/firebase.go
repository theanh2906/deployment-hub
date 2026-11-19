package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultFirebaseCertsURL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
	minCertCacheTTL         = 5 * time.Minute
	maxCertCacheTTL         = 6 * time.Hour
	defaultCertCacheTTL     = 1 * time.Hour
	certRefetchCooldown     = 30 * time.Second
)

// SetFirebaseCertsURLForTest overrides the Google X.509 public certificates URL for unit tests.
func (m *Manager) SetFirebaseCertsURLForTest(certsURL string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if strings.TrimSpace(certsURL) != "" {
		m.firebaseCertsURL = strings.TrimSpace(certsURL)
	}
	m.certCache = make(map[string]*rsa.PublicKey)
	m.certCacheExpires = time.Time{}
	m.certCacheFetchedAt = time.Time{}
}

func (m *Manager) activeFirebaseConfig() (FirebasePublicConfig, string, bool) {
	m.mu.RLock()
	envKey := m.envFirebaseAPIKey
	envDomain := m.envFirebaseAuthDomain
	envProj := m.envFirebaseProjectID
	fileCfg := m.fileCfg
	m.mu.RUnlock()

	if envKey != "" && envProj != "" {
		if envDomain == "" {
			envDomain = envProj + ".firebaseapp.com"
		}
		return FirebasePublicConfig{
			APIKey:     envKey,
			AuthDomain: envDomain,
			ProjectID:  envProj,
		}, "env", true
	}

	if fileCfg.FirebaseAPIKey != "" && fileCfg.FirebaseProjectID != "" {
		domain := fileCfg.FirebaseAuthDomain
		if domain == "" {
			domain = fileCfg.FirebaseProjectID + ".firebaseapp.com"
		}
		return FirebasePublicConfig{
			APIKey:     fileCfg.FirebaseAPIKey,
			AuthDomain: domain,
			ProjectID:  fileCfg.FirebaseProjectID,
		}, "file", true
	}

	return FirebasePublicConfig{}, "none", false
}

// IsFirebaseConfigured reports whether Firebase Web Auth configuration is present.
func (m *Manager) IsFirebaseConfigured() bool {
	_, _, ok := m.activeFirebaseConfig()
	return ok
}

// SaveFirebaseConfig validates and persists Firebase Web SDK settings atomically on disk.
func (m *Manager) SaveFirebaseConfig(apiKey, authDomain, projectID string) error {
	cleanKey := strings.TrimSpace(apiKey)
	cleanProj := strings.TrimSpace(projectID)
	cleanDomain := strings.TrimSpace(authDomain)
	if cleanKey == "" {
		return errors.New("firebase apiKey is required")
	}
	if cleanProj == "" {
		return errors.New("firebase projectId is required")
	}
	if cleanDomain == "" {
		cleanDomain = cleanProj + ".firebaseapp.com"
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	nextCfg := m.fileCfg
	nextCfg.FirebaseAPIKey = cleanKey
	nextCfg.FirebaseAuthDomain = cleanDomain
	nextCfg.FirebaseProjectID = cleanProj
	nextCfg.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	if err := m.persistConfigLocked(nextCfg); err != nil {
		return err
	}
	m.fileCfg = nextCfg
	return nil
}

// VerifyFirebaseIDTokenAndLogin verifies a Firebase ID Token's RS256 signature against Google's
// X.509 public keys, enforces Google Sign-In provider ("google.com") and single-admin email match,
// and issues an encrypted DeploymentHub session cookie.
func (m *Manager) VerifyFirebaseIDTokenAndLogin(w http.ResponseWriter, r *http.Request, idToken string) (*Session, string, error) {
	fbCfg, _, configured := m.activeFirebaseConfig()
	if !configured {
		return nil, "not_configured", errors.New("firebase auth is not configured")
	}

	parts := strings.Split(strings.TrimSpace(idToken), ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, "invalid_token", errors.New("malformed Firebase ID token")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, "invalid_token", fmt.Errorf("decode JWT header: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return nil, "invalid_token", fmt.Errorf("parse JWT header: %w", err)
	}
	if hdr.Alg != "RS256" || strings.TrimSpace(hdr.Kid) == "" {
		return nil, "invalid_token", fmt.Errorf("unsupported Firebase token alg=%q kid=%q", hdr.Alg, hdr.Kid)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, "invalid_token", fmt.Errorf("decode JWT signature: %w", err)
	}

	pubKey, err := m.getFirebasePublicKey(r.Context(), hdr.Kid)
	if err != nil {
		return nil, "invalid_token", err
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	digest := sha256.Sum256(signingInput)
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest[:], sigBytes); err != nil {
		return nil, "invalid_token", fmt.Errorf("firebase token signature verification failed: %w", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "invalid_token", fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims struct {
		Audience      string `json:"aud"`
		Issuer        string `json:"iss"`
		Subject       string `json:"sub"`
		ExpiresAt     int64  `json:"exp"`
		IssuedAt      int64  `json:"iat"`
		AuthTime      int64  `json:"auth_time"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		Firebase      struct {
			SignInProvider string `json:"sign_in_provider"`
		} `json:"firebase"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, "invalid_token", fmt.Errorf("parse JWT claims: %w", err)
	}

	expectedIssuer := "https://securetoken.google.com/" + fbCfg.ProjectID
	now := time.Now().Unix()
	if claims.Audience != fbCfg.ProjectID {
		return nil, "invalid_token", fmt.Errorf("unexpected token audience %q", claims.Audience)
	}
	if claims.Issuer != expectedIssuer {
		return nil, "invalid_token", fmt.Errorf("unexpected token issuer %q", claims.Issuer)
	}
	if strings.TrimSpace(claims.Subject) == "" || len(claims.Subject) > 128 {
		return nil, "invalid_token", errors.New("invalid token subject")
	}
	if claims.ExpiresAt <= now-30 {
		return nil, "invalid_token", errors.New("firebase token has expired")
	}
	if claims.IssuedAt > now+60 || claims.AuthTime > now+60 {
		return nil, "invalid_token", errors.New("firebase token timestamps are in the future")
	}

	if strings.TrimSpace(claims.Firebase.SignInProvider) != "google.com" {
		return nil, "google_only_required", fmt.Errorf("provider %q rejected (google.com required)", claims.Firebase.SignInProvider)
	}

	m.mu.RLock()
	allowedEmail := m.adminEmail
	m.mu.RUnlock()

	cleanEmail := strings.ToLower(strings.TrimSpace(claims.Email))
	if !claims.EmailVerified || cleanEmail == "" || subtle.ConstantTimeCompare([]byte(cleanEmail), []byte(allowedEmail)) != 1 {
		return nil, "unauthorized_email", fmt.Errorf("firebase account %q is not authorized (allowed=%s verified=%v)", cleanEmail, allowedEmail, claims.EmailVerified)
	}

	return m.issueSessionCookie(w, r, cleanEmail, claims.Name, claims.Picture)
}

func (m *Manager) getFirebasePublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	now := time.Now()
	m.mu.RLock()
	cachedKey := m.certCache[kid]
	expires := m.certCacheExpires
	fetchedAt := m.certCacheFetchedAt
	certsURL := m.firebaseCertsURL
	client := m.httpClient
	m.mu.RUnlock()

	if cachedKey != nil && now.Before(expires) {
		return cachedKey, nil
	}

	// Avoid spamming Google certs endpoint on bursts of bogus kid values while permitting rotation refresh.
	if now.Before(expires) && !fetchedAt.IsZero() && now.Sub(fetchedAt) < certRefetchCooldown {
		return nil, fmt.Errorf("unknown Firebase signing key id %q", kid)
	}

	keys, ttl, err := fetchGoogleX509Keys(ctx, client, certsURL)
	if err != nil {
		// Fall back to stale cached key if still present and network temporarily failed
		if cachedKey != nil {
			return cachedKey, nil
		}
		return nil, err
	}

	m.mu.Lock()
	m.certCache = keys
	m.certCacheFetchedAt = now
	m.certCacheExpires = now.Add(ttl)
	pub := m.certCache[kid]
	m.mu.Unlock()

	if pub == nil {
		return nil, fmt.Errorf("unknown Firebase signing key id %q", kid)
	}
	return pub, nil
}

func fetchGoogleX509Keys(ctx context.Context, client *http.Client, certsURL string) (map[string]*rsa.PublicKey, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, certsURL, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch Firebase public certs: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, 0, fmt.Errorf("fetch Firebase public certs returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, 0, err
	}

	var rawMap map[string]string
	if err := json.Unmarshal(body, &rawMap); err != nil {
		return nil, 0, fmt.Errorf("decode Firebase public certs: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(rawMap))
	for kid, pemStr := range rawMap {
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if rsaPub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			keys[kid] = rsaPub
		}
	}
	if len(keys) == 0 {
		return nil, 0, errors.New("no valid RSA certificates returned by Firebase certs endpoint")
	}

	ttl := parseCacheControlMaxAge(resp.Header.Get("Cache-Control"))
	return keys, ttl, nil
}

func parseCacheControlMaxAge(hdr string) time.Duration {
	ttl := defaultCertCacheTTL
	for _, part := range strings.Split(hdr, ",") {
		kv := strings.TrimSpace(part)
		if k, v, ok := strings.Cut(kv, "="); ok && strings.EqualFold(strings.TrimSpace(k), "max-age") {
			if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs > 0 {
				ttl = time.Duration(secs) * time.Second
			}
			break
		}
	}
	if ttl < minCertCacheTTL {
		return minCertCacheTTL
	}
	if ttl > maxCertCacheTTL {
		return maxCertCacheTTL
	}
	return ttl
}
