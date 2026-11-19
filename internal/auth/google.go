// Package auth provides Google OAuth 2.0 (PKCE) single-admin authentication,
// AES-256-GCM encrypted session cookies, and encrypted credential persistence.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"deploymenthub/internal/vault"
)

const (
	// DefaultAdminEmail is the sole Google account permitted to access DeploymentHub.
	DefaultAdminEmail = "theanh2906@gmail.com"
	// SessionCookieName stores the AES-256-GCM sealed admin session on the client browser.
	SessionCookieName = "dh_session"
	// OAuthStateCookieName binds the OAuth authorization flow to the initiating browser.
	OAuthStateCookieName = "dh_oauth_state"

	sessionTTL       = 7 * 24 * time.Hour
	oauthStateTTL    = 10 * time.Minute
	maxPendingStates = 256

	defaultGoogleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	defaultGoogleTokenURL    = "https://oauth2.googleapis.com/token"
	defaultGoogleUserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
)

// Session represents an authenticated DeploymentHub single-admin session.
type Session struct {
	JTI       string `json:"jti"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Picture   string `json:"picture,omitempty"`
	IssuedAt  int64  `json:"issuedAt"`
	ExpiresAt int64  `json:"expiresAt"`
}

// PersistedConfig stores UI-configured Google OAuth client settings on disk
// with the client secret sealed via the DeploymentHub AES-256-GCM vault.
type PersistedConfig struct {
	ClientID              string `json:"clientId"`
	EncryptedClientSecret string `json:"encryptedClientSecret"`
	RedirectURL           string `json:"redirectUrl,omitempty"`
	UpdatedAt             string `json:"updatedAt,omitempty"`
}

// Status reports the authentication gate and Google OAuth configuration state.
type Status struct {
	Enforced          bool     `json:"enforced"`
	Configured        bool     `json:"configured"`
	Authenticated     bool     `json:"authenticated"`
	AdminEmail        string   `json:"adminEmail"`
	ClientIDPreview   string   `json:"clientIdPreview"`
	SecretPreview     string   `json:"secretPreview"`
	CallbackURL       string   `json:"callbackUrl"`
	RecommendedOrigin string   `json:"recommendedOrigin,omitempty"`
	Source            string   `json:"source"`
	User              *Session `json:"user,omitempty"`
}

type pendingOAuthState struct {
	codeVerifier string
	redirectURI  string
	expiresAt    int64
}

// Manager implements Google OAuth 2.0 + PKCE login restricted to a single admin email.
type Manager struct {
	mu              sync.RWMutex
	vault           *vault.Vault
	dataFilePath    string
	adminEmail      string
	enforceSetup    bool
	envClientID     string
	envClientSecret string
	envRedirectURL  string
	fileCfg         PersistedConfig

	authURL     string
	tokenURL    string
	userInfoURL string
	httpClient  *http.Client

	pending map[string]pendingOAuthState
	revoked map[string]int64
}

// NewManager initializes an auth.Manager from environment variables and AUTH_DATA_FILE.
func NewManager(v *vault.Vault) *Manager {
	adminEmail := strings.ToLower(strings.TrimSpace(os.Getenv("AUTH_ADMIN_EMAIL")))
	if adminEmail == "" {
		adminEmail = DefaultAdminEmail
	}
	enforceEnv := strings.ToLower(strings.TrimSpace(os.Getenv("AUTH_ENFORCE_SETUP")))
	enforceSetup := enforceEnv == "true" || enforceEnv == "1" || enforceEnv == "yes"
	dataFile := strings.TrimSpace(os.Getenv("AUTH_DATA_FILE"))

	m := NewManagerWithConfig(v, dataFile, adminEmail, enforceSetup)
	m.mu.Lock()
	m.envClientID = strings.TrimSpace(os.Getenv("GOOGLE_CLIENT_ID"))
	m.envClientSecret = strings.TrimSpace(os.Getenv("GOOGLE_CLIENT_SECRET"))
	m.envRedirectURL = strings.TrimSpace(os.Getenv("GOOGLE_REDIRECT_URL"))
	m.mu.Unlock()
	return m
}

// NewManagerWithConfig constructs an auth.Manager with explicit storage and policy settings.
func NewManagerWithConfig(v *vault.Vault, dataFile, adminEmail string, enforceSetup bool) *Manager {
	cleanAdmin := strings.ToLower(strings.TrimSpace(adminEmail))
	if cleanAdmin == "" {
		cleanAdmin = DefaultAdminEmail
	}
	m := &Manager{
		vault:        v,
		dataFilePath: strings.TrimSpace(dataFile),
		adminEmail:   cleanAdmin,
		enforceSetup: enforceSetup,
		authURL:      defaultGoogleAuthURL,
		tokenURL:     defaultGoogleTokenURL,
		userInfoURL:  defaultGoogleUserInfoURL,
		httpClient:   &http.Client{Timeout: 12 * time.Second},
		pending:      make(map[string]pendingOAuthState),
		revoked:      make(map[string]int64),
	}
	m.loadFromDisk()
	return m
}

// SetEndpointsForTest overrides Google OAuth endpoints for unit tests.
func (m *Manager) SetEndpointsForTest(authURL, tokenURL, userInfoURL string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if strings.TrimSpace(authURL) != "" {
		m.authURL = strings.TrimSpace(authURL)
	}
	if strings.TrimSpace(tokenURL) != "" {
		m.tokenURL = strings.TrimSpace(tokenURL)
	}
	if strings.TrimSpace(userInfoURL) != "" {
		m.userInfoURL = strings.TrimSpace(userInfoURL)
	}
}

// SetHTTPClient overrides the HTTP client used for OAuth token/userinfo calls.
func (m *Manager) SetHTTPClient(c *http.Client) {
	if c == nil {
		return
	}
	m.mu.Lock()
	m.httpClient = c
	m.mu.Unlock()
}

func (m *Manager) loadFromDisk() {
	if m.dataFilePath == "" {
		return
	}
	raw, err := os.ReadFile(m.dataFilePath)
	if err != nil {
		return
	}
	var cfg PersistedConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return
	}
	m.mu.Lock()
	m.fileCfg = cfg
	m.mu.Unlock()
}

func (m *Manager) activeCredentials() (clientID, clientSecret, redirectURL, source, secretPreview string, configured bool) {
	m.mu.RLock()
	envID := m.envClientID
	envSec := m.envClientSecret
	envRedir := m.envRedirectURL
	fileCfg := m.fileCfg
	v := m.vault
	m.mu.RUnlock()

	if envID != "" && envSec != "" {
		return envID, envSec, envRedir, "env", "env:configured", true
	}

	if fileCfg.ClientID != "" && fileCfg.EncryptedClientSecret != "" && v != nil {
		dec, err := v.Decrypt(fileCfg.EncryptedClientSecret)
		if err == nil && strings.TrimSpace(dec) != "" {
			preview := "enc:v1:***"
			if len(fileCfg.EncryptedClientSecret) > 16 {
				preview = fileCfg.EncryptedClientSecret[:16] + "..."
			}
			redir := envRedir
			if redir == "" {
				redir = fileCfg.RedirectURL
			}
			return fileCfg.ClientID, dec, redir, "file", preview, true
		}
	}

	return "", "", envRedir, "none", "", false
}

// IsConfigured reports whether active Google OAuth client credentials are available.
func (m *Manager) IsConfigured() bool {
	_, _, _, _, _, ok := m.activeCredentials()
	return ok
}

// IsEnforced reports whether requests to protected endpoints must carry a valid admin session.
func (m *Manager) IsEnforced() bool {
	m.mu.RLock()
	enforce := m.enforceSetup
	m.mu.RUnlock()
	return enforce || m.IsConfigured()
}

// AdminEmail returns the configured single-admin email address.
func (m *Manager) AdminEmail() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.adminEmail
}

// SaveConfig validates and stores Google OAuth credentials atomically on disk.
// If clientSecret is empty when updating existing config, the previously encrypted secret is preserved.
func (m *Manager) SaveConfig(clientID, clientSecret, redirectURL string) error {
	cleanID := strings.TrimSpace(clientID)
	cleanSecret := strings.TrimSpace(clientSecret)
	cleanRedirect := strings.TrimSpace(redirectURL)
	if cleanID == "" {
		return errors.New("google clientId is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.vault == nil {
		return errors.New("crypto vault is unavailable")
	}

	encSecret := m.fileCfg.EncryptedClientSecret
	if cleanSecret != "" {
		var err error
		encSecret, err = m.vault.Encrypt(cleanSecret)
		if err != nil {
			return fmt.Errorf("encrypt clientSecret: %w", err)
		}
	} else if encSecret == "" {
		return errors.New("google clientSecret is required")
	}

	nextCfg := PersistedConfig{
		ClientID:              cleanID,
		EncryptedClientSecret: encSecret,
		RedirectURL:           cleanRedirect,
		UpdatedAt:             time.Now().UTC().Format(time.RFC3339),
	}

	if m.dataFilePath != "" {
		encoded, err := json.MarshalIndent(nextCfg, "", "  ")
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(m.dataFilePath), 0o755); err != nil {
			return fmt.Errorf("create auth config dir: %w", err)
		}
		if err := writeFileAtomic(m.dataFilePath, encoded, 0o600); err != nil {
			return fmt.Errorf("persist auth config: %w", err)
		}
	}

	m.fileCfg = nextCfg
	return nil
}

// ResolveCallbackURL determines the Google OAuth redirect URI for the incoming request,
// preferring recommendedOrigin (HTTPS domain) when accessed over a raw IP address.
func (m *Manager) ResolveCallbackURL(r *http.Request, recommendedOrigin string) string {
	_, _, explicitRedirect, _, _, _ := m.activeCredentials()
	if explicitRedirect != "" {
		return explicitRedirect
	}

	rec := strings.TrimRight(strings.TrimSpace(recommendedOrigin), "/")
	reqHost := requestHost(r)
	if rec != "" && isIPHost(reqHost) {
		return rec + "/api/v1/auth/google/callback"
	}

	scheme := requestScheme(r)
	if reqHost == "" {
		if rec != "" {
			return rec + "/api/v1/auth/google/callback"
		}
		reqHost = "localhost:4180"
	}
	return scheme + "://" + reqHost + "/api/v1/auth/google/callback"
}

// StatusForRequest returns public/admin auth status suitable for /api/v1/auth/status.
func (m *Manager) StatusForRequest(r *http.Request, recommendedOrigin string) Status {
	sess, authed := m.AuthenticateRequest(r)
	clientID, _, _, source, secretPreview, configured := m.activeCredentials()
	st := Status{
		Enforced:          m.IsEnforced(),
		Configured:        configured,
		Authenticated:     authed,
		AdminEmail:        m.AdminEmail(),
		ClientIDPreview:   maskClientID(clientID, authed),
		SecretPreview:     secretPreview,
		CallbackURL:       m.ResolveCallbackURL(r, recommendedOrigin),
		RecommendedOrigin: strings.TrimRight(strings.TrimSpace(recommendedOrigin), "/"),
		Source:            source,
	}
	if authed && sess != nil {
		copied := *sess
		st.User = &copied
	}
	return st
}

// StartGoogleLogin initiates Google OAuth 2.0 Authorization Code + PKCE flow,
// sets the HttpOnly state cookie, and returns Google's authorization URL.
func (m *Manager) StartGoogleLogin(w http.ResponseWriter, r *http.Request, recommendedOrigin string) (string, error) {
	clientID, _, _, _, _, configured := m.activeCredentials()
	if !configured || clientID == "" {
		return "", errors.New("google OAuth is not configured")
	}

	redirectURI := m.ResolveCallbackURL(r, recommendedOrigin)
	stateToken, err := randomHex(32)
	if err != nil {
		return "", err
	}
	verifier, err := randomBase64URL(32)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	now := time.Now().Unix()

	m.mu.Lock()
	for k, v := range m.pending {
		if now > v.expiresAt {
			delete(m.pending, k)
		}
	}
	if len(m.pending) >= maxPendingStates {
		var oldestKey string
		var oldestExp int64
		for k, v := range m.pending {
			if oldestKey == "" || v.expiresAt < oldestExp {
				oldestKey = k
				oldestExp = v.expiresAt
			}
		}
		if oldestKey != "" {
			delete(m.pending, oldestKey)
		}
	}
	m.pending[stateToken] = pendingOAuthState{
		codeVerifier: verifier,
		redirectURI:  redirectURI,
		expiresAt:    time.Now().Add(oauthStateTTL).Unix(),
	}
	authEndpoint := m.authURL
	adminHint := m.adminEmail
	m.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     OAuthStateCookieName,
		Value:    stateToken,
		Path:     "/",
		MaxAge:   int(oauthStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})

	parsed, err := url.Parse(authEndpoint)
	if err != nil {
		return "", fmt.Errorf("invalid Google auth URL: %w", err)
	}
	q := parsed.Query()
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", "openid email profile")
	q.Set("state", stateToken)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("prompt", "select_account")
	if adminHint != "" {
		q.Set("login_hint", adminHint)
	}
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

// HandleGoogleCallback validates the OAuth callback, exchanges the authorization code,
// verifies email_verified and single-admin email match, and issues an encrypted session cookie.
// Returns (session, errorCode, err).
func (m *Manager) HandleGoogleCallback(w http.ResponseWriter, r *http.Request) (*Session, string, error) {
	http.SetCookie(w, &http.Cookie{
		Name:     OAuthStateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})

	q := r.URL.Query()
	if oauthErr := strings.TrimSpace(q.Get("error")); oauthErr != "" {
		return nil, "google_denied", fmt.Errorf("google returned error: %s", oauthErr)
	}

	clientID, clientSecret, _, _, _, configured := m.activeCredentials()
	if !configured {
		return nil, "not_configured", errors.New("google OAuth is not configured")
	}

	stateQuery := strings.TrimSpace(q.Get("state"))
	stateCookie, err := r.Cookie(OAuthStateCookieName)
	if err != nil || stateQuery == "" || subtle.ConstantTimeCompare([]byte(stateCookie.Value), []byte(stateQuery)) != 1 {
		return nil, "invalid_state", errors.New("OAuth state cookie mismatch")
	}

	m.mu.Lock()
	pending, exists := m.pending[stateQuery]
	if exists {
		delete(m.pending, stateQuery)
	}
	tokenEndpoint := m.tokenURL
	userInfoEndpoint := m.userInfoURL
	client := m.httpClient
	v := m.vault
	allowedEmail := m.adminEmail
	m.mu.Unlock()

	if !exists || time.Now().Unix() > pending.expiresAt {
		return nil, "invalid_state", errors.New("OAuth state expired or already consumed")
	}

	code := strings.TrimSpace(q.Get("code"))
	if code == "" {
		return nil, "missing_code", errors.New("missing authorization code")
	}

	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("redirect_uri", pending.redirectURI)
	form.Set("grant_type", "authorization_code")
	form.Set("code_verifier", pending.codeVerifier)

	tokenReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, "token_exchange_failed", err
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("Accept", "application/json")

	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		return nil, "token_exchange_failed", fmt.Errorf("exchange code: %w", err)
	}
	tokenBody, _ := io.ReadAll(io.LimitReader(tokenResp.Body, 1<<20))
	_ = tokenResp.Body.Close()
	if tokenResp.StatusCode < 200 || tokenResp.StatusCode >= 300 {
		return nil, "token_exchange_failed", fmt.Errorf("google token endpoint HTTP %d: %s", tokenResp.StatusCode, strings.TrimSpace(string(tokenBody)))
	}

	var tokenData struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(tokenBody, &tokenData); err != nil || strings.TrimSpace(tokenData.AccessToken) == "" {
		return nil, "token_exchange_failed", errors.New("missing access_token in Google response")
	}

	infoReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, userInfoEndpoint, nil)
	if err != nil {
		return nil, "userinfo_failed", err
	}
	infoReq.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	infoReq.Header.Set("Accept", "application/json")

	infoResp, err := client.Do(infoReq)
	if err != nil {
		return nil, "userinfo_failed", fmt.Errorf("fetch userinfo: %w", err)
	}
	infoBody, _ := io.ReadAll(io.LimitReader(infoResp.Body, 1<<20))
	_ = infoResp.Body.Close()
	if infoResp.StatusCode < 200 || infoResp.StatusCode >= 300 {
		return nil, "userinfo_failed", fmt.Errorf("google userinfo HTTP %d: %s", infoResp.StatusCode, strings.TrimSpace(string(infoBody)))
	}

	var userInfo struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}
	if err := json.Unmarshal(infoBody, &userInfo); err != nil {
		return nil, "userinfo_failed", fmt.Errorf("decode userinfo: %w", err)
	}

	cleanEmail := strings.ToLower(strings.TrimSpace(userInfo.Email))
	if !userInfo.EmailVerified || cleanEmail == "" || subtle.ConstantTimeCompare([]byte(cleanEmail), []byte(allowedEmail)) != 1 {
		return nil, "unauthorized_email", fmt.Errorf("google account %q is not authorized (allowed=%s verified=%v)", cleanEmail, allowedEmail, userInfo.EmailVerified)
	}

	jti, err := randomHex(16)
	if err != nil {
		return nil, "session_error", err
	}
	now := time.Now()
	sess := &Session{
		JTI:       jti,
		Email:     cleanEmail,
		Name:      strings.TrimSpace(userInfo.Name),
		Picture:   strings.TrimSpace(userInfo.Picture),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(sessionTTL).Unix(),
	}

	if v == nil {
		return nil, "session_error", errors.New("crypto vault unavailable")
	}
	rawSession, err := json.Marshal(sess)
	if err != nil {
		return nil, "session_error", err
	}
	sealed, err := v.Encrypt(string(rawSession))
	if err != nil {
		return nil, "session_error", err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sealed,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})

	return sess, "", nil
}

// AuthenticateRequest verifies the encrypted session cookie and checks single-admin authorization.
func (m *Manager) AuthenticateRequest(r *http.Request) (*Session, bool) {
	if r == nil {
		return nil, false
	}
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return nil, false
	}

	m.mu.RLock()
	v := m.vault
	allowedEmail := m.adminEmail
	m.mu.RUnlock()

	if v == nil {
		return nil, false
	}
	plaintext, err := v.Decrypt(cookie.Value)
	if err != nil {
		return nil, false
	}
	var sess Session
	if err := json.Unmarshal([]byte(plaintext), &sess); err != nil {
		return nil, false
	}
	now := time.Now().Unix()
	if sess.JTI == "" || sess.ExpiresAt <= now {
		return nil, false
	}
	cleanEmail := strings.ToLower(strings.TrimSpace(sess.Email))
	if subtle.ConstantTimeCompare([]byte(cleanEmail), []byte(allowedEmail)) != 1 {
		return nil, false
	}

	m.mu.RLock()
	revExp, revoked := m.revoked[sess.JTI]
	m.mu.RUnlock()
	if revoked && revExp > now {
		return nil, false
	}

	return &sess, true
}

// Logout revokes the current session JTI in memory and clears the browser session cookie.
func (m *Manager) Logout(w http.ResponseWriter, r *http.Request) {
	if sess, ok := m.AuthenticateRequest(r); ok && sess != nil {
		now := time.Now().Unix()
		m.mu.Lock()
		for id, exp := range m.revoked {
			if exp <= now {
				delete(m.revoked, id)
			}
		}
		m.revoked[sess.JTI] = sess.ExpiresAt
		m.mu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func maskClientID(clientID string, authed bool) string {
	clean := strings.TrimSpace(clientID)
	if clean == "" {
		return ""
	}
	if authed {
		return clean
	}
	if len(clean) <= 16 {
		return "configured"
	}
	return "..." + clean[len(clean)-12:]
}

func requestHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	if xfh := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); xfh != "" {
		if first, _, _ := strings.Cut(xfh, ","); strings.TrimSpace(first) != "" {
			return strings.TrimSpace(first)
		}
	}
	return strings.TrimSpace(r.Host)
}

func requestScheme(r *http.Request) string {
	if r == nil {
		return "http"
	}
	if xfp := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); xfp != "" {
		first, _, _ := strings.Cut(xfp, ",")
		lower := strings.ToLower(strings.TrimSpace(first))
		if lower == "https" || lower == "http" {
			return lower
		}
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func isHTTPS(r *http.Request) bool {
	return requestScheme(r) == "https"
}

func isIPHost(hostPort string) bool {
	h := strings.TrimSpace(hostPort)
	if h == "" {
		return false
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	return net.ParseIP(h) != nil
}

func randomHex(numBytes int) (string, error) {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func randomBase64URL(numBytes int) (string, error) {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
