package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"deploymenthub/internal/vault"
)

func TestGoogleAuthSingleAdminPKCEAndPersistence(t *testing.T) {
	const (
		testClientID     = "1234567890-abcdef.apps.googleusercontent.com"
		testClientSecret = "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999"
	)

	mockEmail := DefaultAdminEmail
	mockVerified := true
	lastCodeChallenge := ""

	googleSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if r.Form.Get("client_id") != testClientID || r.Form.Get("client_secret") != testClientSecret {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			verifier := r.Form.Get("code_verifier")
			sum := sha256.Sum256([]byte(verifier))
			gotChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
			if lastCodeChallenge == "" || gotChallenge != lastCodeChallenge {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"PKCE mismatch"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "ya29.mock-access-token-" + r.Form.Get("code"),
				"token_type":   "Bearer",
				"expires_in":   3600,
			})

		case "/userinfo":
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ya29.mock-access-token-") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sub":            "10987654321",
				"email":          mockEmail,
				"email_verified": mockVerified,
				"name":           "The Anh",
				"picture":        "https://lh3.googleusercontent.com/avatar.png",
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer googleSrv.Close()

	v, err := vault.New("unit-test-master-key-for-google-auth")
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}

	authFile := filepath.Join(t.TempDir(), "auth.json")
	mgr := NewManagerWithConfig(v, authFile, DefaultAdminEmail, true)
	mgr.SetEndpointsForTest("https://accounts.google.com/o/oauth2/v2/auth", googleSrv.URL+"/token", googleSrv.URL+"/userinfo")

	if mgr.IsConfigured() {
		t.Fatal("expected IsConfigured=false before saving Google OAuth config")
	}
	if !mgr.IsEnforced() {
		t.Fatal("expected IsEnforced=true when enforceSetup=true")
	}

	// Verify raw IP host automatically resolves to recommended HTTPS origin callback
	ipReq := httptest.NewRequest(http.MethodGet, "http://169.58.206.8:4180/api/v1/auth/status", nil)
	if cb := mgr.ResolveCallbackURL(ipReq, "https://hub.bennasolutions.com"); cb != "https://hub.bennasolutions.com/api/v1/auth/google/callback" {
		t.Fatalf("unexpected callback URL for IP host: %q", cb)
	}

	// Save credentials & verify 0600 file and zero plaintext secret on disk
	if err := mgr.SaveConfig(testClientID, testClientSecret, ""); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}
	rawDisk, err := os.ReadFile(authFile)
	if err != nil {
		t.Fatalf("read auth.json: %v", err)
	}
	if strings.Contains(string(rawDisk), testClientSecret) {
		t.Fatal("raw Google client secret leaked to auth.json")
	}
	if info, err := os.Stat(authFile); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("expected auth.json mode 0600, got %v (err=%v)", info.Mode().Perm(), err)
	}

	// Reload from disk and verify secret preservation when clientSecret="" on update
	reloaded := NewManagerWithConfig(v, authFile, DefaultAdminEmail, true)
	reloaded.SetEndpointsForTest("https://accounts.google.com/o/oauth2/v2/auth", googleSrv.URL+"/token", googleSrv.URL+"/userinfo")
	if !reloaded.IsConfigured() {
		t.Fatal("expected reloaded Manager IsConfigured=true")
	}
	if err := reloaded.SaveConfig(testClientID, "", ""); err != nil {
		t.Fatalf("SaveConfig preserving secret failed: %v", err)
	}

	findCookie := func(cookies []*http.Cookie, name string) *http.Cookie {
		for _, c := range cookies {
			if c.Name == name && c.Value != "" {
				return c
			}
		}
		return nil
	}

	startFlow := func() (state string, stateCookie *http.Cookie) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://hub.bennasolutions.com/api/v1/auth/google/login", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		authURL, startErr := reloaded.StartGoogleLogin(rec, req, "https://hub.bennasolutions.com")
		if startErr != nil {
			t.Fatalf("StartGoogleLogin failed: %v", startErr)
		}
		parsed, parseErr := url.Parse(authURL)
		if parseErr != nil {
			t.Fatalf("parse authURL: %v", parseErr)
		}
		q := parsed.Query()
		if q.Get("login_hint") != DefaultAdminEmail || q.Get("code_challenge_method") != "S256" {
			t.Fatalf("unexpected Google auth query params: %v", q)
		}
		lastCodeChallenge = q.Get("code_challenge")
		sc := findCookie(rec.Result().Cookies(), OAuthStateCookieName)
		if sc == nil || !sc.HttpOnly {
			t.Fatalf("expected HttpOnly %s cookie, got %+v", OAuthStateCookieName, rec.Result().Cookies())
		}
		return q.Get("state"), sc
	}

	// 1. Rejection of non-admin Google email
	mockEmail = "attacker@gmail.com"
	mockVerified = true
	st1, sc1 := startFlow()
	cbRec1 := httptest.NewRecorder()
	cbReq1 := httptest.NewRequest(http.MethodGet, "https://hub.bennasolutions.com/api/v1/auth/google/callback?state="+url.QueryEscape(st1)+"&code=auth-code-1", nil)
	cbReq1.AddCookie(sc1)
	if _, code, cbErr := reloaded.HandleGoogleCallback(cbRec1, cbReq1); cbErr == nil || code != "unauthorized_email" {
		t.Fatalf("expected unauthorized_email for non-admin account, got code=%q err=%v", code, cbErr)
	}
	if findCookie(cbRec1.Result().Cookies(), SessionCookieName) != nil {
		t.Fatal("must NOT set session cookie for non-admin account")
	}

	// 2. Rejection of unverified email even if email matches admin
	mockEmail = DefaultAdminEmail
	mockVerified = false
	st2, sc2 := startFlow()
	cbRec2 := httptest.NewRecorder()
	cbReq2 := httptest.NewRequest(http.MethodGet, "https://hub.bennasolutions.com/api/v1/auth/google/callback?state="+url.QueryEscape(st2)+"&code=auth-code-2", nil)
	cbReq2.AddCookie(sc2)
	if _, code, cbErr := reloaded.HandleGoogleCallback(cbRec2, cbReq2); cbErr == nil || code != "unauthorized_email" {
		t.Fatalf("expected unauthorized_email for unverified email, got code=%q err=%v", code, cbErr)
	}

	// 3. Rejection of CSRF state mismatch / replay
	st3, sc3 := startFlow()
	badCbRec := httptest.NewRecorder()
	badCbReq := httptest.NewRequest(http.MethodGet, "https://hub.bennasolutions.com/api/v1/auth/google/callback?state=wrong-state&code=auth-code-3", nil)
	badCbReq.AddCookie(sc3)
	if _, code, cbErr := reloaded.HandleGoogleCallback(badCbRec, badCbReq); cbErr == nil || code != "invalid_state" {
		t.Fatalf("expected invalid_state on state mismatch, got code=%q err=%v", code, cbErr)
	}

	// 4. Valid login for single admin theanh2906@gmail.com (email_verified: true)
	mockEmail = "TheAnh2906@gmail.com" // mixed case from provider must normalize cleanly
	mockVerified = true
	cbRecOk := httptest.NewRecorder()
	cbReqOk := httptest.NewRequest(http.MethodGet, "https://hub.bennasolutions.com/api/v1/auth/google/callback?state="+url.QueryEscape(st3)+"&code=auth-code-ok", nil)
	cbReqOk.Header.Set("X-Forwarded-Proto", "https")
	cbReqOk.AddCookie(sc3)
	sess, code, cbErr := reloaded.HandleGoogleCallback(cbRecOk, cbReqOk)
	if cbErr != nil || code != "" || sess == nil || sess.Email != DefaultAdminEmail {
		t.Fatalf("expected valid admin login, got sess=%+v code=%q err=%v", sess, code, cbErr)
	}
	sessCookie := findCookie(cbRecOk.Result().Cookies(), SessionCookieName)
	if sessCookie == nil || !sessCookie.HttpOnly || !sessCookie.Secure {
		t.Fatalf("expected HttpOnly+Secure session cookie, got %+v", sessCookie)
	}

	// Replaying the same OAuth state must fail
	replayRec := httptest.NewRecorder()
	replayReq := httptest.NewRequest(http.MethodGet, "https://hub.bennasolutions.com/api/v1/auth/google/callback?state="+url.QueryEscape(st3)+"&code=auth-code-ok", nil)
	replayReq.AddCookie(sc3)
	if _, replayCode, _ := reloaded.HandleGoogleCallback(replayRec, replayReq); replayCode != "invalid_state" {
		t.Fatalf("expected replayed state to fail with invalid_state, got %q", replayCode)
	}

	// AuthenticateRequest accepts valid cookie
	authReq := httptest.NewRequest(http.MethodGet, "https://hub.bennasolutions.com/api/v1/overview", nil)
	authReq.AddCookie(sessCookie)
	gotSess, ok := reloaded.AuthenticateRequest(authReq)
	if !ok || gotSess.Email != DefaultAdminEmail {
		t.Fatalf("expected AuthenticateRequest=true, got ok=%v sess=%+v", ok, gotSess)
	}

	// Logout revokes JTI so replaying old cookie fails
	logoutRec := httptest.NewRecorder()
	logoutReq := httptest.NewRequest(http.MethodPost, "https://hub.bennasolutions.com/api/v1/auth/logout", nil)
	logoutReq.AddCookie(sessCookie)
	reloaded.Logout(logoutRec, logoutReq)

	if _, stillOK := reloaded.AuthenticateRequest(authReq); stillOK {
		t.Fatal("expected old session cookie to be rejected after Logout revocation")
	}
}
