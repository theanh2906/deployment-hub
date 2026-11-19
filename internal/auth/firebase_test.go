package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"deploymenthub/internal/vault"
)

func generateTestRSACert(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "securetoken@system.gserviceaccount.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return priv, string(pemBytes)
}

func signTestFirebaseJWT(t *testing.T, priv *rsa.PrivateKey, header map[string]any, claims map[string]any) string {
	t.Helper()
	hdrJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal JWT header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal JWT claims: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hdrJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestFirebaseIDTokenVerificationAndPersistence(t *testing.T) {
	const (
		testAPIKey    = "AIzaSyTestPublicWebKey123456"
		testProjectID = "useful-tool"
		testKid       = "test-kid-1"
	)

	priv, pemCert := generateTestRSACert(t)
	certsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_ = json.NewEncoder(w).Encode(map[string]string{
			testKid: pemCert,
		})
	}))
	defer certsSrv.Close()

	v, err := vault.New("firebase-test-master-key")
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	authFile := filepath.Join(t.TempDir(), "auth.json")
	mgr := NewManagerWithConfig(v, authFile, DefaultAdminEmail, true)
	mgr.SetFirebaseCertsURLForTest(certsSrv.URL)

	if mgr.IsConfigured() || mgr.IsFirebaseConfigured() {
		t.Fatal("expected Firebase auth unconfigured initially")
	}

	if err := mgr.SaveFirebaseConfig(testAPIKey, "", testProjectID); err != nil {
		t.Fatalf("SaveFirebaseConfig failed: %v", err)
	}
	if info, err := os.Stat(authFile); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("expected auth.json mode 0600, got %v (err=%v)", info.Mode().Perm(), err)
	}

	reloaded := NewManagerWithConfig(v, authFile, DefaultAdminEmail, true)
	reloaded.SetFirebaseCertsURLForTest(certsSrv.URL)
	if !reloaded.IsConfigured() || !reloaded.IsFirebaseConfigured() {
		t.Fatal("expected reloaded manager to report Firebase configured")
	}
	st := reloaded.StatusForRequest(httptest.NewRequest(http.MethodGet, "https://hub.bennasolutions.com/api/v1/auth/status", nil), "https://hub.bennasolutions.com")
	if !st.FirebaseConfigured || st.Firebase == nil || st.Firebase.AuthDomain != "useful-tool.firebaseapp.com" || st.AuthorizedDomain != "hub.bennasolutions.com" {
		t.Fatalf("unexpected Firebase status: %+v", st)
	}

	now := time.Now().Unix()
	baseClaims := func() map[string]any {
		return map[string]any{
			"aud":            testProjectID,
			"iss":            "https://securetoken.google.com/" + testProjectID,
			"sub":            "uid-admin-1",
			"iat":            now - 10,
			"auth_time":      now - 10,
			"exp":            now + 3600,
			"email":          DefaultAdminEmail,
			"email_verified": true,
			"name":           "The Anh",
			"picture":        "https://lh3.googleusercontent.com/pic.png",
			"firebase": map[string]any{
				"sign_in_provider": "google.com",
			},
		}
	}

	verifyToken := func(tok string) (*httptest.ResponseRecorder, *Session, string, error) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "https://hub.bennasolutions.com/api/v1/auth/firebase/login", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		sess, code, vErr := reloaded.VerifyFirebaseIDTokenAndLogin(rec, req, tok)
		return rec, sess, code, vErr
	}

	// 1. Non-admin email rejected
	cBadEmail := baseClaims()
	cBadEmail["email"] = "attacker@gmail.com"
	if rec, _, code, _ := verifyToken(signTestFirebaseJWT(t, priv, map[string]any{"alg": "RS256", "kid": testKid}, cBadEmail)); code != "unauthorized_email" || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("expected unauthorized_email with no cookies, got code=%q cookies=%v", code, rec.Result().Cookies())
	}

	// 2. Unverified email rejected
	cUnverified := baseClaims()
	cUnverified["email_verified"] = false
	if _, _, code, _ := verifyToken(signTestFirebaseJWT(t, priv, map[string]any{"alg": "RS256", "kid": testKid}, cUnverified)); code != "unauthorized_email" {
		t.Fatalf("expected unauthorized_email for unverified email, got code=%q", code)
	}

	// 3. Non-Google provider rejected even for admin email
	cPassword := baseClaims()
	cPassword["firebase"] = map[string]any{"sign_in_provider": "password"}
	if _, _, code, _ := verifyToken(signTestFirebaseJWT(t, priv, map[string]any{"alg": "RS256", "kid": testKid}, cPassword)); code != "google_only_required" {
		t.Fatalf("expected google_only_required for password provider, got code=%q", code)
	}

	// 4. Wrong audience / issuer rejected
	cWrongAud := baseClaims()
	cWrongAud["aud"] = "other-firebase-project"
	if _, _, code, _ := verifyToken(signTestFirebaseJWT(t, priv, map[string]any{"alg": "RS256", "kid": testKid}, cWrongAud)); code != "invalid_token" {
		t.Fatalf("expected invalid_token for wrong aud, got code=%q", code)
	}

	// 5. Expired token rejected
	cExpired := baseClaims()
	cExpired["exp"] = now - 120
	if _, _, code, _ := verifyToken(signTestFirebaseJWT(t, priv, map[string]any{"alg": "RS256", "kid": testKid}, cExpired)); code != "invalid_token" {
		t.Fatalf("expected invalid_token for expired token, got code=%q", code)
	}

	// 6. Tampered signature or alg=none rejected
	validTok := signTestFirebaseJWT(t, priv, map[string]any{"alg": "RS256", "kid": testKid}, baseClaims())
	tampered := validTok[:len(validTok)-4] + "AAAA"
	if _, _, code, _ := verifyToken(tampered); code != "invalid_token" {
		t.Fatalf("expected invalid_token for tampered signature, got code=%q", code)
	}
	noneAlgTok := signTestFirebaseJWT(t, priv, map[string]any{"alg": "none", "kid": testKid}, baseClaims())
	if _, _, code, _ := verifyToken(noneAlgTok); code != "invalid_token" {
		t.Fatalf("expected invalid_token for alg=none, got code=%q", code)
	}

	// 7. Valid Google Firebase ID token succeeds & sets HttpOnly + Secure dh_session cookie
	recOK, sessOK, codeOK, errOK := verifyToken(validTok)
	if errOK != nil || codeOK != "" || sessOK == nil || sessOK.Email != DefaultAdminEmail {
		t.Fatalf("expected valid Firebase Google login, got sess=%+v code=%q err=%v", sessOK, codeOK, errOK)
	}
	var sessCookie *http.Cookie
	for _, c := range recOK.Result().Cookies() {
		if c.Name == SessionCookieName {
			sessCookie = c
		}
	}
	if sessCookie == nil || !sessCookie.HttpOnly || !sessCookie.Secure {
		t.Fatalf("expected HttpOnly+Secure %s cookie, got %+v", SessionCookieName, sessCookie)
	}

	authReq := httptest.NewRequest(http.MethodGet, "https://hub.bennasolutions.com/api/v1/overview", nil)
	authReq.AddCookie(sessCookie)
	if gotSess, ok := reloaded.AuthenticateRequest(authReq); !ok || gotSess.Email != DefaultAdminEmail {
		t.Fatalf("AuthenticateRequest rejected issued Firebase session cookie: ok=%v", ok)
	}
}
