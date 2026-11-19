package server

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"deploymenthub/internal/auth"
	"deploymenthub/internal/detector"
	"deploymenthub/internal/docker"
	"deploymenthub/internal/mah"
	"deploymenthub/internal/vault"
)

func newTestHandler(t *testing.T, webhookSecret string) (http.Handler, *docker.Engine) {
	t.Helper()
	v, err := vault.New("test-master-key-deploymenthub")
	if err != nil {
		t.Fatalf("vault.New failed: %v", err)
	}
	eng := docker.NewEngine("", v)
	fsys := fstest.MapFS{
		"index.html": &fstest.MapFile{
			Data: []byte("<!doctype html><html><body>DeploymentHub Test UI</body></html>"),
		},
	}
	return New(eng, v, webhookSecret, fsys), eng
}

func doReq(t *testing.T, h http.Handler, method, target string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		switch v := body.(type) {
		case []byte:
			buf.Write(v)
		case string:
			buf.WriteString(v)
		default:
			if err := json.NewEncoder(&buf).Encode(v); err != nil {
				t.Fatalf("encode request body: %v", err)
			}
		}
	}
	req := httptest.NewRequest(method, target, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func signGitHub(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestHealthOverviewProjectsAndWebUI(t *testing.T) {
	h, _ := newTestHandler(t, "whsec-test")

	// Web UI at "/"
	res := doReq(t, h, http.MethodGet, "/", nil, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", res.Code)
	}
	if !strings.Contains(res.Body.String(), "DeploymentHub Test UI") {
		t.Fatalf("GET / unexpected body: %s", res.Body.String())
	}

	// Unknown /api route must return 404 JSON, not index.html
	res404 := doReq(t, h, http.MethodGet, "/api/v1/does-not-exist", nil, nil)
	if res404.Code != http.StatusNotFound {
		t.Fatalf("GET unknown api status = %d, want 404", res404.Code)
	}

	// OPTIONS CORS preflight
	resOpt := doReq(t, h, http.MethodOptions, "/api/v1/overview", nil, nil)
	if resOpt.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS status = %d, want 204", resOpt.Code)
	}

	// Health
	resHealth := doReq(t, h, http.MethodGet, "/api/v1/health", nil, nil)
	if resHealth.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/health status = %d", resHealth.Code)
	}
	var health map[string]any
	if err := json.Unmarshal(resHealth.Body.Bytes(), &health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if health["status"] != "ok" || health["runtimeMode"] != "simulator" {
		t.Fatalf("unexpected health payload: %#v", health)
	}

	// Overview starts cleanly with zero mock entities.
	resOv := doReq(t, h, http.MethodGet, "/api/v1/overview", nil, nil)
	if resOv.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/overview status = %d", resOv.Code)
	}
	var ov docker.Overview
	if err := json.Unmarshal(resOv.Body.Bytes(), &ov); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	if len(ov.Projects) != 0 || len(ov.Containers) != 0 || len(ov.Images) != 0 || len(ov.ProxyRoutes) != 0 {
		t.Fatalf("expected clean empty overview, got projects=%d containers=%d images=%d routes=%d",
			len(ov.Projects), len(ov.Containers), len(ov.Images), len(ov.ProxyRoutes))
	}

	// Projects list matches overview.
	resProj := doReq(t, h, http.MethodGet, "/api/v1/projects", nil, nil)
	if resProj.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/projects status = %d", resProj.Code)
	}
	var projs []docker.Project
	if err := json.Unmarshal(resProj.Body.Bytes(), &projs); err != nil {
		t.Fatalf("decode projects: %v", err)
	}
	if len(projs) != len(ov.Projects) {
		t.Fatalf("projects count mismatch: %d vs %d", len(projs), len(ov.Projects))
	}
}

func deploySyncForTest(t *testing.T, eng *docker.Engine, req docker.DeployRequest) {
	t.Helper()
	rec, err := eng.StartDeployment(req)
	if err != nil {
		t.Fatalf("StartDeployment failed: %v", err)
	}
	history, ch, unsub, ok := eng.SubscribeDeployment(rec.ID)
	if !ok {
		t.Fatalf("SubscribeDeployment(%s) returned ok=false", rec.ID)
	}
	defer unsub()
	events := append([]docker.DeployEvent{}, history...)
	timeout := time.After(5 * time.Second)
	for len(events) == 0 || !events[len(events)-1].Done {
		select {
		case ev, open := <-ch:
			if !open {
				return
			}
			events = append(events, ev)
		case <-timeout:
			t.Fatalf("timed out waiting for deployment %s", rec.ID)
		}
	}
}

func TestProjectContainerImageAndProxyOperations(t *testing.T) {
	h, eng := newTestHandler(t, "whsec-test")
	req := docker.DeployRequest{
		AppName:    "test-api-svc",
		RepoURL:    "https://github.com/example-org/test-api-svc",
		Branch:     "main",
		Domain:     "test-api.localhost",
		DetectMode: "hybrid",
		PresetKey:  "go",
	}
	deploySyncForTest(t, eng, req)
	deploySyncForTest(t, eng, req) // populate PreviousTags

	ov := eng.GetOverview()
	projID := ov.Projects[0].ID
	cntID := ov.Containers[0].ID
	routeID := ov.ProxyRoutes[0].ID
	initialSSL := ov.ProxyRoutes[0].SSL

	// Redeploy & Restart project
	if res := doReq(t, h, http.MethodPost, "/api/v1/projects/"+projID+"/redeploy", nil, nil); res.Code != http.StatusOK {
		t.Fatalf("redeploy status = %d, body=%s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodPost, "/api/v1/projects/"+projID+"/restart", nil, nil); res.Code != http.StatusOK {
		t.Fatalf("restart status = %d, body=%s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodPost, "/api/v1/projects/missing-id/restart", nil, nil); res.Code != http.StatusNotFound {
		t.Fatalf("restart missing project status = %d, want 404", res.Code)
	}

	// Container actions (stop -> start -> rollback -> invalid)
	for _, action := range []string{"stop", "start", "restart"} {
		res := doReq(t, h, http.MethodPost, "/api/v1/containers/"+cntID+"/action", map[string]string{
			"action": action,
		}, nil)
		if res.Code != http.StatusOK {
			t.Fatalf("container action %s status = %d, body=%s", action, res.Code, res.Body.String())
		}
	}
	var rollbackTarget string
	if len(ov.Containers[0].PreviousTags) > 0 {
		rollbackTarget = ov.Containers[0].PreviousTags[0]
	}
	resRB := doReq(t, h, http.MethodPost, "/api/v1/containers/"+cntID+"/action", map[string]string{
		"action":    "rollback",
		"targetTag": rollbackTarget,
	}, nil)
	if resRB.Code != http.StatusOK {
		t.Fatalf("container rollback status = %d, body=%s", resRB.Code, resRB.Body.String())
	}
	resBad := doReq(t, h, http.MethodPost, "/api/v1/containers/"+cntID+"/action", map[string]string{
		"action": "explode",
	}, nil)
	if resBad.Code != http.StatusBadRequest {
		t.Fatalf("invalid container action status = %d, want 400", resBad.Code)
	}

	// Prune dangling images using a mock Docker Engine returning 1 dangling image.
	dockerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_ping":
			_, _ = w.Write([]byte("OK"))
		case "/version":
			_ = json.NewEncoder(w).Encode(map[string]string{"Version": "27.1.0"})
		case "/containers/json":
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		case "/images/json":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"Id": "sha256:aaa", "RepoTags": []string{"test-api-svc:v1"}, "Size": 20 * 1024 * 1024, "Containers": 1, "Created": 1700000000},
				{"Id": "sha256:bbb", "RepoTags": []string{}, "Size": 50 * 1024 * 1024, "Containers": 0, "Created": 1700000000},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer dockerSrv.Close()
	vPrune, _ := vault.New("test-master-key-deploymenthub")
	hPrune := New(docker.NewEngine(dockerSrv.URL, vPrune), vPrune, "whsec-test", fstest.MapFS{})
	resPrune := doReq(t, hPrune, http.MethodPost, "/api/v1/images/prune", nil, nil)
	if resPrune.Code != http.StatusOK {
		t.Fatalf("prune status = %d", resPrune.Code)
	}
	var pruneRes docker.PruneResult
	if err := json.Unmarshal(resPrune.Body.Bytes(), &pruneRes); err != nil {
		t.Fatalf("decode prune result: %v", err)
	}
	if pruneRes.RemovedCount != 1 || pruneRes.ReclaimedMb != 50 {
		t.Fatalf("expected 1 dangling image (50 MB) removed, got %#v", pruneRes)
	}

	// Toggle proxy SSL
	resSSL := doReq(t, h, http.MethodPost, "/api/v1/proxy/routes/"+routeID+"/toggle-ssl", nil, nil)
	if resSSL.Code != http.StatusOK {
		t.Fatalf("toggle ssl status = %d", resSSL.Code)
	}
	var updatedRoute docker.ProxyRoute
	if err := json.Unmarshal(resSSL.Body.Bytes(), &updatedRoute); err != nil {
		t.Fatalf("decode route: %v", err)
	}
	if updatedRoute.SSL == initialSSL {
		t.Fatalf("expected SSL state to toggle from %v", initialSSL)
	}

	// Clean mock data
	resClean := doReq(t, h, http.MethodPost, "/api/v1/mock/clean", nil, nil)
	if resClean.Code != http.StatusOK {
		t.Fatalf("clean mock data status = %d", resClean.Code)
	}
	resClearedOv := doReq(t, h, http.MethodGet, "/api/v1/overview", nil, nil)
	var clearedOv docker.Overview
	if err := json.Unmarshal(resClearedOv.Body.Bytes(), &clearedOv); err != nil {
		t.Fatalf("decode cleared overview: %v", err)
	}
	if len(clearedOv.Projects) != 0 || len(clearedOv.Containers) != 0 || len(clearedOv.Images) != 0 || len(clearedOv.ProxyRoutes) != 0 {
		t.Fatalf("expected empty overview after mock/clean, got p=%d c=%d i=%d r=%d",
			len(clearedOv.Projects), len(clearedOv.Containers), len(clearedOv.Images), len(clearedOv.ProxyRoutes))
	}
}

func TestSCMDetectorAndBuildDoctor(t *testing.T) {
	h, _ := newTestHandler(t, "whsec-test")

	// Invalid PAT
	resBadPAT := doReq(t, h, http.MethodPost, "/api/v1/scm/verify-pat", map[string]string{
		"token":   "short",
		"repoUrl": "https://github.com/example-org/next-shop",
	}, nil)
	if resBadPAT.Code != http.StatusBadRequest {
		t.Fatalf("short PAT status = %d, want 400", resBadPAT.Code)
	}

	// Valid PAT
	rawPAT := "ghp_superSecretToken123456"
	resPAT := doReq(t, h, http.MethodPost, "/api/v1/scm/verify-pat", map[string]string{
		"token":   rawPAT,
		"repoUrl": "https://github.com/example-org/next-shop",
	}, nil)
	if resPAT.Code != http.StatusOK {
		t.Fatalf("valid PAT status = %d, body=%s", resPAT.Code, resPAT.Body.String())
	}
	if strings.Contains(resPAT.Body.String(), rawPAT) {
		t.Fatalf("verify-pat response echoed raw PAT")
	}

	// Detect hybrid vs file
	resDet := doReq(t, h, http.MethodPost, "/api/v1/detect", detector.DetectRequest{
		RepoURL: "https://github.com/example-org/rust-ws-api",
		Branch:  "main",
		Mode:    "hybrid",
	}, nil)
	if resDet.Code != http.StatusOK {
		t.Fatalf("detect status = %d", resDet.Code)
	}
	var detRes detector.DetectResult
	if err := json.Unmarshal(resDet.Body.Bytes(), &detRes); err != nil {
		t.Fatalf("decode detect result: %v", err)
	}
	if detRes.PresetKey != "rust" {
		t.Fatalf("expected rust preset, got %q", detRes.PresetKey)
	}

	// Generate Dockerfile
	resDF := doReq(t, h, http.MethodPost, "/api/v1/detect/dockerfile", detector.DockerfileRequest{
		PresetKey:  "nextjs",
		Mode:       "hybrid",
		AppName:    "storefront",
		NativeDeps: []string{"openssl"},
	}, nil)
	if resDF.Code != http.StatusOK || !strings.Contains(resDF.Body.String(), "standalone") {
		t.Fatalf("dockerfile endpoint failed: %d %s", resDF.Code, resDF.Body.String())
	}

	// Build Doctor diagnosis
	resDoc := doReq(t, h, http.MethodPost, "/api/v1/detect/diagnose", map[string]any{
		"logs": []string{"npm run build", "Killed (Exit Code 137)"},
	}, nil)
	if resDoc.Code != http.StatusOK {
		t.Fatalf("diagnose status = %d", resDoc.Code)
	}
	var docRes detector.BuildDoctorResult
	if err := json.Unmarshal(resDoc.Body.Bytes(), &docRes); err != nil {
		t.Fatalf("decode diagnose result: %v", err)
	}
	if docRes.RootCause == "" || docRes.DiffPreview == "" {
		t.Fatalf("expected non-empty diagnosis, got %#v", docRes)
	}
}

func TestDeploymentAndSSEStream(t *testing.T) {
	h, _ := newTestHandler(t, "whsec-test")
	ts := httptest.NewServer(h)
	defer ts.Close()

	// Start deployment
	payload, _ := json.Marshal(docker.DeployRequest{
		AppName:    "billing-go-svc",
		RepoURL:    "https://github.com/example-org/billing-go-svc",
		Branch:     "main",
		Domain:     "billing.localhost",
		SCMMode:    "pat",
		PAT:        "ghp_deploymentSecret99999",
		DetectMode: "hybrid",
		PresetKey:  "go",
	})
	resp, err := http.Post(ts.URL+"/api/v1/deployments", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST /api/v1/deployments failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /api/v1/deployments status = %d, want 202", resp.StatusCode)
	}
	var rec docker.DeploymentRecord
	if err := json.NewDecoder(resp.Body).Decode(&rec); err != nil {
		t.Fatalf("decode deployment record: %v", err)
	}
	if rec.ID == "" {
		t.Fatalf("expected deployment id")
	}

	// GET deployment status
	getResp, err := http.Get(ts.URL + "/api/v1/deployments/" + rec.ID)
	if err != nil {
		t.Fatalf("GET deployment failed: %v", err)
	}
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET deployment status = %d", getResp.StatusCode)
	}

	// Stream SSE events until Done == true
	client := &http.Client{Timeout: 10 * time.Second}
	sseResp, err := client.Get(ts.URL + "/api/v1/deployments/" + rec.ID + "/stream")
	if err != nil {
		t.Fatalf("GET SSE stream failed: %v", err)
	}
	defer sseResp.Body.Close()
	if ct := sseResp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("unexpected SSE Content-Type: %q", ct)
	}

	scanner := bufio.NewScanner(sseResp.Body)
	var events []docker.DeployEvent
	sawDone := false
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var ev docker.DeployEvent
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ev); err != nil {
			t.Fatalf("decode SSE event: %v (line=%s)", err, line)
		}
		events = append(events, ev)
		if ev.Done {
			sawDone = true
			break
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("SSE scanner error: %v", err)
	}
	if !sawDone || len(events) < 5 {
		t.Fatalf("expected >=5 SSE events ending with Done=true, got %d (sawDone=%v)", len(events), sawDone)
	}

	// Verify newly deployed project is present in overview
	ovResp, err := http.Get(ts.URL + "/api/v1/overview")
	if err != nil {
		t.Fatalf("GET overview failed: %v", err)
	}
	defer ovResp.Body.Close()
	var ov docker.Overview
	if err := json.NewDecoder(ovResp.Body).Decode(&ov); err != nil {
		t.Fatalf("decode overview after deploy: %v", err)
	}
	found := false
	for _, p := range ov.Projects {
		if p.Name == "billing-go-svc" || p.Domain == "billing.localhost" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("newly deployed project not found in overview")
	}
}

func TestGitHubWebhookHMAC(t *testing.T) {
	const secret = "super-secret-hmac-key"
	h, eng := newTestHandler(t, secret)
	deploySyncForTest(t, eng, docker.DeployRequest{
		AppName:    "webhook-app",
		RepoURL:    "https://github.com/example-org/webhook-app",
		Branch:     "main",
		Domain:     "webhook.localhost",
		PresetKey:  "go",
		DetectMode: "hybrid",
	})
	ov := eng.GetOverview()
	targetProj := ov.Projects[0]

	bodyMap := map[string]any{
		"ref": "refs/heads/" + targetProj.Branch,
		"repository": map[string]string{
			"full_name": normalizeRepoSlug(targetProj.Repo),
			"html_url":  "https://github.com/" + normalizeRepoSlug(targetProj.Repo),
		},
		"head_commit": map[string]string{
			"message": "feat: optimize docker layer",
		},
	}
	bodyBytes, _ := json.Marshal(bodyMap)

	// Invalid signature -> 401
	resInvalid := doReq(t, h, http.MethodPost, "/api/v1/webhooks/github", bodyBytes, map[string]string{
		"X-GitHub-Event":      "push",
		"X-Hub-Signature-256": "sha256=deadbeef",
	})
	if resInvalid.Code != http.StatusUnauthorized {
		t.Fatalf("invalid webhook sig status = %d, want 401", resInvalid.Code)
	}

	// Valid signature -> 200 and triggers matching project
	validSig := signGitHub(secret, bodyBytes)
	resValid := doReq(t, h, http.MethodPost, "/api/v1/webhooks/github", bodyBytes, map[string]string{
		"X-GitHub-Event":      "push",
		"X-Hub-Signature-256": validSig,
	})
	if resValid.Code != http.StatusOK {
		t.Fatalf("valid webhook status = %d, body=%s", resValid.Code, resValid.Body.String())
	}
	var hookRes struct {
		Status            string   `json:"status"`
		TriggeredProjects []string `json:"triggeredProjects"`
	}
	if err := json.Unmarshal(resValid.Body.Bytes(), &hookRes); err != nil {
		t.Fatalf("decode webhook response: %v", err)
	}
	if hookRes.Status != "accepted" || len(hookRes.TriggeredProjects) == 0 {
		t.Fatalf("expected matching project triggered, got %#v", hookRes)
	}

	// Ping event with valid signature
	pingBytes := []byte(`{"zen":"Keep it logically awesome."}`)
	resPing := doReq(t, h, http.MethodPost, "/api/v1/webhooks/github", pingBytes, map[string]string{
		"X-GitHub-Event":      "ping",
		"X-Hub-Signature-256": signGitHub(secret, pingBytes),
	})
	if resPing.Code != http.StatusOK || !strings.Contains(resPing.Body.String(), "pong") {
		t.Fatalf("ping webhook failed: %d %s", resPing.Code, resPing.Body.String())
	}
}

func TestMahEndpoints(t *testing.T) {
	const rawToken = "mah_wk_live_server_secret_9876543210"
	t.Setenv("MAH_API_URL", "http://127.0.0.1:1")
	t.Setenv("MAH_API_TOKEN", rawToken)

	h, _ := newTestHandler(t, "whsec-test")

	// Verify CORS allows GET, POST, PATCH, DELETE, OPTIONS.
	resCORS := doReq(t, h, http.MethodOptions, "/api/v1/mah/config", nil, nil)
	if resCORS.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS status = %d, want 204", resCORS.Code)
	}
	allowMethods := resCORS.Header().Get("Access-Control-Allow-Methods")
	for _, m := range []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"} {
		if !strings.Contains(allowMethods, m) {
			t.Fatalf("expected %s in Access-Control-Allow-Methods %q", m, allowMethods)
		}
	}

	// 1. Standalone mode: GET config masks token and never echoes raw token.
	resCfg := doReq(t, h, http.MethodGet, "/api/v1/mah/config", nil, nil)
	if resCfg.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/mah/config status = %d, body=%s", resCfg.Code, resCfg.Body.String())
	}
	if strings.Contains(resCfg.Body.String(), rawToken) {
		t.Fatal("GET /api/v1/mah/config leaked raw token")
	}
	var cfg mah.Config
	if err := json.Unmarshal(resCfg.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if !cfg.HasToken || cfg.APIToken != "mah_wk_live_...3210" {
		t.Fatalf("unexpected masked config: %+v", cfg)
	}

	// Standalone snapshot.
	resSnap := doReq(t, h, http.MethodGet, "/api/v1/mah/snapshot", nil, nil)
	if resSnap.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/mah/snapshot status = %d", resSnap.Code)
	}
	var snap mah.Snapshot
	if err := json.Unmarshal(resSnap.Body.Bytes(), &snap); err != nil {
		t.Fatalf("decode standalone snapshot: %v", err)
	}
	if snap.Mode != "standalone" || snap.Agents == nil || snap.Tasks == nil {
		t.Fatalf("unexpected standalone snapshot: %+v", snap)
	}

	// Standalone RegisterAgent -> SendMessage -> DelegateTask -> CancelTask -> DeleteMessage -> UnregisterSession (404).
	resAg := doReq(t, h, http.MethodPost, "/api/v1/mah/agents", map[string]any{
		"logicalName":  "standalone-agent",
		"description":  "local worker",
		"capabilities": []map[string]any{{"capability": "code_review"}},
	}, nil)
	if resAg.Code != http.StatusCreated {
		t.Fatalf("standalone POST /agents status = %d, body=%s", resAg.Code, resAg.Body.String())
	}
	var createdAg map[string]any
	_ = json.Unmarshal(resAg.Body.Bytes(), &createdAg)
	agID, _ := createdAg["id"].(string)

	resMsg := doReq(t, h, http.MethodPost, "/api/v1/mah/messages", map[string]any{
		"recipient": map[string]any{"scope": "AGENT", "agentId": agID},
		"type":      "agent.message",
		"payload":   map[string]any{"text": "hello standalone"},
	}, nil)
	if resMsg.Code != http.StatusCreated {
		t.Fatalf("standalone POST /messages status = %d, body=%s", resMsg.Code, resMsg.Body.String())
	}
	var createdMsg map[string]any
	_ = json.Unmarshal(resMsg.Body.Bytes(), &createdMsg)
	msgID, _ := createdMsg["messageId"].(string)

	resTask := doReq(t, h, http.MethodPost, "/api/v1/mah/tasks", map[string]any{
		"targetAgentId": agID,
		"input":         map[string]any{"objective": "run checks"},
	}, nil)
	if resTask.Code != http.StatusCreated {
		t.Fatalf("standalone POST /tasks status = %d, body=%s", resTask.Code, resTask.Body.String())
	}
	var createdTask map[string]any
	_ = json.Unmarshal(resTask.Body.Bytes(), &createdTask)
	taskID, _ := createdTask["taskId"].(string)

	resCancel := doReq(t, h, http.MethodPost, "/api/v1/mah/tasks/"+taskID+"/cancel", nil, nil)
	if resCancel.Code != http.StatusOK {
		t.Fatalf("standalone POST /tasks/{id}/cancel status = %d, body=%s", resCancel.Code, resCancel.Body.String())
	}

	resDelMsg := doReq(t, h, http.MethodDelete, "/api/v1/mah/messages/"+msgID, nil, nil)
	if resDelMsg.Code != http.StatusOK {
		t.Fatalf("standalone DELETE /messages/{id} status = %d, body=%s", resDelMsg.Code, resDelMsg.Body.String())
	}

	resMissingSess := doReq(t, h, http.MethodDelete, "/api/v1/mah/sessions/sess_missing", nil, nil)
	if resMissingSess.Code != http.StatusNotFound {
		t.Fatalf("missing session delete status = %d, want 404", resMissingSess.Code)
	}

	// 2. Live mode with mock MAH API server.
	mockMah := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/health" && r.Header.Get("Authorization") != "Bearer "+rawToken {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{"code": "UNAUTHORIZED", "message": "bad bearer token"},
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/health":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "ok", "service": "@mah/api", "version": "0.1.0",
				"checks": map[string]any{"database": "up"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agents":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{
					{"id": "agt_live_1", "workspaceId": "ws_live_test", "logicalName": "live-agent", "status": "ACTIVE"},
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agents/agt_live_1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "agt_live_1", "workspaceId": "ws_live_test", "logicalName": "live-agent", "status": "ACTIVE",
				"sessions": []map[string]any{{"id": "sess_live_1", "agentId": "agt_live_1", "machineId": "mach_live_1", "connectionStatus": "CONNECTED"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agents/agt_live_1/inbox":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/machines":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{{"id": "mach_live_1", "workspaceId": "ws_live_test", "name": "node-1", "hostname": "node-1.local"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{{"taskId": "tsk_live_1", "workspaceId": "ws_live_test", "status": "PENDING", "createdAt": "2026-11-17T12:00:00Z"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks/tsk_live_1/events":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/agents":
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b["logicalName"] == "conflict-agent" {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]any{"code": "CONFLICT", "message": "agent exists"},
				})
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "agt_live_2", "logicalName": b["logicalName"]})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/messages":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"messageId": "msg_live_99", "status": "QUEUED"})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/messages/msg_live_99":
			_ = json.NewEncoder(w).Encode(map[string]any{"messageId": "msg_live_99", "status": "DELETED"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tasks":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"taskId": "tsk_live_99", "status": "PENDING"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tasks/tsk_live_99/cancel":
			_ = json.NewEncoder(w).Encode(map[string]any{"taskId": "tsk_live_99", "status": "CANCELLED"})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/sessions/sess_live_1":
			_ = json.NewEncoder(w).Encode(map[string]any{"sessionId": "sess_live_1", "status": "UNREGISTERED"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockMah.Close()

	// POST /api/v1/mah/config preserving masked token while switching to mockMah.URL.
	resUpd := doReq(t, h, http.MethodPost, "/api/v1/mah/config", map[string]any{
		"apiUrl":   mockMah.URL,
		"apiToken": cfg.APIToken,
	}, nil)
	if resUpd.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/mah/config status = %d, body=%s", resUpd.Code, resUpd.Body.String())
	}

	resLiveSnap := doReq(t, h, http.MethodGet, "/api/v1/mah/snapshot", nil, nil)
	if resLiveSnap.Code != http.StatusOK {
		t.Fatalf("live GET /snapshot status = %d", resLiveSnap.Code)
	}
	var liveSnap mah.Snapshot
	if err := json.Unmarshal(resLiveSnap.Body.Bytes(), &liveSnap); err != nil {
		t.Fatalf("decode live snapshot: %v", err)
	}
	if liveSnap.Mode != "live" || liveSnap.WorkspaceID != "ws_live_test" || len(liveSnap.Agents) != 1 || len(liveSnap.Sessions) != 1 {
		t.Fatalf("unexpected live snapshot: %+v", liveSnap)
	}

	// Upstream >= 400 error mapping preserves status code.
	resConflict := doReq(t, h, http.MethodPost, "/api/v1/mah/agents", map[string]any{
		"logicalName": "conflict-agent",
	}, nil)
	if resConflict.Code != http.StatusConflict || !strings.Contains(resConflict.Body.String(), "agent exists") {
		t.Fatalf("expected 409 Conflict with upstream message, got %d %s", resConflict.Code, resConflict.Body.String())
	}

	if res := doReq(t, h, http.MethodPost, "/api/v1/mah/agents", map[string]any{"logicalName": "live-new"}, nil); res.Code != http.StatusCreated {
		t.Fatalf("live POST /agents status = %d, body=%s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodPost, "/api/v1/mah/messages", map[string]any{
		"recipient": map[string]any{"scope": "AGENT", "agentId": "agt_live_1"},
		"payload":   map[string]any{"text": "hi"},
	}, nil); res.Code != http.StatusCreated {
		t.Fatalf("live POST /messages status = %d, body=%s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodPost, "/api/v1/mah/tasks", map[string]any{
		"targetAgentId": "agt_live_1",
		"input":         map[string]any{"objective": "audit"},
	}, nil); res.Code != http.StatusCreated {
		t.Fatalf("live POST /tasks status = %d, body=%s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodPost, "/api/v1/mah/tasks/tsk_live_99/cancel", map[string]any{"reason": "done"}, nil); res.Code != http.StatusOK {
		t.Fatalf("live POST /tasks/tsk_live_99/cancel status = %d, body=%s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodDelete, "/api/v1/mah/messages/msg_live_99", nil, nil); res.Code != http.StatusOK {
		t.Fatalf("live DELETE /messages/msg_live_99 status = %d, body=%s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodDelete, "/api/v1/mah/sessions/sess_live_1", nil, nil); res.Code != http.StatusOK {
		t.Fatalf("live DELETE /sessions/sess_live_1 status = %d, body=%s", res.Code, res.Body.String())
	}
}

func TestNativeGoMahAndV1AndMCPRoutes(t *testing.T) {
	dataPath := filepath.Join(t.TempDir(), "mah_server_state.json")
	t.Setenv("MAH_API_URL", "")
	t.Setenv("MAH_DATA_FILE", dataPath)

	h, _ := newTestHandler(t, "whsec-test")

	// 1. Canonical /v1/health & native /api/v1/mah/snapshot
	resV1Health := doReq(t, h, http.MethodGet, "/v1/health", nil, nil)
	if resV1Health.Code != http.StatusOK {
		t.Fatalf("GET /v1/health status = %d", resV1Health.Code)
	}
	var health map[string]any
	_ = json.Unmarshal(resV1Health.Body.Bytes(), &health)
	if health["status"] != "ok" || health["service"] != "deploymenthub-mah-go" {
		t.Fatalf("unexpected /v1/health payload: %+v", health)
	}

	resSnap := doReq(t, h, http.MethodGet, "/api/v1/mah/snapshot", nil, nil)
	if resSnap.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/mah/snapshot status = %d", resSnap.Code)
	}
	var snap mah.Snapshot
	_ = json.Unmarshal(resSnap.Body.Bytes(), &snap)
	if snap.Mode != "live" || snap.Health["service"] != "deploymenthub-mah-go" {
		t.Fatalf("expected live native Go snapshot, got %+v", snap)
	}

	// 2. Register machine + agent + sessions + heartbeat fencing (409)
	resMach := doReq(t, h, http.MethodPost, "/v1/machines", map[string]any{
		"name": "worker-box-1", "hostname": "worker1.internal",
	}, nil)
	if resMach.Code != http.StatusCreated {
		t.Fatalf("POST /v1/machines status = %d, body=%s", resMach.Code, resMach.Body.String())
	}
	var mach map[string]any
	_ = json.Unmarshal(resMach.Body.Bytes(), &mach)
	machID, _ := mach["id"].(string)

	resAg := doReq(t, h, http.MethodPost, "/v1/agents", map[string]any{
		"logicalName":  "native-reviewer",
		"capabilities": []string{"code_review"},
	}, nil)
	if resAg.Code != http.StatusCreated {
		t.Fatalf("POST /v1/agents status = %d, body=%s", resAg.Code, resAg.Body.String())
	}
	var ag map[string]any
	_ = json.Unmarshal(resAg.Body.Bytes(), &ag)
	agID, _ := ag["id"].(string)

	// Create 2 sessions so connectionGeneration increments to 2
	if res := doReq(t, h, http.MethodPost, "/v1/agents/"+agID+"/sessions", map[string]any{"machineId": machID}, nil); res.Code != http.StatusCreated {
		t.Fatalf("POST /v1/agents/{id}/sessions #1 status = %d, body=%s", res.Code, res.Body.String())
	}
	resSess2 := doReq(t, h, http.MethodPost, "/api/v1/mah/sessions", map[string]any{"agentId": agID, "machineId": machID}, nil)
	if resSess2.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/mah/sessions #2 status = %d, body=%s", resSess2.Code, resSess2.Body.String())
	}
	var sess2Wrap map[string]any
	_ = json.Unmarshal(resSess2.Body.Bytes(), &sess2Wrap)
	sess2, _ := sess2Wrap["session"].(map[string]any)
	sess2ID, _ := sess2["id"].(string)

	// Stale generation -> 409
	resStale := doReq(t, h, http.MethodPost, "/v1/sessions/"+sess2ID+"/heartbeat", map[string]any{"connectionGeneration": 1}, nil)
	if resStale.Code != http.StatusConflict {
		t.Fatalf("expected 409 on stale heartbeat, got %d %s", resStale.Code, resStale.Body.String())
	}
	resHB := doReq(t, h, http.MethodPost, "/api/v1/mah/sessions/"+sess2ID+"/heartbeat", map[string]any{"connectionGeneration": 2, "executionStatus": "IDLE"}, nil)
	if resHB.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/mah/sessions/{id}/heartbeat status = %d, body=%s", resHB.Code, resHB.Body.String())
	}

	// Verify /v1/agents, /v1/agents/{id}, /v1/machines, /v1/machines/{id}
	if res := doReq(t, h, http.MethodGet, "/v1/agents", nil, nil); res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "native-reviewer") {
		t.Fatalf("GET /v1/agents failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodGet, "/v1/agents/"+agID, nil, nil); res.Code != http.StatusOK {
		t.Fatalf("GET /v1/agents/{id} status = %d", res.Code)
	}
	if res := doReq(t, h, http.MethodGet, "/v1/machines", nil, nil); res.Code != http.StatusOK {
		t.Fatalf("GET /v1/machines status = %d", res.Code)
	}
	if res := doReq(t, h, http.MethodGet, "/v1/machines/"+machID, nil, nil); res.Code != http.StatusOK {
		t.Fatalf("GET /v1/machines/{id} status = %d", res.Code)
	}

	// 3. Messaging: send -> inbox -> nack -> ack -> delete
	resMsg := doReq(t, h, http.MethodPost, "/v1/messages", map[string]any{
		"targetAgentId": agID,
		"text":          "Review Go migration",
	}, nil)
	if resMsg.Code != http.StatusCreated {
		t.Fatalf("POST /v1/messages status = %d, body=%s", resMsg.Code, resMsg.Body.String())
	}
	var msgResp map[string]any
	_ = json.Unmarshal(resMsg.Body.Bytes(), &msgResp)
	msgID, _ := msgResp["messageId"].(string)

	if res := doReq(t, h, http.MethodGet, "/v1/agents/"+agID+"/inbox", nil, nil); res.Code != http.StatusOK || !strings.Contains(res.Body.String(), msgID) {
		t.Fatalf("GET /v1/agents/{id}/inbox failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodPost, "/api/v1/mah/messages/"+msgID+"/nack", map[string]any{"retryable": true}, nil); res.Code != http.StatusOK {
		t.Fatalf("POST nack status = %d, body=%s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodPost, "/v1/messages/"+msgID+"/ack", map[string]any{"sessionId": sess2ID, "connectionGeneration": 2}, nil); res.Code != http.StatusOK {
		t.Fatalf("POST ack status = %d, body=%s", res.Code, res.Body.String())
	}

	// 4. 5-stage task lifecycle across /v1/tasks/* and /api/v1/mah/tasks/*
	resTsk := doReq(t, h, http.MethodPost, "/v1/tasks", map[string]any{
		"targetAgentId": agID,
		"input":         map[string]any{"objective": "run e2e"},
	}, nil)
	if resTsk.Code != http.StatusCreated {
		t.Fatalf("POST /v1/tasks status = %d, body=%s", resTsk.Code, resTsk.Body.String())
	}
	var tskResp map[string]any
	_ = json.Unmarshal(resTsk.Body.Bytes(), &tskResp)
	tskID, _ := tskResp["taskId"].(string)

	for _, step := range []struct {
		url  string
		body map[string]any
	}{
		{"/api/v1/mah/tasks/" + tskID + "/accept", map[string]any{"assignmentGeneration": 2}},
		{"/api/v1/mah/tasks/" + tskID + "/start", map[string]any{"assignmentGeneration": 2}},
		{"/api/v1/mah/tasks/" + tskID + "/complete", map[string]any{"assignmentGeneration": 2, "result": map[string]any{"ok": true}}},
	} {
		if res := doReq(t, h, http.MethodPost, step.url, step.body, nil); res.Code != http.StatusOK {
			t.Fatalf("POST %s failed: %d %s", step.url, res.Code, res.Body.String())
		}
	}

	if res := doReq(t, h, http.MethodGet, "/v1/tasks", nil, nil); res.Code != http.StatusOK || !strings.Contains(res.Body.String(), tskID) {
		t.Fatalf("GET /v1/tasks failed: %d", res.Code)
	}
	if res := doReq(t, h, http.MethodGet, "/v1/tasks/"+tskID, nil, nil); res.Code != http.StatusOK {
		t.Fatalf("GET /v1/tasks/{id} status = %d", res.Code)
	}
	resEv := doReq(t, h, http.MethodGet, "/v1/tasks/"+tskID+"/events", nil, nil)
	if resEv.Code != http.StatusOK {
		t.Fatalf("GET /v1/tasks/{id}/events status = %d", resEv.Code)
	}
	var evPage struct {
		Items []map[string]any `json:"items"`
	}
	_ = json.Unmarshal(resEv.Body.Bytes(), &evPage)
	if len(evPage.Items) != 5 {
		t.Fatalf("expected 5 task events, got %d", len(evPage.Items))
	}

	// FailTask test on second task
	resTsk2 := doReq(t, h, http.MethodPost, "/api/v1/mah/tasks", map[string]any{"targetAgentId": agID, "objective": "fail test"}, nil)
	var tsk2Resp map[string]any
	_ = json.Unmarshal(resTsk2.Body.Bytes(), &tsk2Resp)
	tsk2ID, _ := tsk2Resp["taskId"].(string)
	if res := doReq(t, h, http.MethodPost, "/api/v1/mah/tasks/"+tsk2ID+"/fail", map[string]any{"reason": "boom"}, nil); res.Code != http.StatusOK {
		t.Fatalf("POST /tasks/{id}/fail status = %d, body=%s", res.Code, res.Body.String())
	}

	// 5. MCP HTTP JSON-RPC on both /mcp and /api/v1/mah/mcp
	resMCPInit := doReq(t, h, http.MethodPost, "/mcp", map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
	}, nil)
	if resMCPInit.Code != http.StatusOK || !strings.Contains(resMCPInit.Body.String(), "deploymenthub-mah-go") {
		t.Fatalf("POST /mcp initialize failed: %d %s", resMCPInit.Code, resMCPInit.Body.String())
	}

	resMCPNotif := doReq(t, h, http.MethodPost, "/api/v1/mah/mcp", map[string]any{
		"jsonrpc": "2.0", "method": "notifications/initialized",
	}, nil)
	if resMCPNotif.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for MCP notification, got %d", resMCPNotif.Code)
	}

	resMCPTools := doReq(t, h, http.MethodPost, "/api/v1/mah/mcp", map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/list",
	}, nil)
	if resMCPTools.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/mah/mcp tools/list status = %d", resMCPTools.Code)
	}
	var mcpList struct {
		Result struct {
			Tools []map[string]any `json:"tools"`
		} `json:"result"`
	}
	_ = json.Unmarshal(resMCPTools.Body.Bytes(), &mcpList)
	if len(mcpList.Result.Tools) != 11 {
		t.Fatalf("expected 11 MCP tools, got %d", len(mcpList.Result.Tools))
	}

	resMCPCall := doReq(t, h, http.MethodPost, "/api/v1/mah/mcp", map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]any{
			"name":      "list_agents",
			"arguments": map[string]any{"capability": "code_review"},
		},
	}, nil)
	if resMCPCall.Code != http.StatusOK || !strings.Contains(resMCPCall.Body.String(), "native-reviewer") {
		t.Fatalf("POST /api/v1/mah/mcp tools/call failed: %d %s", resMCPCall.Code, resMCPCall.Body.String())
	}

	// Delete message & unregister session via /v1/* routes
	if res := doReq(t, h, http.MethodDelete, "/v1/messages/"+msgID, nil, nil); res.Code != http.StatusOK {
		t.Fatalf("DELETE /v1/messages/{id} status = %d", res.Code)
	}
	if res := doReq(t, h, http.MethodDelete, "/v1/sessions/"+sess2ID, nil, nil); res.Code != http.StatusOK {
		t.Fatalf("DELETE /v1/sessions/{id} status = %d", res.Code)
	}
}

func TestGoogleAuthGateEndToEnd(t *testing.T) {
	const (
		clientID     = "gate-test-client.apps.googleusercontent.com"
		clientSecret = "GOCSPX-gateTestSecret123456"
	)
	mockEmail := "stranger@gmail.com"
	googleSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "ya29.gate-token",
				"token_type":   "Bearer",
			})
		case "/userinfo":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sub":            "sub-1",
				"email":          mockEmail,
				"email_verified": true,
				"name":           "Test Admin",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer googleSrv.Close()

	v, err := vault.New("server-auth-gate-test-master-key")
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	eng := docker.NewEngine("", v)
	authFile := filepath.Join(t.TempDir(), "auth.json")
	authMgr := auth.NewManagerWithConfig(v, authFile, auth.DefaultAdminEmail, true)
	authMgr.SetEndpointsForTest(googleSrv.URL+"/oauth", googleSrv.URL+"/token", googleSrv.URL+"/userinfo")

	fsys := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<!doctype html><html><body>DeploymentHub Auth UI</body></html>")},
	}
	h := NewWithAuth(eng, v, "hook-secret", fsys, authMgr)

	// 1. Unconfigured + enforced: health, web UI, auth/status = 200; overview & v1/agents = 401
	if res := doReq(t, h, http.MethodGet, "/api/v1/health", nil, nil); res.Code != http.StatusOK {
		t.Fatalf("expected /api/v1/health 200, got %d", res.Code)
	}
	if res := doReq(t, h, http.MethodGet, "/", nil, nil); res.Code != http.StatusOK {
		t.Fatalf("expected / 200, got %d", res.Code)
	}
	stRes := doReq(t, h, http.MethodGet, "/api/v1/auth/status", nil, nil)
	if stRes.Code != http.StatusOK || !strings.Contains(stRes.Body.String(), `"enforced":true`) || !strings.Contains(stRes.Body.String(), `"configured":false`) {
		t.Fatalf("unexpected /api/v1/auth/status: %d %s", stRes.Code, stRes.Body.String())
	}
	ovUnauth := doReq(t, h, http.MethodGet, "/api/v1/overview", nil, nil)
	if ovUnauth.Code != http.StatusUnauthorized || !strings.Contains(ovUnauth.Body.String(), `"setupRequired":true`) {
		t.Fatalf("expected 401 setupRequired on /api/v1/overview, got %d %s", ovUnauth.Code, ovUnauth.Body.String())
	}
	if res := doReq(t, h, http.MethodGet, "/v1/agents", nil, nil); res.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on /v1/agents, got %d", res.Code)
	}

	// 2. First-time bootstrap POST /api/v1/auth/google/config succeeds without prior cookie
	cfgRes := doReq(t, h, http.MethodPost, "/api/v1/auth/google/config", map[string]any{
		"clientId":     clientID,
		"clientSecret": clientSecret,
	}, nil)
	if cfgRes.Code != http.StatusOK || !strings.Contains(cfgRes.Body.String(), `"configured":true`) {
		t.Fatalf("bootstrap config failed: %d %s", cfgRes.Code, cfgRes.Body.String())
	}

	// 3. After configuration, unauthenticated POST /api/v1/auth/google/config must return 401
	reCfgUnauth := doReq(t, h, http.MethodPost, "/api/v1/auth/google/config", map[string]any{
		"clientId":     "evil-id",
		"clientSecret": "evil-secret",
	}, nil)
	if reCfgUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated overwrite attempt to fail 401, got %d", reCfgUnauth.Code)
	}

	startLogin := func() (*http.Cookie, string) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/google/login", nil)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("expected 302 from /api/v1/auth/google/login, got %d", rec.Code)
		}
		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatalf("parse redirect: %v", err)
		}
		var stateCookie *http.Cookie
		for _, c := range rec.Result().Cookies() {
			if c.Name == auth.OAuthStateCookieName {
				stateCookie = c
			}
		}
		if stateCookie == nil {
			t.Fatal("missing OAuth state cookie")
		}
		return stateCookie, loc.Query().Get("state")
	}

	// 4. Unauthorized email redirects to /?auth_error=unauthorized_email without session cookie
	mockEmail = "stranger@gmail.com"
	scBad, stateBad := startLogin()
	cbBadReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/google/callback?state="+url.QueryEscape(stateBad)+"&code=bad-code", nil)
	cbBadReq.AddCookie(scBad)
	cbBadRec := httptest.NewRecorder()
	h.ServeHTTP(cbBadRec, cbBadReq)
	if cbBadRec.Code != http.StatusFound || cbBadRec.Header().Get("Location") != "/?auth_error=unauthorized_email" {
		t.Fatalf("unexpected unauthorized callback redirect: %d loc=%q", cbBadRec.Code, cbBadRec.Header().Get("Location"))
	}

	// 5. Valid admin login sets dh_session cookie and unlocks protected APIs
	mockEmail = auth.DefaultAdminEmail
	scOk, stateOk := startLogin()
	cbOkReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/google/callback?state="+url.QueryEscape(stateOk)+"&code=good-code", nil)
	cbOkReq.AddCookie(scOk)
	cbOkRec := httptest.NewRecorder()
	h.ServeHTTP(cbOkRec, cbOkReq)
	if cbOkRec.Code != http.StatusFound || cbOkRec.Header().Get("Location") != "/" {
		t.Fatalf("unexpected admin callback redirect: %d loc=%q", cbOkRec.Code, cbOkRec.Header().Get("Location"))
	}
	var sessCookie *http.Cookie
	for _, c := range cbOkRec.Result().Cookies() {
		if c.Name == auth.SessionCookieName && c.Value != "" {
			sessCookie = c
		}
	}
	if sessCookie == nil {
		t.Fatal("expected dh_session cookie on admin login")
	}

	ovReq := httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil)
	ovReq.AddCookie(sessCookie)
	ovRec := httptest.NewRecorder()
	h.ServeHTTP(ovRec, ovReq)
	if ovRec.Code != http.StatusOK {
		t.Fatalf("expected /api/v1/overview 200 with admin cookie, got %d", ovRec.Code)
	}

	stAuthedReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/status", nil)
	stAuthedReq.AddCookie(sessCookie)
	stAuthedRec := httptest.NewRecorder()
	h.ServeHTTP(stAuthedRec, stAuthedReq)
	if stAuthedRec.Code != http.StatusOK || !strings.Contains(stAuthedRec.Body.String(), `"authenticated":true`) {
		t.Fatalf("expected authenticated:true in /api/v1/auth/status, got %d %s", stAuthedRec.Code, stAuthedRec.Body.String())
	}

	// 6. Logout revokes session so replaying cookie returns 401
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logoutReq.AddCookie(sessCookie)
	logoutRec := httptest.NewRecorder()
	h.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/auth/logout, got %d", logoutRec.Code)
	}

	replayRec := httptest.NewRecorder()
	h.ServeHTTP(replayRec, ovReq)
	if replayRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected replayed session cookie after logout to fail 401, got %d", replayRec.Code)
	}
}

func TestFirebaseAuthGateEndToEnd(t *testing.T) {
	const (
		fbProjectID = "useful-tool"
		fbAPIKey    = "AIzaSyUsefulToolPublicKey12345"
		fbKid       = "fb-kid-1"
	)

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
	pemCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	certsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_ = json.NewEncoder(w).Encode(map[string]string{fbKid: pemCert})
	}))
	defer certsSrv.Close()

	signJWT := func(email, provider string) string {
		now := time.Now().Unix()
		hB, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": fbKid})
		cB, _ := json.Marshal(map[string]any{
			"aud":            fbProjectID,
			"iss":            "https://securetoken.google.com/" + fbProjectID,
			"sub":            "uid-1",
			"iat":            now - 5,
			"auth_time":      now - 5,
			"exp":            now + 3600,
			"email":          email,
			"email_verified": true,
			"name":           "The Anh",
			"firebase":       map[string]any{"sign_in_provider": provider},
		})
		inp := base64.RawURLEncoding.EncodeToString(hB) + "." + base64.RawURLEncoding.EncodeToString(cB)
		sum := sha256.Sum256([]byte(inp))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
		return inp + "." + base64.RawURLEncoding.EncodeToString(sig)
	}

	v, err := vault.New("server-firebase-auth-test-key")
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	eng := docker.NewEngine("", v)
	authMgr := auth.NewManagerWithConfig(v, filepath.Join(t.TempDir(), "auth.json"), auth.DefaultAdminEmail, true)
	authMgr.SetFirebaseCertsURLForTest(certsSrv.URL)

	h := NewWithAuth(eng, v, "hook-secret", fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<!doctype html><html><body>UI</body></html>")},
	}, authMgr)

	// 1. One-time Firebase config save succeeds
	cfgRes := doReq(t, h, http.MethodPost, "/api/v1/auth/firebase/config", map[string]any{
		"apiKey":    fbAPIKey,
		"projectId": fbProjectID,
	}, nil)
	if cfgRes.Code != http.StatusOK || !strings.Contains(cfgRes.Body.String(), `"firebaseConfigured":true`) {
		t.Fatalf("expected firebase bootstrap config 200, got %d %s", cfgRes.Code, cfgRes.Body.String())
	}

	// 2. Unauthenticated overwrite blocked with 401
	if res := doReq(t, h, http.MethodPost, "/api/v1/auth/firebase/config", map[string]any{"apiKey": "evil", "projectId": "evil"}, nil); res.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated firebase overwrite 401, got %d", res.Code)
	}

	// 3. Reject wrong email (403) and non-Google provider (403)
	if res := doReq(t, h, http.MethodPost, "/api/v1/auth/firebase/login", map[string]any{"idToken": signJWT("other@gmail.com", "google.com")}, nil); res.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for wrong email, got %d %s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodPost, "/api/v1/auth/firebase/login", map[string]any{"idToken": signJWT(auth.DefaultAdminEmail, "password")}, nil); res.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for password provider, got %d %s", res.Code, res.Body.String())
	}

	// 4. Valid Google Firebase login for admin issues dh_session cookie unlocking /api/v1/overview
	loginRes := doReq(t, h, http.MethodPost, "/api/v1/auth/firebase/login", map[string]any{"idToken": signJWT(auth.DefaultAdminEmail, "google.com")}, nil)
	if loginRes.Code != http.StatusOK || !strings.Contains(loginRes.Body.String(), `"authenticated":true`) {
		t.Fatalf("expected valid Firebase admin login 200, got %d %s", loginRes.Code, loginRes.Body.String())
	}
	var sessCookie *http.Cookie
	for _, c := range loginRes.Result().Cookies() {
		if c.Name == auth.SessionCookieName && c.Value != "" {
			sessCookie = c
		}
	}
	if sessCookie == nil {
		t.Fatal("missing dh_session cookie on Firebase login")
	}

	ovReq := httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil)
	ovReq.AddCookie(sessCookie)
	ovRec := httptest.NewRecorder()
	h.ServeHTTP(ovRec, ovReq)
	if ovRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/v1/overview with Firebase session, got %d", ovRec.Code)
	}

	// 5. Logout revokes session so replaying cookie returns 401
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logoutReq.AddCookie(sessCookie)
	logoutRec := httptest.NewRecorder()
	h.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("expected 200 logout, got %d", logoutRec.Code)
	}
	replayRec := httptest.NewRecorder()
	h.ServeHTTP(replayRec, ovReq)
	if replayRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on replayed cookie after logout, got %d", replayRec.Code)
	}
}

func TestDockerDeepEndpointsCheckpoint1(t *testing.T) {
	dockerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/_ping":
			_, _ = w.Write([]byte("OK"))
		case r.URL.Path == "/version":
			_ = json.NewEncoder(w).Encode(map[string]string{"Version": "29.1.3"})
		case r.URL.Path == "/info":
			_ = json.NewEncoder(w).Encode(map[string]any{"Name": "http-test-node", "NCPU": 4, "MemTotal": int64(8) << 30, "ServerVersion": "29.1.3"})
		case r.URL.Path == "/containers/json":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"Id": "sys9999999999999", "Names": []string{"/deploymenthub-control-plane"},
					"Image": "hub:latest", "State": "running", "Status": "Up 1h",
					"Ports": []map[string]any{}, "Labels": map[string]string{},
				},
				{
					"Id": "app8888888888888", "Names": []string{"/dh-sample"},
					"Image": "sample:v2", "State": "running", "Status": "Up 5m",
					"Ports": []map[string]any{{"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 4201, "Type": "tcp"}}, "Labels": map[string]string{},
				},
			})
		case r.URL.Path == "/images/json":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"Id": "sha256:img1", "RepoTags": []string{"sample:v2"}, "Size": 20 << 20, "Containers": 1, "Created": 1700000100},
				{"Id": "sha256:img2", "RepoTags": []string{"unused:v1"}, "Size": 10 << 20, "Containers": 0, "Created": 1700000000},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/system/df":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"LayersSize": int64(30 << 20),
				"Images":     []map[string]any{{"Size": int64(30 << 20), "Containers": 1}},
				"Containers": []map[string]any{},
				"Volumes":    []map[string]any{},
				"BuildCache": []map[string]any{{"Size": int64(12 << 20), "InUse": false}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/containers/app8888888888888/json":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Id": "app8888888888888", "Name": "/dh-sample", "Created": "2026-11-19T00:00:00Z",
				"State": map[string]any{"Status": "running", "Running": true, "Pid": 99},
				"Config": map[string]any{
					"Image": "sample:v2", "Tty": true, "Env": []string{"FOO=bar"}, "Cmd": []string{"nginx"},
					"Labels": map[string]string{}, "ExposedPorts": map[string]any{},
				},
				"HostConfig":      map[string]any{"Memory": int64(256 << 20), "NanoCpus": int64(500000000), "RestartPolicy": map[string]any{"Name": "unless-stopped"}},
				"NetworkSettings": map[string]any{"Ports": map[string]any{}, "Networks": map[string]any{}},
				"Mounts":          []map[string]any{},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/containers/app8888888888888/stats":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"read":         "2026-11-19T12:00:00Z",
				"cpu_stats":    map[string]any{"cpu_usage": map[string]any{"total_usage": 2000}, "system_cpu_usage": 10000, "online_cpus": 1},
				"precpu_stats": map[string]any{"cpu_usage": map[string]any{"total_usage": 1000}, "system_cpu_usage": 9000},
				"memory_stats": map[string]any{"usage": 64 << 20, "limit": 256 << 20, "stats": map[string]any{}},
				"networks":     map[string]any{},
				"pids_stats":   map[string]any{"current": 3},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/containers/app8888888888888/top":
			_ = json.NewEncoder(w).Encode(map[string]any{"Titles": []string{"PID", "CMD"}, "Processes": [][]string{{"1", "nginx"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/containers/app8888888888888/update":
			_ = json.NewEncoder(w).Encode(map[string]any{"Warnings": []string{}})
		case r.Method == http.MethodGet && r.URL.Path == "/containers/app8888888888888/logs":
			_, _ = w.Write([]byte("tty boot line 1\ntty ready line 2\n"))
		case r.Method == http.MethodDelete && r.URL.Path == "/images/img2":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"Deleted": "sha256:img2"}})
		case r.Method == http.MethodGet && r.URL.Path == "/images/img1/history":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"Id": "sha256:aaa", "Created": 1700000000, "CreatedBy": "CMD nginx", "Size": 1024}})
		case r.Method == http.MethodPost && r.URL.Path == "/build/prune":
			_ = json.NewEncoder(w).Encode(map[string]any{"CachesDeleted": []string{"b1"}, "SpaceReclaimed": int64(12 << 20)})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer dockerSrv.Close()

	v, _ := vault.New("cp1-http-test-master-key")
	eng := docker.NewEngine(dockerSrv.URL, v)
	h := New(eng, v, "hook", fstest.MapFS{})

	// 1. Protected system container stop must return 403 Forbidden
	resProt := doReq(t, h, http.MethodPost, "/api/v1/containers/sys9999999999999/action", map[string]string{"action": "stop"}, nil)
	if resProt.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on system container stop, got %d %s", resProt.Code, resProt.Body.String())
	}

	// 2. /docker/df & /containers/stats & inspect & stats & top & update
	if res := doReq(t, h, http.MethodGet, "/api/v1/docker/df", nil, nil); res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"buildCache"`) {
		t.Fatalf("GET /docker/df failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodGet, "/api/v1/containers/stats", nil, nil); res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"app8888888888888"`) {
		t.Fatalf("GET /containers/stats failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodGet, "/api/v1/containers/app8888888888888/inspect", nil, nil); res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"FOO=bar"`) {
		t.Fatalf("GET inspect failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodGet, "/api/v1/containers/app8888888888888/stats", nil, nil); res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"pids":3`) {
		t.Fatalf("GET stats failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodGet, "/api/v1/containers/app8888888888888/top", nil, nil); res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"nginx"`) {
		t.Fatalf("GET top failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodPost, "/api/v1/containers/app8888888888888/update", map[string]any{"memoryMb": 512, "cpuCores": 1, "restartPolicy": "always"}, nil); res.Code != http.StatusOK {
		t.Fatalf("POST update failed: %d %s", res.Code, res.Body.String())
	}

	// 3. SSE log stream & download .log
	ts := httptest.NewServer(h)
	defer ts.Close()
	sseResp, err := http.Get(ts.URL + "/api/v1/containers/app8888888888888/logs/stream?tail=50")
	if err != nil {
		t.Fatalf("GET SSE logs failed: %v", err)
	}
	defer sseResp.Body.Close()
	if ct := sseResp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("expected text/event-stream, got %q", ct)
	}
	scanner := bufio.NewScanner(sseResp.Body)
	var sseLines []string
	for scanner.Scan() {
		sseLines = append(sseLines, scanner.Text())
		if strings.Contains(scanner.Text(), "tty ready line 2") {
			break
		}
	}
	if !strings.Contains(strings.Join(sseLines, "\n"), "tty boot line 1") {
		t.Fatalf("expected streamed log line in SSE output: %v", sseLines)
	}

	resDL := doReq(t, h, http.MethodGet, "/api/v1/containers/app8888888888888/logs/download", nil, nil)
	if resDL.Code != http.StatusOK || !strings.Contains(resDL.Header().Get("Content-Disposition"), "dh-sample.log") || !strings.Contains(resDL.Body.String(), "tty ready line 2") {
		t.Fatalf("GET logs/download failed: %d disp=%q body=%q", resDL.Code, resDL.Header().Get("Content-Disposition"), resDL.Body.String())
	}

	// 4. Image history, delete image, build-cache prune
	if res := doReq(t, h, http.MethodGet, "/api/v1/images/img1/history", nil, nil); res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "CMD nginx") {
		t.Fatalf("GET image history failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodDelete, "/api/v1/images/img2", nil, nil); res.Code != http.StatusOK {
		t.Fatalf("DELETE image failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodPost, "/api/v1/build-cache/prune", map[string]any{"all": true}, nil); res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"cachesDeleted":1`) {
		t.Fatalf("POST build-cache/prune failed: %d %s", res.Code, res.Body.String())
	}

	// 5. Enforced auth gate rejects unauthenticated Checkpoint 1 endpoints with 401
	authMgr := auth.NewManagerWithConfig(v, filepath.Join(t.TempDir(), "auth_cp1.json"), auth.DefaultAdminEmail, true)
	hAuth := NewWithAuth(eng, v, "hook", fstest.MapFS{}, authMgr)
	for _, ep := range []string{"/api/v1/docker/df", "/api/v1/containers/stats", "/api/v1/containers/app8888888888888/logs/stream"} {
		if r401 := doReq(t, hAuth, http.MethodGet, ep, nil, nil); r401.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 on %s when auth enforced, got %d", ep, r401.Code)
		}
	}
}

func TestDockerResourcesAndEventsCheckpoint2(t *testing.T) {
	dockerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/_ping":
			_, _ = w.Write([]byte("OK"))
		case r.URL.Path == "/version":
			_ = json.NewEncoder(w).Encode(map[string]string{"Version": "29.1.3"})
		case r.URL.Path == "/info":
			_ = json.NewEncoder(w).Encode(map[string]any{"Name": "cp2-srv", "NCPU": 4, "MemTotal": int64(8) << 30, "ServerVersion": "29.1.3"})
		case r.URL.Path == "/containers/json" || r.URL.Path == "/images/json":
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		case r.URL.Path == "/system/df":
			_ = json.NewEncoder(w).Encode(map[string]any{"Volumes": []map[string]any{}})
		case r.Method == http.MethodGet && r.URL.Path == "/volumes":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Volumes": []map[string]any{
					{"Name": "hub_data", "Driver": "local", "Scope": "local"},
					{"Name": "user_vol", "Driver": "local", "Scope": "local"},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/volumes/create":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"Name": "created_vol", "Driver": "local", "Scope": "local"})
		case r.Method == http.MethodDelete && r.URL.Path == "/volumes/user_vol":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/volumes/prune":
			_ = json.NewEncoder(w).Encode(map[string]any{"VolumesDeleted": []string{"old_v"}, "SpaceReclaimed": int64(2048)})
		case r.Method == http.MethodGet && r.URL.Path == "/networks":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"Id": "n_sys", "Name": "bridge", "Driver": "bridge", "Scope": "local", "Containers": map[string]any{}},
				{"Id": "n_app", "Name": "app_net", "Driver": "bridge", "Scope": "local", "Containers": map[string]any{}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/networks/create":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"Id": "n_created"})
		case r.Method == http.MethodPost && (r.URL.Path == "/networks/n_app/connect" || r.URL.Path == "/networks/n_app/disconnect"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && r.URL.Path == "/networks/n_app":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/networks/prune":
			_ = json.NewEncoder(w).Encode(map[string]any{"NetworksDeleted": []string{"unused_n"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer dockerSrv.Close()

	v, _ := vault.New("cp2-http-test-master-key")
	eng := docker.NewEngine(dockerSrv.URL, v)
	eng.RecordDockerEvent(docker.DockerEvent{Type: "container", Action: "start", ActorID: "c1", ActorName: "dh-app", Timestamp: "2026-11-19T12:00:00Z"})
	h := New(eng, v, "hook", fstest.MapFS{})

	// Volumes endpoints + 403 protected guard
	if res := doReq(t, h, http.MethodGet, "/api/v1/volumes", nil, nil); res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "hub_data") {
		t.Fatalf("GET /volumes failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodDelete, "/api/v1/volumes/hub_data", nil, nil); res.Code != http.StatusForbidden {
		t.Fatalf("expected 403 deleting hub_data, got %d", res.Code)
	}
	if res := doReq(t, h, http.MethodPost, "/api/v1/volumes", map[string]string{"name": "created_vol"}, nil); res.Code != http.StatusCreated {
		t.Fatalf("POST /volumes failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodDelete, "/api/v1/volumes/user_vol", nil, nil); res.Code != http.StatusOK {
		t.Fatalf("DELETE /volumes/user_vol failed: %d", res.Code)
	}
	if res := doReq(t, h, http.MethodPost, "/api/v1/volumes/prune", nil, nil); res.Code != http.StatusOK {
		t.Fatalf("POST /volumes/prune failed: %d", res.Code)
	}

	// Networks endpoints + 403 protected guard
	if res := doReq(t, h, http.MethodGet, "/api/v1/networks", nil, nil); res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "app_net") {
		t.Fatalf("GET /networks failed: %d %s", res.Code, res.Body.String())
	}
	if res := doReq(t, h, http.MethodDelete, "/api/v1/networks/bridge", nil, nil); res.Code != http.StatusForbidden {
		t.Fatalf("expected 403 deleting bridge network, got %d", res.Code)
	}
	if res := doReq(t, h, http.MethodPost, "/api/v1/networks", map[string]any{"name": "my_net", "driver": "bridge"}, nil); res.Code != http.StatusCreated {
		t.Fatalf("POST /networks failed: %d", res.Code)
	}
	if res := doReq(t, h, http.MethodPost, "/api/v1/networks/n_app/connect", map[string]string{"containerId": "c1"}, nil); res.Code != http.StatusOK {
		t.Fatalf("POST connect failed: %d", res.Code)
	}
	if res := doReq(t, h, http.MethodPost, "/api/v1/networks/n_app/disconnect", map[string]string{"containerId": "c1"}, nil); res.Code != http.StatusOK {
		t.Fatalf("POST disconnect failed: %d", res.Code)
	}
	if res := doReq(t, h, http.MethodDelete, "/api/v1/networks/n_app", nil, nil); res.Code != http.StatusOK {
		t.Fatalf("DELETE /networks/n_app failed: %d", res.Code)
	}
	if res := doReq(t, h, http.MethodPost, "/api/v1/networks/prune", nil, nil); res.Code != http.StatusOK {
		t.Fatalf("POST /networks/prune failed: %d", res.Code)
	}

	// Docker Events list & SSE stream
	if res := doReq(t, h, http.MethodGet, "/api/v1/docker/events", nil, nil); res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "dh-app") {
		t.Fatalf("GET /docker/events failed: %d %s", res.Code, res.Body.String())
	}
	ts := httptest.NewServer(h)
	defer ts.Close()
	sseResp, err := http.Get(ts.URL + "/api/v1/docker/events/stream")
	if err != nil {
		t.Fatalf("GET /docker/events/stream failed: %v", err)
	}
	defer sseResp.Body.Close()
	scanner := bufio.NewScanner(sseResp.Body)
	foundEvent := false
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "dh-app") {
			foundEvent = true
			break
		}
	}
	if !foundEvent {
		t.Fatal("expected initial cached event on /api/v1/docker/events/stream")
	}

	// Auth enforcement check
	authMgr := auth.NewManagerWithConfig(v, filepath.Join(t.TempDir(), "auth_cp2.json"), auth.DefaultAdminEmail, true)
	hAuth := NewWithAuth(eng, v, "hook", fstest.MapFS{}, authMgr)
	for _, ep := range []string{"/api/v1/volumes", "/api/v1/networks", "/api/v1/docker/events", "/api/v1/docker/events/stream"} {
		if r401 := doReq(t, hAuth, http.MethodGet, ep, nil, nil); r401.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 on %s when auth enforced, got %d", ep, r401.Code)
		}
	}
}
