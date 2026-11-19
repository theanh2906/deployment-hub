package server

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

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
