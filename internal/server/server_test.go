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
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"deploymenthub/internal/detector"
	"deploymenthub/internal/docker"
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

	// Overview
	resOv := doReq(t, h, http.MethodGet, "/api/v1/overview", nil, nil)
	if resOv.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/overview status = %d", resOv.Code)
	}
	var ov docker.Overview
	if err := json.Unmarshal(resOv.Body.Bytes(), &ov); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	if len(ov.Projects) < 5 || len(ov.Containers) < 5 || len(ov.Images) < 5 || len(ov.ProxyRoutes) < 5 {
		t.Fatalf("expected seeded entities, got projects=%d containers=%d images=%d routes=%d",
			len(ov.Projects), len(ov.Containers), len(ov.Images), len(ov.ProxyRoutes))
	}

	// Projects list
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

func TestProjectContainerImageAndProxyOperations(t *testing.T) {
	h, eng := newTestHandler(t, "whsec-test")
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

	// Prune dangling images
	resPrune := doReq(t, h, http.MethodPost, "/api/v1/images/prune", nil, nil)
	if resPrune.Code != http.StatusOK {
		t.Fatalf("prune status = %d", resPrune.Code)
	}
	var pruneRes docker.PruneResult
	if err := json.Unmarshal(resPrune.Body.Bytes(), &pruneRes); err != nil {
		t.Fatalf("decode prune result: %v", err)
	}
	if pruneRes.RemovedCount == 0 || pruneRes.ReclaimedMb == 0 {
		t.Fatalf("expected dangling images removed, got %#v", pruneRes)
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
}

func TestSCMDetectorAndBuildDoctor(t *testing.T) {
	h, _ := newTestHandler(t, "whsec-test")

	// Invalid PAT
	resBadPAT := doReq(t, h, http.MethodPost, "/api/v1/scm/verify-pat", map[string]string{
		"token":   "short",
		"repoUrl": "https://github.com/anh-tang/next-shop",
	}, nil)
	if resBadPAT.Code != http.StatusBadRequest {
		t.Fatalf("short PAT status = %d, want 400", resBadPAT.Code)
	}

	// Valid PAT
	rawPAT := "ghp_superSecretToken123456"
	resPAT := doReq(t, h, http.MethodPost, "/api/v1/scm/verify-pat", map[string]string{
		"token":   rawPAT,
		"repoUrl": "https://github.com/anh-tang/next-shop",
	}, nil)
	if resPAT.Code != http.StatusOK {
		t.Fatalf("valid PAT status = %d, body=%s", resPAT.Code, resPAT.Body.String())
	}
	if strings.Contains(resPAT.Body.String(), rawPAT) {
		t.Fatalf("verify-pat response echoed raw PAT")
	}

	// Detect hybrid vs file
	resDet := doReq(t, h, http.MethodPost, "/api/v1/detect", detector.DetectRequest{
		RepoURL: "https://github.com/anh-tang/rust-ws-api",
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
		RepoURL:    "https://github.com/anh-tang/billing-go-svc",
		Branch:     "main",
		Domain:     "billing.anna.dev",
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
		if p.Name == "billing-go-svc" || p.Domain == "billing.anna.dev" {
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
