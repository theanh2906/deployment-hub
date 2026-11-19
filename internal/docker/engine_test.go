package docker

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"deploymenthub/internal/detector"
	"deploymenthub/internal/vault"
)

func newTestEngine(t *testing.T, dockerHost string) *Engine {
	t.Helper()
	v, err := vault.New("test-master-key")
	if err != nil {
		t.Fatalf("vault.New failed: %v", err)
	}
	return NewEngine(dockerHost, v)
}

func deployAndWait(t *testing.T, eng *Engine, req DeployRequest) DeploymentRecord {
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

	events := append([]DeployEvent{}, history...)
	timeout := time.After(5 * time.Second)
	for len(events) == 0 || !events[len(events)-1].Done {
		select {
		case ev, open := <-ch:
			if !open {
				goto done
			}
			events = append(events, ev)
		case <-timeout:
			t.Fatalf("timed out waiting for deployment %s", rec.ID)
		}
	}
done:
	finalRec, exists := eng.GetDeployment(rec.ID)
	if !exists || finalRec.Status != "success" {
		t.Fatalf("deployment %s did not succeed: exists=%v rec=%+v", rec.ID, exists, finalRec)
	}
	return finalRec
}

func TestNewEngineSimulatorSeedAndProbeFallback(t *testing.T) {
	eng := newTestEngine(t, "http://127.0.0.1:1") // unreachable should cleanly fallback
	ov := eng.GetOverview()

	if ov.VPS.RuntimeMode != "simulator" {
		t.Fatalf("expected simulator fallback mode, got %q", ov.VPS.RuntimeMode)
	}
	if ov.VPS.Host == "" {
		t.Fatal("expected non-empty host from readHostTelemetry()")
	}
	if len(ov.Projects) != 0 || len(ov.Containers) != 0 || len(ov.Images) != 0 || len(ov.ProxyRoutes) != 0 {
		t.Fatalf("expected clean empty state with zero mock data, got p=%d c=%d i=%d r=%d",
			len(ov.Projects), len(ov.Containers), len(ov.Images), len(ov.ProxyRoutes))
	}
	if ov.WebhookURL == "" {
		t.Fatal("expected webhook URL")
	}

	// Probe live mock Docker Engine HTTP endpoint (handles /_ping and /version only).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_ping":
			_, _ = w.Write([]byte("OK"))
		case "/version":
			_ = json.NewEncoder(w).Encode(map[string]string{"Version": "27.0.3"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	liveEng := newTestEngine(t, srv.URL)
	liveOv := liveEng.GetOverview()
	if liveOv.VPS.RuntimeMode != "docker" {
		t.Fatalf("expected docker runtimeMode when ping succeeds, got %q", liveOv.VPS.RuntimeMode)
	}
	if !strings.Contains(liveOv.VPS.DockerVersion, "27.0.3") {
		t.Fatalf("expected probed DockerVersion, got %q", liveOv.VPS.DockerVersion)
	}
}

func TestProjectAndContainerLifecycleAndPruneAndSSL(t *testing.T) {
	eng := newTestEngine(t, "")

	req := DeployRequest{
		AppName:     "sample-web-app",
		RepoURL:     "https://github.com/example-org/sample-web-app.git",
		Branch:      "main",
		Domain:      "web.localhost",
		DetectMode:  "hybrid",
		PresetKey:   "nextjs",
		PortMapping: "3000 -> 443",
	}
	deployAndWait(t, eng, req)
	// Second deployment populates PreviousTags for rollback testing.
	deployAndWait(t, eng, req)

	initialOv := eng.GetOverview()
	if len(initialOv.Projects) != 1 || len(initialOv.Containers) != 1 || len(initialOv.ProxyRoutes) != 1 {
		t.Fatalf("expected 1 deployed project/container/route, got p=%d c=%d r=%d",
			len(initialOv.Projects), len(initialOv.Containers), len(initialOv.ProxyRoutes))
	}
	cntID := initialOv.Containers[0].ID
	prevTag := initialOv.Containers[0].PreviousTags[0]

	// Container stop -> parent project reflects Stopped -> RestartProject brings it back Running.
	stopped, err := eng.ContainerAction(cntID, "stop", "")
	if err != nil || stopped.Status != "Stopped" || stopped.RAMMb != 0 {
		t.Fatalf("stop action failed: %+v, err=%v", stopped, err)
	}
	ovAfterStop := eng.GetOverview()
	if ovAfterStop.Projects[0].Status != "Stopped" {
		t.Fatalf("expected parent project to reflect Stopped when its only container stops")
	}

	restarted, err := eng.RestartProject("sample-web-app")
	if err != nil {
		t.Fatalf("RestartProject failed: %v", err)
	}
	if restarted.Status != "Running" || restarted.RAMMb == 0 {
		t.Fatalf("expected stopped project to start with non-zero RAM, got %+v", restarted)
	}

	// Redeploy project -> new commit SHA & logs.
	prevCommit := initialOv.Projects[0].Commit
	redeployed, err := eng.RedeployProject("sample-web-app")
	if err != nil {
		t.Fatalf("RedeployProject failed: %v", err)
	}
	if redeployed.Commit == prevCommit || redeployed.Status != "Running" {
		t.Fatalf("expected new commit and Running status, got %+v", redeployed)
	}

	// Container start -> rollback -> invalid action.
	started, err := eng.ContainerAction(cntID, "start", "")
	if err != nil || started.Status != "Running" || started.RAMMb == 0 {
		t.Fatalf("start action failed: %+v, err=%v", started, err)
	}

	rolled, err := eng.ContainerAction(cntID, "rollback", prevTag)
	if err != nil {
		t.Fatalf("rollback action failed: %v", err)
	}
	if rolled.Image != prevTag {
		t.Fatalf("expected rolled back image tag %q, got %q", prevTag, rolled.Image)
	}
	if _, err := eng.ContainerAction(cntID, "unknown", ""); err == nil {
		t.Fatal("expected error for unsupported container action")
	}

	// Toggle proxy SSL.
	rt, err := eng.ToggleProxySSL(initialOv.ProxyRoutes[0].ID)
	if err != nil {
		t.Fatalf("ToggleProxySSL failed: %v", err)
	}
	if rt.SSL || rt.Protocol != "HTTP Only" {
		t.Fatalf("expected SSL toggled off on route, got %+v", rt)
	}

	// ClearMockData resets all entities.
	eng.ClearMockData()
	cleared := eng.GetOverview()
	if len(cleared.Projects) != 0 || len(cleared.Containers) != 0 || len(cleared.Images) != 0 || len(cleared.ProxyRoutes) != 0 {
		t.Fatalf("expected all entities cleared after ClearMockData, got p=%d c=%d i=%d r=%d",
			len(cleared.Projects), len(cleared.Containers), len(cleared.Images), len(cleared.ProxyRoutes))
	}

	// Test live Docker Engine discovery + PruneDanglingImages via mock Docker Engine API.
	dockerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_ping":
			_, _ = w.Write([]byte("OK"))
		case "/version":
			_ = json.NewEncoder(w).Encode(map[string]string{"Version": "27.1.0"})
		case "/info":
			_ = json.NewEncoder(w).Encode(map[string]any{"Name": "docker-test-host", "NCPU": 4, "MemTotal": int64(8) * 1024 * 1024 * 1024, "ServerVersion": "27.1.0"})
		case "/containers/json":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"Id":     "cnt-live-1",
					"Names":  []string{"/web-svc"},
					"Image":  "web-svc:v1",
					"State":  "running",
					"Status": "Up 10 minutes",
					"Ports":  []map[string]any{{"IP": "0.0.0.0", "PrivatePort": 8080, "PublicPort": 8080, "Type": "tcp"}},
					"Labels": map[string]string{"com.docker.compose.project": "live-stack"},
				},
			})
		case "/images/json":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"Id": "sha256:1111", "RepoTags": []string{"web-svc:v1"}, "Size": 25 * 1024 * 1024, "Containers": 1, "Created": 1700000000},
				{"Id": "sha256:2222", "RepoTags": []string{}, "Size": 64 * 1024 * 1024, "Containers": 0, "Created": 1700000000},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer dockerSrv.Close()

	liveEng := newTestEngine(t, dockerSrv.URL)
	liveOv := liveEng.GetOverview()
	if liveOv.VPS.Host != "docker-test-host" || len(liveOv.Containers) != 1 || len(liveOv.Images) != 2 {
		t.Fatalf("unexpected live docker overview: host=%q c=%d i=%d", liveOv.VPS.Host, len(liveOv.Containers), len(liveOv.Images))
	}
	pruneRes := liveEng.PruneDanglingImages()
	if pruneRes.RemovedCount != 1 || pruneRes.ReclaimedMb != 64 || len(pruneRes.Images) != 1 {
		t.Fatalf("unexpected prune result: %+v", pruneRes)
	}
}

func TestVerifyPATNeverEchoesRawToken(t *testing.T) {
	eng := newTestEngine(t, "")
	rawPAT := "ghp_SuperSecretTokenValue987654"

	res, err := eng.VerifyPAT(rawPAT, "https://github.com/example-org/go-api-service.git")
	if err != nil {
		t.Fatalf("VerifyPAT failed: %v", err)
	}
	if valid, _ := res["valid"].(bool); !valid {
		t.Fatalf("expected valid=true, got %+v", res)
	}
	preview, _ := res["encryptedTokenPreview"].(string)
	if !strings.HasPrefix(preview, "enc:v1:") || strings.Contains(preview, rawPAT) {
		t.Fatalf("encryptedTokenPreview leaked or malformed: %q", preview)
	}
	if det, ok := res["detectResult"].(detector.DetectResult); !ok || det.PresetKey != "go" {
		t.Fatalf("expected go detectResult, got %#v", res["detectResult"])
	}

	if _, err := eng.VerifyPAT("bad", "https://github.com/example-org/repo"); err == nil {
		t.Fatal("expected invalid short PAT to fail")
	}
}

func TestStartDeploymentAsyncPipelineAndSubscribe(t *testing.T) {
	eng := newTestEngine(t, "")
	secretPAT := "ghp_SecretDeployToken123456"
	secretEnv := "sk_live_very_secret_998877"

	rec, err := eng.StartDeployment(DeployRequest{
		AppName:     "billing-go-svc",
		RepoURL:     "https://github.com/example-org/go-billing-service.git",
		Branch:      "main",
		Domain:      "billing.localhost",
		SCMMode:     "pat",
		PAT:         secretPAT,
		DetectMode:  "hybrid",
		PresetKey:   "go",
		PortMapping: "8080 -> 443",
		EnvVars: []detector.EnvVar{
			{Key: "PORT", Value: "8080", Secret: false},
			{Key: "STRIPE_SECRET", Value: secretEnv, Secret: true},
		},
	})
	if err != nil {
		t.Fatalf("StartDeployment failed: %v", err)
	}
	if rec.ID == "" || rec.Status != "running" {
		t.Fatalf("unexpected initial deployment record: %+v", rec)
	}

	history, ch, unsub, ok := eng.SubscribeDeployment(rec.ID)
	if !ok {
		t.Fatal("expected SubscribeDeployment ok=true")
	}
	defer unsub()

	events := append([]DeployEvent{}, history...)
	timeout := time.After(5 * time.Second)
	for len(events) == 0 || !events[len(events)-1].Done {
		_, _ = eng.GetDeployment(rec.ID)
		select {
		case ev, open := <-ch:
			if !open {
				goto doneCollect
			}
			events = append(events, ev)
		case <-timeout:
			t.Fatalf("timed out waiting for deployment %s to finish (got %d events)", rec.ID, len(events))
		}
	}

doneCollect:
	final := events[len(events)-1]
	if !final.Done || final.Stage != 5 || final.Status != "success" {
		t.Fatalf("expected stage 5 success final event, got %+v", final)
	}

	gotRec, exists := eng.GetDeployment(rec.ID)
	if !exists || gotRec.Status != "success" || gotRec.Stage != 5 {
		t.Fatalf("unexpected final GetDeployment: exists=%v rec=%+v", exists, gotRec)
	}
	for _, l := range gotRec.Logs {
		if strings.Contains(l, secretPAT) || strings.Contains(l, secretEnv) {
			t.Fatalf("secret leaked in deployment logs: %q", l)
		}
	}

	// Late subscriber after completion should immediately receive history and closed channel.
	lateHist, lateCh, lateUnsub, lateOK := eng.SubscribeDeployment(rec.ID)
	defer lateUnsub()
	if !lateOK || len(lateHist) < 5 || !lateHist[len(lateHist)-1].Done {
		t.Fatalf("expected complete history for late subscriber, got %d events", len(lateHist))
	}
	if _, open := <-lateCh; open {
		t.Fatal("expected late subscriber channel to be pre-closed")
	}

	// Verify Overview now includes the newly deployed Project, Container, Image, and ProxyRoute.
	ov := eng.GetOverview()
	foundProj, foundRoute := false, false
	for _, p := range ov.Projects {
		if p.Name == "billing-go-svc" && p.Status == "Running" {
			foundProj = true
		}
	}
	for _, r := range ov.ProxyRoutes {
		if r.Domain == "billing.localhost" && r.SSL {
			foundRoute = true
		}
	}
	if !foundProj || !foundRoute {
		t.Fatalf("expected deployed project (%v) and proxy route (%v) in Overview", foundProj, foundRoute)
	}

	// Validation error check.
	if _, err := eng.StartDeployment(DeployRequest{}); err == nil {
		t.Fatal("expected validation error for empty DeployRequest")
	}
}

func TestParseDockerMultiplexedStream(t *testing.T) {
	makeFrame := func(streamType byte, payload string) []byte {
		hdr := make([]byte, 8)
		hdr[0] = streamType
		binary.BigEndian.PutUint32(hdr[4:8], uint32(len(payload)))
		return append(hdr, []byte(payload)...)
	}

	var raw []byte
	raw = append(raw, makeFrame(1, "listening on :8080\nGET /healthz 200\n")...)
	raw = append(raw, makeFrame(2, "warn: slow query 120ms\n")...)
	raw = append(raw, makeFrame(1, "ready\r\n")...)

	stdout, stderr, err := ParseDockerMultiplexedStream(raw)
	if err != nil {
		t.Fatalf("ParseDockerMultiplexedStream failed: %v", err)
	}
	if len(stdout) != 3 || stdout[0] != "listening on :8080" || stdout[1] != "GET /healthz 200" || stdout[2] != "ready" {
		t.Fatalf("unexpected stdout lines: %#v", stdout)
	}
	if len(stderr) != 1 || stderr[0] != "warn: slow query 120ms" {
		t.Fatalf("unexpected stderr lines: %#v", stderr)
	}

	if _, _, err := ParseDockerMultiplexedStream([]byte{1, 0, 0}); err == nil {
		t.Fatal("expected error for truncated frame header")
	}
	if _, _, err := ParseDockerMultiplexedStream([]byte{1, 0, 0, 0, 0, 0, 0, 10, 'a', 'b'}); err == nil {
		t.Fatal("expected error for truncated frame payload")
	}
}

func TestEngineConcurrentAccess(t *testing.T) {
	eng := newTestEngine(t, "")
	deployAndWait(t, eng, DeployRequest{
		AppName:    "concurrent-app",
		RepoURL:    "https://github.com/example-org/concurrent-app.git",
		Domain:     "concurrent.localhost",
		PresetKey:  "go",
		DetectMode: "hybrid",
	})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = eng.GetOverview()
			if idx%2 == 0 {
				_, _ = eng.RestartProject("concurrent-app")
			} else {
				_, _ = eng.ToggleProxySSL("concurrent.localhost")
			}
		}(i)
	}
	wg.Wait()
}

func TestTraefikConfigMatchesAndWriteFileAtomic(t *testing.T) {
	desired := map[string]string{
		"--providers.file.directory":                              "/etc/traefik/dynamic",
		"--providers.file.watch":                                  "true",
		"--certificatesresolvers.cloudflare.acme.dnschallenge":    "true",
		"--certificatesresolvers.cloudflare.acme.dnschallenge.provider": "cloudflare",
		"--certificatesresolvers.cloudflare.acme.dnschallenge.resolvers": "1.1.1.1:53,8.8.8.8:53",
		"--certificatesresolvers.cloudflare.acme.email":           "theanh2906@gmail.com",
		"--certificatesresolvers.cloudflare.acme.storage":         "/letsencrypt/acme.json",
	}

	env := []string{"PATH=/usr/local/sbin:/usr/local/bin", "CF_DNS_API_TOKEN=cf_tok_123"}
	cmd := []string{
		"--providers.docker=true",
		"--certificatesresolvers.cloudflare.acme.storage=/letsencrypt/acme.json",
		"--certificatesresolvers.cloudflare.acme.email=theanh2906@gmail.com",
		"--providers.file.watch=true",
		"--providers.file.directory=/etc/traefik/dynamic",
		"--certificatesresolvers.cloudflare.acme.dnschallenge.resolvers=1.1.1.1:53,8.8.8.8:53",
		"--certificatesresolvers.cloudflare.acme.dnschallenge.provider=cloudflare",
		"--certificatesresolvers.cloudflare.acme.dnschallenge=true",
	}

	if !traefikConfigMatches(env, cmd, "cf_tok_123", desired) {
		t.Fatal("expected traefikConfigMatches=true when token and all flags match regardless of order")
	}
	if traefikConfigMatches(env, cmd, "cf_tok_other", desired) {
		t.Fatal("expected traefikConfigMatches=false when token differs")
	}
	cmdDiffFlag := append([]string(nil), cmd...)
	cmdDiffFlag[2] = "--certificatesresolvers.cloudflare.acme.email=other@example.com"
	if traefikConfigMatches(env, cmdDiffFlag, "cf_tok_123", desired) {
		t.Fatal("expected traefikConfigMatches=false when a flag value differs")
	}

	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "hub-domain.yml")
	first := []byte("http:\n  routers:\n    demo: {}\n")
	if err := writeFileAtomic(targetPath, first, 0o644); err != nil {
		t.Fatalf("first writeFileAtomic failed: %v", err)
	}
	got, err := os.ReadFile(targetPath)
	if err != nil || !bytes.Equal(got, first) {
		t.Fatalf("unexpected file contents after first write: err=%v got=%q", err, got)
	}
	info1, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}

	// Same bytes should return nil without rewriting the file
	time.Sleep(10 * time.Millisecond)
	if err := writeFileAtomic(targetPath, first, 0o644); err != nil {
		t.Fatalf("no-op writeFileAtomic failed: %v", err)
	}
	info2, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("stat 2 failed: %v", err)
	}
	if !info1.ModTime().Equal(info2.ModTime()) {
		t.Fatalf("expected identical writeFileAtomic to skip disk write (mtime changed from %v to %v)", info1.ModTime(), info2.ModTime())
	}

	second := []byte("http:\n  routers:\n    demo2: {}\n")
	if err := writeFileAtomic(targetPath, second, 0o644); err != nil {
		t.Fatalf("second writeFileAtomic failed: %v", err)
	}
	got2, err := os.ReadFile(targetPath)
	if err != nil || !bytes.Equal(got2, second) {
		t.Fatalf("unexpected file contents after update: err=%v got=%q", err, got2)
	}
}
