package docker

import (
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestNewEngineSimulatorSeedAndProbeFallback(t *testing.T) {
	eng := newTestEngine(t, "http://127.0.0.1:1") // unreachable should cleanly fallback
	ov := eng.GetOverview()

	if ov.VPS.RuntimeMode != "simulator" {
		t.Fatalf("expected simulator fallback mode, got %q", ov.VPS.RuntimeMode)
	}
	if len(ov.Projects) != 5 {
		t.Fatalf("expected 5 seeded projects, got %d", len(ov.Projects))
	}
	if len(ov.Containers) != 7 {
		t.Fatalf("expected 7 seeded containers, got %d", len(ov.Containers))
	}
	if len(ov.Images) != 6 {
		t.Fatalf("expected 6 seeded images, got %d", len(ov.Images))
	}
	if len(ov.ProxyRoutes) != 5 {
		t.Fatalf("expected 5 seeded proxy routes, got %d", len(ov.ProxyRoutes))
	}
	if ov.WebhookURL == "" {
		t.Fatal("expected seeded webhook URL")
	}

	// Probe live mock Docker Engine HTTP endpoint.
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

	// Restart Stopped project -> Running and syncs container + VPS RAM.
	initialOv := eng.GetOverview()
	restarted, err := eng.RestartProject("react-admin-portal")
	if err != nil {
		t.Fatalf("RestartProject failed: %v", err)
	}
	if restarted.Status != "Running" || restarted.RAMMb == 0 {
		t.Fatalf("expected stopped project to start with non-zero RAM, got %+v", restarted)
	}

	// Redeploy project -> new commit SHA & logs.
	prevCommit := initialOv.Projects[0].Commit
	redeployed, err := eng.RedeployProject("nextjs-commerce-store")
	if err != nil {
		t.Fatalf("RedeployProject failed: %v", err)
	}
	if redeployed.Commit == prevCommit || redeployed.Status != "Running" {
		t.Fatalf("expected new commit and Running status, got %+v", redeployed)
	}

	// Container stop -> start -> rollback.
	stopped, err := eng.ContainerAction("cnt-next", "stop", "")
	if err != nil || stopped.Status != "Stopped" || stopped.RAMMb != 0 {
		t.Fatalf("stop action failed: %+v, err=%v", stopped, err)
	}
	ovAfterStop := eng.GetOverview()
	if ovAfterStop.Projects[0].Status != "Stopped" {
		t.Fatalf("expected parent project to reflect Stopped when its only container stops")
	}

	started, err := eng.ContainerAction("cnt-next", "start", "")
	if err != nil || started.Status != "Running" || started.RAMMb == 0 {
		t.Fatalf("start action failed: %+v, err=%v", started, err)
	}

	rolled, err := eng.ContainerAction("cnt-next", "rollback", "nextjs-commerce:sha-7c10b4")
	if err != nil {
		t.Fatalf("rollback action failed: %v", err)
	}
	if rolled.Image != "nextjs-commerce:sha-7c10b4" {
		t.Fatalf("expected rolled back image tag, got %q", rolled.Image)
	}
	if _, err := eng.ContainerAction("cnt-next", "unknown", ""); err == nil {
		t.Fatal("expected error for unsupported container action")
	}

	// Prune dangling images (2 dangling images totaling 1180 MB).
	pruneRes := eng.PruneDanglingImages()
	if pruneRes.RemovedCount != 2 || pruneRes.ReclaimedMb != 1180 {
		t.Fatalf("unexpected prune result: %+v", pruneRes)
	}
	if len(pruneRes.Images) != 4 {
		t.Fatalf("expected 4 remaining images after prune, got %d", len(pruneRes.Images))
	}

	// Toggle proxy SSL.
	rt, err := eng.ToggleProxySSL("rt-5")
	if err != nil {
		t.Fatalf("ToggleProxySSL failed: %v", err)
	}
	if !rt.SSL || rt.Protocol != "HTTP/2 + TLS 1.3" {
		t.Fatalf("expected SSL enabled on rt-5, got %+v", rt)
	}
}

func TestVerifyPATNeverEchoesRawToken(t *testing.T) {
	eng := newTestEngine(t, "")
	rawPAT := "ghp_SuperSecretTokenValue987654"

	res, err := eng.VerifyPAT(rawPAT, "https://github.com/my-org/private-go-api.git")
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

	if _, err := eng.VerifyPAT("bad", "https://github.com/org/repo"); err == nil {
		t.Fatal("expected invalid short PAT to fail")
	}
}

func TestStartDeploymentAsyncPipelineAndSubscribe(t *testing.T) {
	eng := newTestEngine(t, "")
	secretPAT := "ghp_SecretDeployToken123456"
	secretEnv := "sk_live_very_secret_998877"

	rec, err := eng.StartDeployment(DeployRequest{
		AppName:     "billing-go-svc",
		RepoURL:     "https://github.com/anh-tang/go-billing-service.git",
		Branch:      "main",
		Domain:      "billing.anna.dev",
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
		if r.Domain == "billing.anna.dev" && r.SSL {
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
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = eng.GetOverview()
			if idx%2 == 0 {
				_, _ = eng.RestartProject("react-admin-portal")
			} else {
				_, _ = eng.ToggleProxySSL("rt-5")
			}
		}(i)
	}
	wg.Wait()
}
