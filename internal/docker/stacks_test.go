package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestDockerStacksTemplatesAndRegistryRunCheckpoint3(t *testing.T) {
	stacksDir := t.TempDir()
	regFile := filepath.Join(t.TempDir(), "registries.json")
	mockLogDir := t.TempDir()
	argsLog := filepath.Join(mockLogDir, "args.log")
	envSnapLog := filepath.Join(mockLogDir, "env_snap.log")

	mockBin := filepath.Join(t.TempDir(), "mock-docker")
	mockScript := "#!/bin/sh\n" +
		"echo \"$*\" >> " + argsLog + "\n" +
		"prev=\"\"\n" +
		"for a in \"$@\"; do\n" +
		"  if [ \"$prev\" = \"--env-file\" ] && [ -f \"$a\" ]; then\n" +
		"    cat \"$a\" >> " + envSnapLog + "\n" +
		"    echo \"---\" >> " + envSnapLog + "\n" +
		"  fi\n" +
		"  prev=\"$a\"\n" +
		"done\n" +
		"echo \"mock docker compose ok: $*\"\n"
	if err := os.WriteFile(mockBin, []byte(mockScript), 0o755); err != nil {
		t.Fatalf("write mock compose bin: %v", err)
	}

	t.Setenv("STACKS_DIR", stacksDir)
	t.Setenv("REGISTRIES_DATA_FILE", regFile)
	t.Setenv("DOCKER_COMPOSE_BIN", mockBin)

	var mu sync.Mutex
	var pullAuthHdr string
	var createdPayloads []map[string]any
	createdOnce := false
	startedCustom := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/_ping":
			_, _ = w.Write([]byte("OK"))
		case r.URL.Path == "/version":
			_ = json.NewEncoder(w).Encode(map[string]string{"Version": "29.1.3"})
		case r.URL.Path == "/info":
			_ = json.NewEncoder(w).Encode(map[string]any{"Name": "cp3-host", "NCPU": 4, "MemTotal": int64(8) << 30, "ServerVersion": "29.1.3"})
		case r.URL.Path == "/containers/json":
			containers := []map[string]any{
				{
					"Id":     "sys0000000000001",
					"Names":  []string{"/deploymenthub-control-plane"},
					"Image":  "deploymenthub:latest",
					"State":  "running",
					"Status": "Up 2h",
					"Labels": map[string]string{"com.docker.compose.project": "deployment-hub"},
				},
			}
			if startedCustom {
				containers = append(containers, map[string]any{
					"Id":     "cust999999999999",
					"Names":  []string{"/custom-web"},
					"Image":  "ghcr.io/org/custom-web:v1",
					"State":  "running",
					"Status": "Up 2s",
					"Ports":  []map[string]any{{"IP": "127.0.0.1", "PrivatePort": 8080, "PublicPort": 18080, "Type": "tcp"}},
					"Labels": map[string]string{"deploymenthub.custom": "true"},
				})
			}
			_ = json.NewEncoder(w).Encode(containers)
		case r.URL.Path == "/images/json":
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		case r.URL.Path == "/networks":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"Id": "net1", "Name": "deploymenthub_proxy", "Driver": "bridge"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/images/create":
			pullAuthHdr = r.Header.Get("X-Registry-Auth")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{\"status\":\"Pulling from org/custom-web\",\"id\":\"v1\"}\n{\"status\":\"Pull complete\",\"id\":\"abc\"}\n"))
		case r.Method == http.MethodPost && r.URL.Path == "/containers/create":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			createdPayloads = append(createdPayloads, body)
			if !createdOnce {
				createdOnce = true
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "No such image"})
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"Id": "cust999999999999"})
		case r.Method == http.MethodPost && r.URL.Path == "/containers/cust999999999999/start":
			startedCustom = true
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	eng := newTestEngine(t, srv.URL)
	ctx := context.Background()

	// 1. Service Templates: 6 templates & distinct CSPRNG passwords
	t1 := eng.GetServiceTemplates()
	t2 := eng.GetServiceTemplates()
	if len(t1) != 6 {
		t.Fatalf("expected 6 service templates, got %d", len(t1))
	}
	seenKeys := map[string]bool{}
	for _, tpl := range t1 {
		seenKeys[tpl.Key] = true
		if strings.TrimSpace(tpl.ComposeYAML) == "" || strings.TrimSpace(tpl.EnvText) == "" {
			t.Fatalf("template %q missing yaml or envText", tpl.Key)
		}
	}
	for _, want := range []string{"postgres16", "redis7", "mysql8", "mongodb7", "minio", "nats"} {
		if !seenKeys[want] {
			t.Fatalf("missing template %q", want)
		}
	}
	if t1[0].EnvText == t2[0].EnvText {
		t.Fatal("expected CSPRNG distinct template passwords across invocations")
	}

	// 2. Stack lifecycle + encrypted .env + masked secret preservation
	composeYAML := "services:\n  cache:\n    image: redis:7-alpine\n"
	res, err := eng.DeployStack(ctx, "redis-stack", composeYAML, "REDIS_PASSWORD=supersecret-val\nPUBLIC_PORT=6379\n")
	if err != nil || !res.Success {
		t.Fatalf("DeployStack failed: err=%v out=%s", err, res.Output)
	}

	// Verify env.enc on disk is Vault-encrypted and does not contain plaintext secret
	encBytes, err := os.ReadFile(filepath.Join(stacksDir, "redis-stack", "env.enc"))
	if err != nil || !strings.HasPrefix(string(encBytes), "enc:v1:") || strings.Contains(string(encBytes), "supersecret-val") {
		t.Fatalf("expected Vault encrypted env.enc without plaintext secret, err=%v", err)
	}

	detail, err := eng.GetStackDetail("redis-stack")
	if err != nil || detail.ComposeYAML != composeYAML || len(detail.EnvEntries) != 2 {
		t.Fatalf("GetStackDetail mismatch: err=%v detail=%+v", err, detail)
	}
	for _, ent := range detail.EnvEntries {
		if ent.Preview != "••••••••" {
			t.Fatalf("expected masked preview, got %+v", ent)
		}
	}

	// Re-deploy sending masked placeholder should preserve existing secret
	if _, err := eng.DeployStack(ctx, "redis-stack", composeYAML, "REDIS_PASSWORD=••••••••\nPUBLIC_PORT=6380\n"); err != nil {
		t.Fatalf("redeploy stack with masked secret failed: %v", err)
	}

	snaps, _ := os.ReadFile(envSnapLog)
	if !strings.Contains(string(snaps), "REDIS_PASSWORD=supersecret-val") || !strings.Contains(string(snaps), "PUBLIC_PORT=6380") {
		t.Fatalf("expected temp --env-file to preserve decrypted secret, got:\n%s", string(snaps))
	}

	// System stack protection
	if _, err := eng.DeployStack(ctx, "deployment-hub", composeYAML, ""); !errors.Is(err, ErrProtectedContainer) {
		t.Fatalf("expected ErrProtectedContainer modifying deployment-hub stack, got %v", err)
	}
	if _, err := eng.StackAction(ctx, "deployment-hub", "stop"); !errors.Is(err, ErrProtectedContainer) {
		t.Fatalf("expected ErrProtectedContainer stopping deployment-hub stack, got %v", err)
	}

	if actRes, err := eng.StackAction(ctx, "redis-stack", "logs"); err != nil || !actRes.Success {
		t.Fatalf("StackAction logs failed: err=%v res=%+v", err, actRes)
	}
	if _, err := eng.DeleteStack(ctx, "redis-stack", false); err != nil {
		t.Fatalf("DeleteStack failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stacksDir, "redis-stack")); !os.IsNotExist(err) {
		t.Fatalf("expected deleted stack dir to be removed")
	}

	// 3. Registries + Pull Image + Run Custom Container (auto-pull on 404 + Traefik SSL labels)
	reg, err := eng.SaveRegistry("GHCR", "https://ghcr.io/", "theanh", "ghp_verysecrettoken99")
	if err != nil {
		t.Fatalf("SaveRegistry failed: %v", err)
	}
	if reg.Server != "ghcr.io" || reg.PasswordPreview == "ghp_verysecrettoken99" {
		t.Fatalf("unexpected sanitized registry: %+v", reg)
	}
	regs := eng.ListRegistries()
	if len(regs) != 1 || regs[0].ID != reg.ID {
		t.Fatalf("expected 1 listed registry, got %+v", regs)
	}

	rawRegFile, err := os.ReadFile(regFile)
	if err != nil || strings.Contains(string(rawRegFile), "ghp_verysecrettoken99") {
		t.Fatalf("expected encrypted secret in registries.json, err=%v", err)
	}

	pullRes, err := eng.PullImage(ctx, "ghcr.io/org/custom-web:v1", reg.ID)
	if err != nil || !pullRes.Success || len(pullRes.Lines) == 0 {
		t.Fatalf("PullImage failed: err=%v res=%+v", err, pullRes)
	}
	decodedAuth, err := base64.StdEncoding.DecodeString(pullAuthHdr)
	if err != nil || !strings.Contains(string(decodedAuth), "ghp_verysecrettoken99") || !strings.Contains(string(decodedAuth), `"serveraddress":"ghcr.io"`) {
		t.Fatalf("expected valid X-Registry-Auth header, got %q (decoded=%q)", pullAuthHdr, string(decodedAuth))
	}

	// Reset pullAuthHdr and verify RunCustomContainer 404 -> auto-pull -> retry create -> start
	mu.Lock()
	pullAuthHdr = ""
	mu.Unlock()

	createdCnt, err := eng.RunCustomContainer(ctx, RunContainerRequest{
		Name:          "custom-web",
		Image:         "ghcr.io/org/custom-web:v1",
		RegistryID:    reg.ID,
		Ports:         []string{"127.0.0.1:18080:8080"},
		Env:           []string{"APP_ENV=prod"},
		Volumes:       []string{"custom_data:/data"},
		RestartPolicy: "unless-stopped",
		MemoryMb:      256,
		CPUCores:      0.5,
		Domain:        "tool.example.com",
		ContainerPort: "8080",
		EnableSSL:     true,
		ForceHTTPS:    true,
	})
	if err != nil {
		t.Fatalf("RunCustomContainer failed: %v", err)
	}
	if createdCnt.Name != "custom-web" || createdCnt.Status != "Running" {
		t.Fatalf("unexpected created container: %+v", createdCnt)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(createdPayloads) != 2 {
		t.Fatalf("expected 2 /containers/create attempts (404 then auto-pull retry), got %d", len(createdPayloads))
	}
	if pullAuthHdr == "" {
		t.Fatal("expected auto-pull to attach X-Registry-Auth")
	}
	lbls, _ := createdPayloads[1]["Labels"].(map[string]any)
	if lbls["traefik.enable"] != "true" {
		t.Fatalf("expected Traefik labels on custom container when Domain is set, got %+v", lbls)
	}
	netCfg, _ := createdPayloads[1]["NetworkingConfig"].(map[string]any)
	eps, _ := netCfg["EndpointsConfig"].(map[string]any)
	if _, ok := eps["deploymenthub_proxy"]; !ok {
		t.Fatalf("expected domain container attached to deploymenthub_proxy network, got %+v", eps)
	}

	if err := eng.DeleteRegistry(reg.ID); err != nil {
		t.Fatalf("DeleteRegistry failed: %v", err)
	}
	if len(eng.ListRegistries()) != 0 {
		t.Fatal("expected empty registries after delete")
	}
}
