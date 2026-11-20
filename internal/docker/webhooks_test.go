package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestGitHubWebhookPermissionAndProjectLifecycle(t *testing.T) {
	t.Setenv("WEBHOOKS_DATA_FILE", filepath.Join(t.TempDir(), "webhooks.json"))
	t.Setenv("HUB_DOMAIN", "hub.example.com")

	var mu sync.Mutex
	hooksCreated := 0
	hooksUpdated := 0
	hooksDeleted := 0
	var lastHookSecret string
	var hookList []map[string]any

	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := strings.TrimSpace(r.Header.Get("Authorization"))
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/user":
			if authHdr == "Bearer bad_token_401" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if authHdr == "Bearer token_read_only" {
				w.Header().Set("X-OAuth-Scopes", "repo")
			} else {
				w.Header().Set("X-OAuth-Scopes", "repo, admin:repo_hook")
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"login": "theanh2906"})

		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/web-app/hooks":
			if authHdr == "Bearer token_read_only" {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "Resource not accessible by personal access token"})
				return
			}
			mu.Lock()
			list := append([]map[string]any{}, hookList...)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(list)

		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/web-app/hooks":
			if authHdr == "Bearer token_read_only" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			var payload struct {
				Config struct {
					URL    string `json:"url"`
					Secret string `json:"secret"`
				} `json:"config"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			mu.Lock()
			hooksCreated++
			lastHookSecret = payload.Config.Secret
			hookList = []map[string]any{
				{"id": 7788, "active": true, "config": map[string]string{"url": payload.Config.URL}},
			}
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":     7788,
				"config": map[string]string{"url": payload.Config.URL},
			})

		case r.Method == http.MethodPatch && r.URL.Path == "/repos/acme/web-app/hooks/7788":
			var payload struct {
				Config struct {
					URL    string `json:"url"`
					Secret string `json:"secret"`
				} `json:"config"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			mu.Lock()
			hooksUpdated++
			lastHookSecret = payload.Config.Secret
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":     7788,
				"config": map[string]string{"url": payload.Config.URL},
			})

		case r.Method == http.MethodDelete && r.URL.Path == "/repos/acme/web-app/hooks/7788":
			mu.Lock()
			hooksDeleted++
			hookList = nil
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ghSrv.Close()

	eng := newTestEngine(t, "")
	eng.SetWebhookSecret("my-webhook-hmac-secret")
	eng.githubAPIBase = ghSrv.URL

	// Seed a deployed project belonging to acme/web-app
	eng.registerCompletedDeployment(DeployRequest{
		AppName:     "web-app",
		RepoURL:     "https://github.com/acme/web-app",
		Branch:      "main",
		Domain:      "web.example.com",
		PresetKey:   "nextjs",
		PortMapping: "3000:3000",
	}, "abc1234", "initial commit", nil, "live")

	// 1. Missing token -> denied cleanly
	cEmpty := eng.CheckGitHubWebhookPermission("", "https://github.com/acme/web-app")
	if cEmpty.CanManageWebhook || cEmpty.HasToken {
		t.Fatalf("expected empty token without saved PAT to report CanManageWebhook=false, got %+v", cEmpty)
	}

	// 2. Read-only PAT (403 on /hooks) -> CanManageWebhook=false with clear warning reason
	cNoHook := eng.CheckGitHubWebhookPermission("token_read_only", "acme/web-app")
	if !cNoHook.Valid || cNoHook.CanManageWebhook || !strings.Contains(cNoHook.WebhookReason, "403") {
		t.Fatalf("expected Valid=true CanManageWebhook=false HTTP 403 reason, got %+v", cNoHook)
	}

	// 3. Read-only PAT attempting ConfigureProjectWebhook(autoWebhook=true) must fail cleanly
	if _, err := eng.ConfigureProjectWebhook("web-app", "acme/web-app", "main", "token_read_only", true); err == nil {
		t.Fatal("expected ConfigureProjectWebhook with read-only PAT to fail")
	}

	// 4. VerifyPAT with full-permission PAT returns canManageWebhook=true and encrypts PAT
	vp, err := eng.VerifyPAT("token_admin_hooks_ok", "https://github.com/acme/web-app")
	if err != nil {
		t.Fatalf("VerifyPAT failed: %v", err)
	}
	if valid, _ := vp["valid"].(bool); !valid {
		t.Fatalf("expected valid=true, got %+v", vp)
	}
	if canHook, _ := vp["canManageWebhook"].(bool); !canHook {
		t.Fatalf("expected canManageWebhook=true, got %+v", vp)
	}

	// 5. ConfigureProjectWebhook creates GitHub webhook #7788 using saved PAT
	cfg, err := eng.ConfigureProjectWebhook("web-app", "acme/web-app", "main", "", true)
	if err != nil {
		t.Fatalf("ConfigureProjectWebhook create failed: %v", err)
	}
	if !cfg.Active || cfg.HookID != 7788 || cfg.HookURL != "https://hub.example.com/api/v1/webhooks/github" {
		t.Fatalf("unexpected created webhook config: %+v", cfg)
	}
	mu.Lock()
	if hooksCreated != 1 || lastHookSecret != "my-webhook-hmac-secret" {
		mu.Unlock()
		t.Fatalf("expected 1 webhook POST with configured secret, created=%d secret=%q", hooksCreated, lastHookSecret)
	}
	mu.Unlock()

	// Confirm raw PAT never stored plaintext in webhooks.json
	rawDisk, err := os.ReadFile(os.Getenv("WEBHOOKS_DATA_FILE"))
	if err != nil || strings.Contains(string(rawDisk), "token_admin_hooks_ok") {
		t.Fatalf("expected encrypted PAT on disk without plaintext leak, err=%v", err)
	}

	// 6. Calling ConfigureProjectWebhook again updates existing hook #7788 (PATCH)
	cfg2, err := eng.ConfigureProjectWebhook("web-app", "acme/web-app", "prod", "", true)
	if err != nil || !cfg2.Active || cfg2.HookID != 7788 {
		t.Fatalf("ConfigureProjectWebhook patch failed: err=%v cfg=%+v", err, cfg2)
	}
	mu.Lock()
	if hooksUpdated != 1 {
		mu.Unlock()
		t.Fatalf("expected 1 webhook PATCH update, got %d", hooksUpdated)
	}
	mu.Unlock()

	// Overview should show WebhookActive=true on Project
	ov := eng.GetOverview()
	foundProj := false
	for _, p := range ov.Projects {
		if p.Name == "web-app" {
			foundProj = true
			if !p.WebhookActive || p.WebhookID != 7788 {
				t.Fatalf("expected Project.WebhookActive=true HookID=7788 in Overview, got %+v", p)
			}
		}
	}
	if !foundProj {
		t.Fatal("expected web-app in Overview.Projects")
	}

	// 7. DeleteProjectWebhook removes GitHub webhook and clears active state
	delCfg, err := eng.DeleteProjectWebhook(context.Background(), "web-app", "")
	if err != nil || delCfg.Active {
		t.Fatalf("DeleteProjectWebhook failed: err=%v cfg=%+v", err, delCfg)
	}
	mu.Lock()
	if hooksDeleted != 1 {
		mu.Unlock()
		t.Fatalf("expected 1 GitHub DELETE hook call, got %d", hooksDeleted)
	}
	mu.Unlock()
}
