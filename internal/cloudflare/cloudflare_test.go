package cloudflare

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"deploymenthub/internal/vault"
)

func TestCloudflareManagerConnectUpsertSSLAndPersistence(t *testing.T) {
	const testToken = "cf_token_secret_1234567890"
	const testZoneID = "zone-benna-123"
	const testDomain = "bennasolutions.com"

	var mu sync.Mutex
	sslMode := "flexible"
	records := map[string]map[string]any{}
	postCount := 0
	putCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": false,
				"errors":  []map[string]any{{"code": 10000, "message": "Authentication error"}},
			})
			return
		}

		mu.Lock()
		defer mu.Unlock()

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result": []map[string]any{
					{
						"id":           testZoneID,
						"name":         testDomain,
						"status":       "active",
						"name_servers": []string{"hank.ns.cloudflare.com", "lara.ns.cloudflare.com"},
					},
				},
			})

		case r.Method == http.MethodGet && r.URL.Path == "/zones/"+testZoneID+"/settings/ssl":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  map[string]any{"id": "ssl", "value": sslMode},
			})

		case r.Method == http.MethodPatch && r.URL.Path == "/zones/"+testZoneID+"/settings/ssl":
			var body struct {
				Value string `json:"value"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			sslMode = body.Value
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  map[string]any{"id": "ssl", "value": sslMode},
			})

		case r.Method == http.MethodGet && r.URL.Path == "/zones/"+testZoneID+"/dns_records":
			filterName := r.URL.Query().Get("name")
			list := make([]map[string]any, 0, len(records))
			for _, rec := range records {
				if filterName == "" || rec["name"] == filterName {
					list = append(list, rec)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  list,
			})

		case r.Method == http.MethodPost && r.URL.Path == "/zones/"+testZoneID+"/dns_records":
			postCount++
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			id := "rec-1"
			if body["name"] == "*."+testDomain {
				id = "rec-wildcard"
			}
			rec := map[string]any{
				"id":          id,
				"type":        body["type"],
				"name":        body["name"],
				"content":     body["content"],
				"ttl":         1,
				"proxied":     body["proxied"],
				"modified_on": "2026-11-19T06:00:00Z",
			}
			records[id] = rec
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": rec})

		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/zones/"+testZoneID+"/dns_records/"):
			putCount++
			id := strings.TrimPrefix(r.URL.Path, "/zones/"+testZoneID+"/dns_records/")
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			rec := map[string]any{
				"id":          id,
				"type":        body["type"],
				"name":        body["name"],
				"content":     body["content"],
				"ttl":         1,
				"proxied":     body["proxied"],
				"modified_on": "2026-11-19T06:05:00Z",
			}
			records[id] = rec
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": rec})

		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/zones/"+testZoneID+"/dns_records/"):
			id := strings.TrimPrefix(r.URL.Path, "/zones/"+testZoneID+"/dns_records/")
			delete(records, id)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": id}})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	dataFile := filepath.Join(t.TempDir(), "cloudflare.json")
	v, err := vault.New("unit-test-master-key-32-bytes-ok")
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}

	mgr := NewManager(v, dataFile)
	mgr.SetAPIBaseURL(srv.URL)

	// Invalid token must return error without persisting
	if _, _, err := mgr.Connect("bad_token", "", testDomain, "169.58.206.8", true); err == nil {
		t.Fatal("expected invalid token to fail Connect")
	}

	cfg, zones, err := mgr.Connect(testToken, "", testDomain, "169.58.206.8", true)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	if !cfg.Enabled || cfg.ZoneID != testZoneID || cfg.BaseDomain != testDomain || cfg.ServerIP != "169.58.206.8" {
		t.Fatalf("unexpected Connect cfg: %+v", cfg)
	}
	if cfg.EncryptedToken != "" || !strings.HasPrefix(cfg.TokenPreview, "enc:v1:") || strings.Contains(cfg.TokenPreview, testToken) {
		t.Fatalf("Connect leaked or failed to encrypt token: preview=%q raw=%q", cfg.TokenPreview, cfg.EncryptedToken)
	}
	if len(zones) != 1 || zones[0].Name != testDomain {
		t.Fatalf("unexpected zones: %+v", zones)
	}

	// Upsert wildcard create + idempotent update + no-op repeat
	wc, err := mgr.UpsertARecord("*", "169.58.206.8", true)
	if err != nil || wc.Name != "*."+testDomain || !wc.Proxied {
		t.Fatalf("wildcard create failed: rec=%+v err=%v", wc, err)
	}
	wc2, err := mgr.UpsertARecord("*."+testDomain, "169.58.206.8", false)
	if err != nil || wc2.ID != wc.ID || wc2.Proxied {
		t.Fatalf("wildcard update idempotency failed: rec=%+v err=%v", wc2, err)
	}
	mu.Lock()
	putsBeforeRepeat := putCount
	postsBeforeRepeat := postCount
	mu.Unlock()
	if putsBeforeRepeat != 1 || postsBeforeRepeat != 1 {
		t.Fatalf("expected 1 post and 1 put before no-op test, got post=%d put=%d", postsBeforeRepeat, putsBeforeRepeat)
	}

	// Repeating with identical IP & proxied flag should be an idempotent no-op (zero PUT calls)
	wc3, err := mgr.UpsertARecord("*."+testDomain, "169.58.206.8", false)
	if err != nil || wc3.ID != wc.ID || wc3.Proxied {
		t.Fatalf("wildcard repeat failed: rec=%+v err=%v", wc3, err)
	}
	mu.Lock()
	putsAfterRepeat := putCount
	mu.Unlock()
	if putsAfterRepeat != putsBeforeRepeat {
		t.Fatalf("expected identical UpsertARecord to skip PUT; puts went from %d to %d", putsBeforeRepeat, putsAfterRepeat)
	}

	// Concurrent UpsertARecord burst for the same record must serialize cleanly without duplicate POSTs
	var burstWG sync.WaitGroup
	for i := 0; i < 6; i++ {
		burstWG.Add(1)
		go func() {
			defer burstWG.Done()
			if _, upsertErr := mgr.UpsertARecord("api", "169.58.206.8", true); upsertErr != nil {
				t.Errorf("concurrent UpsertARecord failed: %v", upsertErr)
			}
		}()
	}
	burstWG.Wait()
	mu.Lock()
	postsAfterBurst := postCount
	putsAfterBurst := putCount
	mu.Unlock()
	if postsAfterBurst != 2 || putsAfterBurst != putsAfterRepeat {
		t.Fatalf("expected serialized concurrent UpsertARecord to execute 1 POST and 0 PUTs; post=%d put=%d", postsAfterBurst, putsAfterBurst)
	}

	// Set SSL mode strict
	newMode, err := mgr.SetSSLMode("strict")
	if err != nil || newMode != "strict" {
		t.Fatalf("SetSSLMode(strict) failed: mode=%q err=%v", newMode, err)
	}

	// Verify raw token never appears in persisted JSON on disk
	diskBytes, err := os.ReadFile(dataFile)
	if err != nil {
		t.Fatalf("read persisted cloudflare.json: %v", err)
	}
	if strings.Contains(string(diskBytes), testToken) {
		t.Fatal("raw token leaked on disk in cloudflare.json")
	}

	// Reload in new Manager with same vault key and verify decrypted token + state
	reloaded := NewManager(v, dataFile)
	reloaded.SetAPIBaseURL(srv.URL)
	recfg := reloaded.GetSanitizedConfig()
	if !recfg.Enabled || !recfg.WildcardEnabled || recfg.SSLMode != "strict" {
		t.Fatalf("reloaded config mismatch: %+v", recfg)
	}
	decTok, err := reloaded.GetDecryptedToken()
	if err != nil || decTok != testToken {
		t.Fatalf("GetDecryptedToken mismatch: got %q err=%v", decTok, err)
	}

	if err := reloaded.DeleteDNSRecord(wc2.ID); err != nil {
		t.Fatalf("DeleteDNSRecord failed: %v", err)
	}
	if reloaded.GetSanitizedConfig().WildcardEnabled {
		t.Fatal("expected WildcardEnabled=false after deleting wildcard record")
	}
}
