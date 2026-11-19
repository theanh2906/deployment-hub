package mah

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewHubConfigMaskingAndUpdate(t *testing.T) {
	const testToken = "mah_wk_test_fixture_token_1234567890"
	t.Setenv("MAH_API_URL", "http://127.0.0.1:3999/")
	t.Setenv("MAH_API_TOKEN", testToken)
	t.Setenv("MAH_SERVER_HOST", "10.0.0.5")
	t.Setenv("MAH_SSH_USER", "ubuntu")

	hub := NewHub()
	cfg := hub.GetConfig()

	if cfg.APIURL != "http://127.0.0.1:3999" {
		t.Fatalf("expected trimmed APIURL, got %q", cfg.APIURL)
	}
	if !cfg.HasToken {
		t.Fatal("expected HasToken=true")
	}
	wantMasked := "mah_wk_test_...7890"
	if cfg.APIToken != wantMasked {
		t.Fatalf("expected masked token %q, got %q", wantMasked, cfg.APIToken)
	}
	if cfg.ServerHost != "10.0.0.5" || cfg.SSHUser != "ubuntu" {
		t.Fatalf("unexpected host/user config: %+v", cfg)
	}
	if cfg.MCPScriptPath == "" {
		t.Fatal("expected non-empty MCPScriptPath from os.Executable()")
	}

	// Empty or masked token preserves raw token; only non-empty fields update.
	updated := hub.UpdateConfig("http://127.0.0.1:4100/", wantMasked, "", "deploy", "")
	if updated.APIURL != "http://127.0.0.1:4100" || updated.SSHUser != "deploy" || updated.ServerHost != "10.0.0.5" {
		t.Fatalf("unexpected UpdateConfig result: %+v", updated)
	}
	if _, rawTok := hub.endpointAndToken("", ""); rawTok != testToken {
		t.Fatalf("raw token was not preserved: %q", rawTok)
	}

	// Replace with new token.
	updated2 := hub.UpdateConfig("", "mah_wk_newtoken_9876543210", "", "", "/usr/local/bin/deploymenthub")
	if !updated2.HasToken || updated2.APIToken != "mah_wk_newto...3210" || updated2.MCPScriptPath != "/usr/local/bin/deploymenthub" {
		t.Fatalf("unexpected UpdateConfig replacement: %+v", updated2)
	}

	// Clear token with sentinel.
	cleared := hub.UpdateConfig("", "__CLEAR__", "", "", "")
	if cleared.HasToken || cleared.APIToken != "" {
		t.Fatalf("expected cleared token, got %+v", cleared)
	}
}

func TestIsExternalUpstreamAndNativeDefaults(t *testing.T) {
	t.Setenv("MAH_API_URL", "")
	t.Setenv("MAH_DATA_FILE", "")
	hub := NewHub()

	cfg := hub.GetConfig()
	if cfg.APIURL != "http://127.0.0.1:4180" {
		t.Fatalf("expected default native APIURL http://127.0.0.1:4180, got %q", cfg.APIURL)
	}
	if cfg.MCPScriptPath == "" {
		t.Fatal("expected non-empty MCPScriptPath")
	}

	for _, localURL := range []string{"", "native", "local", "http://127.0.0.1:4180", "http://localhost:4180", "http://deploymenthub:4180"} {
		if hub.isExternalUpstream(localURL) {
			t.Fatalf("expected %q not to be treated as external upstream", localURL)
		}
	}
	for _, extURL := range []string{"http://127.0.0.1:3000", "http://127.0.0.1:1", "https://mah.example.com"} {
		if !hub.isExternalUpstream(extURL) {
			t.Fatalf("expected %q to be treated as external upstream", extURL)
		}
	}

	snap := hub.GetSnapshot("", "")
	if snap.Mode != "live" || snap.WorkspaceID != "ws_mah_go" || snap.Health["service"] != "deploymenthub-mah-go" {
		t.Fatalf("unexpected native snapshot defaults: mode=%q ws=%q health=%+v", snap.Mode, snap.WorkspaceID, snap.Health)
	}
}

func TestGetSnapshotLiveAggregationAndHealthEnrichment(t *testing.T) {
	const expectedToken = "mah_wk_test_token_1234567890"
	var mu sync.Mutex
	seenAuth := true

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/health" && r.Header.Get("Authorization") != "Bearer "+expectedToken {
			mu.Lock()
			seenAuth = false
			mu.Unlock()
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{"code": "UNAUTHORIZED", "message": "invalid bearer token"},
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/health":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "ok",
				"service": "@mah/api",
				"version": "0.1.0",
				"checks": map[string]any{
					"database": "up",
				},
			})

		case "/v1/agents":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{
					{"id": "agt_1", "workspaceId": "ws_alpha", "logicalName": "reviewer", "status": "ACTIVE"},
					{"id": "agt_2", "workspaceId": "ws_alpha", "logicalName": "builder", "status": "ACTIVE"},
				},
				"hasMore": false,
			})

		case "/v1/agents/agt_1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":          "agt_1",
				"workspaceId": "ws_alpha",
				"logicalName": "reviewer",
				"status":      "ACTIVE",
				"available":   true,
				"sessions": []map[string]any{
					{"id": "sess_1", "agentId": "agt_1", "machineId": "mach_1", "connectionStatus": "CONNECTED"},
				},
			})

		case "/v1/agents/agt_2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":          "agt_2",
				"workspaceId": "ws_alpha",
				"logicalName": "builder",
				"status":      "ACTIVE",
				"available":   true,
				"sessions": []map[string]any{
					{"id": "sess_2", "agentId": "agt_2", "machineId": "mach_2", "connectionStatus": "CONNECTED"},
				},
			})

		case "/v1/agents/agt_1/inbox":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{
					{
						"status": "QUEUED",
						"envelope": map[string]any{
							"messageId": "msg_old",
							"createdAt": "2026-11-17T10:00:00Z",
						},
					},
					{
						"status": "DELIVERED",
						"envelope": map[string]any{
							"messageId": "msg_shared",
							"createdAt": "2026-11-17T12:00:00Z",
						},
					},
				},
			})

		case "/v1/agents/agt_2/inbox":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{
					{
						"status": "DELIVERED",
						"envelope": map[string]any{
							"messageId": "msg_shared",
							"createdAt": "2026-11-17T12:00:00Z",
						},
					},
					{
						"status": "ACKED",
						"envelope": map[string]any{
							"messageId": "msg_new",
							"createdAt": "2026-11-17T13:00:00Z",
						},
					},
				},
			})

		case "/v1/machines":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{
					{"id": "mach_1", "workspaceId": "ws_alpha", "name": "host-1", "hostname": "h1.local"},
				},
			})

		case "/v1/machines/mach_2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "mach_2", "workspaceId": "ws_alpha", "name": "host-2", "hostname": "h2.local",
			})

		case "/v1/tasks":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{
					{"taskId": "tsk_1", "workspaceId": "ws_alpha", "status": "PROCESSING", "createdAt": "2026-11-17T11:00:00Z"},
				},
			})

		case "/v1/tasks/tsk_1/events":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{
					{"id": "ev_1", "taskId": "tsk_1", "eventType": "TASK_CREATED", "createdAt": "2026-11-17T11:00:00Z"},
					{"id": "ev_2", "taskId": "tsk_1", "eventType": "TASK_STARTED", "createdAt": "2026-11-17T11:00:05Z"},
				},
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("MAH_API_URL", "http://127.0.0.1:1")
	t.Setenv("MAH_API_TOKEN", "wrong-token")
	hub := NewHub()

	snap := hub.GetSnapshot(srv.URL, expectedToken)
	if !seenAuth {
		t.Fatal("expected Authorization Bearer token to be passed to all authenticated endpoints")
	}
	if snap.Mode != "live" {
		t.Fatalf("expected live mode, got %q (reason: %s)", snap.Mode, snap.FallbackReason)
	}
	if snap.WorkspaceID != "ws_alpha" || snap.WorkspaceName != "Workspace ws_alpha" {
		t.Fatalf("unexpected workspace metadata: id=%q name=%q", snap.WorkspaceID, snap.WorkspaceName)
	}

	checks, _ := snap.Health["checks"].(map[string]any)
	if checks["postgres"] != "up" || checks["redis"] != "up" || checks["nats"] != "up" {
		t.Fatalf("expected enriched checks (postgres/redis/nats), got %+v", checks)
	}
	if len(snap.Agents) != 2 || len(snap.Sessions) != 2 || len(snap.Machines) != 2 {
		t.Fatalf("expected 2 agents, 2 sessions, 2 merged machines; got a=%d s=%d m=%d",
			len(snap.Agents), len(snap.Sessions), len(snap.Machines))
	}
	if len(snap.Messages) != 3 {
		t.Fatalf("expected 3 deduplicated messages, got %d", len(snap.Messages))
	}
	if gotFirst := messageIDFromItem(snap.Messages[0]); gotFirst != "msg_new" {
		t.Fatalf("expected newest message first (msg_new), got %q", gotFirst)
	}
	if gotLast := messageIDFromItem(snap.Messages[2]); gotLast != "msg_old" {
		t.Fatalf("expected oldest message last (msg_old), got %q", gotLast)
	}
	if len(snap.Tasks) != 1 || len(snap.TaskEventsByTaskID["tsk_1"]) != 2 {
		t.Fatalf("expected 1 task with 2 events, got tasks=%d events=%d",
			len(snap.Tasks), len(snap.TaskEventsByTaskID["tsk_1"]))
	}
}

func TestLiveMutationsAndUpstreamErrorPropagation(t *testing.T) {
	var lastMsgBody map[string]any
	var lastTaskBody map[string]any
	deletedMsgID := ""
	unregisteredSessID := ""
	cancelledTaskID := ""

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/agents":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["logicalName"] == "bad-agent" {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]any{"code": "CONFLICT", "message": "agent already exists"},
				})
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "agt_created", "logicalName": body["logicalName"]})

		case r.Method == http.MethodPost && r.URL.Path == "/v1/messages":
			_ = json.NewDecoder(r.Body).Decode(&lastMsgBody)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"messageId": "msg_live_1", "status": "QUEUED"})

		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/messages/"):
			deletedMsgID = strings.TrimPrefix(r.URL.Path, "/v1/messages/")
			_ = json.NewEncoder(w).Encode(map[string]any{"messageId": deletedMsgID, "status": "DELETED"})

		case r.Method == http.MethodPost && r.URL.Path == "/v1/tasks":
			_ = json.NewDecoder(r.Body).Decode(&lastTaskBody)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"taskId": "tsk_live_1", "status": "PENDING"})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/cancel"):
			cancelledTaskID = strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/tasks/"), "/cancel")
			_ = json.NewEncoder(w).Encode(map[string]any{"taskId": cancelledTaskID, "status": "CANCELLED"})

		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/sessions/"):
			unregisteredSessID = strings.TrimPrefix(r.URL.Path, "/v1/sessions/")
			_ = json.NewEncoder(w).Encode(map[string]any{"sessionId": unregisteredSessID, "status": "UNREGISTERED"})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("MAH_API_URL", srv.URL)
	hub := NewHub()

	if _, err := hub.RegisterAgent(map[string]any{"logicalName": "good-agent", "capabilities": "code_review, security"}); err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	_, err := hub.RegisterAgent(map[string]any{"logicalName": "bad-agent"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict || !strings.Contains(err.Error(), "agent already exists") {
		t.Fatalf("expected propagated 409 APIError, got %v", err)
	}

	// Simplified UI SendMessage normalization.
	if _, err := hub.SendMessage(map[string]any{
		"targetAgentId": "agt_created",
		"text":          "Run unit tests",
		"priority":      "HIGH",
	}); err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}
	rec, _ := lastMsgBody["recipient"].(map[string]any)
	pl, _ := lastMsgBody["payload"].(map[string]any)
	if rec["agentId"] != "agt_created" || rec["scope"] != "AGENT" || pl["text"] != "Run unit tests" {
		t.Fatalf("unexpected normalized SendMessage payload: %+v", lastMsgBody)
	}

	if err := hub.DeleteMessage("msg_live_1"); err != nil || deletedMsgID != "msg_live_1" {
		t.Fatalf("DeleteMessage failed: err=%v deleted=%q", err, deletedMsgID)
	}

	// Simplified UI DelegateTask normalization.
	if _, err := hub.DelegateTask(map[string]any{
		"targetAgentId":      "agt_created",
		"capability":         "code_review",
		"objective":          "Review PR #42",
		"requiredCapability": "",
	}); err != nil {
		t.Fatalf("DelegateTask failed: %v", err)
	}
	inp, _ := lastTaskBody["input"].(map[string]any)
	if lastTaskBody["targetAgentId"] != "agt_created" || lastTaskBody["requiredCapability"] != "code_review" || inp["objective"] != "Review PR #42" {
		t.Fatalf("unexpected normalized DelegateTask payload: %+v", lastTaskBody)
	}

	if _, err := hub.CancelTask("tsk_live_1", map[string]any{"reason": "superseded"}); err != nil || cancelledTaskID != "tsk_live_1" {
		t.Fatalf("CancelTask failed: err=%v cancelled=%q", err, cancelledTaskID)
	}

	if err := hub.UnregisterSession("sess_live_1"); err != nil || unregisteredSessID != "sess_live_1" {
		t.Fatalf("UnregisterSession failed: err=%v unregistered=%q", err, unregisteredSessID)
	}
}

func TestStandaloneFallbackAndMutations(t *testing.T) {
	t.Setenv("MAH_API_URL", "http://127.0.0.1:1")
	hub := NewHub()

	emptySnap := hub.GetSnapshot("", "")
	if emptySnap.Mode != "standalone" || emptySnap.FallbackReason == "" {
		t.Fatalf("expected standalone mode with FallbackReason, got mode=%q reason=%q", emptySnap.Mode, emptySnap.FallbackReason)
	}
	if emptySnap.Agents == nil || emptySnap.Machines == nil || emptySnap.Sessions == nil || emptySnap.Messages == nil || emptySnap.Tasks == nil || emptySnap.TaskEventsByTaskID == nil {
		t.Fatal("expected non-nil slices and TaskEventsByTaskID in standalone snapshot")
	}

	ag, err := hub.RegisterAgent(map[string]any{
		"logicalName":  "local-worker",
		"description":  "Standalone test agent",
		"capabilities": []string{"build", "test"},
	})
	if err != nil {
		t.Fatalf("standalone RegisterAgent failed: %v", err)
	}
	agID := stringVal(ag["id"])

	msgRes, err := hub.SendMessage(map[string]any{
		"recipient": map[string]any{"scope": "AGENT", "agentId": agID},
		"type":      "agent.ping",
		"payload":   map[string]any{"ping": true},
	})
	if err != nil {
		t.Fatalf("standalone SendMessage failed: %v", err)
	}
	msgID := stringVal(msgRes["messageId"])

	taskRes, err := hub.DelegateTask(map[string]any{
		"targetAgentId": agID,
		"input":         map[string]any{"cmd": "go test"},
	})
	if err != nil {
		t.Fatalf("standalone DelegateTask failed: %v", err)
	}
	taskID := stringVal(taskRes["taskId"])

	snap := hub.GetSnapshot("", "")
	if len(snap.Agents) != 1 || len(snap.Messages) != 1 || len(snap.Tasks) != 1 || len(snap.TaskEventsByTaskID[taskID]) != 1 {
		t.Fatalf("unexpected standalone snapshot counts: a=%d m=%d t=%d ev=%d",
			len(snap.Agents), len(snap.Messages), len(snap.Tasks), len(snap.TaskEventsByTaskID[taskID]))
	}

	if _, err := hub.CancelTask(taskID, map[string]any{"reason": "done"}); err != nil {
		t.Fatalf("standalone CancelTask failed: %v", err)
	}
	if err := hub.DeleteMessage(msgID); err != nil {
		t.Fatalf("standalone DeleteMessage failed: %v", err)
	}

	snapAfter := hub.GetSnapshot("", "")
	if len(snapAfter.Messages) != 0 {
		t.Fatalf("expected 0 messages after delete, got %d", len(snapAfter.Messages))
	}
	if snapAfter.Tasks[0]["status"] != "CANCELLED" || len(snapAfter.TaskEventsByTaskID[taskID]) != 2 {
		t.Fatalf("expected CANCELLED task with 2 events, got status=%v events=%d",
			snapAfter.Tasks[0]["status"], len(snapAfter.TaskEventsByTaskID[taskID]))
	}
}

func TestHubConcurrentAccess(t *testing.T) {
	t.Setenv("MAH_API_URL", "http://127.0.0.1:1")
	hub := NewHub()

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = hub.GetConfig()
			_ = hub.GetSnapshot("", "")
			if idx%3 == 0 {
				_, _ = hub.RegisterAgent(map[string]any{"logicalName": "worker-concurrent"})
			} else if idx%3 == 1 {
				_, _ = hub.SendMessage(map[string]any{"targetAgentId": "worker-concurrent", "text": "ping"})
			} else {
				_, _ = hub.DelegateTask(map[string]any{"targetAgentId": "worker-concurrent", "objective": "check"})
			}
		}(i)
	}
	wg.Wait()
}

func TestSnapshotAuthFailureTriggersStandaloneAndNonNullJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/health" {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{"code": "UNAUTHORIZED", "message": "bad token"},
		})
	}))
	defer srv.Close()

	t.Setenv("MAH_API_URL", srv.URL)
	hub := NewHub()
	snap := hub.GetSnapshot("", "")
	if snap.Mode != "standalone" {
		t.Fatalf("expected standalone fallback on 401, got %q", snap.Mode)
	}
	if !strings.Contains(snap.FallbackReason, "401") {
		t.Fatalf("expected 401 in FallbackReason, got %q", snap.FallbackReason)
	}

	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("json.Marshal snapshot failed: %v", err)
	}
	encoded := string(raw)
	for _, needle := range []string{`"agents":[]`, `"machines":[]`, `"sessions":[]`, `"messages":[]`, `"tasks":[]`, `"taskEventsByTaskId":{}`} {
		if !strings.Contains(encoded, needle) {
			t.Fatalf("expected %s in JSON output, got %s", needle, encoded)
		}
	}
}

func TestStandaloneUnregisterSessionAndDefaultEnv(t *testing.T) {
	t.Setenv("MAH_API_URL", "http://127.0.0.1:1")
	t.Setenv("MAH_API_TOKEN", "")
	t.Setenv("MAH_SERVER_HOST", "")
	t.Setenv("MAH_SSH_USER", "")
	t.Setenv("MAH_MCP_SCRIPT_PATH", "")
	t.Setenv("MAH_DATA_FILE", "")

	hub := NewHub()
	cfg := hub.GetConfig()
	if cfg.HasToken || cfg.APIToken != "" || cfg.ServerHost == "" || cfg.SSHUser == "" || cfg.MCPScriptPath == "" {
		t.Fatalf("unexpected default env config: %+v", cfg)
	}

	ag, err := hub.RegisterAgent(map[string]any{
		"logicalName":   "local-session-agent",
		"createSession": true,
		"machineName":   "local-box",
	})
	if err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}
	sessList := extractMapSlice(ag["sessions"])
	if len(sessList) != 1 {
		t.Fatalf("expected 1 session created, got %d", len(sessList))
	}
	sessID := stringVal(sessList[0]["id"])

	if err := hub.UnregisterSession(sessID); err != nil {
		t.Fatalf("UnregisterSession standalone failed: %v", err)
	}
	if err := hub.UnregisterSession("sess_missing"); err == nil {
		t.Fatal("expected error for missing standalone session")
	}
	snap := hub.GetSnapshot("", "")
	if len(snap.Sessions) != 0 {
		t.Fatalf("expected 0 standalone sessions after unregister, got %d", len(snap.Sessions))
	}
}

func TestNativeGoEngineFullLifecycleAndLeaseSweeps(t *testing.T) {
	t.Setenv("MAH_API_URL", "")
	t.Setenv("MAH_DATA_FILE", "")
	hub := NewHub()

	// 1. Register agent with machine + session -> available=true.
	ag, err := hub.RegisterAgent(map[string]any{
		"logicalName":   "code-reviewer",
		"description":   "Reviews PRs",
		"capabilities":  []string{"code_review", "security_audit"},
		"machineName":   "macbook-pro",
		"hostname":      "macbook.local",
		"createSession": true,
	})
	if err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}
	agID := stringVal(ag["id"])
	if !boolVal(ag["available"]) || ag["onlineSessionCount"] != 1 {
		t.Fatalf("expected available=true and onlineSessionCount=1, got %+v", ag)
	}
	sessions := extractMapSlice(ag["sessions"])
	sess1ID := stringVal(sessions[0]["id"])
	machID := stringVal(sessions[0]["machineId"])

	// 2. Create second session on same (agent, machine) -> connectionGeneration increments to 2.
	sess2Resp, err := hub.CreateSession(agID, map[string]any{"machineId": machID})
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	sess2 := asMap(sess2Resp["session"])
	if intVal(sess2["connectionGeneration"]) != 2 {
		t.Fatalf("expected connectionGeneration=2, got %v", sess2["connectionGeneration"])
	}
	sess2ID := stringVal(sess2["id"])

	// 3. Stale heartbeat fencing check (409 STALE_CONNECTION_GENERATION).
	_, staleErr := hub.HeartbeatSession(sess2ID, map[string]any{"connectionGeneration": 1})
	var apiErr *APIError
	if !errors.As(staleErr, &apiErr) || apiErr.StatusCode != http.StatusConflict || apiErr.Code != "STALE_CONNECTION_GENERATION" {
		t.Fatalf("expected 409 STALE_CONNECTION_GENERATION, got %v", staleErr)
	}

	hbResp, err := hub.HeartbeatSession(sess2ID, map[string]any{"connectionGeneration": 2, "executionStatus": "IDLE"})
	if err != nil || hbResp["connectionStatus"] != "CONNECTED" {
		t.Fatalf("HeartbeatSession failed: resp=%+v err=%v", hbResp, err)
	}

	// 4. Messaging: idempotency, DELIVERED while online, ACK, NACK, ONLINE_ONLY fail when disconnected.
	msg1, err := hub.SendMessage(map[string]any{
		"targetAgentId":  "code-reviewer",
		"text":           "Check diff",
		"idempotencyKey": "idem-msg-1",
	})
	if err != nil || msg1["status"] != "DELIVERED" || boolVal(msg1["duplicate"]) {
		t.Fatalf("expected DELIVERED message, got %+v err=%v", msg1, err)
	}
	msg1Dup, err := hub.SendMessage(map[string]any{
		"targetAgentId":  "code-reviewer",
		"text":           "Check diff",
		"idempotencyKey": "idem-msg-1",
	})
	if err != nil || !boolVal(msg1Dup["duplicate"]) || msg1Dup["messageId"] != msg1["messageId"] {
		t.Fatalf("expected duplicate=true on idempotent send, got %+v err=%v", msg1Dup, err)
	}
	inbox := hub.GetInbox("code-reviewer", "")
	if len(inbox) != 1 {
		t.Fatalf("expected 1 message in inbox, got %d", len(inbox))
	}
	ackRes, err := hub.AckMessage(stringVal(msg1["messageId"]), map[string]any{
		"sessionId":            sess2ID,
		"connectionGeneration": 2,
	})
	if err != nil || ackRes["status"] != "ACKED" {
		t.Fatalf("AckMessage failed: %+v err=%v", ackRes, err)
	}

	// 5. Task delegation by requiredCapability + 5-stage lifecycle + fencing.
	tskResp, err := hub.DelegateTask(map[string]any{
		"requiredCapability": "code_review",
		"input":              map[string]any{"pr": 42},
	})
	if err != nil || tskResp["status"] != "DELIVERED" {
		t.Fatalf("DelegateTask expected DELIVERED, got %+v err=%v", tskResp, err)
	}
	tskID := stringVal(tskResp["taskId"])

	if _, err := hub.AcceptTask(tskID, map[string]any{"assignmentGeneration": 1}); !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 STALE_ASSIGNMENT_GENERATION on stale accept, got %v", err)
	}
	if res, err := hub.AcceptTask(tskID, map[string]any{"assignmentGeneration": 2}); err != nil || res["status"] != "ACCEPTED" {
		t.Fatalf("AcceptTask failed: %+v err=%v", res, err)
	}
	if res, err := hub.StartTask(tskID, map[string]any{"assignmentGeneration": 2}); err != nil || res["status"] != "PROCESSING" {
		t.Fatalf("StartTask failed: %+v err=%v", res, err)
	}
	if res, err := hub.CompleteTask(tskID, map[string]any{"assignmentGeneration": 2, "result": map[string]any{"approved": true}}); err != nil || res["status"] != "COMPLETED" {
		t.Fatalf("CompleteTask failed: %+v err=%v", res, err)
	}
	if _, err := hub.CancelTask(tskID, nil); !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 INVALID_STATE_TRANSITION cancelling completed task, got %v", err)
	}

	events, err := hub.ListTaskEvents(tskID)
	if err != nil || len(events) != 5 {
		t.Fatalf("expected 5 task events (CREATED, DELIVERED, ACCEPTED, STARTED, COMPLETED), got %d err=%v", len(events), err)
	}

	// 6. Lease sweeps: >60s -> SUSPECT, >90s -> DISCONNECTED + STOPPED.
	hub.mu.Lock()
	past70s := time.Now().UTC().Add(-70 * time.Second).Format(time.RFC3339)
	past100s := time.Now().UTC().Add(-100 * time.Second).Format(time.RFC3339)
	for i := range hub.sessions {
		if stringVal(hub.sessions[i]["id"]) == sess1ID {
			hub.sessions[i]["lastHeartbeatAt"] = past70s
		} else if stringVal(hub.sessions[i]["id"]) == sess2ID {
			hub.sessions[i]["lastHeartbeatAt"] = past100s
			hub.sessions[i]["leaseExpiresAt"] = time.Now().UTC().Add(-10 * time.Second).Format(time.RFC3339)
		}
	}
	hub.mu.Unlock()

	snap := hub.GetSnapshot("", "")
	var s1Status, s2Status string
	for _, s := range snap.Sessions {
		if s["id"] == sess1ID {
			s1Status = stringVal(s["connectionStatus"])
		} else if s["id"] == sess2ID {
			s2Status = stringVal(s["connectionStatus"])
		}
	}
	if s1Status != "SUSPECT" || s2Status != "DISCONNECTED" {
		t.Fatalf("expected lease sweep SUSPECT & DISCONNECTED, got s1=%q s2=%q", s1Status, s2Status)
	}

	// Disconnect sess1 -> ONLINE_ONLY + FAIL message marks FAILED.
	if _, err := hub.DisconnectSession(sess1ID, nil); err != nil {
		t.Fatalf("DisconnectSession failed: %v", err)
	}
	failMsg, err := hub.SendMessage(map[string]any{
		"targetAgentId":  agID,
		"deliveryPolicy": "ONLINE_ONLY",
		"fallbackPolicy": "FAIL",
		"text":           "must be online",
	})
	if err != nil || failMsg["status"] != "FAILED" {
		t.Fatalf("expected FAILED for ONLINE_ONLY+FAIL while offline, got %+v err=%v", failMsg, err)
	}
}

func TestDurableDiskPersistence(t *testing.T) {
	dataPath := filepath.Join(t.TempDir(), "mah_state.json")
	t.Setenv("MAH_API_URL", "")
	t.Setenv("MAH_DATA_FILE", dataPath)

	hub1 := NewHub()
	ag, err := hub1.RegisterAgent(map[string]any{
		"logicalName":   "persisted-agent",
		"capabilities":  []string{"deploy"},
		"machineName":   "prod-vps",
		"createSession": true,
	})
	if err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}
	if _, err := hub1.SendMessage(map[string]any{"targetAgentId": "persisted-agent", "text": "hello disk"}); err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}
	if _, err := hub1.DelegateTask(map[string]any{"targetAgentId": "persisted-agent", "objective": "survive restart"}); err != nil {
		t.Fatalf("DelegateTask failed: %v", err)
	}

	if _, err := os.Stat(dataPath); err != nil {
		t.Fatalf("expected persisted state file at %s: %v", dataPath, err)
	}

	// Simulate process restart with a brand new Hub loading from MAH_DATA_FILE.
	hub2 := NewHub()
	snap := hub2.GetSnapshot("", "")
	if len(snap.Agents) != 1 || snap.Agents[0]["id"] != ag["id"] {
		t.Fatalf("expected persisted agent after reload, got %+v", snap.Agents)
	}
	if len(snap.Machines) != 1 || len(snap.Sessions) != 1 || len(snap.Messages) != 1 || len(snap.Tasks) != 1 {
		t.Fatalf("expected persisted entities after reload: m=%d s=%d msg=%d t=%d",
			len(snap.Machines), len(snap.Sessions), len(snap.Messages), len(snap.Tasks))
	}
}

func TestMCPJSONRPCAndStdio(t *testing.T) {
	t.Setenv("MAH_API_URL", "")
	t.Setenv("MAH_DATA_FILE", filepath.Join(t.TempDir(), "mcp_state.json"))
	hub := NewHub()

	// 1. Initialize
	initRespBytes, ok := hub.HandleMCPJSONRPC([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`))
	if !ok {
		t.Fatal("expected initialize response")
	}
	var initResp map[string]any
	_ = json.Unmarshal(initRespBytes, &initResp)
	resMap := asMap(initResp["result"])
	if resMap["protocolVersion"] != "2024-11-05" || asMap(resMap["serverInfo"])["name"] != "deploymenthub-mah-go" {
		t.Fatalf("unexpected initialize result: %+v", initResp)
	}

	// 2. Notification produces no response
	if _, hasResp := hub.HandleMCPJSONRPC([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)); hasResp {
		t.Fatal("expected notification to return hasResp=false")
	}

	// 3. tools/list returns exact 11 tools
	listRespBytes, ok := hub.HandleMCPJSONRPC([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	if !ok {
		t.Fatal("expected tools/list response")
	}
	var listResp map[string]any
	_ = json.Unmarshal(listRespBytes, &listResp)
	tools := extractMapSlice(asMap(listResp["result"])["tools"])
	if len(tools) != 11 {
		t.Fatalf("expected 11 MCP tools, got %d", len(tools))
	}

	// 4. tools/call register_agent + list_agents + delegate_task + accept_task + complete_task
	callReg, ok := hub.HandleMCPJSONRPC([]byte(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"register_agent","arguments":{"logicalName":"mcp-worker","capabilities":["go"],"createSession":true,"machineName":"mcp-host"}}}`))
	if !ok || strings.Contains(string(callReg), `"isError":true`) {
		t.Fatalf("register_agent MCP call failed: %s", string(callReg))
	}

	// 5. Stdio forwarding to live HTTP MCP endpoint & offline fallback.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/mah/mcp" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		raw, _ := json.Marshal(req)
		resp, has := hub.HandleMCPJSONRPC(raw)
		if !has {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(resp)
	}))
	defer srv.Close()

	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	}, "\n") + "\n"

	var out bytes.Buffer
	if err := RunMCPStdio(srv.URL, "tok", strings.NewReader(input), &out); err != nil {
		t.Fatalf("RunMCPStdio HTTP forward failed: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSON-RPC responses (notification skipped), got %d: %s", len(lines), out.String())
	}

	// Offline fallback in RunMCPStdio
	var offlineOut bytes.Buffer
	if err := RunMCPStdio("http://127.0.0.1:1", "", strings.NewReader(`{"jsonrpc":"2.0","id":9,"method":"ping"}`+"\n"), &offlineOut); err != nil {
		t.Fatalf("RunMCPStdio offline fallback failed: %v", err)
	}
	if !strings.Contains(offlineOut.String(), `"id":9`) {
		t.Fatalf("expected ping response from offline fallback, got %s", offlineOut.String())
	}
}
