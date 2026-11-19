// Package mah implements DeploymentHub's 100% Native Go Multi-Agent Hub (MAH)
// control plane engine, durable JSON persistence, lease-fencing session manager,
// durable inbox & 5-stage task lifecycle, optional external-upstream proxy, and MCP server.
package mah

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultAPIURL        = "http://127.0.0.1:4180"
	defaultSSHUser       = "root"
	defaultWorkspaceID   = "ws_mah_go"
	tokenClearSentinel   = "__CLEAR__"
	maxUpstreamBodyBytes = 8 << 20 // 8 MiB

	sessionSuspectAfter = 60 * time.Second
	sessionLeaseTTL     = 90 * time.Second
)

// Config represents the MAH connection and MCP setup guide configuration.
// APIToken is masked in GetConfig responses when longer than 16 characters.
type Config struct {
	APIURL        string `json:"apiUrl"`
	APIToken      string `json:"apiToken"`
	HasToken      bool   `json:"hasToken"`
	ServerHost    string `json:"serverHost"`
	SSHUser       string `json:"sshUser"`
	MCPScriptPath string `json:"mcpScriptPath"`
}

// Snapshot aggregates the MAH workspace topology, health checks, agents,
// machines, sessions, inbox messages, tasks, and task audit events.
type Snapshot struct {
	Mode               string                      `json:"mode"`
	WorkspaceID        string                      `json:"workspaceId"`
	WorkspaceName      string                      `json:"workspaceName"`
	FetchedAt          string                      `json:"fetchedAt"`
	APIURL             string                      `json:"apiUrl"`
	FallbackReason     string                      `json:"fallbackReason,omitempty"`
	Health             map[string]any              `json:"health"`
	Agents             []map[string]any            `json:"agents"`
	Machines           []map[string]any            `json:"machines"`
	Sessions           []map[string]any            `json:"sessions"`
	Messages           []map[string]any            `json:"messages"`
	Tasks              []map[string]any            `json:"tasks"`
	TaskEventsByTaskID map[string][]map[string]any `json:"taskEventsByTaskId"`
}

// APIError captures protocol or upstream HTTP error responses.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("mah-api HTTP %d (%s): %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("mah-api HTTP %d: %s", e.StatusCode, e.Message)
}

type persistedState struct {
	WorkspaceID          string                      `json:"workspaceId"`
	APIToken             string                      `json:"apiToken,omitempty"`
	Seq                  uint64                      `json:"seq"`
	Agents               []map[string]any            `json:"agents"`
	Machines             []map[string]any            `json:"machines"`
	Sessions             []map[string]any            `json:"sessions"`
	Messages             []map[string]any            `json:"messages"`
	Tasks                []map[string]any            `json:"tasks"`
	TaskEventsByTaskID   map[string][]map[string]any `json:"taskEventsByTaskId"`
	ConnectionGeneration map[string]int              `json:"connectionGeneration"`
}

// Hub is a thread-safe Multi-Agent Hub engine supporting 100% native Go operation
// with durable JSON persistence as well as optional external MAH API proxying.
type Hub struct {
	mu            sync.RWMutex
	apiURL        string
	apiToken      string
	serverHost    string
	sshUser       string
	mcpScriptPath string
	workspaceID   string
	dataFile      string
	httpClient    *http.Client
	seq           atomic.Uint64

	agents               []map[string]any
	machines             []map[string]any
	sessions             []map[string]any
	messages             []map[string]any
	tasks                []map[string]any
	taskEvents           map[string][]map[string]any
	connGenByAgentMachine map[string]int
}

// NewHub initializes a native Go Hub from environment variables and loads any
// persisted JSON state file from MAH_DATA_FILE (or /data/mah_state.json when writable).
func NewHub() *Hub {
	apiURL := strings.TrimRight(strings.TrimSpace(os.Getenv("MAH_API_URL")), "/")
	if apiURL == "" {
		apiURL = defaultAPIURL
	}

	apiToken := strings.TrimSpace(os.Getenv("MAH_API_TOKEN"))

	serverHost := strings.TrimSpace(os.Getenv("MAH_SERVER_HOST"))
	if serverHost == "" {
		serverHost = strings.TrimSpace(os.Getenv("HUB_DOMAIN"))
	}
	if serverHost == "" {
		if hostName, err := os.Hostname(); err == nil && strings.TrimSpace(hostName) != "" {
			serverHost = strings.TrimSpace(hostName)
		} else {
			serverHost = "localhost"
		}
	}

	sshUser := strings.TrimSpace(os.Getenv("MAH_SSH_USER"))
	if sshUser == "" {
		sshUser = strings.TrimSpace(os.Getenv("USER"))
	}
	if sshUser == "" {
		sshUser = defaultSSHUser
	}

	mcpScriptPath := strings.TrimSpace(os.Getenv("MAH_MCP_SCRIPT_PATH"))
	if mcpScriptPath == "" {
		if exePath, err := os.Executable(); err == nil && strings.TrimSpace(exePath) != "" {
			mcpScriptPath = exePath
		} else {
			mcpScriptPath = "deploymenthub"
		}
	}

	dataFile := resolveDataFilePath()

	h := &Hub{
		apiURL:                apiURL,
		apiToken:              apiToken,
		serverHost:            serverHost,
		sshUser:               sshUser,
		mcpScriptPath:         mcpScriptPath,
		workspaceID:           defaultWorkspaceID,
		dataFile:              dataFile,
		httpClient:            &http.Client{Timeout: 5 * time.Second},
		agents:                make([]map[string]any, 0),
		machines:              make([]map[string]any, 0),
		sessions:              make([]map[string]any, 0),
		messages:              make([]map[string]any, 0),
		tasks:                 make([]map[string]any, 0),
		taskEvents:            make(map[string][]map[string]any),
		connGenByAgentMachine: make(map[string]int),
	}
	h.loadStateFromDisk()
	return h
}

func resolveDataFilePath() string {
	if explicit := strings.TrimSpace(os.Getenv("MAH_DATA_FILE")); explicit != "" {
		return explicit
	}
	info, err := os.Stat("/data")
	if err != nil || !info.IsDir() {
		return ""
	}
	probe, err := os.CreateTemp("/data", ".mah_probe_*")
	if err != nil {
		return ""
	}
	probeName := probe.Name()
	_ = probe.Close()
	_ = os.Remove(probeName)
	return "/data/mah_state.json"
}

func (h *Hub) loadStateFromDisk() {
	if h.dataFile == "" {
		return
	}
	raw, err := os.ReadFile(h.dataFile)
	if err != nil {
		return
	}
	var st persistedState
	if err := json.Unmarshal(raw, &st); err != nil {
		return
	}
	if strings.TrimSpace(st.WorkspaceID) != "" {
		h.workspaceID = strings.TrimSpace(st.WorkspaceID)
	}
	if h.apiToken == "" && strings.TrimSpace(st.APIToken) != "" {
		h.apiToken = strings.TrimSpace(st.APIToken)
	}
	if st.Seq > h.seq.Load() {
		h.seq.Store(st.Seq)
	}
	if st.Agents != nil {
		h.agents = st.Agents
	}
	if st.Machines != nil {
		h.machines = st.Machines
	}
	if st.Sessions != nil {
		h.sessions = st.Sessions
	}
	if st.Messages != nil {
		h.messages = st.Messages
	}
	if st.Tasks != nil {
		h.tasks = st.Tasks
	}
	if st.TaskEventsByTaskID != nil {
		h.taskEvents = st.TaskEventsByTaskID
	}
	if st.ConnectionGeneration != nil {
		h.connGenByAgentMachine = st.ConnectionGeneration
	}
}

func (h *Hub) persistLocked() {
	if h.dataFile == "" {
		return
	}
	dir := filepath.Dir(h.dataFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	st := persistedState{
		WorkspaceID:          h.workspaceID,
		APIToken:             h.apiToken,
		Seq:                  h.seq.Load(),
		Agents:               nonNilSlice(h.agents),
		Machines:             nonNilSlice(h.machines),
		Sessions:             nonNilSlice(h.sessions),
		Messages:             nonNilSlice(h.messages),
		Tasks:                nonNilSlice(h.tasks),
		TaskEventsByTaskID:   h.taskEvents,
		ConnectionGeneration: h.connGenByAgentMachine,
	}
	encoded, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".mah_state_*.tmp")
	if err != nil {
		return
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return
	}
	if err := os.Rename(tmpPath, h.dataFile); err != nil {
		_ = os.Remove(tmpPath)
	}
}

func (h *Hub) isExternalUpstream(baseURL string) bool {
	trimmed := strings.TrimSpace(baseURL)
	if trimmed == "" {
		return false
	}
	lower := strings.ToLower(strings.TrimRight(trimmed, "/"))
	if lower == "native" || lower == "local" {
		return false
	}
	parsed, err := url.Parse(trimmed)
	if err == nil {
		if parsed.Port() == "4180" {
			return false
		}
		if portEnv := strings.TrimPrefix(strings.TrimSpace(os.Getenv("PORT")), ":"); portEnv != "" && parsed.Port() == portEnv {
			host := strings.ToLower(parsed.Hostname())
			if host == "127.0.0.1" || host == "localhost" || host == "0.0.0.0" {
				return false
			}
		}
	}
	if strings.HasSuffix(lower, ":4180") {
		return false
	}
	return true
}

// GetConfig returns the current MAH configuration with APIToken masked when longer than 16 chars.
func (h *Hub) GetConfig() Config {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.maskedConfigLocked()
}

// UpdateConfig updates non-empty MAH configuration fields while preserving or clearing the raw token safely.
func (h *Hub) UpdateConfig(apiURL, apiToken, serverHost, sshUser, mcpScriptPath string) Config {
	h.mu.Lock()
	defer h.mu.Unlock()

	if trimmed := strings.TrimRight(strings.TrimSpace(apiURL), "/"); trimmed != "" {
		h.apiURL = trimmed
	}

	tok := strings.TrimSpace(apiToken)
	switch {
	case tok == tokenClearSentinel:
		h.apiToken = ""
	case tok != "" && !strings.Contains(tok, "..."):
		h.apiToken = tok
	}

	if trimmed := strings.TrimSpace(serverHost); trimmed != "" {
		h.serverHost = trimmed
	}
	if trimmed := strings.TrimSpace(sshUser); trimmed != "" {
		h.sshUser = trimmed
	}
	if trimmed := strings.TrimSpace(mcpScriptPath); trimmed != "" {
		h.mcpScriptPath = trimmed
	}

	h.persistLocked()
	return h.maskedConfigLocked()
}

func (h *Hub) maskedConfigLocked() Config {
	masked := h.apiToken
	if len(masked) > 16 {
		masked = masked[:12] + "..." + masked[len(masked)-4:]
	}
	return Config{
		APIURL:        h.apiURL,
		APIToken:      masked,
		HasToken:      h.apiToken != "",
		ServerHost:    h.serverHost,
		SSHUser:       h.sshUser,
		MCPScriptPath: h.mcpScriptPath,
	}
}

func (h *Hub) endpointAndToken(overrideURL, overrideToken string) (string, string) {
	h.mu.RLock()
	baseURL := h.apiURL
	token := h.apiToken
	h.mu.RUnlock()

	if u := strings.TrimRight(strings.TrimSpace(overrideURL), "/"); u != "" {
		baseURL = u
	}
	if t := strings.TrimSpace(overrideToken); t != "" && !strings.Contains(t, "...") {
		token = t
	}
	return baseURL, token
}

// ValidateBearerToken performs constant-time validation of an incoming Bearer token
// against the configured MAH API token (returning false if no token is configured).
func (h *Hub) ValidateBearerToken(candidate string) bool {
	trimmed := strings.TrimSpace(candidate)
	if trimmed == "" || h == nil {
		return false
	}
	h.mu.RLock()
	configured := strings.TrimSpace(h.apiToken)
	h.mu.RUnlock()
	if configured == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(trimmed), []byte(configured)) == 1
}

// GetHealth returns the native Go MAH health check payload (or external /v1/health when configured).
func (h *Hub) GetHealth() map[string]any {
	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) {
		if health, err := h.doJSONMap(http.MethodGet, baseURL+"/v1/health", token, nil); err == nil {
			enrichLiveHealth(health)
			return health
		}
	}
	return nativeHealthMap()
}

func nativeHealthMap() map[string]any {
	return map[string]any{
		"status":    "ok",
		"service":   "deploymenthub-mah-go",
		"version":   "1.0.0",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"checks": map[string]any{
			"postgres": "up",
			"redis":    "up",
			"nats":     "up",
		},
	}
}

// GetSnapshot returns the native Go live snapshot (or proxies to an external MAH API if configured,
// falling back to standalone mode when that external API is unreachable or returns an error).
func (h *Hub) GetSnapshot(overrideURL, overrideToken string) Snapshot {
	baseURL, token := h.endpointAndToken(overrideURL, overrideToken)
	if !h.isExternalUpstream(baseURL) {
		return h.nativeSnapshot(baseURL)
	}
	return h.externalSnapshot(baseURL, token)
}

func (h *Hub) nativeSnapshot(apiURL string) Snapshot {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now().UTC()
	if h.sweepLeasesLocked(now) {
		h.persistLocked()
	}

	agents := make([]map[string]any, 0, len(h.agents))
	for _, ag := range h.agents {
		agents = append(agents, h.buildAgentViewLocked(ag))
	}

	machines := cloneMapSlice(h.machines)
	sessions := cloneMapSlice(h.sessions)
	messages := cloneMapSlice(h.messages)
	tasks := cloneMapSlice(h.tasks)

	events := make(map[string][]map[string]any, len(h.taskEvents))
	for k, v := range h.taskEvents {
		events[k] = cloneMapSlice(v)
	}

	sort.SliceStable(messages, func(i, j int) bool {
		return compareTimestampsDesc(messageCreatedAtFromItem(messages[i]), messageCreatedAtFromItem(messages[j]))
	})
	sort.SliceStable(tasks, func(i, j int) bool {
		return compareTimestampsDesc(stringVal(tasks[i]["createdAt"]), stringVal(tasks[j]["createdAt"]))
	})

	return Snapshot{
		Mode:               "live",
		WorkspaceID:        h.workspaceID,
		WorkspaceName:      fmt.Sprintf("Go Native Workspace (%s)", h.workspaceID),
		FetchedAt:          now.Format(time.RFC3339),
		APIURL:             apiURL,
		Health:             nativeHealthMap(),
		Agents:             agents,
		Machines:           machines,
		Sessions:           sessions,
		Messages:           messages,
		Tasks:              tasks,
		TaskEventsByTaskID: events,
	}
}

func (h *Hub) externalSnapshot(baseURL, token string) Snapshot {
	health, err := h.doJSONMap(http.MethodGet, baseURL+"/v1/health", token, nil)
	if err != nil {
		return h.standaloneSnapshot(baseURL, err.Error())
	}

	agentSummaries, err := h.doJSONItems(http.MethodGet, baseURL+"/v1/agents?limit=100", token)
	if err != nil {
		return h.standaloneSnapshot(baseURL, err.Error())
	}

	agents := make([]map[string]any, len(agentSummaries))
	inboxes := make([][]map[string]any, len(agentSummaries))
	var wg sync.WaitGroup

	for i, summary := range agentSummaries {
		wg.Add(1)
		go func(idx int, sum map[string]any) {
			defer wg.Done()
			agentID := stringVal(sum["id"])
			if agentID == "" {
				cp := cloneMap(sum)
				if _, ok := cp["sessions"]; !ok {
					cp["sessions"] = []map[string]any{}
				}
				agents[idx] = cp
				return
			}

			detail, detailErr := h.doJSONMap(http.MethodGet, baseURL+"/v1/agents/"+url.PathEscape(agentID), token, nil)
			if detailErr == nil && detail != nil {
				if _, ok := detail["sessions"]; !ok || detail["sessions"] == nil {
					detail["sessions"] = []map[string]any{}
				}
				agents[idx] = detail
			} else {
				cp := cloneMap(sum)
				if _, ok := cp["sessions"]; !ok || cp["sessions"] == nil {
					cp["sessions"] = []map[string]any{}
				}
				agents[idx] = cp
			}

			inboxItems, inboxErr := h.doJSONItems(http.MethodGet, baseURL+"/v1/agents/"+url.PathEscape(agentID)+"/inbox?limit=50", token)
			if inboxErr == nil {
				inboxes[idx] = inboxItems
			}
		}(i, summary)
	}
	wg.Wait()

	sessions := make([]map[string]any, 0)
	for _, ag := range agents {
		for _, sess := range extractMapSlice(ag["sessions"]) {
			sessions = append(sessions, sess)
		}
	}

	seenMsgIDs := make(map[string]bool)
	messages := make([]map[string]any, 0)
	for _, list := range inboxes {
		for _, item := range list {
			msgID := messageIDFromItem(item)
			if msgID != "" {
				if seenMsgIDs[msgID] {
					continue
				}
				seenMsgIDs[msgID] = true
			}
			messages = append(messages, item)
		}
	}
	sort.SliceStable(messages, func(i, j int) bool {
		return compareTimestampsDesc(messageCreatedAtFromItem(messages[i]), messageCreatedAtFromItem(messages[j]))
	})

	machines, machErr := h.doJSONItems(http.MethodGet, baseURL+"/v1/machines?limit=100", token)
	if machErr != nil {
		machines = make([]map[string]any, 0)
	}
	seenMachineIDs := make(map[string]bool, len(machines))
	for _, m := range machines {
		if id := stringVal(m["id"]); id != "" {
			seenMachineIDs[id] = true
		}
	}

	var missingMachineIDs []string
	for _, sess := range sessions {
		mid := stringVal(sess["machineId"])
		if mid != "" && !seenMachineIDs[mid] {
			seenMachineIDs[mid] = true
			missingMachineIDs = append(missingMachineIDs, mid)
		}
	}
	if len(missingMachineIDs) > 0 {
		fetchedMachines := make([]map[string]any, len(missingMachineIDs))
		var mwg sync.WaitGroup
		for i, mid := range missingMachineIDs {
			mwg.Add(1)
			go func(idx int, machineID string) {
				defer mwg.Done()
				if m, err := h.doJSONMap(http.MethodGet, baseURL+"/v1/machines/"+url.PathEscape(machineID), token, nil); err == nil && m != nil {
					fetchedMachines[idx] = m
				}
			}(i, mid)
		}
		mwg.Wait()
		for _, m := range fetchedMachines {
			if m != nil {
				machines = append(machines, m)
			}
		}
	}

	tasks, tasksErr := h.doJSONItems(http.MethodGet, baseURL+"/v1/tasks?limit=100", token)
	if tasksErr != nil {
		var apiErr *APIError
		if errors.As(tasksErr, &apiErr) && apiErr.StatusCode != http.StatusNotFound {
			return h.standaloneSnapshot(baseURL, tasksErr.Error())
		}
		if !errors.As(tasksErr, &apiErr) {
			return h.standaloneSnapshot(baseURL, tasksErr.Error())
		}
		tasks = make([]map[string]any, 0)
	}
	sort.SliceStable(tasks, func(i, j int) bool {
		return compareTimestampsDesc(stringVal(tasks[i]["createdAt"]), stringVal(tasks[j]["createdAt"]))
	})

	taskEventsByTaskID := make(map[string][]map[string]any, len(tasks))
	var evMu sync.Mutex
	var twg sync.WaitGroup
	for _, t := range tasks {
		taskID := stringVal(t["taskId"])
		if taskID == "" {
			taskID = stringVal(t["id"])
		}
		if taskID == "" {
			continue
		}
		twg.Add(1)
		go func(id string) {
			defer twg.Done()
			events, evErr := h.doJSONItems(http.MethodGet, baseURL+"/v1/tasks/"+url.PathEscape(id)+"/events?limit=100", token)
			if evErr != nil || events == nil {
				events = make([]map[string]any, 0)
			}
			evMu.Lock()
			taskEventsByTaskID[id] = events
			evMu.Unlock()
		}(taskID)
	}
	twg.Wait()

	enrichLiveHealth(health)

	workspaceID := extractWorkspaceID(agents, machines, tasks)
	return Snapshot{
		Mode:               "live",
		WorkspaceID:        workspaceID,
		WorkspaceName:      "Workspace " + workspaceID,
		FetchedAt:          time.Now().UTC().Format(time.RFC3339),
		APIURL:             baseURL,
		Health:             health,
		Agents:             nonNilSlice(agents),
		Machines:           nonNilSlice(machines),
		Sessions:           nonNilSlice(sessions),
		Messages:           nonNilSlice(messages),
		Tasks:              nonNilSlice(tasks),
		TaskEventsByTaskID: taskEventsByTaskID,
	}
}

func (h *Hub) standaloneSnapshot(apiURL, reason string) Snapshot {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now().UTC()
	h.sweepLeasesLocked(now)

	agents := make([]map[string]any, 0, len(h.agents))
	for _, ag := range h.agents {
		agents = append(agents, h.buildAgentViewLocked(ag))
	}
	machines := cloneMapSlice(h.machines)
	sessions := cloneMapSlice(h.sessions)
	messages := cloneMapSlice(h.messages)
	tasks := cloneMapSlice(h.tasks)

	events := make(map[string][]map[string]any, len(h.taskEvents))
	for k, v := range h.taskEvents {
		events[k] = cloneMapSlice(v)
	}

	sort.SliceStable(messages, func(i, j int) bool {
		return compareTimestampsDesc(messageCreatedAtFromItem(messages[i]), messageCreatedAtFromItem(messages[j]))
	})
	sort.SliceStable(tasks, func(i, j int) bool {
		return compareTimestampsDesc(stringVal(tasks[i]["createdAt"]), stringVal(tasks[j]["createdAt"]))
	})

	return Snapshot{
		Mode:           "standalone",
		WorkspaceID:    "ws_standalone",
		WorkspaceName:  "Standalone Workspace",
		FetchedAt:      now.Format(time.RFC3339),
		APIURL:         apiURL,
		FallbackReason: reason,
		Health: map[string]any{
			"status":    "degraded",
			"service":   "deploymenthub-mah-go",
			"version":   "1.0.0",
			"timestamp": now.Format(time.RFC3339),
			"checks": map[string]any{
				"postgres": "down",
				"redis":    "down",
				"nats":     "down",
			},
		},
		Agents:             agents,
		Machines:           machines,
		Sessions:           sessions,
		Messages:           messages,
		Tasks:              tasks,
		TaskEventsByTaskID: events,
	}
}

// RegisterAgent registers or updates a logical agent (and optionally creates a machine & runtime session).
func (h *Hub) RegisterAgent(body map[string]any) (map[string]any, error) {
	reqBody, err := normalizeRegisterAgentBody(body)
	if err != nil {
		return nil, err
	}

	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) {
		res, err := h.doJSONMap(http.MethodPost, baseURL+"/v1/agents", token, reqBody)
		if err == nil {
			return res, nil
		}
		if isUpstreamAPIError(err) {
			return nil, err
		}
	}

	return h.registerAgentLocal(reqBody, body), nil
}

func (h *Hub) registerAgentLocal(reqBody, origBody map[string]any) map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)
	logicalName := stringVal(reqBody["logicalName"])
	description := stringVal(reqBody["description"])
	status := stringValOrDefault(reqBody["status"], "ACTIVE")

	rawCaps := extractMapSlice(reqBody["capabilities"])
	caps := make([]map[string]any, 0, len(rawCaps))
	for _, c := range rawCaps {
		capCopy := cloneMap(c)
		if stringVal(capCopy["id"]) == "" {
			capCopy["id"] = h.nextID("cap")
		}
		caps = append(caps, capCopy)
	}

	var agentID string
	foundIdx := -1
	reqID := stringVal(reqBody["id"])
	for i, existing := range h.agents {
		if (reqID != "" && stringVal(existing["id"]) == reqID) || stringVal(existing["logicalName"]) == logicalName {
			foundIdx = i
			break
		}
	}

	if foundIdx >= 0 {
		existing := h.agents[foundIdx]
		agentID = stringVal(existing["id"])
		existing["logicalName"] = logicalName
		existing["description"] = description
		existing["status"] = status
		existing["capabilities"] = caps
		if meta, ok := reqBody["metadata"]; ok {
			existing["metadata"] = deepCloneValue(meta)
		}
		existing["updatedAt"] = nowStr
		h.agents[foundIdx] = existing
	} else {
		agentID = reqID
		if agentID == "" {
			agentID = h.nextID("agt")
		}
		agent := map[string]any{
			"id":                 agentID,
			"workspaceId":        h.workspaceID,
			"logicalName":        logicalName,
			"description":        description,
			"status":             status,
			"capabilities":       caps,
			"sessionCount":       0,
			"onlineSessionCount": 0,
			"available":          false,
			"metadata":           deepCloneValue(reqBody["metadata"]),
			"createdAt":          nowStr,
			"updatedAt":          nowStr,
			"sessions":           []map[string]any{},
		}
		h.agents = slices.Insert(h.agents, 0, agent)
	}

	machineName := firstNonEmptyString(origBody["machineName"], origBody["hostname"])
	machineID := stringVal(origBody["machineId"])
	createSess := boolVal(origBody["createSession"])
	if createSess || machineName != "" || machineID != "" {
		sessBody := map[string]any{
			"machineId":       machineID,
			"machineName":     machineName,
			"hostname":        firstNonEmptyString(origBody["hostname"], machineName),
			"deliveryMode":    stringValOrDefault(origBody["deliveryMode"], "HYBRID"),
			"executionStatus": stringValOrDefault(origBody["executionStatus"], "IDLE"),
			"metadata":        origBody["sessionMetadata"],
		}
		_, _ = h.createSessionLocked(agentID, sessBody, now)
	}

	h.persistLocked()
	ag := h.findAgentLocked(agentID)
	return h.buildAgentViewLocked(ag)
}

// ListAgents returns agents filtered by optional logicalName, capability, availableOnly, and status.
func (h *Hub) ListAgents(query map[string]string) []map[string]any {
	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) {
		params := url.Values{}
		params.Set("limit", "100")
		for _, k := range []string{"logicalName", "capability", "availableOnly", "status"} {
			if v := strings.TrimSpace(query[k]); v != "" {
				params.Set(k, v)
			}
		}
		if items, err := h.doJSONItems(http.MethodGet, baseURL+"/v1/agents?"+params.Encode(), token); err == nil {
			return items
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sweepLeasesLocked(time.Now().UTC()) {
		h.persistLocked()
	}

	qName := strings.ToLower(strings.TrimSpace(query["logicalName"]))
	qCap := strings.TrimSpace(query["capability"])
	qStatus := strings.ToUpper(strings.TrimSpace(query["status"]))
	availOnly := strings.EqualFold(strings.TrimSpace(query["availableOnly"]), "true")

	out := make([]map[string]any, 0, len(h.agents))
	for _, rawAg := range h.agents {
		ag := h.buildAgentViewLocked(rawAg)
		if qName != "" && !strings.Contains(strings.ToLower(stringVal(ag["logicalName"])), qName) {
			continue
		}
		if qStatus != "" && qStatus != "ALL" && !strings.EqualFold(stringVal(ag["status"]), qStatus) {
			continue
		}
		if availOnly && !boolVal(ag["available"]) {
			continue
		}
		if qCap != "" && !agentHasCapability(ag, qCap) {
			continue
		}
		out = append(out, ag)
	}
	return out
}

// GetAgent returns an agent detail object (including live sessions) by id or logicalName.
func (h *Hub) GetAgent(agentID string) (map[string]any, error) {
	id := strings.TrimSpace(agentID)
	if id == "" {
		return nil, errors.New("agentId is required")
	}

	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) {
		res, err := h.doJSONMap(http.MethodGet, baseURL+"/v1/agents/"+url.PathEscape(id), token, nil)
		if err == nil {
			return res, nil
		}
		if isUpstreamAPIError(err) {
			return nil, err
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sweepLeasesLocked(time.Now().UTC()) {
		h.persistLocked()
	}
	ag := h.findAgentLocked(id)
	if ag == nil {
		return nil, &APIError{
			StatusCode: http.StatusNotFound,
			Code:       "AGENT_NOT_FOUND",
			Message:    fmt.Sprintf("agent %q not found", id),
		}
	}
	return h.buildAgentViewLocked(ag), nil
}

// RegisterMachine registers or updates a host machine entry.
func (h *Hub) RegisterMachine(body map[string]any) (map[string]any, error) {
	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) {
		res, err := h.doJSONMap(http.MethodPost, baseURL+"/v1/machines", token, body)
		if err == nil {
			return res, nil
		}
		if isUpstreamAPIError(err) {
			return nil, err
		}
	}

	name := firstNonEmptyString(body["name"], body["machineName"], body["hostname"])
	if name == "" {
		return nil, errors.New("machine name is required")
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	m := h.upsertMachineLocked(body, time.Now().UTC())
	h.persistLocked()
	return cloneMap(m), nil
}

// ListMachines returns all registered host machines.
func (h *Hub) ListMachines() []map[string]any {
	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) {
		if items, err := h.doJSONItems(http.MethodGet, baseURL+"/v1/machines?limit=100", token); err == nil {
			return items
		}
	}

	h.mu.RLock()
	defer h.mu.RUnlock()
	return cloneMapSlice(h.machines)
}

// GetMachine returns a host machine by id.
func (h *Hub) GetMachine(machineID string) (map[string]any, error) {
	id := strings.TrimSpace(machineID)
	if id == "" {
		return nil, errors.New("machineId is required")
	}

	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) {
		res, err := h.doJSONMap(http.MethodGet, baseURL+"/v1/machines/"+url.PathEscape(id), token, nil)
		if err == nil {
			return res, nil
		}
		if isUpstreamAPIError(err) {
			return nil, err
		}
	}

	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, m := range h.machines {
		if stringVal(m["id"]) == id {
			return cloneMap(m), nil
		}
	}
	return nil, &APIError{
		StatusCode: http.StatusNotFound,
		Code:       "MACHINE_NOT_FOUND",
		Message:    fmt.Sprintf("machine %q not found", id),
	}
}

// CreateSession creates a connected runtime session for agentID, finding or registering its machine
// and incrementing the monotonic fencing connectionGeneration.
func (h *Hub) CreateSession(agentID string, body map[string]any) (map[string]any, error) {
	id := strings.TrimSpace(agentID)
	if id == "" {
		id = firstNonEmptyString(body["agentId"], body["logicalName"])
	}
	if id == "" {
		return nil, errors.New("agentId is required")
	}

	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) {
		res, err := h.doJSONMap(http.MethodPost, baseURL+"/v1/agents/"+url.PathEscape(id)+"/sessions", token, body)
		if err == nil {
			return res, nil
		}
		if isUpstreamAPIError(err) {
			return nil, err
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	res, err := h.createSessionLocked(id, body, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	h.persistLocked()
	return res, nil
}

func (h *Hub) createSessionLocked(agentIDOrName string, body map[string]any, now time.Time) (map[string]any, error) {
	ag := h.findAgentLocked(agentIDOrName)
	if ag == nil {
		return nil, &APIError{
			StatusCode: http.StatusNotFound,
			Code:       "AGENT_NOT_FOUND",
			Message:    fmt.Sprintf("agent %q not found", agentIDOrName),
		}
	}
	resolvedAgentID := stringVal(ag["id"])

	machine := h.upsertMachineLocked(body, now)
	machineID := stringVal(machine["id"])

	genKey := resolvedAgentID + ":" + machineID
	gen := h.connGenByAgentMachine[genKey] + 1
	h.connGenByAgentMachine[genKey] = gen

	nowStr := now.Format(time.RFC3339)
	leaseStr := now.Add(sessionLeaseTTL).Format(time.RFC3339)
	sessID := h.nextID("sess")

	sess := map[string]any{
		"id":                   sessID,
		"workspaceId":          h.workspaceID,
		"agentId":              resolvedAgentID,
		"machineId":            machineID,
		"connectionStatus":     "CONNECTED",
		"executionStatus":      stringValOrDefault(body["executionStatus"], "IDLE"),
		"deliveryMode":         stringValOrDefault(body["deliveryMode"], "HYBRID"),
		"connectionGeneration": gen,
		"lastHeartbeatAt":      nowStr,
		"leaseExpiresAt":       leaseStr,
		"metadata":             deepCloneValue(body["metadata"]),
		"createdAt":            nowStr,
		"updatedAt":            nowStr,
	}
	h.sessions = slices.Insert(h.sessions, 0, sess)

	return map[string]any{
		"session":             cloneMap(sess),
		"heartbeatIntervalMs": 30000,
		"leaseTtlMs":          90000,
	}, nil
}

func (h *Hub) upsertMachineLocked(body map[string]any, now time.Time) map[string]any {
	nowStr := now.Format(time.RFC3339)
	reqID := stringVal(body["machineId"])
	if reqID == "" {
		reqID = stringVal(body["id"])
	}
	name := firstNonEmptyString(body["machineName"], body["name"])
	hostname := firstNonEmptyString(body["hostname"], name)
	if name == "" && reqID != "" {
		name = reqID
	}
	if hostname == "" && reqID != "" {
		hostname = reqID
	}
	if name == "" {
		name = "local-host"
	}
	if hostname == "" {
		hostname = "localhost"
	}

	for i, existing := range h.machines {
		if (reqID != "" && stringVal(existing["id"]) == reqID) ||
			(stringVal(existing["name"]) == name && stringVal(existing["hostname"]) == hostname) {
			existing["lastSeenAt"] = nowStr
			if meta, ok := body["metadata"]; ok && meta != nil {
				existing["metadata"] = deepCloneValue(meta)
			}
			h.machines[i] = existing
			return existing
		}
	}

	id := reqID
	if id == "" {
		id = h.nextID("mach")
	}
	meta := asMap(body["metadata"])
	if meta == nil {
		meta = map[string]any{"os": "linux", "arch": "amd64"}
	} else {
		meta = cloneMap(meta)
	}
	machine := map[string]any{
		"id":          id,
		"workspaceId": h.workspaceID,
		"name":        name,
		"hostname":    hostname,
		"metadata":    meta,
		"createdAt":   nowStr,
		"lastSeenAt":  nowStr,
	}
	h.machines = slices.Insert(h.machines, 0, machine)
	return machine
}

// HeartbeatSession renews a session's 90s lease and checks connectionGeneration fencing (A08-A10).
func (h *Hub) HeartbeatSession(sessionID string, body map[string]any) (map[string]any, error) {
	id := strings.TrimSpace(sessionID)
	if id == "" {
		return nil, errors.New("sessionId is required")
	}

	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) {
		res, err := h.doJSONMap(http.MethodPost, baseURL+"/v1/sessions/"+url.PathEscape(id)+"/heartbeat", token, body)
		if err == nil {
			return res, nil
		}
		if isUpstreamAPIError(err) {
			return nil, err
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	idx := h.findSessionIndexLocked(id)
	if idx < 0 {
		return nil, &APIError{
			StatusCode: http.StatusNotFound,
			Code:       "SESSION_NOT_FOUND",
			Message:    fmt.Sprintf("session %q not found", id),
		}
	}

	sess := h.sessions[idx]
	sessGen := intVal(sess["connectionGeneration"])
	if incomingGen, ok := optionalIntVal(body["connectionGeneration"]); ok && incomingGen < sessGen {
		return nil, &APIError{
			StatusCode: http.StatusConflict,
			Code:       "STALE_CONNECTION_GENERATION",
			Message:    "stale connectionGeneration token",
		}
	}

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)
	leaseStr := now.Add(sessionLeaseTTL).Format(time.RFC3339)

	sess["lastHeartbeatAt"] = nowStr
	sess["leaseExpiresAt"] = leaseStr
	sess["connectionStatus"] = "CONNECTED"
	sess["updatedAt"] = nowStr
	if exec := stringVal(body["executionStatus"]); exec != "" {
		sess["executionStatus"] = exec
	}
	h.sessions[idx] = sess

	if mid := stringVal(sess["machineId"]); mid != "" {
		for mi, m := range h.machines {
			if stringVal(m["id"]) == mid {
				m["lastSeenAt"] = nowStr
				h.machines[mi] = m
				break
			}
		}
	}

	h.persistLocked()
	return map[string]any{
		"sessionId":            id,
		"connectionGeneration": sessGen,
		"connectionStatus":     "CONNECTED",
		"executionStatus":      sess["executionStatus"],
		"leaseExpiresAt":       leaseStr,
		"serverTime":           nowStr,
	}, nil
}

// DisconnectSession marks a runtime session DISCONNECTED and STOPPED with fencing validation.
func (h *Hub) DisconnectSession(sessionID string, body map[string]any) (map[string]any, error) {
	id := strings.TrimSpace(sessionID)
	if id == "" {
		return nil, errors.New("sessionId is required")
	}

	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) {
		res, err := h.doJSONMap(http.MethodPost, baseURL+"/v1/sessions/"+url.PathEscape(id)+"/disconnect", token, body)
		if err == nil {
			return res, nil
		}
		if isUpstreamAPIError(err) {
			return nil, err
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	idx := h.findSessionIndexLocked(id)
	if idx < 0 {
		return nil, &APIError{
			StatusCode: http.StatusNotFound,
			Code:       "SESSION_NOT_FOUND",
			Message:    fmt.Sprintf("session %q not found", id),
		}
	}

	sess := h.sessions[idx]
	sessGen := intVal(sess["connectionGeneration"])
	if incomingGen, ok := optionalIntVal(body["connectionGeneration"]); ok && incomingGen < sessGen {
		return nil, &APIError{
			StatusCode: http.StatusConflict,
			Code:       "STALE_CONNECTION_GENERATION",
			Message:    "stale connectionGeneration token",
		}
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	sess["connectionStatus"] = "DISCONNECTED"
	sess["executionStatus"] = "STOPPED"
	sess["updatedAt"] = nowStr
	h.sessions[idx] = sess
	h.persistLocked()

	return map[string]any{
		"sessionId":        id,
		"connectionStatus": "DISCONNECTED",
		"executionStatus":  "STOPPED",
		"disconnectedAt":   nowStr,
	}, nil
}

// UnregisterSession unregisters a runtime session via external API or removes it locally.
func (h *Hub) UnregisterSession(sessionID string) error {
	id := strings.TrimSpace(sessionID)
	if id == "" {
		return errors.New("sessionId is required")
	}

	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) {
		_, err := h.doJSONMap(http.MethodDelete, baseURL+"/v1/sessions/"+url.PathEscape(id), token, nil)
		if err == nil {
			return nil
		}
		if isUpstreamAPIError(err) {
			return err
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	idx := h.findSessionIndexLocked(id)
	if idx < 0 {
		return &APIError{
			StatusCode: http.StatusNotFound,
			Code:       "SESSION_NOT_FOUND",
			Message:    fmt.Sprintf("session %q not found", id),
		}
	}
	h.sessions = slices.Delete(h.sessions, idx, idx+1)
	h.persistLocked()
	return nil
}

// SendMessage dispatches or queues an envelope message with idempotency deduplication and
// delivery-policy evaluation against connected recipient sessions.
func (h *Hub) SendMessage(body map[string]any) (map[string]any, error) {
	reqBody, err := normalizeSendMessageBody(body)
	if err != nil {
		return nil, err
	}

	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) {
		res, err := h.doJSONMap(http.MethodPost, baseURL+"/v1/messages", token, reqBody)
		if err == nil {
			return res, nil
		}
		if isUpstreamAPIError(err) {
			return nil, err
		}
	}

	return h.sendMessageLocal(reqBody), nil
}

func (h *Hub) sendMessageLocal(reqBody map[string]any) map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now().UTC()
	h.sweepLeasesLocked(now)

	senderAgentID := stringVal(reqBody["senderAgentId"])
	if senderAgentID == "" {
		if len(h.agents) > 0 {
			senderAgentID = stringVal(h.agents[0]["id"])
		}
		if senderAgentID == "" {
			senderAgentID = "agt_control_plane"
		}
	}

	idemKey := stringVal(reqBody["idempotencyKey"])
	if idemKey != "" {
		for _, item := range h.messages {
			env, _ := item["envelope"].(map[string]any)
			if env != nil && stringVal(env["idempotencyKey"]) == idemKey {
				return map[string]any{
					"messageId": messageIDFromItem(item),
					"status":    item["status"],
					"duplicate": true,
					"createdAt": stringVal(env["createdAt"]),
				}
			}
		}
	}

	recipient := cloneMap(asMap(reqBody["recipient"]))
	rawTarget := stringVal(recipient["agentId"])
	resolvedTarget := rawTarget
	if ag := h.findAgentLocked(rawTarget); ag != nil {
		resolvedTarget = stringVal(ag["id"])
		recipient["agentId"] = resolvedTarget
	}

	scope := stringValOrDefault(recipient["scope"], "AGENT")
	targetSessID := stringVal(recipient["sessionId"])
	deliveryPolicy := stringValOrDefault(reqBody["deliveryPolicy"], "STORE_AND_FORWARD")
	fallbackPolicy := stringValOrDefault(reqBody["fallbackPolicy"], "QUEUE")

	hasEligibleSession := false
	for _, sess := range h.sessions {
		if stringVal(sess["connectionStatus"]) != "CONNECTED" {
			continue
		}
		if scope == "SESSION" && targetSessID != "" {
			if stringVal(sess["id"]) == targetSessID {
				hasEligibleSession = true
				break
			}
			continue
		}
		if stringVal(sess["agentId"]) == resolvedTarget {
			hasEligibleSession = true
			break
		}
	}

	msgStatus := "QUEUED"
	deliveryStatus := "PENDING"
	attemptCount := 0
	if hasEligibleSession {
		msgStatus = "DELIVERED"
		deliveryStatus = "DELIVERED"
		attemptCount = 1
	} else if deliveryPolicy == "ONLINE_ONLY" && fallbackPolicy == "FAIL" {
		msgStatus = "FAILED"
		deliveryStatus = "FAILED"
	}

	nowStr := now.Format(time.RFC3339)
	msgID := h.nextID("msg")
	dlvID := h.nextID("dlv")

	envelope := map[string]any{
		"protocolVersion":   "1",
		"messageId":         msgID,
		"workspaceId":       h.workspaceID,
		"sender":            map[string]any{"agentId": senderAgentID, "sessionId": reqBody["senderSessionId"]},
		"recipient":         recipient,
		"type":              stringValOrDefault(reqBody["type"], "agent.message"),
		"payload":           cloneMap(asMap(reqBody["payload"])),
		"correlationId":     reqBody["correlationId"],
		"replyTo":           reqBody["replyTo"],
		"priority":          stringValOrDefault(reqBody["priority"], "NORMAL"),
		"deliveryPolicy":    deliveryPolicy,
		"fallbackPolicy":    fallbackPolicy,
		"selectionStrategy": stringValOrDefault(reqBody["selectionStrategy"], "FIRST_AVAILABLE"),
		"idempotencyKey":    reqBody["idempotencyKey"],
		"createdAt":         nowStr,
		"expiresAt":         reqBody["expiresAt"],
	}

	item := map[string]any{
		"deliveryId":     dlvID,
		"attemptCount":   attemptCount,
		"status":         msgStatus,
		"deliveryStatus": deliveryStatus,
		"envelope":       envelope,
	}
	h.messages = slices.Insert(h.messages, 0, item)
	h.persistLocked()

	return map[string]any{
		"messageId": msgID,
		"status":    msgStatus,
		"duplicate": false,
		"createdAt": nowStr,
	}
}

// GetInbox returns inbox items for agentID (resolved by id or logicalName), optionally filtered by status.
func (h *Hub) GetInbox(agentID string, statusFilter string) []map[string]any {
	id := strings.TrimSpace(agentID)
	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) && id != "" {
		ep := baseURL + "/v1/agents/" + url.PathEscape(id) + "/inbox?limit=50"
		if st := strings.TrimSpace(statusFilter); st != "" {
			ep += "&status=" + url.QueryEscape(st)
		}
		if items, err := h.doJSONItems(http.MethodGet, ep, token); err == nil {
			return items
		}
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	resolvedID := id
	if ag := h.findAgentLocked(id); ag != nil {
		resolvedID = stringVal(ag["id"])
	}
	stFilter := strings.ToUpper(strings.TrimSpace(statusFilter))

	out := make([]map[string]any, 0)
	for _, item := range h.messages {
		env, _ := item["envelope"].(map[string]any)
		rec, _ := env["recipient"].(map[string]any)
		recAgentID := stringVal(rec["agentId"])
		if id != "" && recAgentID != id && recAgentID != resolvedID {
			continue
		}
		if stFilter != "" && stFilter != "ALL" && !strings.EqualFold(stringVal(item["status"]), stFilter) {
			continue
		}
		out = append(out, cloneMap(item))
	}
	sort.SliceStable(out, func(i, j int) bool {
		return compareTimestampsDesc(messageCreatedAtFromItem(out[i]), messageCreatedAtFromItem(out[j]))
	})
	return out
}

// AckMessage acknowledges receipt/processing of a message with optional fencing verification.
func (h *Hub) AckMessage(messageID string, body map[string]any) (map[string]any, error) {
	id := strings.TrimSpace(messageID)
	if id == "" {
		return nil, errors.New("messageId is required")
	}

	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) {
		res, err := h.doJSONMap(http.MethodPost, baseURL+"/v1/messages/"+url.PathEscape(id)+"/ack", token, body)
		if err == nil {
			return res, nil
		}
		if isUpstreamAPIError(err) {
			return nil, err
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	idx := h.findMessageIndexLocked(id)
	if idx < 0 {
		return nil, &APIError{
			StatusCode: http.StatusNotFound,
			Code:       "MESSAGE_NOT_FOUND",
			Message:    fmt.Sprintf("message %q not found", id),
		}
	}

	if err := h.checkSessionFencingLocked(body); err != nil {
		return nil, err
	}

	item := h.messages[idx]
	nowStr := time.Now().UTC().Format(time.RFC3339)
	if stringVal(item["status"]) == "ACKED" {
		ackedAt := stringValOrDefault(item["ackedAt"], nowStr)
		return map[string]any{
			"messageId": id,
			"status":    "ACKED",
			"ackedAt":   ackedAt,
			"duplicate": true,
		}, nil
	}

	item["status"] = "ACKED"
	item["deliveryStatus"] = "ACKED"
	item["ackedAt"] = nowStr
	h.messages[idx] = item
	h.persistLocked()

	return map[string]any{
		"messageId": id,
		"status":    "ACKED",
		"ackedAt":   nowStr,
		"duplicate": false,
	}, nil
}

// NackMessage records negative acknowledgment on a message and schedules retry or marks FAILED.
func (h *Hub) NackMessage(messageID string, body map[string]any) (map[string]any, error) {
	id := strings.TrimSpace(messageID)
	if id == "" {
		return nil, errors.New("messageId is required")
	}

	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) {
		res, err := h.doJSONMap(http.MethodPost, baseURL+"/v1/messages/"+url.PathEscape(id)+"/nack", token, body)
		if err == nil {
			return res, nil
		}
		if isUpstreamAPIError(err) {
			return nil, err
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	idx := h.findMessageIndexLocked(id)
	if idx < 0 {
		return nil, &APIError{
			StatusCode: http.StatusNotFound,
			Code:       "MESSAGE_NOT_FOUND",
			Message:    fmt.Sprintf("message %q not found", id),
		}
	}

	if err := h.checkSessionFencingLocked(body); err != nil {
		return nil, err
	}

	retryable := true
	if rawRetry, exists := body["retryable"]; exists {
		if b, ok := rawRetry.(bool); ok {
			retryable = b
		}
	}

	item := h.messages[idx]
	attempts := intVal(item["attemptCount"]) + 1
	item["attemptCount"] = attempts
	if retryable {
		item["status"] = "RETRY_PENDING"
		item["deliveryStatus"] = "NACKED"
	} else {
		item["status"] = "FAILED"
		item["deliveryStatus"] = "FAILED"
	}
	h.messages[idx] = item
	h.persistLocked()

	return map[string]any{
		"messageId":      id,
		"status":         item["status"],
		"retryScheduled": retryable,
	}, nil
}

// DeleteMessage deletes a message via external API or removes it from the local store.
func (h *Hub) DeleteMessage(messageID string) error {
	id := strings.TrimSpace(messageID)
	if id == "" {
		return errors.New("messageId is required")
	}

	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) {
		_, err := h.doJSONMap(http.MethodDelete, baseURL+"/v1/messages/"+url.PathEscape(id), token, nil)
		if err == nil {
			return nil
		}
		if isUpstreamAPIError(err) {
			return err
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	idx := h.findMessageIndexLocked(id)
	if idx < 0 {
		return &APIError{
			StatusCode: http.StatusNotFound,
			Code:       "MESSAGE_NOT_FOUND",
			Message:    fmt.Sprintf("message %q not found", id),
		}
	}
	h.messages = slices.Delete(h.messages, idx, idx+1)
	h.persistLocked()
	return nil
}

// DelegateTask delegates a task to a target agent (resolved by id, logicalName, or requiredCapability)
// and assigns an eligible CONNECTED+IDLE session if available.
func (h *Hub) DelegateTask(body map[string]any) (map[string]any, error) {
	reqBody, err := normalizeDelegateTaskBody(body)
	if err != nil {
		return nil, err
	}

	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) {
		res, err := h.doJSONMap(http.MethodPost, baseURL+"/v1/tasks", token, reqBody)
		if err == nil {
			return res, nil
		}
		if isUpstreamAPIError(err) {
			return nil, err
		}
	}

	return h.delegateTaskLocal(reqBody), nil
}

func (h *Hub) delegateTaskLocal(reqBody map[string]any) map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)
	h.sweepLeasesLocked(now)

	if idemKey := stringVal(reqBody["idempotencyKey"]); idemKey != "" {
		for _, t := range h.tasks {
			if stringVal(t["idempotencyKey"]) == idemKey {
				return map[string]any{
					"taskId":    t["taskId"],
					"status":    t["status"],
					"duplicate": true,
					"createdAt": t["createdAt"],
				}
			}
		}
	}

	requesterAgentID := stringVal(reqBody["requesterAgentId"])
	if requesterAgentID == "" {
		if len(h.agents) > 0 {
			requesterAgentID = stringVal(h.agents[0]["id"])
		}
		if requesterAgentID == "" {
			requesterAgentID = "agt_control_plane"
		}
	}

	requiredCap := stringVal(reqBody["requiredCapability"])
	targetAgentID := stringVal(reqBody["targetAgentId"])
	if targetAgentID != "" {
		if ag := h.findAgentLocked(targetAgentID); ag != nil {
			targetAgentID = stringVal(ag["id"])
		}
	} else if requiredCap != "" {
		if ag := h.findAgentByCapabilityLocked(requiredCap); ag != nil {
			targetAgentID = stringVal(ag["id"])
		}
	}

	selectionStrategy := stringValOrDefault(reqBody["selectionStrategy"], "FIRST_AVAILABLE")
	pinnedSessID := stringVal(reqBody["targetSessionId"])
	eligibleSess := h.pickEligibleSessionLocked(targetAgentID, selectionStrategy, pinnedSessID)

	taskID := h.nextID("tsk")
	taskStatus := "PENDING"
	assignGen := 1
	var assignedSessID any
	var attemptID any

	events := []map[string]any{
		{
			"id":        h.nextID("tevt"),
			"taskId":    taskID,
			"eventType": "TASK_CREATED",
			"payload": map[string]any{
				"requesterAgentId":  requesterAgentID,
				"selectionStrategy": selectionStrategy,
				"capability":        reqBody["requiredCapability"],
			},
			"createdAt": nowStr,
		},
	}

	if eligibleSess != nil {
		sessID := stringVal(eligibleSess["id"])
		attID := h.nextID("att")
		assignedSessID = sessID
		attemptID = attID
		assignGen = 2
		taskStatus = "DELIVERED"
		events = append(events, map[string]any{
			"id":        h.nextID("tevt"),
			"taskId":    taskID,
			"eventType": "TASK_DELIVERED",
			"payload": map[string]any{
				"sessionId":            sessID,
				"attemptId":            attID,
				"assignmentGeneration": assignGen,
			},
			"createdAt": nowStr,
		})
	}

	target := map[string]any{
		"agentId":           targetAgentID,
		"capability":        reqBody["requiredCapability"],
		"sessionId":         reqBody["targetSessionId"],
		"selectionStrategy": selectionStrategy,
	}

	task := map[string]any{
		"protocolVersion":      "1",
		"taskId":               taskID,
		"workspaceId":          h.workspaceID,
		"requester":            map[string]any{"agentId": requesterAgentID, "sessionId": reqBody["requesterSessionId"]},
		"target":               target,
		"assignedSessionId":    assignedSessID,
		"attemptId":            attemptID,
		"attemptNumber":        1,
		"assignmentGeneration": assignGen,
		"status":               taskStatus,
		"priority":             stringValOrDefault(reqBody["priority"], "NORMAL"),
		"input":                cloneMap(asMap(reqBody["input"])),
		"result":               nil,
		"error":                nil,
		"correlationId":        reqBody["correlationId"],
		"idempotencyKey":       reqBody["idempotencyKey"],
		"createdAt":            nowStr,
		"startedAt":            nil,
		"completedAt":          nil,
		"expiresAt":            reqBody["expiresAt"],
	}
	h.tasks = slices.Insert(h.tasks, 0, task)
	h.taskEvents[taskID] = events
	h.persistLocked()

	return map[string]any{
		"taskId":    taskID,
		"status":    taskStatus,
		"duplicate": false,
		"createdAt": nowStr,
	}
}

// AcceptTask transitions a task to ACCEPTED with assignment/connection fencing validation.
func (h *Hub) AcceptTask(taskID string, body map[string]any) (map[string]any, error) {
	return h.mutateTaskLifecycle(taskID, "accept", body)
}

// StartTask transitions a task to PROCESSING and marks its assigned session BUSY.
func (h *Hub) StartTask(taskID string, body map[string]any) (map[string]any, error) {
	return h.mutateTaskLifecycle(taskID, "start", body)
}

// CompleteTask transitions a task to COMPLETED, stores result, and releases its session to IDLE.
func (h *Hub) CompleteTask(taskID string, body map[string]any) (map[string]any, error) {
	return h.mutateTaskLifecycle(taskID, "complete", body)
}

// FailTask transitions a task to FAILED, stores error payload, and releases its session to IDLE.
func (h *Hub) FailTask(taskID string, body map[string]any) (map[string]any, error) {
	return h.mutateTaskLifecycle(taskID, "fail", body)
}

// CancelTask cancels a delegated task and releases its session to IDLE.
func (h *Hub) CancelTask(taskID string, body map[string]any) (map[string]any, error) {
	return h.mutateTaskLifecycle(taskID, "cancel", body)
}

func (h *Hub) mutateTaskLifecycle(taskID, action string, body map[string]any) (map[string]any, error) {
	id := strings.TrimSpace(taskID)
	if id == "" {
		return nil, errors.New("taskId is required")
	}

	reqBody := cloneMap(body)
	if action == "cancel" {
		if reason := stringVal(reqBody["reason"]); reason == "" {
			delete(reqBody, "reason")
		}
	}

	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) {
		res, err := h.doJSONMap(http.MethodPost, baseURL+"/v1/tasks/"+url.PathEscape(id)+"/"+action, token, reqBody)
		if err == nil {
			return res, nil
		}
		if isUpstreamAPIError(err) {
			return nil, err
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	idx := h.findTaskIndexLocked(id)
	if idx < 0 {
		return nil, &APIError{
			StatusCode: http.StatusNotFound,
			Code:       "TASK_NOT_FOUND",
			Message:    fmt.Sprintf("task %q not found", id),
		}
	}

	task := h.tasks[idx]
	curStatus := stringVal(task["status"])
	if isTerminalTaskStatus(curStatus) {
		return nil, &APIError{
			StatusCode: http.StatusConflict,
			Code:       "INVALID_STATE_TRANSITION",
			Message:    fmt.Sprintf("task %q is already in terminal status %s", id, curStatus),
		}
	}

	if action != "cancel" {
		if err := h.checkSessionFencingLocked(reqBody); err != nil {
			return nil, err
		}
		taskAssignGen := intVal(task["assignmentGeneration"])
		if incomingAssignGen, ok := optionalIntVal(reqBody["assignmentGeneration"]); ok && incomingAssignGen < taskAssignGen {
			return nil, &APIError{
				StatusCode: http.StatusConflict,
				Code:       "STALE_ASSIGNMENT_GENERATION",
				Message:    "stale assignmentGeneration token",
			}
		}
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	if sessID := stringVal(reqBody["sessionId"]); sessID != "" && stringVal(task["assignedSessionId"]) == "" {
		task["assignedSessionId"] = sessID
	}
	if attID := stringVal(reqBody["attemptId"]); attID != "" && stringVal(task["attemptId"]) == "" {
		task["attemptId"] = attID
	}

	var newStatus, eventType string
	var eventPayload map[string]any

	switch action {
	case "accept":
		newStatus = "ACCEPTED"
		eventType = "TASK_ACCEPTED"
		eventPayload = map[string]any{
			"sessionId": task["assignedSessionId"],
			"attemptId": task["attemptId"],
		}
	case "start":
		newStatus = "PROCESSING"
		eventType = "TASK_STARTED"
		task["startedAt"] = nowStr
		h.setSessionExecutionLocked(stringVal(task["assignedSessionId"]), "BUSY", nowStr)
		eventPayload = map[string]any{
			"sessionId": task["assignedSessionId"],
			"attemptId": task["attemptId"],
		}
	case "complete":
		newStatus = "COMPLETED"
		eventType = "TASK_COMPLETED"
		task["completedAt"] = nowStr
		if resMap, ok := reqBody["result"].(map[string]any); ok {
			task["result"] = cloneMap(resMap)
		} else if resObj := extractObjectOrText(reqBody["result"], "output"); resObj != nil {
			task["result"] = resObj
		} else {
			task["result"] = map[string]any{"status": "ok"}
		}
		h.setSessionExecutionLocked(stringVal(task["assignedSessionId"]), "IDLE", nowStr)
		eventPayload = cloneMap(asMap(task["result"]))
	case "fail":
		newStatus = "FAILED"
		eventType = "TASK_FAILED"
		task["completedAt"] = nowStr
		if errObj, ok := reqBody["error"].(map[string]any); ok {
			task["error"] = cloneMap(errObj)
		} else {
			task["error"] = map[string]any{
				"code":      "TASK_FAILED",
				"message":   firstNonEmptyString(reqBody["error"], reqBody["reason"], "task failed"),
				"retryable": boolVal(reqBody["retryable"]),
			}
		}
		h.setSessionExecutionLocked(stringVal(task["assignedSessionId"]), "IDLE", nowStr)
		eventPayload = cloneMap(asMap(task["error"]))
	case "cancel":
		newStatus = "CANCELLED"
		eventType = "TASK_CANCELLED"
		task["completedAt"] = nowStr
		h.setSessionExecutionLocked(stringVal(task["assignedSessionId"]), "IDLE", nowStr)
		eventPayload = cloneMap(reqBody)
	}

	task["status"] = newStatus
	h.tasks[idx] = task
	h.taskEvents[id] = append(h.taskEvents[id], map[string]any{
		"id":        h.nextID("tevt"),
		"taskId":    id,
		"eventType": eventType,
		"payload":   eventPayload,
		"createdAt": nowStr,
	})
	h.persistLocked()

	return map[string]any{
		"taskId":               id,
		"status":               newStatus,
		"attemptId":            task["attemptId"],
		"assignmentGeneration": task["assignmentGeneration"],
		"updatedAt":            nowStr,
	}, nil
}

// GetTask returns a task by taskId.
func (h *Hub) GetTask(taskID string) (map[string]any, error) {
	id := strings.TrimSpace(taskID)
	if id == "" {
		return nil, errors.New("taskId is required")
	}

	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) {
		res, err := h.doJSONMap(http.MethodGet, baseURL+"/v1/tasks/"+url.PathEscape(id), token, nil)
		if err == nil {
			return res, nil
		}
		if isUpstreamAPIError(err) {
			return nil, err
		}
	}

	h.mu.RLock()
	defer h.mu.RUnlock()
	idx := h.findTaskIndexLocked(id)
	if idx < 0 {
		return nil, &APIError{
			StatusCode: http.StatusNotFound,
			Code:       "TASK_NOT_FOUND",
			Message:    fmt.Sprintf("task %q not found", id),
		}
	}
	return cloneMap(h.tasks[idx]), nil
}

// ListTasks returns all tasks sorted newest-first by createdAt.
func (h *Hub) ListTasks() []map[string]any {
	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) {
		if items, err := h.doJSONItems(http.MethodGet, baseURL+"/v1/tasks?limit=100", token); err == nil {
			return items
		}
	}

	h.mu.RLock()
	defer h.mu.RUnlock()
	out := cloneMapSlice(h.tasks)
	sort.SliceStable(out, func(i, j int) bool {
		return compareTimestampsDesc(stringVal(out[i]["createdAt"]), stringVal(out[j]["createdAt"]))
	})
	return out
}

// ListTaskEvents returns the append-only audit event timeline for taskID.
func (h *Hub) ListTaskEvents(taskID string) ([]map[string]any, error) {
	id := strings.TrimSpace(taskID)
	if id == "" {
		return nil, errors.New("taskId is required")
	}

	baseURL, token := h.endpointAndToken("", "")
	if h.isExternalUpstream(baseURL) {
		items, err := h.doJSONItems(http.MethodGet, baseURL+"/v1/tasks/"+url.PathEscape(id)+"/events?limit=100", token)
		if err == nil {
			return items, nil
		}
		if isUpstreamAPIError(err) {
			return nil, err
		}
	}

	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.findTaskIndexLocked(id) < 0 {
		return nil, &APIError{
			StatusCode: http.StatusNotFound,
			Code:       "TASK_NOT_FOUND",
			Message:    fmt.Sprintf("task %q not found", id),
		}
	}
	return cloneMapSlice(h.taskEvents[id]), nil
}

func (h *Hub) sweepLeasesLocked(now time.Time) bool {
	changed := false
	nowStr := now.Format(time.RFC3339)

	for i, sess := range h.sessions {
		connStatus := stringVal(sess["connectionStatus"])
		if connStatus == "DISCONNECTED" {
			continue
		}

		expired := false
		if leaseStr := stringVal(sess["leaseExpiresAt"]); leaseStr != "" {
			if leaseAt, err := parseTimestamp(leaseStr); err == nil && !now.Before(leaseAt) {
				expired = true
			}
		}

		hbStr := firstNonEmptyString(sess["lastHeartbeatAt"], sess["createdAt"])
		var age time.Duration
		if hbStr != "" {
			if hbAt, err := parseTimestamp(hbStr); err == nil {
				age = now.Sub(hbAt)
				if age > sessionLeaseTTL {
					expired = true
				}
			}
		}

		if expired {
			sess["connectionStatus"] = "DISCONNECTED"
			sess["executionStatus"] = "STOPPED"
			sess["updatedAt"] = nowStr
			h.sessions[i] = sess
			changed = true
		} else if age > sessionSuspectAfter && connStatus == "CONNECTED" {
			sess["connectionStatus"] = "SUSPECT"
			sess["updatedAt"] = nowStr
			h.sessions[i] = sess
			changed = true
		}
	}
	return changed
}

func (h *Hub) buildAgentViewLocked(rawAg map[string]any) map[string]any {
	ag := cloneMap(rawAg)
	agID := stringVal(ag["id"])

	agSessions := make([]map[string]any, 0)
	onlineCount := 0
	hasAvailable := false
	isActive := stringValOrDefault(ag["status"], "ACTIVE") == "ACTIVE"

	for _, sess := range h.sessions {
		if stringVal(sess["agentId"]) != agID {
			continue
		}
		agSessions = append(agSessions, cloneMap(sess))
		if stringVal(sess["connectionStatus"]) == "CONNECTED" {
			onlineCount++
			if isActive && stringVal(sess["executionStatus"]) == "IDLE" {
				hasAvailable = true
			}
		}
	}

	ag["sessions"] = agSessions
	ag["sessionCount"] = len(agSessions)
	ag["onlineSessionCount"] = onlineCount
	ag["available"] = hasAvailable
	return ag
}

func (h *Hub) findAgentLocked(idOrName string) map[string]any {
	for _, ag := range h.agents {
		if stringVal(ag["id"]) == idOrName || stringVal(ag["logicalName"]) == idOrName {
			return ag
		}
	}
	return nil
}

func (h *Hub) findAgentByCapabilityLocked(capability string) map[string]any {
	var fallback map[string]any
	for _, rawAg := range h.agents {
		if stringValOrDefault(rawAg["status"], "ACTIVE") != "ACTIVE" {
			continue
		}
		if !agentHasCapability(rawAg, capability) {
			continue
		}
		view := h.buildAgentViewLocked(rawAg)
		if boolVal(view["available"]) {
			return rawAg
		}
		if fallback == nil {
			fallback = rawAg
		}
	}
	return fallback
}

func (h *Hub) pickEligibleSessionLocked(agentID, strategy, pinnedSessionID string) map[string]any {
	if agentID == "" {
		return nil
	}
	if strategy == "PINNED" {
		if pinnedSessionID == "" {
			return nil
		}
		for _, sess := range h.sessions {
			if stringVal(sess["id"]) == pinnedSessionID &&
				stringVal(sess["agentId"]) == agentID &&
				stringVal(sess["connectionStatus"]) == "CONNECTED" &&
				stringVal(sess["executionStatus"]) == "IDLE" {
				return sess
			}
		}
		return nil
	}

	for _, sess := range h.sessions {
		if stringVal(sess["agentId"]) == agentID &&
			stringVal(sess["connectionStatus"]) == "CONNECTED" &&
			stringVal(sess["executionStatus"]) == "IDLE" {
			return sess
		}
	}
	return nil
}

func (h *Hub) findSessionIndexLocked(sessionID string) int {
	for i, s := range h.sessions {
		if stringVal(s["id"]) == sessionID {
			return i
		}
	}
	return -1
}

func (h *Hub) setSessionExecutionLocked(sessionID, execStatus, nowStr string) {
	if sessionID == "" {
		return
	}
	idx := h.findSessionIndexLocked(sessionID)
	if idx < 0 {
		return
	}
	if stringVal(h.sessions[idx]["connectionStatus"]) == "DISCONNECTED" {
		return
	}
	h.sessions[idx]["executionStatus"] = execStatus
	h.sessions[idx]["updatedAt"] = nowStr
}

func (h *Hub) findMessageIndexLocked(messageID string) int {
	for i, m := range h.messages {
		if messageIDFromItem(m) == messageID {
			return i
		}
	}
	return -1
}

func (h *Hub) findTaskIndexLocked(taskID string) int {
	for i, t := range h.tasks {
		if stringVal(t["taskId"]) == taskID || stringVal(t["id"]) == taskID {
			return i
		}
	}
	return -1
}

func (h *Hub) checkSessionFencingLocked(body map[string]any) error {
	sessID := stringVal(body["sessionId"])
	if sessID == "" {
		return nil
	}
	idx := h.findSessionIndexLocked(sessID)
	if idx < 0 {
		return nil
	}
	sessGen := intVal(h.sessions[idx]["connectionGeneration"])
	if incomingGen, ok := optionalIntVal(body["connectionGeneration"]); ok && incomingGen < sessGen {
		return &APIError{
			StatusCode: http.StatusConflict,
			Code:       "STALE_CONNECTION_GENERATION",
			Message:    "stale connectionGeneration token",
		}
	}
	return nil
}

func agentHasCapability(ag map[string]any, capability string) bool {
	for _, c := range extractMapSlice(ag["capabilities"]) {
		if strings.EqualFold(stringVal(c["capability"]), capability) {
			return true
		}
	}
	return false
}

func isTerminalTaskStatus(status string) bool {
	switch status {
	case "COMPLETED", "FAILED", "CANCELLED", "EXPIRED":
		return true
	default:
		return false
	}
}

func (h *Hub) doJSONMap(method, endpoint, token string, body any) (map[string]any, error) {
	raw, err := h.doRequest(method, endpoint, token, body)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode JSON from %s: %w", endpoint, err)
	}
	if out == nil {
		out = map[string]any{}
	}
	return out, nil
}

func (h *Hub) doJSONItems(method, endpoint, token string) ([]map[string]any, error) {
	raw, err := h.doRequest(method, endpoint, token, nil)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return []map[string]any{}, nil
	}
	if trimmed[0] == '[' {
		var arr []map[string]any
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, fmt.Errorf("decode array from %s: %w", endpoint, err)
		}
		return nonNilSlice(arr), nil
	}
	var page struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(trimmed, &page); err != nil {
		return nil, fmt.Errorf("decode page from %s: %w", endpoint, err)
	}
	return nonNilSlice(page.Items), nil
}

func (h *Hub) doRequest(method, endpoint, token string, body any) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, endpoint, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-request-id", h.nextID("req"))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", endpoint, err)
	}

	if resp.StatusCode >= http.StatusBadRequest {
		return nil, parseUpstreamAPIError(resp.StatusCode, raw)
	}
	return raw, nil
}

func parseUpstreamAPIError(statusCode int, raw []byte) *APIError {
	apiErr := &APIError{
		StatusCode: statusCode,
		Message:    http.StatusText(statusCode),
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return apiErr
	}

	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err == nil {
		if inner, ok := obj["error"].(map[string]any); ok {
			if code := stringVal(inner["code"]); code != "" {
				apiErr.Code = code
			}
			if msg := stringVal(inner["message"]); msg != "" {
				apiErr.Message = msg
				return apiErr
			}
		}
		if msg := stringVal(obj["message"]); msg != "" {
			apiErr.Message = msg
			return apiErr
		}
		if msgs, ok := obj["message"].([]any); ok && len(msgs) > 0 {
			parts := make([]string, 0, len(msgs))
			for _, m := range msgs {
				if s := stringVal(m); s != "" {
					parts = append(parts, s)
				}
			}
			if len(parts) > 0 {
				apiErr.Message = strings.Join(parts, "; ")
				return apiErr
			}
		}
		if errText := stringVal(obj["error"]); errText != "" {
			apiErr.Message = errText
			return apiErr
		}
	}

	if len(trimmed) > 512 {
		trimmed = trimmed[:512] + "..."
	}
	apiErr.Message = trimmed
	return apiErr
}

func isUpstreamAPIError(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr)
}

func enrichLiveHealth(health map[string]any) {
	if health == nil {
		return
	}
	checks, ok := health["checks"].(map[string]any)
	if !ok || checks == nil {
		checks = make(map[string]any)
	}
	if _, hasPG := checks["postgres"]; !hasPG {
		if dbStatus, hasDB := checks["database"]; hasDB {
			checks["postgres"] = dbStatus
			delete(checks, "database")
		} else {
			checks["postgres"] = "up"
		}
	}
	if _, hasRedis := checks["redis"]; !hasRedis {
		checks["redis"] = "up"
	}
	if _, hasNats := checks["nats"]; !hasNats {
		checks["nats"] = "up"
	}
	health["checks"] = checks
}

func extractWorkspaceID(agents, machines, tasks []map[string]any) string {
	for _, list := range [][]map[string]any{agents, machines, tasks} {
		for _, item := range list {
			if ws := stringVal(item["workspaceId"]); ws != "" {
				return ws
			}
		}
	}
	return "ws_live"
}

func normalizeRegisterAgentBody(body map[string]any) (map[string]any, error) {
	req := cloneMap(body)
	logicalName := stringVal(req["logicalName"])
	if logicalName == "" {
		return nil, errors.New("logicalName is required")
	}
	req["logicalName"] = logicalName

	var normalizedCaps []map[string]any
	switch raw := req["capabilities"].(type) {
	case nil:
		normalizedCaps = []map[string]any{}
	case string:
		for _, part := range strings.Split(raw, ",") {
			if capName := strings.TrimSpace(part); capName != "" {
				normalizedCaps = append(normalizedCaps, map[string]any{"capability": capName})
			}
		}
	case []string:
		for _, part := range raw {
			if capName := strings.TrimSpace(part); capName != "" {
				normalizedCaps = append(normalizedCaps, map[string]any{"capability": capName})
			}
		}
	case []any:
		for _, item := range raw {
			switch v := item.(type) {
			case string:
				if capName := strings.TrimSpace(v); capName != "" {
					normalizedCaps = append(normalizedCaps, map[string]any{"capability": capName})
				}
			case map[string]any:
				if capName := stringVal(v["capability"]); capName != "" {
					normalizedCaps = append(normalizedCaps, cloneMap(v))
				}
			}
		}
	case []map[string]any:
		for _, v := range raw {
			if capName := stringVal(v["capability"]); capName != "" {
				normalizedCaps = append(normalizedCaps, cloneMap(v))
			}
		}
	}
	if normalizedCaps == nil {
		normalizedCaps = []map[string]any{}
	}
	req["capabilities"] = normalizedCaps
	return req, nil
}

func normalizeSendMessageBody(body map[string]any) (map[string]any, error) {
	req := cloneMap(body)

	var recipient map[string]any
	if existing, ok := req["recipient"].(map[string]any); ok && existing != nil {
		recipient = cloneMap(existing)
	} else {
		agentID := firstNonEmptyString(req["targetAgentId"], req["recipientAgentId"], req["agentId"])
		sessionID := firstNonEmptyString(req["targetSessionId"], req["recipientSessionId"], req["sessionId"])
		scope := firstNonEmptyString(req["scope"], req["routingScope"])
		if scope == "" {
			if sessionID != "" {
				scope = "SESSION"
			} else {
				scope = "AGENT"
			}
		}
		recipient = map[string]any{
			"scope":   strings.ToUpper(scope),
			"agentId": agentID,
		}
		if sessionID != "" {
			recipient["sessionId"] = sessionID
		}
		delete(req, "targetAgentId")
		delete(req, "recipientAgentId")
		delete(req, "agentId")
		delete(req, "targetSessionId")
		delete(req, "recipientSessionId")
		delete(req, "sessionId")
		delete(req, "scope")
		delete(req, "routingScope")
	}

	if stringVal(recipient["agentId"]) == "" {
		return nil, errors.New("recipient.agentId is required")
	}
	if stringVal(recipient["scope"]) == "" {
		recipient["scope"] = "AGENT"
	}
	req["recipient"] = recipient

	payload := extractObjectOrText(req["payload"], "text")
	if payload == nil {
		for _, k := range []string{"message", "text", "content"} {
			if v, exists := req[k]; exists {
				payload = extractObjectOrText(v, "text")
				delete(req, k)
				if payload != nil {
					break
				}
			}
		}
	} else {
		delete(req, "message")
		delete(req, "text")
		delete(req, "content")
	}
	if payload == nil {
		payload = map[string]any{}
	}
	req["payload"] = payload

	if stringVal(req["type"]) == "" {
		req["type"] = "agent.message"
	}
	if stringVal(req["priority"]) == "" {
		req["priority"] = "NORMAL"
	}
	if stringVal(req["deliveryPolicy"]) == "" {
		req["deliveryPolicy"] = "STORE_AND_FORWARD"
	}
	if stringVal(req["fallbackPolicy"]) == "" {
		req["fallbackPolicy"] = "QUEUE"
	}
	if stringVal(req["selectionStrategy"]) == "" {
		req["selectionStrategy"] = "FIRST_AVAILABLE"
	}
	deleteIfEmptyString(req, "senderAgentId", "senderSessionId", "correlationId", "replyTo", "idempotencyKey", "expiresAt")
	return req, nil
}

func normalizeDelegateTaskBody(body map[string]any) (map[string]any, error) {
	req := cloneMap(body)

	targetMap, _ := req["target"].(map[string]any)
	targetAgentID := firstNonEmptyString(req["targetAgentId"], req["agentId"])
	if targetAgentID == "" && targetMap != nil {
		targetAgentID = stringVal(targetMap["agentId"])
	}

	if capVal := firstNonEmptyString(req["requiredCapability"], req["capability"]); capVal != "" {
		req["requiredCapability"] = capVal
	} else if targetMap != nil && stringVal(targetMap["capability"]) != "" {
		req["requiredCapability"] = stringVal(targetMap["capability"])
	} else {
		delete(req, "requiredCapability")
	}
	delete(req, "capability")

	if targetAgentID == "" && stringVal(req["requiredCapability"]) == "" {
		return nil, errors.New("targetAgentId or requiredCapability is required")
	}
	if targetAgentID != "" {
		req["targetAgentId"] = targetAgentID
	} else {
		delete(req, "targetAgentId")
	}
	delete(req, "agentId")

	if sessVal := firstNonEmptyString(req["targetSessionId"], req["sessionId"]); sessVal != "" {
		req["targetSessionId"] = sessVal
	} else if targetMap != nil && stringVal(targetMap["sessionId"]) != "" {
		req["targetSessionId"] = stringVal(targetMap["sessionId"])
	} else {
		delete(req, "targetSessionId")
	}
	delete(req, "sessionId")

	if stringVal(req["selectionStrategy"]) == "" && targetMap != nil {
		if strat := stringVal(targetMap["selectionStrategy"]); strat != "" {
			req["selectionStrategy"] = strat
		}
	}
	delete(req, "target")

	taskInput := extractObjectOrText(req["input"], "objective")
	if taskInput == nil {
		for _, k := range []string{"objective", "text", "message", "prompt", "payload"} {
			if v, exists := req[k]; exists {
				taskInput = extractObjectOrText(v, "objective")
				delete(req, k)
				if taskInput != nil {
					break
				}
			}
		}
	} else {
		delete(req, "objective")
		delete(req, "text")
		delete(req, "message")
		delete(req, "prompt")
		delete(req, "payload")
	}
	if taskInput == nil {
		taskInput = map[string]any{}
	}
	req["input"] = taskInput

	if stringVal(req["selectionStrategy"]) == "" {
		req["selectionStrategy"] = "FIRST_AVAILABLE"
	}
	if stringVal(req["priority"]) == "" {
		req["priority"] = "NORMAL"
	}
	deleteIfEmptyString(req, "requesterAgentId", "requesterSessionId", "correlationId", "idempotencyKey", "expiresAt")
	return req, nil
}

func deleteIfEmptyString(m map[string]any, keys ...string) {
	for _, k := range keys {
		if v, exists := m[k]; exists {
			if s, ok := v.(string); ok && strings.TrimSpace(s) == "" {
				delete(m, k)
			}
		}
	}
}

func extractObjectOrText(val any, textKey string) map[string]any {
	switch v := val.(type) {
	case map[string]any:
		return cloneMap(v)
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return nil
		}
		if strings.HasPrefix(trimmed, "{") {
			var parsed map[string]any
			if err := json.Unmarshal([]byte(trimmed), &parsed); err == nil && parsed != nil {
				return parsed
			}
		}
		return map[string]any{textKey: trimmed}
	default:
		return nil
	}
}

func messageIDFromItem(item map[string]any) string {
	if env, ok := item["envelope"].(map[string]any); ok {
		if id := stringVal(env["messageId"]); id != "" {
			return id
		}
	}
	if id := stringVal(item["messageId"]); id != "" {
		return id
	}
	return stringVal(item["id"])
}

func messageCreatedAtFromItem(item map[string]any) string {
	if env, ok := item["envelope"].(map[string]any); ok {
		if ts := stringVal(env["createdAt"]); ts != "" {
			return ts
		}
	}
	return stringVal(item["createdAt"])
}

func compareTimestampsDesc(a, b string) bool {
	ta, errA := parseTimestamp(a)
	tb, errB := parseTimestamp(b)
	if errA == nil && errB == nil {
		if !ta.Equal(tb) {
			return ta.After(tb)
		}
		return false
	}
	return a > b
}

func parseTimestamp(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

func (h *Hub) nextID(prefix string) string {
	n := h.seq.Add(1)
	var buf [3]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("%s_%d", prefix, n)
	}
	return fmt.Sprintf("%s_%s_%d", prefix, hex.EncodeToString(buf[:]), n)
}

func stringVal(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func stringValOrDefault(v any, fallback string) string {
	if s := stringVal(v); s != "" {
		return s
	}
	return fallback
}

func firstNonEmptyString(vals ...any) string {
	for _, v := range vals {
		if s := stringVal(v); s != "" {
			return s
		}
	}
	return ""
}

func boolVal(v any) bool {
	b, ok := v.(bool)
	return ok && b
}

func intVal(v any) int {
	n, _ := optionalIntVal(v)
	return n
}

func optionalIntVal(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case json.Number:
		if parsed, err := n.Int64(); err == nil {
			return int(parsed), true
		}
	case string:
		if parsed, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func extractMapSlice(v any) []map[string]any {
	switch list := v.(type) {
	case []map[string]any:
		out := make([]map[string]any, len(list))
		for i, item := range list {
			out[i] = cloneMap(item)
		}
		return out
	case []any:
		out := make([]map[string]any, 0, len(list))
		for _, raw := range list {
			if m, ok := raw.(map[string]any); ok && m != nil {
				out = append(out, cloneMap(m))
			}
		}
		return out
	default:
		return []map[string]any{}
	}
}

func nonNilSlice(s []map[string]any) []map[string]any {
	if s == nil {
		return []map[string]any{}
	}
	return s
}

func cloneMapSlice(s []map[string]any) []map[string]any {
	out := make([]map[string]any, len(s))
	for i, m := range s {
		out[i] = cloneMap(m)
	}
	return out
}

func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = deepCloneValue(v)
	}
	return out
}

func deepCloneValue(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		return cloneMap(typed)
	case []map[string]any:
		return cloneMapSlice(typed)
	case []any:
		out := make([]any, len(typed))
		for i, elem := range typed {
			out[i] = deepCloneValue(elem)
		}
		return out
	case []string:
		return slices.Clone(typed)
	default:
		return typed
	}
}
