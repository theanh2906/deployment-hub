package mah

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	mcpProtocolVersionDefault = "2024-11-05"
	mcpMaxFrameBytes          = 4 << 20 // 4 MiB
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// HandleMCPJSONRPC processes a single or batched JSON-RPC 2.0 MCP request against Hub.
// Returns (nil, false) for pure notifications that require no JSON-RPC response.
func (h *Hub) HandleMCPJSONRPC(rawReq []byte) ([]byte, bool) {
	trimmed := bytes.TrimSpace(rawReq)
	if len(trimmed) == 0 {
		out, _ := json.Marshal(rpcErrorResp(nil, -32700, "Parse error: empty request"))
		return out, true
	}

	if trimmed[0] == '[' {
		var batch []json.RawMessage
		if err := json.Unmarshal(trimmed, &batch); err != nil {
			out, _ := json.Marshal(rpcErrorResp(nil, -32700, "Parse error: "+err.Error()))
			return out, true
		}
		if len(batch) == 0 {
			out, _ := json.Marshal(rpcErrorResp(nil, -32600, "Invalid Request: empty batch"))
			return out, true
		}
		resps := make([]map[string]any, 0, len(batch))
		for _, item := range batch {
			if resp, ok := h.handleSingleMCPRequest(item); ok {
				resps = append(resps, resp)
			}
		}
		if len(resps) == 0 {
			return nil, false
		}
		out, _ := json.Marshal(resps)
		return out, true
	}

	resp, ok := h.handleSingleMCPRequest(trimmed)
	if !ok {
		return nil, false
	}
	out, _ := json.Marshal(resp)
	return out, true
}

func (h *Hub) handleSingleMCPRequest(raw []byte) (map[string]any, bool) {
	var req rpcRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return rpcErrorResp(nil, -32700, "Parse error: "+err.Error()), true
	}

	idBytes := bytes.TrimSpace(req.ID)
	hasID := len(idBytes) > 0
	var idVal any
	if hasID {
		if err := json.Unmarshal(idBytes, &idVal); err != nil {
			idVal = nil
		}
	}

	if strings.TrimSpace(req.Method) == "" {
		if !hasID {
			return nil, false
		}
		return rpcErrorResp(idVal, -32600, "Invalid Request: missing method"), true
	}

	if strings.HasPrefix(req.Method, "notifications/") {
		if !hasID {
			return nil, false
		}
		return rpcSuccessResp(idVal, map[string]any{}), true
	}

	if !hasID {
		// Standard JSON-RPC notification without id produces no response.
		return nil, false
	}

	switch req.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if len(bytes.TrimSpace(req.Params)) > 0 {
			_ = json.Unmarshal(req.Params, &params)
		}
		protoVer := strings.TrimSpace(params.ProtocolVersion)
		if protoVer == "" {
			protoVer = mcpProtocolVersionDefault
		}
		return rpcSuccessResp(idVal, map[string]any{
			"protocolVersion": protoVer,
			"capabilities": map[string]any{
				"tools": map[string]any{"listChanged": false},
			},
			"serverInfo": map[string]any{
				"name":    "deploymenthub-mah-go",
				"version": "1.0.0",
			},
		}), true

	case "ping":
		return rpcSuccessResp(idVal, map[string]any{}), true

	case "tools/list":
		return rpcSuccessResp(idVal, map[string]any{
			"tools": mcpToolDefinitions(),
		}), true

	case "tools/call":
		var params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if len(bytes.TrimSpace(req.Params)) > 0 {
			if err := json.Unmarshal(req.Params, &params); err != nil {
				return rpcErrorResp(idVal, -32602, "Invalid params: "+err.Error()), true
			}
		}
		toolName := strings.TrimSpace(params.Name)
		if toolName == "" {
			return rpcErrorResp(idVal, -32602, "Invalid params: tool name is required"), true
		}
		args := params.Arguments
		if args == nil {
			args = map[string]any{}
		}
		resultPayload, err := h.dispatchMCPToolCall(toolName, args)
		return rpcSuccessResp(idVal, formatMCPToolResult(resultPayload, err)), true

	default:
		return rpcErrorResp(idVal, -32601, fmt.Sprintf("Method not found: %s", req.Method)), true
	}
}

func (h *Hub) dispatchMCPToolCall(name string, args map[string]any) (any, error) {
	switch name {
	case "register_agent":
		return h.RegisterAgent(args)

	case "list_agents":
		query := map[string]string{
			"logicalName": stringVal(args["logicalName"]),
			"capability":  stringVal(args["capability"]),
			"status":      stringVal(args["status"]),
		}
		if b, ok := args["availableOnly"].(bool); ok && b {
			query["availableOnly"] = "true"
		} else if s := stringVal(args["availableOnly"]); s != "" {
			query["availableOnly"] = s
		}
		items := h.ListAgents(query)
		return map[string]any{"items": items, "count": len(items)}, nil

	case "get_agent":
		id := firstNonEmptyString(args["agentId"], args["id"], args["logicalName"])
		return h.GetAgent(id)

	case "heartbeat_session", "update_presence":
		id := firstNonEmptyString(args["sessionId"], args["id"])
		return h.HeartbeatSession(id, args)

	case "disconnect_agent":
		id := firstNonEmptyString(args["sessionId"], args["id"])
		return h.DisconnectSession(id, args)

	case "send_message":
		return h.SendMessage(args)

	case "get_inbox", "receive_messages":
		id := firstNonEmptyString(args["agentId"], args["id"])
		items := h.GetInbox(id, stringVal(args["status"]))
		return map[string]any{"items": items, "count": len(items)}, nil

	case "ack_message":
		id := firstNonEmptyString(args["messageId"], args["id"])
		return h.AckMessage(id, args)

	case "nack_message":
		id := firstNonEmptyString(args["messageId"], args["id"])
		return h.NackMessage(id, args)

	case "delegate_task":
		return h.DelegateTask(args)

	case "accept_task":
		id := firstNonEmptyString(args["taskId"], args["id"])
		return h.AcceptTask(id, args)

	case "start_task":
		id := firstNonEmptyString(args["taskId"], args["id"])
		return h.StartTask(id, args)

	case "complete_task":
		id := firstNonEmptyString(args["taskId"], args["id"])
		return h.CompleteTask(id, args)

	case "fail_task":
		id := firstNonEmptyString(args["taskId"], args["id"])
		return h.FailTask(id, args)

	case "cancel_task":
		id := firstNonEmptyString(args["taskId"], args["id"])
		return h.CancelTask(id, args)

	case "get_task_status":
		id := firstNonEmptyString(args["taskId"], args["id"])
		return h.GetTask(id)

	default:
		return nil, fmt.Errorf("unknown MCP tool %q", name)
	}
}

func formatMCPToolResult(payload any, err error) map[string]any {
	if err != nil {
		errObj := map[string]any{
			"error": err.Error(),
		}
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			errObj["statusCode"] = apiErr.StatusCode
			if apiErr.Code != "" {
				errObj["code"] = apiErr.Code
			}
		}
		prettyErr, _ := json.MarshalIndent(errObj, "", "  ")
		return map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": string(prettyErr)},
			},
			"isError": true,
		}
	}

	pretty, mErr := json.MarshalIndent(payload, "", "  ")
	if mErr != nil {
		pretty = []byte(fmt.Sprintf("%v", payload))
	}
	return map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": string(pretty)},
		},
		"isError": false,
	}
}

func rpcSuccessResp(id, result any) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	}
}

func rpcErrorResp(id any, code int, message string) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	}
}

func mcpToolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name":        "register_agent",
			"description": "Register or update a logical agent in the workspace, optionally registering a host machine and creating an active CONNECTED+IDLE session.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"logicalName"},
				"properties": map[string]any{
					"logicalName":   map[string]any{"type": "string", "description": "Unique logical name for the agent (e.g. code-reviewer)"},
					"description":   map[string]any{"type": "string", "description": "Human-readable description of agent responsibilities"},
					"capabilities":  map[string]any{"type": "array", "description": "List of capability strings or {capability, description} objects"},
					"machineName":   map[string]any{"type": "string", "description": "Optional host machine name to register alongside a new session"},
					"hostname":      map[string]any{"type": "string", "description": "Optional machine hostname"},
					"createSession": map[string]any{"type": "boolean", "description": "When true, automatically opens a CONNECTED+IDLE session"},
				},
			},
		},
		{
			"name":        "list_agents",
			"description": "Discover logical agents in the workspace filtered by capability, logicalName, status, or availability.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"logicalName":   map[string]any{"type": "string"},
					"capability":    map[string]any{"type": "string"},
					"availableOnly": map[string]any{"type": "boolean"},
					"status":        map[string]any{"type": "string", "enum": []string{"ACTIVE", "DISABLED", "ARCHIVED"}},
				},
			},
		},
		{
			"name":        "get_agent",
			"description": "Fetch full details, declared capabilities, and active runtime sessions for an agent by ID or logicalName.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"agentId"},
				"properties": map[string]any{
					"agentId": map[string]any{"type": "string", "description": "Agent ID or logicalName"},
				},
			},
		},
		{
			"name":        "heartbeat_session",
			"description": "Renew a runtime session's 90s lease and update executionStatus with connectionGeneration fencing validation.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"sessionId"},
				"properties": map[string]any{
					"sessionId":            map[string]any{"type": "string"},
					"connectionGeneration": map[string]any{"type": "integer", "minimum": 1},
					"executionStatus":      map[string]any{"type": "string", "enum": []string{"STARTING", "IDLE", "BUSY", "PAUSED", "DRAINING", "STOPPED"}},
					"activeTaskCount":      map[string]any{"type": "integer", "minimum": 0},
				},
			},
		},
		{
			"name":        "send_message",
			"description": "Send a durable or online-only message envelope to a target logical agent or pinned runtime session.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"senderAgentId":  map[string]any{"type": "string"},
					"targetAgentId":  map[string]any{"type": "string", "description": "Shorthand recipient agent ID or logicalName"},
					"recipient":      map[string]any{"type": "object", "description": "{scope: AGENT|SESSION, agentId, sessionId?}"},
					"type":           map[string]any{"type": "string", "default": "agent.message"},
					"payload":        map[string]any{"type": "object", "description": "Structured JSON message payload"},
					"priority":       map[string]any{"type": "string", "enum": []string{"LOW", "NORMAL", "HIGH", "URGENT"}},
					"deliveryPolicy": map[string]any{"type": "string", "enum": []string{"STORE_AND_FORWARD", "PREFER_ONLINE", "ONLINE_ONLY"}},
					"fallbackPolicy": map[string]any{"type": "string", "enum": []string{"DROP", "QUEUE", "FAIL"}},
					"idempotencyKey": map[string]any{"type": "string"},
				},
			},
		},
		{
			"name":        "get_inbox",
			"description": "Read durable inbox messages queued or delivered to an agent.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"agentId"},
				"properties": map[string]any{
					"agentId": map[string]any{"type": "string"},
					"status":  map[string]any{"type": "string"},
				},
			},
		},
		{
			"name":        "ack_message",
			"description": "Acknowledge processing of an inbox message with optional session fencing validation.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"messageId"},
				"properties": map[string]any{
					"messageId":            map[string]any{"type": "string"},
					"sessionId":            map[string]any{"type": "string"},
					"connectionGeneration": map[string]any{"type": "integer", "minimum": 1},
				},
			},
		},
		{
			"name":        "nack_message",
			"description": "Negatively acknowledge a message, scheduling retry or marking FAILED.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"messageId"},
				"properties": map[string]any{
					"messageId":            map[string]any{"type": "string"},
					"sessionId":            map[string]any{"type": "string"},
					"connectionGeneration": map[string]any{"type": "integer", "minimum": 1},
					"retryable":            map[string]any{"type": "boolean", "default": true},
					"reason":               map[string]any{"type": "string"},
				},
			},
		},
		{
			"name":        "delegate_task",
			"description": "Delegate an asynchronous task to a target agent (by ID, logicalName, or requiredCapability) and reserve an eligible session.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"requesterAgentId":   map[string]any{"type": "string"},
					"targetAgentId":      map[string]any{"type": "string"},
					"requiredCapability": map[string]any{"type": "string"},
					"selectionStrategy":  map[string]any{"type": "string", "enum": []string{"FIRST_AVAILABLE", "LEAST_BUSY", "ROUND_ROBIN", "PINNED"}},
					"targetSessionId":    map[string]any{"type": "string"},
					"priority":           map[string]any{"type": "string", "enum": []string{"LOW", "NORMAL", "HIGH", "URGENT"}},
					"input":              map[string]any{"type": "object", "description": "Task input payload"},
					"idempotencyKey":     map[string]any{"type": "string"},
				},
			},
		},
		{
			"name":        "accept_task",
			"description": "Accept an assigned task on a runtime session with assignmentGeneration fencing check.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"taskId"},
				"properties": map[string]any{
					"taskId":               map[string]any{"type": "string"},
					"sessionId":            map[string]any{"type": "string"},
					"connectionGeneration": map[string]any{"type": "integer", "minimum": 1},
					"attemptId":            map[string]any{"type": "string"},
					"assignmentGeneration": map[string]any{"type": "integer", "minimum": 1},
				},
			},
		},
		{
			"name":        "complete_task",
			"description": "Complete a delegated task with structured JSON result and release the assigned session back to IDLE.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"taskId", "result"},
				"properties": map[string]any{
					"taskId":               map[string]any{"type": "string"},
					"sessionId":            map[string]any{"type": "string"},
					"connectionGeneration": map[string]any{"type": "integer", "minimum": 1},
					"attemptId":            map[string]any{"type": "string"},
					"assignmentGeneration": map[string]any{"type": "integer", "minimum": 1},
					"result":               map[string]any{"type": "object"},
				},
			},
		},
	}
}

// RunMCPStdio serves newline-delimited JSON-RPC 2.0 MCP frames from in to out.
// When apiURL is reachable, frames are forwarded to POST <apiURL>/api/v1/mah/mcp so stdio clients
// share live state with the running DeploymentHub control plane; if offline, it falls back to a local Hub.
func RunMCPStdio(apiURL, apiToken string, in io.Reader, out io.Writer) error {
	targetBase := strings.TrimRight(strings.TrimSpace(apiURL), "/")
	if targetBase == "" {
		targetBase = defaultAPIURL
	}
	useLocalOnly := strings.EqualFold(targetBase, "local") || strings.EqualFold(targetBase, "native")

	client := &http.Client{Timeout: 10 * time.Second}
	var localHub *Hub
	getLocalHub := func() *Hub {
		if localHub == nil {
			localHub = NewHub()
		}
		return localHub
	}

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), mcpMaxFrameBytes)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var respBytes []byte
		var hasResp bool

		if !useLocalOnly {
			var reachable bool
			respBytes, hasResp, reachable = forwardMCPFrameHTTP(client, targetBase+"/api/v1/mah/mcp", apiToken, line)
			if !reachable {
				respBytes, hasResp = getLocalHub().HandleMCPJSONRPC(line)
			}
		} else {
			respBytes, hasResp = getLocalHub().HandleMCPJSONRPC(line)
		}

		if hasResp && len(respBytes) > 0 {
			if _, err := out.Write(append(bytes.TrimSpace(respBytes), '\n')); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}

func forwardMCPFrameHTTP(client *http.Client, endpoint, token string, payload []byte) ([]byte, bool, bool) {
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, false, false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, false, false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, false, true
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode >= http.StatusInternalServerError {
		return nil, false, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, mcpMaxFrameBytes))
	if err != nil {
		return nil, false, false
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, false, true
	}
	return trimmed, true, true
}
