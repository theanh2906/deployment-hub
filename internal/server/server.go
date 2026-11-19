// Package server implements the HTTP REST API, SSE streaming endpoints,
// GitHub webhook receiver, and embedded web UI handler for DeploymentHub.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	"deploymenthub/internal/cloudflare"
	"deploymenthub/internal/detector"
	"deploymenthub/internal/docker"
	"deploymenthub/internal/mah"
	"deploymenthub/internal/vault"
)

const maxRequestBodyBytes = 2 << 20 // 2 MiB

type apiServer struct {
	engine        *docker.Engine
	vault         *vault.Vault
	mahHub        *mah.Hub
	webhookSecret string
	webFS         fs.FS
}

// New constructs the DeploymentHub HTTP handler wiring all REST, SSE, webhook,
// and static web UI routes against the provided Docker engine, vault, and webFS.
func New(engine *docker.Engine, v *vault.Vault, webhookSecret string, webFS fs.FS) http.Handler {
	s := &apiServer{
		engine:        engine,
		vault:         v,
		mahHub:        mah.NewHub(),
		webhookSecret: webhookSecret,
		webFS:         webFS,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/overview", s.handleOverview)
	mux.HandleFunc("GET /api/v1/projects", s.handleListProjects)
	mux.HandleFunc("POST /api/v1/projects/{id}/redeploy", s.handleRedeployProject)
	mux.HandleFunc("POST /api/v1/projects/{id}/restart", s.handleRestartProject)
	mux.HandleFunc("POST /api/v1/projects/{id}/ssl", s.handleConfigureProjectSSL)
	mux.HandleFunc("GET /api/v1/ssl/status", s.handleGetSSLStatus)
	mux.HandleFunc("POST /api/v1/ssl/settings", s.handleUpdateSSLSettings)
	mux.HandleFunc("POST /api/v1/ssl/probe", s.handleProbeDomainSSL)
	mux.HandleFunc("GET /api/v1/cloudflare/status", s.handleCloudflareStatus)
	mux.HandleFunc("POST /api/v1/cloudflare/connect", s.handleCloudflareConnect)
	mux.HandleFunc("POST /api/v1/cloudflare/disconnect", s.handleCloudflareDisconnect)
	mux.HandleFunc("POST /api/v1/cloudflare/wildcard", s.handleCloudflareWildcard)
	mux.HandleFunc("POST /api/v1/cloudflare/dns", s.handleCloudflareUpsertDNS)
	mux.HandleFunc("DELETE /api/v1/cloudflare/dns/{id}", s.handleCloudflareDeleteDNS)
	mux.HandleFunc("POST /api/v1/cloudflare/ssl-mode", s.handleCloudflareSSLMode)
	mux.HandleFunc("POST /api/v1/cloudflare/hub-domain", s.handleCloudflareHubDomain)
	mux.HandleFunc("GET /api/v1/scm/repos", s.handleListSCMRepos)
	mux.HandleFunc("GET /api/v1/scm/branches", s.handleListSCMBranches)
	mux.HandleFunc("POST /api/v1/scm/verify-pat", s.handleVerifyPAT)
	mux.HandleFunc("POST /api/v1/detect", s.handleDetect)
	mux.HandleFunc("POST /api/v1/detect/dockerfile", s.handleGenerateDockerfile)
	mux.HandleFunc("POST /api/v1/detect/diagnose", s.handleDiagnoseBuild)
	mux.HandleFunc("POST /api/v1/deployments", s.handleStartDeployment)
	mux.HandleFunc("GET /api/v1/deployments/{id}", s.handleGetDeployment)
	mux.HandleFunc("GET /api/v1/deployments/{id}/stream", s.handleStreamDeployment)
	mux.HandleFunc("POST /api/v1/containers/{id}/action", s.handleContainerAction)
	mux.HandleFunc("GET /api/v1/containers/{id}/logs", s.handleGetContainerLogs)
	mux.HandleFunc("POST /api/v1/images/prune", s.handlePruneImages)
	mux.HandleFunc("POST /api/v1/proxy/routes/{id}/toggle-ssl", s.handleToggleProxySSL)
	mux.HandleFunc("POST /api/v1/mock/clean", s.handleClearMockData)
	mux.HandleFunc("POST /api/v1/webhooks/github", s.handleGitHubWebhook)

	// Multi-Agent Hub (MAH) native Go control plane, proxy & MCP routes.
	mux.HandleFunc("GET /api/v1/mah/snapshot", s.handleMahSnapshot)
	mux.HandleFunc("GET /api/v1/mah/config", s.handleGetMahConfig)
	mux.HandleFunc("POST /api/v1/mah/config", s.handleUpdateMahConfig)
	mux.HandleFunc("POST /api/v1/mah/mcp", s.handleMahMCP)
	mux.HandleFunc("POST /mcp", s.handleMahMCP)
	mux.HandleFunc("POST /api/v1/mah/agents", s.handleMahRegisterAgent)
	mux.HandleFunc("POST /api/v1/mah/sessions", s.handleMahCreateSession)
	mux.HandleFunc("POST /api/v1/mah/sessions/{id}/heartbeat", s.handleMahHeartbeatSession)
	mux.HandleFunc("DELETE /api/v1/mah/sessions/{id}", s.handleMahUnregisterSession)
	mux.HandleFunc("POST /api/v1/mah/messages", s.handleMahSendMessage)
	mux.HandleFunc("POST /api/v1/mah/messages/{id}/ack", s.handleMahAckMessage)
	mux.HandleFunc("POST /api/v1/mah/messages/{id}/nack", s.handleMahNackMessage)
	mux.HandleFunc("DELETE /api/v1/mah/messages/{id}", s.handleMahDeleteMessage)
	mux.HandleFunc("POST /api/v1/mah/tasks", s.handleMahDelegateTask)
	mux.HandleFunc("POST /api/v1/mah/tasks/{id}/accept", s.handleMahAcceptTask)
	mux.HandleFunc("POST /api/v1/mah/tasks/{id}/start", s.handleMahStartTask)
	mux.HandleFunc("POST /api/v1/mah/tasks/{id}/complete", s.handleMahCompleteTask)
	mux.HandleFunc("POST /api/v1/mah/tasks/{id}/fail", s.handleMahFailTask)
	mux.HandleFunc("POST /api/v1/mah/tasks/{id}/cancel", s.handleMahCancelTask)

	// Canonical MAH REST v1 compatibility routes.
	mux.HandleFunc("GET /v1/health", s.handleV1Health)
	mux.HandleFunc("GET /v1/agents", s.handleV1ListAgents)
	mux.HandleFunc("POST /v1/agents", s.handleMahRegisterAgent)
	mux.HandleFunc("GET /v1/agents/{id}", s.handleV1GetAgent)
	mux.HandleFunc("POST /v1/agents/{id}/sessions", s.handleV1CreateSession)
	mux.HandleFunc("GET /v1/agents/{id}/inbox", s.handleV1GetInbox)
	mux.HandleFunc("GET /v1/machines", s.handleV1ListMachines)
	mux.HandleFunc("POST /v1/machines", s.handleV1RegisterMachine)
	mux.HandleFunc("GET /v1/machines/{id}", s.handleV1GetMachine)
	mux.HandleFunc("DELETE /v1/sessions/{id}", s.handleV1UnregisterSession)
	mux.HandleFunc("POST /v1/sessions/{id}/heartbeat", s.handleMahHeartbeatSession)
	mux.HandleFunc("POST /v1/messages", s.handleMahSendMessage)
	mux.HandleFunc("DELETE /v1/messages/{id}", s.handleV1DeleteMessage)
	mux.HandleFunc("POST /v1/messages/{id}/ack", s.handleMahAckMessage)
	mux.HandleFunc("POST /v1/messages/{id}/nack", s.handleMahNackMessage)
	mux.HandleFunc("GET /v1/tasks", s.handleV1ListTasks)
	mux.HandleFunc("POST /v1/tasks", s.handleMahDelegateTask)
	mux.HandleFunc("GET /v1/tasks/{id}", s.handleV1GetTask)
	mux.HandleFunc("GET /v1/tasks/{id}/events", s.handleV1ListTaskEvents)
	mux.HandleFunc("POST /v1/tasks/{id}/accept", s.handleMahAcceptTask)
	mux.HandleFunc("POST /v1/tasks/{id}/start", s.handleMahStartTask)
	mux.HandleFunc("POST /v1/tasks/{id}/complete", s.handleMahCompleteTask)
	mux.HandleFunc("POST /v1/tasks/{id}/fail", s.handleMahFailTask)
	mux.HandleFunc("POST /v1/tasks/{id}/cancel", s.handleMahCancelTask)

	mux.HandleFunc("GET /", s.handleWebUI)

	return withSecurityAndCORS(mux)
}

func withSecurityAndCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "SAMEORIGIN")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Hub-Signature-256, X-GitHub-Event, X-GitHub-Token")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *apiServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	overview := s.engine.GetOverview()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"runtimeMode":   overview.VPS.RuntimeMode,
		"dockerVersion": overview.VPS.DockerVersion,
		"host":          overview.VPS.Host,
		"vaultReady":    s.vault != nil,
	})
}

func (s *apiServer) handleOverview(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.engine.GetOverview())
}

func (s *apiServer) handleListProjects(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.engine.GetOverview().Projects)
}

func (s *apiServer) handleRedeployProject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	proj, err := s.engine.RedeployProject(id)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proj)
}

func (s *apiServer) handleRestartProject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	proj, err := s.engine.RestartProject(id)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proj)
}

func (s *apiServer) handleConfigureProjectSSL(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Domain            string `json:"domain"`
		EnableSSL         bool   `json:"enableSsl"`
		ForceHTTPS        bool   `json:"forceHttps"`
		CloudflareSyncDNS bool   `json:"cloudflareSyncDns"`
		CloudflareProxied bool   `json:"cloudflareProxied"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	proj, probe, err := s.engine.ConfigureProjectSSLWithOptions(
		id, req.Domain, req.EnableSSL, req.ForceHTTPS, req.CloudflareSyncDNS, req.CloudflareProxied,
	)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"project": proj,
		"probe":   probe,
	})
}

func (s *apiServer) handleCloudflareStatus(w http.ResponseWriter, r *http.Request) {
	cf := s.engine.Cloudflare()
	cfg := cf.GetSanitizedConfig()
	serverIP := cfg.ServerIP
	if serverIP == "" {
		serverIP = cf.DetectPublicIPv4()
	}

	records := []cloudflare.DNSRecord{}
	listErr := ""
	if cfg.Enabled {
		if recs, err := cf.ListDNSRecords(); err == nil {
			records = recs
		} else {
			listErr = err.Error()
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"config":   cfg,
		"serverIp": serverIP,
		"records":  records,
		"error":    listErr,
	})
}

func (s *apiServer) handleCloudflareConnect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		APIToken       string `json:"apiToken"`
		ZoneID         string `json:"zoneId"`
		BaseDomain     string `json:"baseDomain"`
		ServerIP       string `json:"serverIp"`
		DefaultProxied bool   `json:"defaultProxied"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	cf := s.engine.Cloudflare()
	cfg, zones, err := cf.Connect(req.APIToken, req.ZoneID, req.BaseDomain, req.ServerIP, req.DefaultProxied)
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "cloudflare API") {
			status = http.StatusBadGateway
		}
		writeError(w, status, err.Error())
		return
	}

	records := []cloudflare.DNSRecord{}
	if recs, recErr := cf.ListDNSRecords(); recErr == nil {
		records = recs
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"config":  cfg,
		"zones":   zones,
		"records": records,
	})
}

func (s *apiServer) handleCloudflareDisconnect(w http.ResponseWriter, r *http.Request) {
	if err := s.engine.Cloudflare().Disconnect(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "disconnected",
		"config": s.engine.Cloudflare().GetSanitizedConfig(),
	})
}

func (s *apiServer) handleCloudflareWildcard(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Proxied           bool `json:"proxied"`
		EnforceFullStrict bool `json:"enforceFullStrict"`
		EnableDNS01       bool `json:"enableDns01"`
	}
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	cf := s.engine.Cloudflare()
	cfg := cf.GetSanitizedConfig()
	if !cfg.Enabled {
		writeError(w, http.StatusBadRequest, "cloudflare is not connected")
		return
	}

	rec, err := cf.UpsertARecord("*", cfg.ServerIP, req.Proxied)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	sslMode := cfg.SSLMode
	if req.EnforceFullStrict {
		if m, sslErr := cf.SetSSLMode("strict"); sslErr == nil {
			sslMode = m
		}
	}

	dns01Warn := ""
	if req.EnableDNS01 {
		if token, tokErr := cf.GetDecryptedToken(); tokErr == nil {
			sslOverview := s.engine.GetSSLOverview()
			email := ""
			if settings, ok := sslOverview["settings"].(docker.SSLSettings); ok {
				email = settings.ACMEEmail
			}
			if syncErr := s.engine.SyncTraefikCloudflareDNS01(token, email, cfg.BaseDomain); syncErr != nil {
				dns01Warn = syncErr.Error()
			}
		} else {
			dns01Warn = tokErr.Error()
		}
	}

	probe := docker.ProbeDomainSSL("wildcard-probe." + cfg.BaseDomain)
	records := []cloudflare.DNSRecord{}
	if recs, recErr := cf.ListDNSRecords(); recErr == nil {
		records = recs
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"config":         cf.GetSanitizedConfig(),
		"wildcardRecord": rec,
		"sslMode":        sslMode,
		"records":        records,
		"probe":          probe,
		"dns01Warning":   dns01Warn,
	})
}

func (s *apiServer) handleCloudflareUpsertDNS(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Content string `json:"content"`
		Proxied bool   `json:"proxied"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	rec, err := s.engine.Cloudflare().UpsertARecord(req.Name, req.Content, req.Proxied)
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "cloudflare API") {
			status = http.StatusBadGateway
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *apiServer) handleCloudflareDeleteDNS(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.engine.Cloudflare().DeleteDNSRecord(id); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "deleted",
		"recordId": id,
	})
}

func (s *apiServer) handleCloudflareSSLMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode string `json:"mode"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	mode, err := s.engine.Cloudflare().SetSSLMode(req.Mode)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sslMode": mode,
		"config":  s.engine.Cloudflare().GetSanitizedConfig(),
	})
}

func (s *apiServer) handleCloudflareHubDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Subdomain string `json:"subdomain"`
		Proxied   bool   `json:"proxied"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	cf := s.engine.Cloudflare()
	cfg := cf.GetSanitizedConfig()
	if !cfg.Enabled || cfg.BaseDomain == "" {
		writeError(w, http.StatusBadRequest, "cloudflare is not connected")
		return
	}
	sub := strings.TrimSpace(req.Subdomain)
	if sub == "" {
		sub = "hub"
	}
	hubDomain := sub
	if !strings.Contains(sub, ".") {
		hubDomain = strings.ToLower(sub) + "." + cfg.BaseDomain
	} else if !strings.HasSuffix(strings.ToLower(sub), "."+cfg.BaseDomain) && strings.ToLower(sub) != cfg.BaseDomain {
		hubDomain = strings.ToLower(sub)
	}

	if !cfg.WildcardEnabled {
		if _, err := cf.UpsertARecord(hubDomain, cfg.ServerIP, req.Proxied); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
	}

	if err := s.engine.ConfigureHubDomain(hubDomain, cfg.TraefikDNS01, cfg.BaseDomain); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"hubDomain": hubDomain,
		"config":    cf.GetSanitizedConfig(),
	})
}

func (s *apiServer) handleGetSSLStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.engine.GetSSLOverview())
}

func (s *apiServer) handleUpdateSSLSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ACMEEmail         string `json:"acmeEmail"`
		WildcardDomain    string `json:"wildcardDomain"`
		AutoRedirectHTTPS bool   `json:"autoRedirectHttps"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	cfg := s.engine.UpdateSSLSettings(req.ACMEEmail, req.WildcardDomain, req.AutoRedirectHTTPS)
	writeJSON(w, http.StatusOK, cfg)
}

func (s *apiServer) handleProbeDomainSSL(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	writeJSON(w, http.StatusOK, docker.ProbeDomainSSL(domain))
}

func (s *apiServer) handleVerifyPAT(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token   string `json:"token"`
		RepoURL string `json:"repoUrl"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	res, err := s.engine.VerifyPAT(req.Token, req.RepoURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *apiServer) handleListSCMRepos(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.URL.Query().Get("user"))
	token := strings.TrimSpace(r.Header.Get("X-GitHub-Token"))
	if token == "" {
		token = strings.TrimSpace(r.URL.Query().Get("token"))
	}
	repos, err := detector.FetchGitHubRepos(user, token)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, repos)
}

func (s *apiServer) handleListSCMBranches(w http.ResponseWriter, r *http.Request) {
	repo := strings.TrimSpace(r.URL.Query().Get("repo"))
	if repo == "" {
		writeError(w, http.StatusBadRequest, "repo query parameter is required")
		return
	}
	token := strings.TrimSpace(r.Header.Get("X-GitHub-Token"))
	if token == "" {
		token = strings.TrimSpace(r.URL.Query().Get("token"))
	}
	branches, err := detector.FetchGitHubBranches(repo, token)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"repo":     repo,
		"branches": branches,
	})
}

func (s *apiServer) handleDetect(w http.ResponseWriter, r *http.Request) {
	var req detector.DetectRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	writeJSON(w, http.StatusOK, detector.Detect(req))
}

func (s *apiServer) handleGenerateDockerfile(w http.ResponseWriter, r *http.Request) {
	var req detector.DockerfileRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"dockerfile": detector.GenerateDockerfile(req),
	})
}

func (s *apiServer) handleDiagnoseBuild(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Logs []string `json:"logs"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	writeJSON(w, http.StatusOK, detector.DiagnoseBuildFailure(req.Logs))
}

func (s *apiServer) handleStartDeployment(w http.ResponseWriter, r *http.Request) {
	var req docker.DeployRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	rec, err := s.engine.StartDeployment(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, rec)
}

func (s *apiServer) handleGetDeployment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, ok := s.engine.GetDeployment(id)
	if !ok {
		writeError(w, http.StatusNotFound, "deployment not found")
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *apiServer) handleStreamDeployment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	history, ch, unsub, ok := s.engine.SubscribeDeployment(id)
	if !ok {
		writeError(w, http.StatusNotFound, "deployment not found")
		return
	}
	defer unsub()

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	writeEvent := func(ev docker.DeployEvent) bool {
		payload, err := json.Marshal(ev)
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	for _, ev := range history {
		if !writeEvent(ev) || ev.Done {
			return
		}
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, open := <-ch:
			if !open {
				return
			}
			if !writeEvent(ev) || ev.Done {
				return
			}
		}
	}
}

func (s *apiServer) handleContainerAction(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Action    string `json:"action"`
		TargetTag string `json:"targetTag"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	c, err := s.engine.ContainerAction(id, req.Action, req.TargetTag)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *apiServer) handleGetContainerLogs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	logs, err := s.engine.GetContainerLogs(id, 100)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":   id,
		"logs": logs,
	})
}

func (s *apiServer) handlePruneImages(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.engine.PruneDanglingImages())
}

func (s *apiServer) handleToggleProxySSL(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	route, err := s.engine.ToggleProxySSL(id)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, route)
}

func (s *apiServer) handleClearMockData(w http.ResponseWriter, r *http.Request) {
	s.engine.ClearMockData()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"message": "Mock data cleared cleanly",
	})
}

func (s *apiServer) handleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read webhook body")
		return
	}

	sig := r.Header.Get("X-Hub-Signature-256")
	if s.webhookSecret == "" || !vault.VerifyGitHubSignature(s.webhookSecret, body, sig) {
		writeError(w, http.StatusUnauthorized, "invalid webhook signature")
		return
	}

	eventName := r.Header.Get("X-GitHub-Event")
	if eventName == "ping" {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "pong",
			"event":  "ping",
		})
		return
	}

	var payload struct {
		Ref        string `json:"ref"`
		After      string `json:"after"`
		Repository struct {
			FullName string `json:"full_name"`
			HTMLURL  string `json:"html_url"`
			CloneURL string `json:"clone_url"`
		} `json:"repository"`
		HeadCommit struct {
			Message string `json:"message"`
		} `json:"head_commit"`
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid webhook json payload")
			return
		}
	}

	if strings.Contains(payload.HeadCommit.Message, "[skip ci]") {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":            "skipped",
			"reason":            "[skip ci] detected",
			"triggeredProjects": []string{},
		})
		return
	}

	branch := strings.TrimPrefix(payload.Ref, "refs/heads/")
	repoCandidates := []string{
		normalizeRepoSlug(payload.Repository.FullName),
		normalizeRepoSlug(payload.Repository.HTMLURL),
		normalizeRepoSlug(payload.Repository.CloneURL),
	}

	triggered := make([]string, 0)
	for _, proj := range s.engine.GetOverview().Projects {
		if !repoMatches(proj.Repo, repoCandidates) {
			continue
		}
		if branch != "" && proj.Branch != "" && !strings.EqualFold(proj.Branch, branch) {
			continue
		}
		if _, err := s.engine.RedeployProject(proj.ID); err == nil {
			triggered = append(triggered, proj.ID)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "accepted",
		"event":             eventName,
		"repo":              payload.Repository.FullName,
		"branch":            branch,
		"triggeredProjects": triggered,
	})
}

func (s *apiServer) handleMahSnapshot(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	overrideURL := q.Get("apiUrl")
	if overrideURL == "" {
		overrideURL = q.Get("url")
	}
	overrideToken := q.Get("apiToken")
	if overrideToken == "" {
		overrideToken = q.Get("token")
	}
	writeJSON(w, http.StatusOK, s.mahHub.GetSnapshot(overrideURL, overrideToken))
}

func (s *apiServer) handleGetMahConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.mahHub.GetConfig())
}

func (s *apiServer) handleUpdateMahConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		APIURL        string `json:"apiUrl"`
		APIToken      string `json:"apiToken"`
		ServerHost    string `json:"serverHost"`
		SSHUser       string `json:"sshUser"`
		MCPScriptPath string `json:"mcpScriptPath"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	cfg := s.mahHub.UpdateConfig(req.APIURL, req.APIToken, req.ServerHost, req.SSHUser, req.MCPScriptPath)
	writeJSON(w, http.StatusOK, cfg)
}

func (s *apiServer) handleMahRegisterAgent(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if !decodeJSON(w, r, &body) {
		return
	}
	res, err := s.mahHub.RegisterAgent(body)
	if err != nil {
		writeMahError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (s *apiServer) handleMahSendMessage(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if !decodeJSON(w, r, &body) {
		return
	}
	res, err := s.mahHub.SendMessage(body)
	if err != nil {
		writeMahError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (s *apiServer) handleMahDeleteMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.mahHub.DeleteMessage(id); err != nil {
		writeMahError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "deleted",
		"messageId": id,
	})
}

func (s *apiServer) handleMahDelegateTask(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if !decodeJSON(w, r, &body) {
		return
	}
	res, err := s.mahHub.DelegateTask(body)
	if err != nil {
		writeMahError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (s *apiServer) handleMahCancelTask(w http.ResponseWriter, r *http.Request) {
	s.handleMahTaskMutation(w, r, s.mahHub.CancelTask)
}

func (s *apiServer) handleMahAcceptTask(w http.ResponseWriter, r *http.Request) {
	s.handleMahTaskMutation(w, r, s.mahHub.AcceptTask)
}

func (s *apiServer) handleMahStartTask(w http.ResponseWriter, r *http.Request) {
	s.handleMahTaskMutation(w, r, s.mahHub.StartTask)
}

func (s *apiServer) handleMahCompleteTask(w http.ResponseWriter, r *http.Request) {
	s.handleMahTaskMutation(w, r, s.mahHub.CompleteTask)
}

func (s *apiServer) handleMahFailTask(w http.ResponseWriter, r *http.Request) {
	s.handleMahTaskMutation(w, r, s.mahHub.FailTask)
}

func (s *apiServer) handleMahTaskMutation(w http.ResponseWriter, r *http.Request, fn func(string, map[string]any) (map[string]any, error)) {
	id := r.PathValue("id")
	body := map[string]any{}
	if !decodeOptionalJSON(w, r, &body) {
		return
	}
	res, err := fn(id, body)
	if err != nil {
		writeMahError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *apiServer) handleMahCreateSession(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if !decodeJSON(w, r, &body) {
		return
	}
	agentID, _ := body["agentId"].(string)
	if agentID == "" {
		agentID = r.URL.Query().Get("agentId")
	}
	res, err := s.mahHub.CreateSession(agentID, body)
	if err != nil {
		writeMahError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (s *apiServer) handleMahHeartbeatSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	body := map[string]any{}
	if !decodeOptionalJSON(w, r, &body) {
		return
	}
	res, err := s.mahHub.HeartbeatSession(id, body)
	if err != nil {
		writeMahError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *apiServer) handleMahAckMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	body := map[string]any{}
	if !decodeOptionalJSON(w, r, &body) {
		return
	}
	res, err := s.mahHub.AckMessage(id, body)
	if err != nil {
		writeMahError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *apiServer) handleMahNackMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	body := map[string]any{}
	if !decodeOptionalJSON(w, r, &body) {
		return
	}
	res, err := s.mahHub.NackMessage(id, body)
	if err != nil {
		writeMahError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *apiServer) handleMahMCP(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read MCP request body")
		return
	}
	respBytes, hasResp := s.mahHub.HandleMCPJSONRPC(raw)
	if !hasResp {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

func (s *apiServer) handleV1Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.mahHub.GetHealth())
}

func (s *apiServer) handleV1ListAgents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	items := s.mahHub.ListAgents(map[string]string{
		"logicalName":   q.Get("logicalName"),
		"capability":    q.Get("capability"),
		"availableOnly": q.Get("availableOnly"),
		"status":        q.Get("status"),
	})
	writeCursorPage(w, items)
}

func (s *apiServer) handleV1GetAgent(w http.ResponseWriter, r *http.Request) {
	ag, err := s.mahHub.GetAgent(r.PathValue("id"))
	if err != nil {
		writeMahError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ag)
}

func (s *apiServer) handleV1CreateSession(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if !decodeJSON(w, r, &body) {
		return
	}
	res, err := s.mahHub.CreateSession(r.PathValue("id"), body)
	if err != nil {
		writeMahError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (s *apiServer) handleV1GetInbox(w http.ResponseWriter, r *http.Request) {
	items := s.mahHub.GetInbox(r.PathValue("id"), r.URL.Query().Get("status"))
	writeCursorPage(w, items)
}

func (s *apiServer) handleV1ListMachines(w http.ResponseWriter, r *http.Request) {
	writeCursorPage(w, s.mahHub.ListMachines())
}

func (s *apiServer) handleV1RegisterMachine(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if !decodeJSON(w, r, &body) {
		return
	}
	res, err := s.mahHub.RegisterMachine(body)
	if err != nil {
		writeMahError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (s *apiServer) handleV1GetMachine(w http.ResponseWriter, r *http.Request) {
	m, err := s.mahHub.GetMachine(r.PathValue("id"))
	if err != nil {
		writeMahError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *apiServer) handleV1UnregisterSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.mahHub.UnregisterSession(id); err != nil {
		writeMahError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sessionId":      id,
		"status":         "UNREGISTERED",
		"unregisteredAt": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *apiServer) handleV1DeleteMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.mahHub.DeleteMessage(id); err != nil {
		writeMahError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"messageId": id,
		"status":    "DELETED",
		"deletedAt": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *apiServer) handleV1ListTasks(w http.ResponseWriter, r *http.Request) {
	writeCursorPage(w, s.mahHub.ListTasks())
}

func (s *apiServer) handleV1GetTask(w http.ResponseWriter, r *http.Request) {
	t, err := s.mahHub.GetTask(r.PathValue("id"))
	if err != nil {
		writeMahError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *apiServer) handleV1ListTaskEvents(w http.ResponseWriter, r *http.Request) {
	items, err := s.mahHub.ListTaskEvents(r.PathValue("id"))
	if err != nil {
		writeMahError(w, err)
		return
	}
	writeCursorPage(w, items)
}

func writeCursorPage(w http.ResponseWriter, items []map[string]any) {
	if items == nil {
		items = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":      items,
		"nextCursor": nil,
		"hasMore":    false,
	})
}

func (s *apiServer) handleMahUnregisterSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.mahHub.UnregisterSession(id); err != nil {
		writeMahError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "unregistered",
		"sessionId": id,
	})
}

func (s *apiServer) handleWebUI(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/v1/") {
		writeError(w, http.StatusNotFound, "api endpoint not found")
		return
	}
	if s.webFS == nil {
		writeError(w, http.StatusNotFound, "web UI bundle not configured")
		return
	}

	cleanPath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if cleanPath == "" || cleanPath == "." {
		cleanPath = "index.html"
	}

	data, err := fs.ReadFile(s.webFS, cleanPath)
	if err != nil {
		// Fall back to index.html for client-side SPA routes without file extensions.
		if !strings.Contains(path.Base(cleanPath), ".") {
			data, err = fs.ReadFile(s.webFS, "index.html")
			cleanPath = "index.html"
		}
		if err != nil {
			writeError(w, http.StatusNotFound, "page not found")
			return
		}
	}

	ctype := mime.TypeByExtension(path.Ext(cleanPath))
	if ctype == "" {
		ctype = "text/html; charset=utf-8"
	}
	w.Header().Set("Content-Type", ctype)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRequestBodyBytes))
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON request body: "+err.Error())
		return false
	}
	return true
}

func decodeOptionalJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Body == nil {
		return true
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRequestBodyBytes))
	if err := dec.Decode(dst); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid JSON request body: "+err.Error())
		return false
	}
	return true
}

func writeMahError(w http.ResponseWriter, err error) {
	var apiErr *mah.APIError
	if errors.As(err, &apiErr) {
		status := apiErr.StatusCode
		if status < http.StatusBadRequest || status > 599 {
			status = http.StatusBadGateway
		}
		writeError(w, status, apiErr.Error())
		return
	}
	if strings.Contains(strings.ToLower(err.Error()), "not found") {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}

func writeEngineError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if strings.Contains(strings.ToLower(err.Error()), "not found") {
		status = http.StatusNotFound
	}
	writeError(w, status, err.Error())
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func normalizeRepoSlug(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "git@github.com:")
	s = strings.TrimPrefix(s, "github.com/")
	s = strings.TrimSuffix(s, ".git")
	return strings.Trim(s, "/")
}

func repoMatches(projRepo string, candidates []string) bool {
	p := normalizeRepoSlug(projRepo)
	if p == "" {
		return false
	}
	for _, c := range candidates {
		if c != "" && c == p {
			return true
		}
	}
	return false
}
