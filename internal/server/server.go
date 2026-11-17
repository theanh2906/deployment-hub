// Package server implements the HTTP REST API, SSE streaming endpoints,
// GitHub webhook receiver, and embedded web UI handler for DeploymentHub.
package server

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	"deploymenthub/internal/detector"
	"deploymenthub/internal/docker"
	"deploymenthub/internal/vault"
)

const maxRequestBodyBytes = 2 << 20 // 2 MiB

type apiServer struct {
	engine        *docker.Engine
	vault         *vault.Vault
	webhookSecret string
	webFS         fs.FS
}

// New constructs the DeploymentHub HTTP handler wiring all REST, SSE, webhook,
// and static web UI routes against the provided Docker engine, vault, and webFS.
func New(engine *docker.Engine, v *vault.Vault, webhookSecret string, webFS fs.FS) http.Handler {
	s := &apiServer{
		engine:        engine,
		vault:         v,
		webhookSecret: webhookSecret,
		webFS:         webFS,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/overview", s.handleOverview)
	mux.HandleFunc("GET /api/v1/projects", s.handleListProjects)
	mux.HandleFunc("POST /api/v1/projects/{id}/redeploy", s.handleRedeployProject)
	mux.HandleFunc("POST /api/v1/projects/{id}/restart", s.handleRestartProject)
	mux.HandleFunc("POST /api/v1/scm/verify-pat", s.handleVerifyPAT)
	mux.HandleFunc("POST /api/v1/detect", s.handleDetect)
	mux.HandleFunc("POST /api/v1/detect/dockerfile", s.handleGenerateDockerfile)
	mux.HandleFunc("POST /api/v1/detect/diagnose", s.handleDiagnoseBuild)
	mux.HandleFunc("POST /api/v1/deployments", s.handleStartDeployment)
	mux.HandleFunc("GET /api/v1/deployments/{id}", s.handleGetDeployment)
	mux.HandleFunc("GET /api/v1/deployments/{id}/stream", s.handleStreamDeployment)
	mux.HandleFunc("POST /api/v1/containers/{id}/action", s.handleContainerAction)
	mux.HandleFunc("POST /api/v1/images/prune", s.handlePruneImages)
	mux.HandleFunc("POST /api/v1/proxy/routes/{id}/toggle-ssl", s.handleToggleProxySSL)
	mux.HandleFunc("POST /api/v1/webhooks/github", s.handleGitHubWebhook)
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
		h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Hub-Signature-256, X-GitHub-Event")

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

func (s *apiServer) handleWebUI(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
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
