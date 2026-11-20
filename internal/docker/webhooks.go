package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"deploymenthub/internal/detector"
)

// ProjectWebhookConfig represents the GitHub Webhook configuration & status for a project.
type ProjectWebhookConfig struct {
	ProjectID        string `json:"projectId"`
	ProjectName      string `json:"projectName"`
	RepoURL          string `json:"repoUrl"`
	Branch           string `json:"branch"`
	AutoWebhook      bool   `json:"autoWebhook"`
	Active           bool   `json:"active"`
	HookID           int64  `json:"hookId,omitempty"`
	HookURL          string `json:"hookUrl"`
	HasSavedPAT      bool   `json:"hasSavedPat"`
	TokenPreview     string `json:"tokenPreview,omitempty"`
	CanManageWebhook bool   `json:"canManageWebhook"`
	StatusMessage    string `json:"statusMessage"`
	UpdatedAt        string `json:"updatedAt,omitempty"`
}

// WebhookPermissionCheck captures the result of verifying a GitHub PAT's webhook permissions.
type WebhookPermissionCheck struct {
	HasToken         bool     `json:"hasToken"`
	UsedSavedPAT     bool     `json:"usedSavedPat"`
	Valid            bool     `json:"valid"`
	GitHubUser       string   `json:"githubUser,omitempty"`
	Scopes           []string `json:"scopes"`
	CanManageWebhook bool     `json:"canManageWebhook"`
	WebhookReason    string   `json:"webhookReason"`
	ExistingHookID   int64    `json:"existingHookId,omitempty"`
	ExistingHookURL  string   `json:"existingHookUrl,omitempty"`
	WebhookURL       string   `json:"webhookUrl"`
}

type storedProjectWebhook struct {
	ProjectName  string `json:"projectName"`
	RepoURL      string `json:"repoUrl"`
	Branch       string `json:"branch"`
	AutoWebhook  bool   `json:"autoWebhook"`
	Active       bool   `json:"active"`
	HookID       int64  `json:"hookId,omitempty"`
	HookURL      string `json:"hookUrl,omitempty"`
	EncryptedPAT string `json:"encryptedPat,omitempty"`
	TokenPreview string `json:"tokenPreview,omitempty"`
	StatusMsg    string `json:"statusMessage,omitempty"`
	UpdatedAt    string `json:"updatedAt,omitempty"`
}

type webhooksStoreFile struct {
	DefaultEncryptedPAT string                          `json:"defaultEncryptedPat,omitempty"`
	Projects            map[string]storedProjectWebhook `json:"projects"`
}

func resolveDataSubpath(envKey, fileOrDirName string, isDir bool) string {
	if custom := strings.TrimSpace(os.Getenv(envKey)); custom != "" {
		if isDir {
			if err := os.MkdirAll(custom, 0o750); err == nil {
				return custom
			}
		} else {
			_ = os.MkdirAll(filepath.Dir(custom), 0o750)
			return custom
		}
	}
	if info, err := os.Stat("/data"); err == nil && info.IsDir() {
		target := filepath.Join("/data", fileOrDirName)
		if isDir {
			if err := os.MkdirAll(target, 0o750); err == nil {
				return target
			}
		} else {
			return target
		}
	}
	fallback := filepath.Join(os.TempDir(), "deploymenthub-"+fileOrDirName)
	if isDir {
		_ = os.MkdirAll(fallback, 0o750)
	}
	return fallback
}

func resolveWebhooksFilePath() string {
	return resolveDataSubpath("WEBHOOKS_DATA_FILE", "webhooks.json", false)
}

func (e *Engine) loadWebhooksLocked() {
	path := resolveWebhooksFilePath()
	if e.webhooksLoaded && e.webhooksLoadedPath == path {
		return
	}
	e.webhooksLoaded = true
	e.webhooksLoadedPath = path
	e.webhooksStore = webhooksStoreFile{
		Projects: make(map[string]storedProjectWebhook),
	}

	raw, err := os.ReadFile(path)
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		return
	}
	var parsed webhooksStoreFile
	if err := json.Unmarshal(raw, &parsed); err == nil {
		if parsed.Projects == nil {
			parsed.Projects = make(map[string]storedProjectWebhook)
		}
		e.webhooksStore = parsed
	}
}

func (e *Engine) persistWebhooksLocked() error {
	path := resolveWebhooksFilePath()
	e.webhooksLoadedPath = path
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	if e.webhooksStore.Projects == nil {
		e.webhooksStore.Projects = make(map[string]storedProjectWebhook)
	}
	raw, err := json.MarshalIndent(e.webhooksStore, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, raw, 0o600)
}

// SetWebhookSecret records the GitHub webhook HMAC secret used when registering repo hooks.
func (e *Engine) SetWebhookSecret(secret string) {
	e.webhooksMu.Lock()
	e.webhookSecret = strings.TrimSpace(secret)
	e.webhooksMu.Unlock()
}

// WebhookSecret returns the configured webhook HMAC secret (falling back to env var).
func (e *Engine) WebhookSecret() string {
	e.webhooksMu.RLock()
	sec := e.webhookSecret
	e.webhooksMu.RUnlock()
	if sec != "" {
		return sec
	}
	return strings.TrimSpace(os.Getenv("GITHUB_WEBHOOK_SECRET"))
}

// PublicWebhookURL returns the external HTTPS callback URL for GitHub webhooks.
func (e *Engine) PublicWebhookURL() string {
	if e.cf != nil {
		cfg := e.cf.GetSanitizedConfig()
		if hd := strings.TrimSpace(cfg.HubDomain); hd != "" {
			return "https://" + hd + "/api/v1/webhooks/github"
		}
		if bd := strings.TrimSpace(cfg.BaseDomain); bd != "" {
			return "https://hub." + bd + "/api/v1/webhooks/github"
		}
	}
	if hd := strings.TrimSpace(os.Getenv("HUB_DOMAIN")); hd != "" && !strings.EqualFold(hd, "localhost") && !strings.HasSuffix(strings.ToLower(hd), ".localhost") && !strings.HasPrefix(hd, "127.") {
		return "https://" + hd + "/api/v1/webhooks/github"
	}
	return e.webhookURL
}

func parseGitHubOwnerRepo(raw string) (owner, repo string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", false
	}
	s = strings.TrimPrefix(s, "https://github.com/")
	s = strings.TrimPrefix(s, "http://github.com/")
	s = strings.TrimPrefix(s, "git@github.com:")
	s = strings.TrimPrefix(s, "github.com/")
	s = strings.TrimSuffix(s, ".git")
	s = strings.Trim(s, "/")
	parts := strings.Split(s, "/")
	if len(parts) < 2 {
		return "", "", false
	}
	owner = strings.TrimSpace(parts[0])
	repo = strings.TrimSpace(parts[1])
	if owner == "" || repo == "" {
		return "", "", false
	}
	return owner, repo, true
}

func normalizeRepoKey(raw string) string {
	if owner, repo, ok := parseGitHubOwnerRepo(raw); ok {
		return strings.ToLower(owner + "/" + repo)
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func (e *Engine) githubBaseURL() string {
	if base := strings.TrimRight(strings.TrimSpace(e.githubAPIBase), "/"); base != "" {
		return base
	}
	return "https://api.github.com"
}

func (e *Engine) saveDefaultPAT(rawPAT string) {
	trimmed := strings.TrimSpace(rawPAT)
	if trimmed == "" || e.vault == nil {
		return
	}
	enc, err := e.vault.Encrypt(trimmed)
	if err != nil {
		return
	}
	e.webhooksMu.Lock()
	e.loadWebhooksLocked()
	e.webhooksStore.DefaultEncryptedPAT = enc
	_ = e.persistWebhooksLocked()
	e.webhooksMu.Unlock()
}

// ResolveSavedPAT decrypts any stored PAT matching the project, repo, or default token in Vault.
func (e *Engine) ResolveSavedPAT(projectOrRepo string) string {
	key := normalizeRepoKey(projectOrRepo)
	rawName := strings.ToLower(strings.TrimSpace(projectOrRepo))

	e.webhooksMu.RLock()
	e.loadWebhooksLocked()
	var encCandidate string
	if entry, ok := e.webhooksStore.Projects[rawName]; ok && entry.EncryptedPAT != "" {
		encCandidate = entry.EncryptedPAT
	} else {
		for _, entry := range e.webhooksStore.Projects {
			if key != "" && normalizeRepoKey(entry.RepoURL) == key && entry.EncryptedPAT != "" {
				encCandidate = entry.EncryptedPAT
				break
			}
		}
	}
	if encCandidate == "" {
		encCandidate = e.webhooksStore.DefaultEncryptedPAT
	}
	e.webhooksMu.RUnlock()

	if encCandidate != "" {
		if dec, err := e.vault.Decrypt(encCandidate); err == nil && strings.TrimSpace(dec) != "" {
			return strings.TrimSpace(dec)
		}
	}

	e.mu.RLock()
	for k, enc := range e.encryptedSecrets {
		if strings.HasPrefix(k, "pat:") && strings.EqualFold(normalizeRepoKey(strings.TrimPrefix(k, "pat:")), key) {
			if dec, err := e.vault.Decrypt(enc); err == nil && strings.TrimSpace(dec) != "" {
				e.mu.RUnlock()
				return strings.TrimSpace(dec)
			}
		}
	}
	e.mu.RUnlock()
	return ""
}

func (e *Engine) enrichProjectWebhookLocked(p *Project) {
	if p == nil {
		return
	}
	e.webhooksMu.RLock()
	e.loadWebhooksLocked()
	if entry, ok := e.webhooksStore.Projects[strings.ToLower(p.Name)]; ok {
		p.WebhookActive = entry.Active
		p.WebhookID = entry.HookID
		p.WebhookStatus = entry.StatusMsg
	} else {
		repoKey := normalizeRepoKey(p.Repo)
		for _, item := range e.webhooksStore.Projects {
			if repoKey != "" && normalizeRepoKey(item.RepoURL) == repoKey {
				p.WebhookActive = item.Active
				p.WebhookID = item.HookID
				p.WebhookStatus = item.StatusMsg
				break
			}
		}
	}
	e.webhooksMu.RUnlock()
}

func filterOutHookScopes(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		low := strings.ToLower(strings.TrimSpace(s))
		if low == "admin:repo_hook" || low == "write:repo_hook" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func hasScopeNamed(scopes []string, want ...string) bool {
	for _, s := range scopes {
		low := strings.ToLower(strings.TrimSpace(s))
		for _, w := range want {
			if low == strings.ToLower(w) {
				return true
			}
		}
	}
	return false
}

// CheckGitHubWebhookPermission probes GitHub API to verify whether the supplied (or Vault-saved)
// PAT can read & create webhooks on the target repository.
func (e *Engine) CheckGitHubWebhookPermission(token, repoURL string) WebhookPermissionCheck {
	hookTargetURL := e.PublicWebhookURL()
	trimmed := strings.TrimSpace(token)
	usedSaved := false
	if trimmed == "" {
		if saved := e.ResolveSavedPAT(repoURL); saved != "" {
			trimmed = saved
			usedSaved = true
		}
	}

	if trimmed == "" {
		return WebhookPermissionCheck{
			HasToken:         false,
			Valid:            false,
			Scopes:           []string{},
			CanManageWebhook: false,
			WebhookReason:    "Chưa có GitHub PAT. Nhập PAT có quyền admin:repo_hook (Classic) hoặc Webhooks: Read and write (Fine-grained) để bật tự động gắn Webhook.",
			WebhookURL:       hookTargetURL,
		}
	}

	if isSyntheticTestRepo(repoURL) && strings.TrimSpace(e.githubAPIBase) == "" {
		lowTok := strings.ToLower(trimmed)
		if strings.Contains(lowTok, "nohook") || strings.Contains(lowTok, "readonly") {
			return WebhookPermissionCheck{
				HasToken:         true,
				UsedSavedPAT:     usedSaved,
				Valid:            true,
				Scopes:           []string{"repo"},
				CanManageWebhook: false,
				WebhookReason:    "PAT chỉ có quyền đọc code (repo), thiếu quyền admin:repo_hook hoặc Webhooks: Read and write.",
				WebhookURL:       hookTargetURL,
			}
		}
		return WebhookPermissionCheck{
			HasToken:         true,
			UsedSavedPAT:     usedSaved,
			Valid:            true,
			Scopes:           []string{"repo", "admin:repo_hook"},
			CanManageWebhook: true,
			WebhookReason:    "PAT hợp lệ và có đủ quyền quản trị GitHub Webhook (admin:repo_hook).",
			WebhookURL:       hookTargetURL,
		}
	}

	client := &http.Client{Timeout: 6 * time.Second}
	apiBase := e.githubBaseURL()

	userReq, err := http.NewRequest(http.MethodGet, apiBase+"/user", nil)
	if err != nil {
		return WebhookPermissionCheck{
			HasToken:      true,
			UsedSavedPAT:  usedSaved,
			WebhookReason: err.Error(),
			WebhookURL:    hookTargetURL,
		}
	}
	userReq.Header.Set("Accept", "application/vnd.github+json")
	userReq.Header.Set("User-Agent", "DeploymentHub-Go-ControlPlane/2.0")
	userReq.Header.Set("Authorization", "Bearer "+trimmed)

	userResp, err := client.Do(userReq)
	if err != nil {
		return WebhookPermissionCheck{
			HasToken:      true,
			UsedSavedPAT:  usedSaved,
			Scopes:        []string{},
			WebhookReason: fmt.Sprintf("Không kết nối được GitHub API: %v", err),
			WebhookURL:    hookTargetURL,
		}
	}
	userBody, _ := io.ReadAll(io.LimitReader(userResp.Body, 64<<10))
	_ = userResp.Body.Close()

	if userResp.StatusCode != http.StatusOK {
		return WebhookPermissionCheck{
			HasToken:         true,
			UsedSavedPAT:     usedSaved,
			Valid:            false,
			Scopes:           []string{},
			CanManageWebhook: false,
			WebhookReason:    fmt.Sprintf("GitHub PAT không hợp lệ hoặc đã hết hạn (HTTP %d).", userResp.StatusCode),
			WebhookURL:       hookTargetURL,
		}
	}

	var userPayload struct {
		Login string `json:"login"`
	}
	_ = json.Unmarshal(userBody, &userPayload)

	var scopes []string
	rawScopes := strings.TrimSpace(userResp.Header.Get("X-OAuth-Scopes"))
	for _, sc := range strings.Split(rawScopes, ",") {
		if s := strings.TrimSpace(sc); s != "" {
			scopes = append(scopes, s)
		}
	}
	if scopes == nil {
		scopes = []string{}
	}

	// Fine-grained tokens omit X-OAuth-Scopes, or classic PATs expose it.
	// Always probe the exact target repo's /hooks endpoint when owner/repo is known.
	owner, repo, hasRepo := parseGitHubOwnerRepo(repoURL)
	if !hasRepo {
		canByScope := hasScopeNamed(scopes, "admin:repo_hook", "write:repo_hook")
		reason := "Vui lòng chọn Repository hợp lệ để kiểm tra quyền gắn Webhook."
		if canByScope {
			reason = "PAT có scope quản trị Webhook (" + strings.Join(scopes, ", ") + ")."
		} else if rawScopes != "" {
			reason = "PAT thiếu scope admin:repo_hook / write:repo_hook."
		}
		return WebhookPermissionCheck{
			HasToken:         true,
			UsedSavedPAT:     usedSaved,
			Valid:            true,
			GitHubUser:       strings.TrimSpace(userPayload.Login),
			Scopes:           scopes,
			CanManageWebhook: canByScope,
			WebhookReason:    reason,
			WebhookURL:       hookTargetURL,
		}
	}

	// Check classic OAuth token read-only hook scope explicitly before calling /hooks.
	if hasScopeNamed(scopes, "read:repo_hook") && !hasScopeNamed(scopes, "admin:repo_hook", "write:repo_hook") {
		return WebhookPermissionCheck{
			HasToken:         true,
			UsedSavedPAT:     usedSaved,
			Valid:            true,
			GitHubUser:       strings.TrimSpace(userPayload.Login),
			Scopes:           filterOutHookScopes(scopes),
			CanManageWebhook: false,
			WebhookReason:    "PAT chỉ có quyền đọc Webhook (read:repo_hook), thiếu quyền admin:repo_hook hoặc write:repo_hook để tạo Webhook.",
			WebhookURL:       hookTargetURL,
		}
	}

	hooksEndpoint := fmt.Sprintf("%s/repos/%s/%s/hooks?per_page=50", apiBase, url.PathEscape(owner), url.PathEscape(repo))
	hooksReq, err := http.NewRequest(http.MethodGet, hooksEndpoint, nil)
	if err != nil {
		return WebhookPermissionCheck{
			HasToken:      true,
			UsedSavedPAT:  usedSaved,
			Valid:         true,
			GitHubUser:    strings.TrimSpace(userPayload.Login),
			Scopes:        scopes,
			WebhookReason: err.Error(),
			WebhookURL:    hookTargetURL,
		}
	}
	hooksReq.Header.Set("Accept", "application/vnd.github+json")
	hooksReq.Header.Set("User-Agent", "DeploymentHub-Go-ControlPlane/2.0")
	hooksReq.Header.Set("Authorization", "Bearer "+trimmed)

	hooksResp, err := client.Do(hooksReq)
	if err != nil {
		return WebhookPermissionCheck{
			HasToken:      true,
			UsedSavedPAT:  usedSaved,
			Valid:         true,
			GitHubUser:    strings.TrimSpace(userPayload.Login),
			Scopes:        scopes,
			WebhookReason: fmt.Sprintf("Không kiểm tra được quyền Webhook trên %s/%s: %v", owner, repo, err),
			WebhookURL:    hookTargetURL,
		}
	}
	hooksBody, _ := io.ReadAll(io.LimitReader(hooksResp.Body, 512<<10))
	_ = hooksResp.Body.Close()

	if hooksResp.StatusCode == http.StatusOK {
		if rawScopes == "" && !hasScopeNamed(scopes, "Webhooks: Read & Write", "admin:repo_hook") {
			scopes = append(scopes, "Webhooks: Read & Write")
		}
		var hookList []struct {
			ID     int64 `json:"id"`
			Active bool  `json:"active"`
			Config struct {
				URL string `json:"url"`
			} `json:"config"`
		}
		var existingID int64
		var existingURL string
		if json.Unmarshal(hooksBody, &hookList) == nil {
			for _, h := range hookList {
				cfgURL := strings.TrimRight(strings.TrimSpace(h.Config.URL), "/")
				if cfgURL == strings.TrimRight(hookTargetURL, "/") || strings.HasSuffix(cfgURL, "/api/v1/webhooks/github") {
					existingID = h.ID
					existingURL = cfgURL
					break
				}
			}
		}
		return WebhookPermissionCheck{
			HasToken:         true,
			UsedSavedPAT:     usedSaved,
			Valid:            true,
			GitHubUser:       strings.TrimSpace(userPayload.Login),
			Scopes:           scopes,
			CanManageWebhook: true,
			ExistingHookID:   existingID,
			ExistingHookURL:  existingURL,
			WebhookReason:    fmt.Sprintf("PAT đủ quyền tạo & cập nhật GitHub Webhook trên %s/%s.", owner, repo),
			WebhookURL:       hookTargetURL,
		}
	}

	// Missing permission (typically HTTP 403 or HTTP 404 when PAT lacks Webhooks scope).
	cleanScopes := filterOutHookScopes(scopes)
	if rawScopes == "" && !hasScopeNamed(cleanScopes, "Contents: Read") {
		cleanScopes = append(cleanScopes, "Contents: Read (Missing Webhooks Write)")
	}
	return WebhookPermissionCheck{
		HasToken:         true,
		UsedSavedPAT:     usedSaved,
		Valid:            true,
		GitHubUser:       strings.TrimSpace(userPayload.Login),
		Scopes:           cleanScopes,
		CanManageWebhook: false,
		WebhookReason:    fmt.Sprintf("GitHub trả về HTTP %d khi kiểm tra %s/%s/hooks: PAT thiếu quyền admin:repo_hook (Classic) hoặc Webhooks: Read and write (Fine-grained), hoặc tài khoản không có quyền Admin repo.", hooksResp.StatusCode, owner, repo),
		WebhookURL:       hookTargetURL,
	}
}

// EnsureGitHubRepoWebhook creates or updates a GitHub repository webhook pointing to PublicWebhookURL().
func (e *Engine) EnsureGitHubRepoWebhook(ctx context.Context, token, repoURL, branch string) (hookID int64, hookURL, action string, err error) {
	check := e.CheckGitHubWebhookPermission(token, repoURL)
	if !check.HasToken || !check.Valid || !check.CanManageWebhook {
		msg := strings.TrimSpace(check.WebhookReason)
		if msg == "" {
			msg = "PAT không đủ quyền gắn GitHub Webhook"
		}
		return 0, "", "", errors.New(msg)
	}

	resolvedToken := strings.TrimSpace(token)
	if resolvedToken == "" {
		resolvedToken = e.ResolveSavedPAT(repoURL)
	}
	hookTargetURL := e.PublicWebhookURL()

	if isSyntheticTestRepo(repoURL) && strings.TrimSpace(e.githubAPIBase) == "" {
		return 1001, hookTargetURL, "created", nil
	}

	owner, repo, ok := parseGitHubOwnerRepo(repoURL)
	if !ok {
		return 0, "", "", fmt.Errorf("không phân tích được GitHub owner/repo từ %q", repoURL)
	}

	cfgPayload := map[string]any{
		"url":          hookTargetURL,
		"content_type": "json",
		"insecure_ssl": "0",
	}
	if sec := e.WebhookSecret(); sec != "" {
		cfgPayload["secret"] = sec
	}

	bodyMap := map[string]any{
		"active": true,
		"events": []string{"push"},
		"config": cfgPayload,
	}

	method := http.MethodPost
	endpoint := fmt.Sprintf("%s/repos/%s/%s/hooks", e.githubBaseURL(), url.PathEscape(owner), url.PathEscape(repo))
	action = "created"
	if check.ExistingHookID > 0 {
		method = http.MethodPatch
		endpoint = fmt.Sprintf("%s/repos/%s/%s/hooks/%d", e.githubBaseURL(), url.PathEscape(owner), url.PathEscape(repo), check.ExistingHookID)
		action = "updated"
	} else {
		bodyMap["name"] = "web"
	}

	rawBody, _ := json.Marshal(bodyMap)
	if ctx == nil {
		ctx = context.Background()
	}
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, method, endpoint, bytes.NewReader(rawBody))
	if err != nil {
		return 0, "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "DeploymentHub-Go-ControlPlane/2.0")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+resolvedToken)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return 0, "", "", fmt.Errorf("gọi GitHub API tạo webhook thất bại: %w", err)
	}
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 128<<10))
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var ghErr struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(respBytes, &ghErr)
		msg := strings.TrimSpace(ghErr.Message)
		if msg == "" {
			msg = strings.TrimSpace(string(respBytes))
		}
		return 0, "", "", fmt.Errorf("GitHub API từ chối gắn webhook (HTTP %d): %s", resp.StatusCode, msg)
	}

	var hookRes struct {
		ID     int64 `json:"id"`
		Config struct {
			URL string `json:"url"`
		} `json:"config"`
	}
	_ = json.Unmarshal(respBytes, &hookRes)
	if hookRes.ID == 0 {
		hookRes.ID = check.ExistingHookID
	}
	outURL := hookRes.Config.URL
	if strings.TrimSpace(outURL) == "" {
		outURL = hookTargetURL
	}
	return hookRes.ID, outURL, action, nil
}

// GetProjectWebhookConfig returns saved & live webhook metadata for a deployed project.
func (e *Engine) GetProjectWebhookConfig(projectID string) (ProjectWebhookConfig, error) {
	e.mu.RLock()
	pIdx := e.findProjectIndexLocked(projectID)
	if pIdx < 0 {
		e.mu.RUnlock()
		return ProjectWebhookConfig{}, fmt.Errorf("project %q not found", projectID)
	}
	proj := cloneProject(e.projects[pIdx])
	e.mu.RUnlock()

	key := strings.ToLower(proj.Name)
	e.webhooksMu.RLock()
	e.loadWebhooksLocked()
	stored, hasStored := e.webhooksStore.Projects[key]
	hasDefaultPAT := strings.TrimSpace(e.webhooksStore.DefaultEncryptedPAT) != ""
	e.webhooksMu.RUnlock()

	hasSavedPAT := hasDefaultPAT || (hasStored && strings.TrimSpace(stored.EncryptedPAT) != "") || e.ResolveSavedPAT(proj.Repo) != ""
	hookURL := e.PublicWebhookURL()
	if hasStored && strings.TrimSpace(stored.HookURL) != "" {
		hookURL = stored.HookURL
	}
	branch := strings.TrimSpace(proj.Branch)
	if hasStored && strings.TrimSpace(stored.Branch) != "" {
		branch = stored.Branch
	}
	if branch == "" || branch == "live" {
		branch = "main"
	}
	repoURL := strings.TrimSpace(proj.Repo)
	if hasStored && strings.TrimSpace(stored.RepoURL) != "" {
		repoURL = stored.RepoURL
	}
	autoWebhook := true
	if hasStored {
		autoWebhook = stored.AutoWebhook
	}

	return ProjectWebhookConfig{
		ProjectID:        proj.ID,
		ProjectName:      proj.Name,
		RepoURL:          repoURL,
		Branch:           branch,
		AutoWebhook:      autoWebhook,
		Active:           hasStored && stored.Active,
		HookID:           stored.HookID,
		HookURL:          hookURL,
		HasSavedPAT:      hasSavedPAT,
		TokenPreview:     stored.TokenPreview,
		CanManageWebhook: false,
		StatusMessage:    stored.StatusMsg,
		UpdatedAt:        stored.UpdatedAt,
	}, nil
}

// CheckProjectWebhookPermission checks PAT permissions against the project's GitHub repository.
func (e *Engine) CheckProjectWebhookPermission(projectID, repoURL, branch, pat string) (WebhookPermissionCheck, error) {
	e.mu.RLock()
	pIdx := e.findProjectIndexLocked(projectID)
	if pIdx < 0 {
		e.mu.RUnlock()
		return WebhookPermissionCheck{}, fmt.Errorf("project %q not found", projectID)
	}
	proj := cloneProject(e.projects[pIdx])
	e.mu.RUnlock()

	targetRepo := strings.TrimSpace(repoURL)
	if targetRepo == "" {
		targetRepo = proj.Repo
	}
	token := strings.TrimSpace(pat)
	if token == "" {
		token = e.ResolveSavedPAT(proj.Name)
		if token == "" {
			token = e.ResolveSavedPAT(targetRepo)
		}
	}

	check := e.CheckGitHubWebhookPermission(token, targetRepo)
	if check.CanManageWebhook && strings.TrimSpace(pat) != "" {
		e.saveDefaultPAT(pat)
	}
	return check, nil
}

// ConfigureProjectWebhook persists repo/branch/PAT settings and registers the GitHub Webhook when autoWebhook is true.
func (e *Engine) ConfigureProjectWebhook(projectID, repoURL, branch, pat string, autoWebhook bool) (ProjectWebhookConfig, error) {
	e.mu.RLock()
	pIdx := e.findProjectIndexLocked(projectID)
	var proj Project
	if pIdx >= 0 {
		proj = cloneProject(e.projects[pIdx])
	}
	e.mu.RUnlock()

	if pIdx < 0 {
		return ProjectWebhookConfig{}, fmt.Errorf("project %q not found", projectID)
	}

	cleanRepo := strings.TrimSpace(repoURL)
	if cleanRepo == "" {
		cleanRepo = proj.Repo
	}
	cleanBranch := strings.TrimSpace(branch)
	if cleanBranch == "" {
		cleanBranch = proj.Branch
	}
	if cleanBranch == "" || cleanBranch == "live" {
		cleanBranch = "main"
	}

	rawPAT := strings.TrimSpace(pat)
	key := strings.ToLower(proj.Name)

	e.webhooksMu.RLock()
	e.loadWebhooksLocked()
	prev := e.webhooksStore.Projects[key]
	e.webhooksMu.RUnlock()

	encPAT := prev.EncryptedPAT
	preview := prev.TokenPreview
	if rawPAT != "" {
		enc, err := e.vault.Encrypt(rawPAT)
		if err != nil {
			return ProjectWebhookConfig{}, fmt.Errorf("encrypt webhook PAT: %w", err)
		}
		encPAT = enc
		preview = enc[:min(24, len(enc))] + "..."
		e.saveDefaultPAT(rawPAT)
	} else {
		rawPAT = e.ResolveSavedPAT(proj.Name)
		if rawPAT == "" {
			rawPAT = e.ResolveSavedPAT(cleanRepo)
		}
	}

	entry := storedProjectWebhook{
		ProjectName:  proj.Name,
		RepoURL:      cleanRepo,
		Branch:       cleanBranch,
		AutoWebhook:  autoWebhook,
		Active:       prev.Active,
		HookID:       prev.HookID,
		HookURL:      e.PublicWebhookURL(),
		EncryptedPAT: encPAT,
		TokenPreview: preview,
		StatusMsg:    prev.StatusMsg,
		UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
	}

	var canManage bool
	if autoWebhook {
		hookID, hookURL, action, err := e.EnsureGitHubRepoWebhook(context.Background(), rawPAT, cleanRepo, cleanBranch)
		if err != nil {
			return ProjectWebhookConfig{}, err
		}
		entry.Active = true
		entry.HookID = hookID
		entry.HookURL = hookURL
		entry.StatusMsg = fmt.Sprintf("GitHub Webhook #%d (%s) đang hoạt động trên nhánh %s", hookID, action, cleanBranch)
		canManage = true
	} else {
		entry.StatusMsg = "Cấu hình thủ công (Auto-Webhook tắt)"
	}

	e.webhooksMu.Lock()
	e.loadWebhooksLocked()
	e.webhooksStore.Projects[key] = entry
	if err := e.persistWebhooksLocked(); err != nil {
		e.webhooksMu.Unlock()
		return ProjectWebhookConfig{}, err
	}
	e.webhooksMu.Unlock()

	// Update in-memory project metadata immediately.
	e.mu.Lock()
	if idx := e.findProjectIndexLocked(proj.Name); idx >= 0 {
		e.projects[idx].Repo = cleanRepo
		e.projects[idx].Branch = cleanBranch
		e.projects[idx].WebhookActive = entry.Active
		e.projects[idx].WebhookID = entry.HookID
		e.projects[idx].WebhookStatus = entry.StatusMsg
	}
	e.mu.Unlock()

	return ProjectWebhookConfig{
		ProjectID:        proj.ID,
		ProjectName:      proj.Name,
		RepoURL:          entry.RepoURL,
		Branch:           entry.Branch,
		AutoWebhook:      entry.AutoWebhook,
		Active:           entry.Active,
		HookID:           entry.HookID,
		HookURL:          entry.HookURL,
		HasSavedPAT:      entry.EncryptedPAT != "" || rawPAT != "",
		TokenPreview:     entry.TokenPreview,
		CanManageWebhook: canManage,
		StatusMessage:    entry.StatusMsg,
		UpdatedAt:        entry.UpdatedAt,
	}, nil
}

// DeleteProjectWebhook unregisters the GitHub repository webhook (if accessible) and clears active status.
func (e *Engine) DeleteProjectWebhook(ctx context.Context, projectID, pat string) (ProjectWebhookConfig, error) {
	e.mu.RLock()
	pIdx := e.findProjectIndexLocked(projectID)
	if pIdx < 0 {
		e.mu.RUnlock()
		return ProjectWebhookConfig{}, fmt.Errorf("project %q not found", projectID)
	}
	proj := cloneProject(e.projects[pIdx])
	e.mu.RUnlock()

	key := strings.ToLower(proj.Name)
	e.webhooksMu.RLock()
	e.loadWebhooksLocked()
	stored := e.webhooksStore.Projects[key]
	e.webhooksMu.RUnlock()

	token := strings.TrimSpace(pat)
	if token == "" {
		token = e.ResolveSavedPAT(proj.Name)
		if token == "" {
			token = e.ResolveSavedPAT(proj.Repo)
		}
	}

	if stored.HookID > 0 && token != "" && !(isSyntheticTestRepo(proj.Repo) && strings.TrimSpace(e.githubAPIBase) == "") {
		if owner, repo, ok := parseGitHubOwnerRepo(stored.RepoURL); ok {
			delURL := fmt.Sprintf("%s/repos/%s/%s/hooks/%d", e.githubBaseURL(), url.PathEscape(owner), url.PathEscape(repo), stored.HookID)
			reqCtx, cancel := context.WithTimeout(ctxOrBg(ctx), 8*time.Second)
			req, err := http.NewRequestWithContext(reqCtx, http.MethodDelete, delURL, nil)
			if err == nil {
				req.Header.Set("Accept", "application/vnd.github+json")
				req.Header.Set("User-Agent", "DeploymentHub-Go-ControlPlane/2.0")
				req.Header.Set("Authorization", "Bearer "+token)
				if resp, doErr := (&http.Client{Timeout: 8 * time.Second}).Do(req); doErr == nil {
					_ = resp.Body.Close()
				}
			}
			cancel()
		}
	}

	e.webhooksMu.Lock()
	e.loadWebhooksLocked()
	if cur, ok := e.webhooksStore.Projects[key]; ok {
		cur.Active = false
		cur.HookID = 0
		cur.AutoWebhook = false
		cur.StatusMsg = "Đã gỡ GitHub Webhook"
		cur.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		e.webhooksStore.Projects[key] = cur
		_ = e.persistWebhooksLocked()
	}
	e.webhooksMu.Unlock()

	e.mu.Lock()
	if idx := e.findProjectIndexLocked(proj.Name); idx >= 0 {
		e.projects[idx].WebhookActive = false
		e.projects[idx].WebhookID = 0
		e.projects[idx].WebhookStatus = "Đã gỡ GitHub Webhook"
	}
	e.mu.Unlock()

	return e.GetProjectWebhookConfig(proj.ID)
}

func ctxOrBg(ctx context.Context) context.Context {
	if ctx != nil {
		return ctx
	}
	return context.Background()
}

func extractContainerPortFromSummary(portSummary string) string {
	tr := strings.TrimSpace(portSummary)
	if idx := strings.Index(tr, "->"); idx >= 0 {
		return extractPrimaryPort(tr[idx+2:])
	}
	return extractPrimaryPort(tr)
}

func fetchContainerEnvVarsForRedeploy(endpoint, containerName string) []detector.EnvVar {
	client, baseURL, ok := newDockerHTTPClient(endpoint, 3*time.Second)
	if !ok {
		return nil
	}
	inspectData, ok := fetchDockerJSON[dockerContainerInspect](client, baseURL+"/containers/"+url.PathEscape(containerName)+"/json")
	if !ok {
		return nil
	}
	skip := map[string]bool{
		"PATH":         true,
		"PORT":         true,
		"NODE_ENV":     true,
		"HOSTNAME":     true,
		"NODE_VERSION": true,
		"YARN_VERSION": true,
	}
	out := make([]detector.EnvVar, 0, len(inspectData.Config.Env))
	seen := make(map[string]bool)
	for _, raw := range inspectData.Config.Env {
		k, v, hasEq := strings.Cut(raw, "=")
		if !hasEq || skip[k] || seen[k] {
			continue
		}
		seen[k] = true
		low := strings.ToLower(k)
		isSecret := strings.Contains(low, "secret") || strings.Contains(low, "key") || strings.Contains(low, "token") || strings.Contains(low, "pass")
		out = append(out, detector.EnvVar{
			Key:    k,
			Value:  v,
			Secret: isSecret,
		})
	}
	return out
}
