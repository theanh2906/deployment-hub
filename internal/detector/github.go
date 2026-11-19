package detector

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// GitHubRepo represents a real GitHub repository fetched from the GitHub REST API.
type GitHubRepo struct {
	FullName      string `json:"repo"`
	Name          string `json:"name"`
	Owner         string `json:"owner"`
	Description   string `json:"desc"`
	Language      string `json:"language"`
	DefaultBranch string `json:"defaultBranch"`
	Private       bool   `json:"private"`
	HTMLURL       string `json:"htmlUrl"`
	UpdatedAt     string `json:"updatedAt"`
	Preset        string `json:"preset"`
}

type cachedReposEntry struct {
	repos     []GitHubRepo
	expiresAt time.Time
}

type cachedTreeEntry struct {
	files          []string
	pkgJSON        string
	envExample     string
	extraManifests string
	defaultBranch  string
	expiresAt      time.Time
}

var (
	ghCacheMu    sync.RWMutex
	ghReposCache = make(map[string]cachedReposEntry)
	ghTreeCache  = make(map[string]cachedTreeEntry)
	ghBranches   = make(map[string]struct {
		branches  []string
		expiresAt time.Time
	})
)

// FetchGitHubRepos queries the live GitHub REST API for a user/org's repositories
// (or the authenticated user's repositories when token is provided and user is empty).
func FetchGitHubRepos(userOrOrg, token string) ([]GitHubRepo, error) {
	user := strings.TrimSpace(userOrOrg)
	tok := strings.TrimSpace(token)
	if user == "" && tok == "" {
		user = strings.TrimSpace(os.Getenv("GITHUB_USER"))
		if user == "" {
			user = "theanh2906"
		}
	}

	cacheKey := strings.ToLower(user) + "|" + shortTokenHash(tok)
	ghCacheMu.RLock()
	if cached, ok := ghReposCache[cacheKey]; ok && time.Now().Before(cached.expiresAt) {
		out := slices.Clone(cached.repos)
		ghCacheMu.RUnlock()
		return out, nil
	}
	ghCacheMu.RUnlock()

	var endpoint string
	if tok != "" && user == "" {
		endpoint = "https://api.github.com/user/repos?sort=updated&per_page=50&affiliation=owner,collaborator,organization_member"
	} else {
		endpoint = fmt.Sprintf("https://api.github.com/users/%s/repos?sort=updated&per_page=50", url.PathEscape(user))
	}

	raw, status, err := doGitHubGet(endpoint, tok, 5*time.Second)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("GitHub API status %d for %s", status, user)
	}

	var items []struct {
		Name          string  `json:"name"`
		FullName      string  `json:"full_name"`
		Description   *string `json:"description"`
		Language      *string `json:"language"`
		DefaultBranch string  `json:"default_branch"`
		Private       bool    `json:"private"`
		HTMLURL       string  `json:"html_url"`
		UpdatedAt     string  `json:"updated_at"`
		Owner         struct {
			Login string `json:"login"`
		} `json:"owner"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("decode GitHub repos: %w", err)
	}

	repos := make([]GitHubRepo, 0, len(items))
	for _, item := range items {
		lang := ""
		if item.Language != nil {
			lang = strings.TrimSpace(*item.Language)
		}
		desc := ""
		if item.Description != nil {
			desc = strings.TrimSpace(*item.Description)
		}
		branch := strings.TrimSpace(item.DefaultBranch)
		if branch == "" {
			branch = "main"
		}
		preset := inferPresetFromGitHubMeta(item.FullName, lang, desc)
		if desc == "" {
			if lang != "" {
				desc = fmt.Sprintf("%s repository • default branch %s", lang, branch)
			} else {
				desc = fmt.Sprintf("GitHub repository • default branch %s", branch)
			}
		}

		repos = append(repos, GitHubRepo{
			FullName:      item.FullName,
			Name:          item.Name,
			Owner:         item.Owner.Login,
			Description:   desc,
			Language:      lang,
			DefaultBranch: branch,
			Private:       item.Private,
			HTMLURL:       item.HTMLURL,
			UpdatedAt:     item.UpdatedAt,
			Preset:        preset,
		})
	}

	ghCacheMu.Lock()
	ghReposCache[cacheKey] = cachedReposEntry{
		repos:     slices.Clone(repos),
		expiresAt: time.Now().Add(2 * time.Minute),
	}
	ghCacheMu.Unlock()

	return repos, nil
}

// FetchGitHubBranches queries the live GitHub REST API for the branches of owner/repo.
func FetchGitHubBranches(repoSlug, token string) ([]string, error) {
	owner, repo, ok := parseGitHubOwnerRepo(repoSlug)
	if !ok {
		return []string{"main"}, fmt.Errorf("invalid GitHub repository slug %q", repoSlug)
	}
	tok := strings.TrimSpace(token)
	cacheKey := strings.ToLower(owner+"/"+repo) + "|" + shortTokenHash(tok)

	ghCacheMu.RLock()
	if cached, exists := ghBranches[cacheKey]; exists && time.Now().Before(cached.expiresAt) {
		out := slices.Clone(cached.branches)
		ghCacheMu.RUnlock()
		return out, nil
	}
	ghCacheMu.RUnlock()

	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/%s/branches?per_page=30", url.PathEscape(owner), url.PathEscape(repo))
	raw, status, err := doGitHubGet(endpoint, tok, 4*time.Second)
	if err != nil || status != http.StatusOK {
		return []string{"main"}, fmt.Errorf("fetch branches for %s/%s failed (status %d)", owner, repo, status)
	}

	var items []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		return []string{"main"}, err
	}

	branches := make([]string, 0, len(items))
	for _, b := range items {
		if name := strings.TrimSpace(b.Name); name != "" {
			branches = append(branches, name)
		}
	}
	if len(branches) == 0 {
		branches = []string{"main"}
	}

	ghCacheMu.Lock()
	ghBranches[cacheKey] = struct {
		branches  []string
		expiresAt time.Time
	}{
		branches:  slices.Clone(branches),
		expiresAt: time.Now().Add(2 * time.Minute),
	}
	ghCacheMu.Unlock()

	return branches, nil
}

func scanRemoteGitHubRepo(repoURL, branch, token string) (files []string, pkgJSON, envExample, extraManifests string, ok bool) {
	if os.Getenv("DETECTOR_OFFLINE") == "1" {
		return nil, "", "", "", false
	}
	owner, repo, valid := parseGitHubOwnerRepo(repoURL)
	if !valid || isSyntheticTestOwner(owner) {
		return nil, "", "", "", false
	}

	ref := strings.TrimSpace(branch)
	if ref == "" {
		ref = "HEAD"
	}
	tok := strings.TrimSpace(token)
	cacheKey := strings.ToLower(owner+"/"+repo+"@"+ref) + "|" + shortTokenHash(tok)

	ghCacheMu.RLock()
	if cached, exists := ghTreeCache[cacheKey]; exists && time.Now().Before(cached.expiresAt) {
		fCopy := slices.Clone(cached.files)
		ghCacheMu.RUnlock()
		return fCopy, cached.pkgJSON, cached.envExample, cached.extraManifests, true
	}
	ghCacheMu.RUnlock()

	treeEndpoint := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/trees/%s?recursive=1",
		url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(ref))
	raw, status, err := doGitHubGet(treeEndpoint, tok, 3500*time.Millisecond)
	if (err != nil || status != http.StatusOK) && ref != "HEAD" {
		ref = "HEAD"
		treeEndpoint = fmt.Sprintf("https://api.github.com/repos/%s/%s/git/trees/HEAD?recursive=1",
			url.PathEscape(owner), url.PathEscape(repo))
		raw, status, err = doGitHubGet(treeEndpoint, tok, 3500*time.Millisecond)
	}
	if err != nil || status != http.StatusOK {
		return nil, "", "", "", false
	}

	var treeResp struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
			Size int    `json:"size"`
		} `json:"tree"`
	}
	if err := json.Unmarshal(raw, &treeResp); err != nil || len(treeResp.Tree) == 0 {
		return nil, "", "", "", false
	}

	skipDirs := map[string]bool{
		".git":         true,
		"node_modules": true,
		"target":       true,
		".next":        true,
		"dist":         true,
		"vendor":       true,
		".turbo":       true,
	}

	var manifestPaths []string
	var pkgPath, envPath string

	for _, entry := range treeResp.Tree {
		if entry.Type != "blob" {
			continue
		}
		norm := filepath.ToSlash(strings.TrimSpace(entry.Path))
		if norm == "" {
			continue
		}
		parts := strings.Split(norm, "/")
		if len(parts) > 3 {
			continue
		}
		skipped := false
		for _, p := range parts[:len(parts)-1] {
			if skipDirs[p] {
				skipped = true
				break
			}
		}
		if skipped {
			continue
		}

		files = append(files, norm)
		lowerBase := strings.ToLower(filepath.Base(norm))
		switch lowerBase {
		case "package.json":
			if pkgPath == "" || norm == "package.json" {
				pkgPath = norm
			} else if len(manifestPaths) < 3 {
				manifestPaths = append(manifestPaths, norm)
			}
		case ".env.example", ".env.sample", ".env.template":
			if envPath == "" || norm == ".env.example" {
				envPath = norm
			}
		case "go.mod", "cargo.toml", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml", "requirements.txt", "pyproject.toml":
			if len(manifestPaths) < 4 {
				manifestPaths = append(manifestPaths, norm)
			}
		}
	}

	if len(files) == 0 {
		return nil, "", "", "", false
	}
	slices.Sort(files)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var extraBuilder strings.Builder

	fetchRawFile := func(filePath string, target *string, appendExtra bool) {
		defer wg.Done()
		rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s",
			url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(ref), filePath)
		data, st, fErr := doGitHubGet(rawURL, tok, 2500*time.Millisecond)
		if fErr != nil || st != http.StatusOK || len(data) == 0 {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if target != nil {
			*target = string(data)
		}
		if appendExtra {
			extraBuilder.Write(data)
			extraBuilder.WriteByte('\n')
		}
	}

	if pkgPath != "" {
		wg.Add(1)
		go fetchRawFile(pkgPath, &pkgJSON, false)
	}
	if envPath != "" {
		wg.Add(1)
		go fetchRawFile(envPath, &envExample, false)
	}
	for _, mp := range manifestPaths {
		wg.Add(1)
		go fetchRawFile(mp, nil, true)
	}
	wg.Wait()

	extraManifests = extraBuilder.String()

	ghCacheMu.Lock()
	ghTreeCache[cacheKey] = cachedTreeEntry{
		files:          slices.Clone(files),
		pkgJSON:        pkgJSON,
		envExample:     envExample,
		extraManifests: extraManifests,
		defaultBranch:  ref,
		expiresAt:      time.Now().Add(3 * time.Minute),
	}
	ghCacheMu.Unlock()

	return files, pkgJSON, envExample, extraManifests, true
}

func inferPresetFromGitHubMeta(fullName, language, desc string) string {
	lang := strings.ToLower(strings.TrimSpace(language))
	combined := strings.ToLower(fullName + " " + desc)

	switch {
	case strings.Contains(combined, "deployment-hub") || lang == "go":
		return "go"
	case lang == "rust" || strings.Contains(combined, "rust") || strings.Contains(combined, "actix"):
		return "rust"
	case strings.Contains(combined, "compose") || strings.Contains(combined, "monorepo") || strings.Contains(combined, "fullstack"):
		return "compose"
	case strings.Contains(combined, "next") || strings.Contains(combined, "nestjs") || strings.Contains(combined, "ai-finance") || strings.Contains(combined, "trip-ai"):
		return "nextjs"
	case lang == "typescript" || lang == "javascript" || lang == "html" || lang == "scss" || lang == "css" || lang == "vue":
		return "spa"
	default:
		return inferPresetFromRepoURL(fullName)
	}
}

func parseGitHubOwnerRepo(raw string) (owner, repo string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", false
	}
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "ssh://")
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
	if owner == "" || repo == "" || strings.ContainsAny(owner, " :@") || strings.ContainsAny(repo, " :@") {
		return "", "", false
	}
	return owner, repo, true
}

func isSyntheticTestOwner(owner string) bool {
	switch strings.ToLower(strings.TrimSpace(owner)) {
	case "org", "my-org", "example-org", "local", "test", "example":
		return true
	default:
		return false
	}
}

func doGitHubGet(endpoint, token string, timeout time.Duration) ([]byte, int, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "DeploymentHub-ControlPlane/1.0")
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func shortTokenHash(token string) string {
	if token == "" {
		return "anon"
	}
	if len(token) <= 8 {
		return token
	}
	return token[:4] + "_" + token[len(token)-4:]
}
