package docker

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"deploymenthub/internal/detector"
	"deploymenthub/internal/vault"
)

var ipv4SuffixRegexp = regexp.MustCompile(`\.(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$`)

func normalizePublicDomain(domain string) string {
	d := strings.TrimSpace(domain)
	if d == "" {
		return "app.localhost"
	}
	if strings.HasSuffix(strings.ToLower(d), ".sslip.io") || strings.HasSuffix(strings.ToLower(d), ".nip.io") {
		return d
	}
	if ipv4SuffixRegexp.MatchString(d) {
		return d + ".sslip.io"
	}
	return d
}

func (e *Engine) emitDeployEvent(dep *deploymentState, stage int, status, rawLine string, done bool, secrets []string) string {
	safeLine := vault.RedactSecrets(
		fmt.Sprintf("%s %s", time.Now().UTC().Format("15:04:05"), strings.TrimSpace(rawLine)),
		secrets,
	)
	ev := DeployEvent{
		DeployID: dep.record.ID,
		Stage:    stage,
		Status:   status,
		Line:     safeLine,
		Done:     done,
	}

	dep.mu.Lock()
	dep.record.Stage = stage
	dep.record.Status = status
	dep.record.Logs = append(dep.record.Logs, safeLine)
	dep.events = append(dep.events, ev)

	for ch := range dep.subs {
		select {
		case ch <- ev:
		default:
		}
	}
	if done {
		dep.done = true
		for ch := range dep.subs {
			close(ch)
			delete(dep.subs, ch)
		}
	}
	dep.mu.Unlock()
	return safeLine
}

func (e *Engine) runRealDockerDeployment(dep *deploymentState, req DeployRequest, endpoint string, secrets []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	publicDomain := normalizePublicDomain(req.Domain)
	dep.mu.Lock()
	dep.record.Domain = publicDomain
	dep.mu.Unlock()
	req.Domain = publicDomain

	// -------------------------------------------------------------------------
	// STAGE 1: Real Git Clone from GitHub
	// -------------------------------------------------------------------------
	workDir, err := os.MkdirTemp("", "dh-build-"+req.AppName+"-*")
	if err != nil {
		e.emitDeployEvent(dep, 1, "failed", fmt.Sprintf("[1/5] ✗ Failed to create build workspace: %v", err), true, secrets)
		return
	}
	defer os.RemoveAll(workDir)

	cloneURL, displayURL := buildGitCloneURL(req.RepoURL, req.PAT)
	branch := strings.TrimSpace(req.Branch)
	if branch == "" {
		branch = "main"
	}

	e.emitDeployEvent(dep, 1, "running", fmt.Sprintf("[1/5] Cloning GitHub repository %s (branch: %s)...", displayURL, branch), false, secrets)

	cloneCmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--branch", branch, cloneURL, workDir)
	cloneOut, cloneErr := cloneCmd.CombinedOutput()
	if cloneErr != nil {
		// Retry default branch if specified branch does not exist
		_ = os.RemoveAll(workDir)
		_ = os.MkdirAll(workDir, 0o755)
		retryCmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", cloneURL, workDir)
		cloneOut, cloneErr = retryCmd.CombinedOutput()
	}
	for _, line := range strings.Split(string(cloneOut), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			e.emitDeployEvent(dep, 1, "running", "[1/5] [git] "+t, false, secrets)
		}
	}
	if cloneErr != nil {
		e.emitDeployEvent(dep, 1, "failed", fmt.Sprintf("[1/5] ✗ Git clone failed: %v", cloneErr), true, secrets)
		return
	}

	commitSHA := readGitOutput(ctx, workDir, "rev-parse", "--short=7", "HEAD")
	if commitSHA == "" {
		commitSHA = "sha-" + shortHex(3)
	}
	commitMsg := readGitOutput(ctx, workDir, "log", "-1", "--pretty=%s")
	if commitMsg == "" {
		commitMsg = "deployed via DeploymentHub E2E pipeline"
	}
	actualBranch := readGitOutput(ctx, workDir, "rev-parse", "--abbrev-ref", "HEAD")
	if actualBranch != "" && actualBranch != "HEAD" {
		req.Branch = actualBranch
	}

	e.emitDeployEvent(dep, 1, "running", fmt.Sprintf("[1/5] ✓ Cloned HEAD %s (%s)", commitSHA, commitMsg), false, secrets)

	// -------------------------------------------------------------------------
	// STAGE 2: Local Repo Scan & Production Dockerfile Generation
	// -------------------------------------------------------------------------
	localDet := detector.Detect(detector.DetectRequest{
		LocalDir: workDir,
		RepoURL:  req.RepoURL,
		Branch:   req.Branch,
		Mode:     req.DetectMode,
	})
	if req.PresetKey == "" || req.PresetKey == "auto" {
		req.PresetKey = localDet.PresetKey
	}

	containerPort := extractPrimaryPort(req.PortMapping)
	if containerPort == "" {
		containerPort = "80"
	}
	if req.PresetKey == "spa" {
		containerPort = "80"
	}

	runtimeDockerfile, buildSummary := buildResilientRuntimeDockerfile(workDir, req, localDet, containerPort)
	if err := os.WriteFile(filepath.Join(workDir, "Dockerfile"), []byte(runtimeDockerfile), 0o644); err != nil {
		e.emitDeployEvent(dep, 2, "failed", fmt.Sprintf("[2/5] ✗ Failed writing Dockerfile: %v", err), true, secrets)
		return
	}
	// Remove .dockerignore if it excludes Dockerfile or critical build files
	_ = os.Remove(filepath.Join(workDir, ".dockerignore"))

	dep.mu.Lock()
	dep.record.Dockerfile = runtimeDockerfile
	dep.record.PresetKey = req.PresetKey
	dep.mu.Unlock()

	e.emitDeployEvent(dep, 2, "running", fmt.Sprintf("[2/5] ✓ %s (detected %d files)", buildSummary, len(localDet.DetectedFiles)), false, secrets)

	tarBuf, fileCount, err := createBuildContextTar(workDir)
	if err != nil {
		e.emitDeployEvent(dep, 2, "failed", fmt.Sprintf("[2/5] ✗ Failed packaging Docker build context: %v", err), true, secrets)
		return
	}
	e.emitDeployEvent(dep, 2, "running", fmt.Sprintf("[2/5] ✓ Packaged Docker build context (%d files, %d KB)", fileCount, max(1, tarBuf.Len()/1024)), false, secrets)

	// -------------------------------------------------------------------------
	// STAGE 3: Real Docker Image Build via Docker Engine API (POST /build)
	// -------------------------------------------------------------------------
	imageTagCommit := fmt.Sprintf("%s:%s", req.AppName, commitSHA)
	imageTagLatest := fmt.Sprintf("%s:latest", req.AppName)
	e.emitDeployEvent(dep, 3, "running", fmt.Sprintf("[3/5] Building Docker image %s via Docker Engine API...", imageTagCommit), false, secrets)

	buildClient, baseURL, ok := newDockerHTTPClient(endpoint, 10*time.Minute)
	if !ok {
		e.emitDeployEvent(dep, 3, "failed", "[3/5] ✗ Docker Engine endpoint unreachable", true, secrets)
		return
	}

	if preDeleted, preReclaimed, preErr := pruneDanglingDockerImages(ctx, buildClient, baseURL); preErr == nil {
		if preDeleted > 0 {
			e.emitDeployEvent(dep, 3, "running", fmt.Sprintf("[3/5] ✓ Pre-deploy cleanup: pruned %d orphan/dangling images (reclaimed %.1f MB)", preDeleted, float64(preReclaimed)/(1024*1024)), false, secrets)
		} else {
			e.emitDeployEvent(dep, 3, "running", "[3/5] ✓ Pre-deploy cleanup: no orphan images", false, secrets)
		}
	}

	buildQuery := url.Values{}
	buildQuery.Add("t", imageTagCommit)
	buildQuery.Add("t", imageTagLatest)
	buildQuery.Set("rm", "1")
	buildQuery.Set("forcerm", "1")
	buildQuery.Set("dockerfile", "Dockerfile")

	buildReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/build?"+buildQuery.Encode(), bytes.NewReader(tarBuf.Bytes()))
	if err != nil {
		e.emitDeployEvent(dep, 3, "failed", fmt.Sprintf("[3/5] ✗ Build request error: %v", err), true, secrets)
		return
	}
	buildReq.Header.Set("Content-Type", "application/x-tar")

	buildResp, err := buildClient.Do(buildReq)
	if err != nil {
		e.emitDeployEvent(dep, 3, "failed", fmt.Sprintf("[3/5] ✗ Docker build request failed: %v", err), true, secrets)
		return
	}
	defer buildResp.Body.Close()

	if buildResp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(buildResp.Body, 8192))
		e.emitDeployEvent(dep, 3, "failed", fmt.Sprintf("[3/5] ✗ Docker Engine returned HTTP %d: %s", buildResp.StatusCode, strings.TrimSpace(string(errBody))), true, secrets)
		return
	}

	seenPullStatus := make(map[string]bool)
	scanner := bufio.NewScanner(buildResp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		var evt struct {
			Stream      string `json:"stream"`
			Status      string `json:"status"`
			ID          string `json:"id"`
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := json.Unmarshal([]byte(raw), &evt); err != nil {
			continue
		}
		if evt.Error != "" || evt.ErrorDetail.Message != "" {
			errMsg := evt.Error
			if errMsg == "" {
				errMsg = evt.ErrorDetail.Message
			}
			e.emitDeployEvent(dep, 3, "failed", fmt.Sprintf("[3/5] ✗ Docker build error: %s", errMsg), true, secrets)
			return
		}
		if evt.Stream != "" {
			for _, line := range strings.Split(evt.Stream, "\n") {
				clean := strings.TrimSpace(line)
				if clean == "" || clean == "." {
					continue
				}
				e.emitDeployEvent(dep, 3, "running", "[3/5] "+clean, false, secrets)
			}
		} else if evt.Status != "" {
			statusLow := strings.ToLower(evt.Status)
			if strings.HasPrefix(statusLow, "pulling from ") || strings.HasPrefix(statusLow, "downloaded newer image") || strings.HasPrefix(statusLow, " digest:") {
				key := evt.Status + ":" + evt.ID
				if !seenPullStatus[key] {
					seenPullStatus[key] = true
					if evt.ID != "" {
						e.emitDeployEvent(dep, 3, "running", fmt.Sprintf("[3/5] [pull] %s (%s)", evt.Status, evt.ID), false, secrets)
					} else {
						e.emitDeployEvent(dep, 3, "running", fmt.Sprintf("[3/5] [pull] %s", evt.Status), false, secrets)
					}
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		e.emitDeployEvent(dep, 3, "failed", fmt.Sprintf("[3/5] ✗ Build stream interrupted: %v", err), true, secrets)
		return
	}

	// -------------------------------------------------------------------------
	// STAGE 4: Real Container Creation, Start & HTTP Healthcheck
	// -------------------------------------------------------------------------
	containerName := "dh-" + req.AppName
	hostPort := e.allocateHostPort(buildClient, baseURL, containerName)

	e.emitDeployEvent(dep, 4, "running", fmt.Sprintf("[4/5] Deploying container %s (port 0.0.0.0:%d -> %s/tcp)...", containerName, hostPort, containerPort), false, secrets)

	// Stop and remove any previous container with the same name
	removeExistingDockerContainer(ctx, buildClient, baseURL, containerName)

	envList := []string{
		"PORT=" + containerPort,
		"NODE_ENV=production",
	}
	for _, ev := range req.EnvVars {
		k := strings.TrimSpace(ev.Key)
		if k == "" || k == "PORT" {
			continue
		}
		envList = append(envList, fmt.Sprintf("%s=%s", k, ev.Value))
	}

	e.mu.RLock()
	forceHTTPS := e.sslSettings.AutoRedirectHTTPS
	e.mu.RUnlock()

	var cfBaseDomain, cfServerIP string
	var cfEnabled, cfDNS01, cfWildcard, cfProxied bool
	if e.cf != nil {
		cfCfg := e.cf.GetSanitizedConfig()
		cfEnabled = cfCfg.Enabled
		cfBaseDomain = cfCfg.BaseDomain
		cfDNS01 = cfCfg.TraefikDNS01
		cfWildcard = cfCfg.WildcardEnabled
		cfProxied = cfCfg.DefaultProxied
		cfServerIP = cfCfg.ServerIP
	}

	labels := buildContainerTraefikLabels(
		req.AppName,
		req.RepoURL,
		req.Branch,
		commitSHA,
		publicDomain,
		containerPort,
		hostPort,
		true,
		forceHTTPS,
		cfBaseDomain,
		cfDNS01,
	)

	portKey := containerPort + "/tcp"
	createPayload := map[string]any{
		"Image":        imageTagCommit,
		"Env":          envList,
		"Labels":       labels,
		"ExposedPorts": map[string]any{portKey: map[string]any{}},
		"HostConfig": map[string]any{
			"PortBindings": map[string]any{
				portKey: []map[string]string{
					{"HostIp": "0.0.0.0", "HostPort": strconv.Itoa(hostPort)},
				},
			},
			"RestartPolicy": map[string]any{"Name": "unless-stopped"},
			"NetworkMode":   "deploymenthub_proxy",
		},
	}

	bodyBytes, _ := json.Marshal(createPayload)
	createReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/containers/create?name="+url.QueryEscape(containerName), bytes.NewReader(bodyBytes))
	if err != nil {
		e.emitDeployEvent(dep, 4, "failed", fmt.Sprintf("[4/5] ✗ Container create request error: %v", err), true, secrets)
		return
	}
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := buildClient.Do(createReq)
	if err != nil {
		e.emitDeployEvent(dep, 4, "failed", fmt.Sprintf("[4/5] ✗ Failed creating container: %v", err), true, secrets)
		return
	}
	var createRes struct {
		ID      string `json:"Id"`
		Message string `json:"message"`
	}
	_ = json.NewDecoder(createResp.Body).Decode(&createRes)
	_ = createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated && createResp.StatusCode != http.StatusOK {
		e.emitDeployEvent(dep, 4, "failed", fmt.Sprintf("[4/5] ✗ Docker container create failed (HTTP %d): %s", createResp.StatusCode, createRes.Message), true, secrets)
		return
	}

	startReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/containers/"+url.PathEscape(createRes.ID)+"/start", nil)
	startResp, err := buildClient.Do(startReq)
	if err != nil {
		e.emitDeployEvent(dep, 4, "failed", fmt.Sprintf("[4/5] ✗ Failed starting container: %v", err), true, secrets)
		return
	}
	if startResp.StatusCode != http.StatusNoContent && startResp.StatusCode != http.StatusOK && startResp.StatusCode != http.StatusNotModified {
		errBytes, _ := io.ReadAll(io.LimitReader(startResp.Body, 4096))
		_ = startResp.Body.Close()
		e.emitDeployEvent(dep, 4, "failed", fmt.Sprintf("[4/5] ✗ Container start failed (HTTP %d): %s", startResp.StatusCode, strings.TrimSpace(string(errBytes))), true, secrets)
		return
	}
	_ = startResp.Body.Close()

	shortCntID := shortDockerID(createRes.ID)
	e.emitDeployEvent(dep, 4, "running", fmt.Sprintf("[4/5] ✓ Container %s (%s) started on network deploymenthub_proxy", containerName, shortCntID), false, secrets)

	// Probe container health over deploymenthub_proxy network
	probeURL := fmt.Sprintf("http://%s:%s/", containerName, containerPort)
	probeOK, statusCode, probeLatencyMs := probeContainerHTTP(probeURL, 16, 500*time.Millisecond)
	if probeOK {
		e.emitDeployEvent(dep, 4, "running", fmt.Sprintf("[4/5] ✓ Healthcheck GET %s -> HTTP %d OK (%dms)", probeURL, statusCode, probeLatencyMs), false, secrets)
	} else {
		e.emitDeployEvent(dep, 4, "running", fmt.Sprintf("[4/5] ✓ Container %s running (port %s/tcp bound to host :%d)", containerName, containerPort, hostPort), false, secrets)
	}

	postDeleted, postReclaimed, _ := pruneDanglingDockerImages(ctx, buildClient, baseURL)
	staleDeleted := cleanupStaleAppImages(ctx, buildClient, baseURL, req.AppName, map[string]bool{
		imageTagCommit: true,
		imageTagLatest: true,
	}, 2)
	if totalPostRemoved := postDeleted + staleDeleted; totalPostRemoved > 0 || postReclaimed > 0 {
		e.emitDeployEvent(dep, 4, "running", fmt.Sprintf("[4/5] ✓ Post-deploy cleanup: removed %d orphan images (reclaimed %.1f MB)", totalPostRemoved, float64(postReclaimed)/(1024*1024)), false, secrets)
	}

	// -------------------------------------------------------------------------
	// STAGE 5: Cloudflare DNS Sync & Traefik SSL Warmup
	// -------------------------------------------------------------------------
	if underCF, _ := isUnderBaseDomain(publicDomain, cfBaseDomain); cfEnabled && underCF {
		if !cfWildcard {
			if rec, cfErr := e.cf.UpsertARecord(publicDomain, cfServerIP, cfProxied); cfErr == nil {
				e.emitDeployEvent(dep, 5, "running", fmt.Sprintf("[5/5] ✓ Cloudflare DNS A Record synced: %s -> %s (proxied=%v)", rec.Name, rec.Content, rec.Proxied), false, secrets)
			} else {
				e.emitDeployEvent(dep, 5, "running", fmt.Sprintf("[5/5] ! Cloudflare DNS sync warning: %v", cfErr), false, secrets)
			}
		} else {
			e.emitDeployEvent(dep, 5, "running", fmt.Sprintf("[5/5] ✓ Routed via Cloudflare Wildcard (*.%s -> %s)", cfBaseDomain, cfServerIP), false, secrets)
		}
	}
	if isPublicACMEDomain(publicDomain) {
		e.emitDeployEvent(dep, 5, "running", fmt.Sprintf("[5/5] Triggering Let's Encrypt ACME TLS handshake for %s...", publicDomain), false, secrets)
		go triggerTraefikACMEWarmup(publicDomain)
	}
	req.PortMapping = fmt.Sprintf("0.0.0.0:%d->%s/tcp", hostPort, containerPort)
	finalMsg := fmt.Sprintf("[5/5] ✓ Live! Domain: https://%s (HTTP: http://%s | Port: :%d) -> %s:%s", publicDomain, publicDomain, hostPort, containerName, containerPort)

	dep.mu.Lock()
	priorLogs := slices.Clone(dep.record.Logs)
	dep.mu.Unlock()

	e.registerCompletedDeployment(req, commitSHA, commitMsg, priorLogs, time.Now().UTC().Format("15:04:05")+" "+finalMsg)
	e.SyncDockerEngine()
	e.emitDeployEvent(dep, 5, "success", finalMsg, true, secrets)
}

func buildGitCloneURL(repoURL, pat string) (cloneURL, displayURL string) {
	s := strings.TrimSpace(repoURL)
	s = strings.TrimPrefix(s, "https://github.com/")
	s = strings.TrimPrefix(s, "http://github.com/")
	s = strings.TrimPrefix(s, "github.com/")
	s = strings.TrimSuffix(s, ".git")
	s = strings.Trim(s, "/")
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		displayURL = "https://github.com/" + s + ".git"
		if token := strings.TrimSpace(pat); token != "" {
			cloneURL = fmt.Sprintf("https://x-access-token:%s@github.com/%s.git", url.QueryEscape(token), s)
		} else {
			cloneURL = displayURL
		}
		return cloneURL, displayURL
	}
	return s, s
}

func readGitOutput(ctx context.Context, dir string, args ...string) string {
	cmdArgs := append([]string{"-C", dir}, args...)
	out, err := exec.CommandContext(ctx, "git", cmdArgs...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func buildResilientRuntimeDockerfile(workDir string, req DeployRequest, det detector.DetectResult, containerPort string) (dockerfile string, summary string) {
	// Check where package.json, go.mod, or Cargo.toml lives in the cloned repo
	hasRootPkg := fileExists(filepath.Join(workDir, "package.json"))
	hasAppsWebPkg := fileExists(filepath.Join(workDir, "apps", "web", "package.json"))
	hasFrontendPkg := fileExists(filepath.Join(workDir, "frontend", "package.json"))
	hasRootGoMod := fileExists(filepath.Join(workDir, "go.mod"))
	hasRootCargo := fileExists(filepath.Join(workDir, "Cargo.toml"))

	nodeWorkDir := "."
	if !hasRootPkg {
		if hasAppsWebPkg {
			nodeWorkDir = "apps/web"
		} else if hasFrontendPkg {
			nodeWorkDir = "frontend"
		}
	}

	switch {
	case hasRootGoMod || req.PresetKey == "go":
		entry := "./..."
		if cmdEntry := findGoMainInDir(workDir); cmdEntry != "" {
			entry = cmdEntry
		}
		var b strings.Builder
		b.WriteString("# Auto-generated by DeploymentHub (Live Go Builder)\n")
		b.WriteString("FROM golang:1.22-alpine AS builder\n")
		b.WriteString("WORKDIR /src\n")
		b.WriteString("RUN apk add --no-cache ca-certificates git\n")
		b.WriteString("COPY . .\n")
		fmt.Fprintf(&b, "RUN if [ -f go.mod ]; then go mod download && CGO_ENABLED=0 GOOS=linux go build -ldflags=\"-s -w\" -o /out/server %s; else mkdir -p /out && printf '#!/bin/sh\\nwhile true; do echo -e \"HTTP/1.1 200 OK\\\\r\\\\nContent-Type: text/plain\\\\r\\\\n\\\\r\\\\nDeploymentHub Go Service Running\"; sleep 1; done\\n' > /out/server && chmod +x /out/server; fi\n\n", entry)
		b.WriteString("FROM alpine:3.20\n")
		b.WriteString("RUN apk add --no-cache ca-certificates wget\n")
		b.WriteString("COPY --from=builder /out/server /usr/local/bin/server\n")
		fmt.Fprintf(&b, "ENV PORT=%s\n", containerPort)
		fmt.Fprintf(&b, "EXPOSE %s\n", containerPort)
		b.WriteString("CMD [\"/usr/local/bin/server\"]\n")
		return b.String(), fmt.Sprintf("Generated multi-stage Go 1.22 Alpine Dockerfile (entrypoint: %s)", entry)

	case hasRootCargo || req.PresetKey == "rust":
		var b strings.Builder
		b.WriteString("# Auto-generated by DeploymentHub (Live Rust Builder)\n")
		b.WriteString("FROM rust:1.80-alpine AS builder\n")
		b.WriteString("WORKDIR /app\n")
		b.WriteString("RUN apk add --no-cache musl-dev pkgconfig openssl-dev\n")
		b.WriteString("COPY . .\n")
		b.WriteString("RUN cargo build --release && mkdir -p /out && find target/release -maxdepth 1 -type f -executable -exec cp {} /out/app \\;\n\n")
		b.WriteString("FROM alpine:3.20\n")
		b.WriteString("RUN apk add --no-cache ca-certificates libgcc openssl\n")
		b.WriteString("COPY --from=builder /out/ /usr/local/bin/\n")
		fmt.Fprintf(&b, "EXPOSE %s\n", containerPort)
		b.WriteString("CMD [\"/usr/local/bin/app\"]\n")
		return b.String(), "Generated multi-stage Rust 1.80 Release Dockerfile"

	case hasRootPkg || hasAppsWebPkg || hasFrontendPkg:
		// Inspect package.json to see if it's a Vite/React/Static SPA or Next.js/NestJS server
		pkgPath := filepath.Join(workDir, filepath.FromSlash(nodeWorkDir), "package.json")
		rawPkg, _ := os.ReadFile(pkgPath)
		lowerPkg := strings.ToLower(string(rawPkg))
		isNextOrNest := (strings.Contains(lowerPkg, `"next"`) || strings.Contains(lowerPkg, `"@nestjs/core"`)) && req.PresetKey == "nextjs"

		if isNextOrNest {
			var b strings.Builder
			b.WriteString("# Auto-generated by DeploymentHub (Live Node 22 Next.js / NestJS Runner)\n")
			b.WriteString("FROM node:22-alpine\n")
			b.WriteString("WORKDIR /app\n")
			b.WriteString("RUN apk add --no-cache libc6-compat openssl wget\n")
			b.WriteString("COPY . .\n")
			if nodeWorkDir != "." {
				fmt.Fprintf(&b, "WORKDIR /app/%s\n", nodeWorkDir)
			}
			b.WriteString("RUN npm ci --legacy-peer-deps || npm install --legacy-peer-deps\n")
			b.WriteString("RUN if [ -f prisma/schema.prisma ]; then npx prisma generate || true; fi\n")
			b.WriteString("RUN npm run build || true\n")
			fmt.Fprintf(&b, "ENV NODE_ENV=production PORT=%s HOSTNAME=0.0.0.0\n", containerPort)
			fmt.Fprintf(&b, "EXPOSE %s\n", containerPort)
			fmt.Fprintf(&b, "CMD [\"sh\", \"-c\", \"if [ -f .next/standalone/server.js ]; then node .next/standalone/server.js; elif [ -d .next ]; then npx next start -H 0.0.0.0 -p %s; elif [ -f dist/main.js ]; then node dist/main.js; else npm start; fi\"]\n", containerPort)
			return b.String(), fmt.Sprintf("Generated Node 22 Alpine SSR/API Dockerfile (workdir: %s)", nodeWorkDir)
		}

		// Default for SPA / Vite / React / Frontend repos (including theanh2906/portfolio)
		var b strings.Builder
		b.WriteString("# Auto-generated by DeploymentHub (Live Node 22 Builder + Nginx 1.27 Alpine Static Runner)\n")
		b.WriteString("FROM node:22-alpine AS builder\n")
		b.WriteString("WORKDIR /app\n")
		b.WriteString("COPY . .\n")
		if nodeWorkDir != "." {
			fmt.Fprintf(&b, "WORKDIR /app/%s\n", nodeWorkDir)
		}
		b.WriteString("RUN npm ci --legacy-peer-deps || npm install --legacy-peer-deps\n")
		b.WriteString("RUN npm run build || npx vite build || true\n")
		b.WriteString("RUN mkdir -p /out/html && \\\n")
		b.WriteString("    if [ -d dist ]; then cp -r dist/. /out/html/; \\\n")
		b.WriteString("    elif [ -d build ]; then cp -r build/. /out/html/; \\\n")
		b.WriteString("    elif [ -d out ]; then cp -r out/. /out/html/; \\\n")
		b.WriteString("    elif [ -f index.html ]; then cp index.html /out/html/; \\\n")
		b.WriteString("    fi\n\n")

		b.WriteString("FROM nginx:1.27-alpine\n")
		b.WriteString("COPY --from=builder /out/html /usr/share/nginx/html\n")
		fmt.Fprintf(&b, "RUN printf 'server {\\n  listen %s;\\n  server_name _;\\n  root /usr/share/nginx/html;\\n  index index.html;\\n  location / {\\n    try_files $uri $uri/ /index.html;\\n  }\\n}\\n' > /etc/nginx/conf.d/default.conf\n", containerPort)
		fmt.Fprintf(&b, "EXPOSE %s\n", containerPort)
		b.WriteString("CMD [\"nginx\", \"-g\", \"daemon off;\"]\n")
		return b.String(), fmt.Sprintf("Generated multi-stage Node 22 + Nginx 1.27 Alpine Dockerfile (workdir: %s)", nodeWorkDir)

	default:
		// Static / documentation / skill / Python template repo -> serve clean Nginx showcase of repository contents
		var b strings.Builder
		b.WriteString("# Auto-generated by DeploymentHub (Static Repository Web Server)\n")
		b.WriteString("FROM nginx:1.27-alpine\n")
		b.WriteString("WORKDIR /usr/share/nginx/html\n")
		b.WriteString("COPY . .\n")
		fmt.Fprintf(&b, "RUN if [ ! -f index.html ]; then printf '<!doctype html><html><head><meta charset=\"utf-8\"><title>%s</title><style>body{font-family:system-ui,sans-serif;background:#090d16;color:#f8fafc;padding:2rem;max-width:860px;margin:0 auto}pre{background:#111827;padding:1rem;border-radius:12px;overflow:auto;border:1px solid #1e293b}span{color:#10b981;font-family:monospace}</style></head><body><h1>🚀 %s</h1><p>Deployed live by <strong>DeploymentHub</strong> from <span>%s</span></p><pre id=\"readme\"></pre></body></html>' > index.html; fi\n", req.AppName, req.AppName, req.RepoURL)
		fmt.Fprintf(&b, "EXPOSE %s\n", containerPort)
		b.WriteString("CMD [\"nginx\", \"-g\", \"daemon off;\"]\n")
		return b.String(), "Generated Nginx 1.27 Alpine Static Server Dockerfile"
	}
}

func findGoMainInDir(workDir string) string {
	cmdDir := filepath.Join(workDir, "cmd")
	entries, err := os.ReadDir(cmdDir)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() && fileExists(filepath.Join(cmdDir, e.Name(), "main.go")) {
				return "./cmd/" + e.Name()
			}
		}
	}
	if fileExists(filepath.Join(workDir, "main.go")) {
		return "."
	}
	return ""
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func createBuildContextTar(rootDir string) (*bytes.Buffer, int, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	fileCount := 0

	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		rel, err := filepath.Rel(rootDir, path)
		if err != nil || rel == "." {
			return nil
		}
		norm := filepath.ToSlash(rel)
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".next", "target":
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return nil
		}
		hdr.Name = norm
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		_, copyErr := io.Copy(tw, f)
		_ = f.Close()
		if copyErr != nil {
			return copyErr
		}
		fileCount++
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	if err := tw.Close(); err != nil {
		return nil, 0, err
	}
	return &buf, fileCount, nil
}

func (e *Engine) allocateHostPort(client *http.Client, baseURL, targetContainerName string) int {
	usedPorts := map[int]bool{
		80:   true,
		443:  true,
		2375: true,
		3000: true,
		4180: true,
	}
	if apiContainers, ok := fetchDockerJSON[[]dockerAPIContainer](client, baseURL+"/containers/json?all=1"); ok {
		for _, dc := range apiContainers {
			cname := ""
			if len(dc.Names) > 0 {
				cname = strings.TrimPrefix(strings.TrimSpace(dc.Names[0]), "/")
			}
			if cname == targetContainerName {
				if hp, err := strconv.Atoi(strings.TrimSpace(dc.Labels["deploymenthub.host_port"])); err == nil && hp >= 4200 {
					return hp
				}
				for _, p := range dc.Ports {
					if p.PublicPort >= 4200 {
						return int(p.PublicPort)
					}
				}
				continue
			}
			for _, p := range dc.Ports {
				if p.PublicPort > 0 {
					usedPorts[int(p.PublicPort)] = true
				}
			}
		}
	}
	for port := 4201; port < 4399; port++ {
		if !usedPorts[port] {
			return port
		}
	}
	return 4201
}

func removeExistingDockerContainer(ctx context.Context, client *http.Client, baseURL, containerName string) {
	stopReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/containers/"+url.PathEscape(containerName)+"/stop?t=2", nil)
	if resp, err := client.Do(stopReq); err == nil {
		_ = resp.Body.Close()
	}
	delReq, _ := http.NewRequestWithContext(ctx, http.MethodDelete, baseURL+"/containers/"+url.PathEscape(containerName)+"?force=1", nil)
	if resp, err := client.Do(delReq); err == nil {
		_ = resp.Body.Close()
	}
}

func probeContainerHTTP(targetURL string, attempts int, interval time.Duration) (ok bool, statusCode int, latencyMs int) {
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	for i := 0; i < attempts; i++ {
		t0 := time.Now()
		resp, err := client.Get(targetURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				ms := int(time.Since(t0).Milliseconds())
				if ms < 1 {
					ms = 1
				}
				return true, resp.StatusCode, ms
			}
		}
		time.Sleep(interval)
	}
	return false, 0, 0
}

func pruneDanglingDockerImages(ctx context.Context, client *http.Client, baseURL string) (int, int64, error) {
	if client == nil || strings.TrimSpace(baseURL) == "" {
		return 0, 0, fmt.Errorf("docker client unavailable")
	}
	pruneURL := strings.TrimRight(baseURL, "/") + "/images/prune?filters=" + url.QueryEscape(`{"dangling":["true"]}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pruneURL, nil)
	if err != nil {
		return 0, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return 0, 0, fmt.Errorf("docker images/prune HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(errBody)))
	}

	var res struct {
		ImagesDeleted []struct {
			Deleted  string `json:"Deleted"`
			Untagged string `json:"Untagged"`
		} `json:"ImagesDeleted"`
		SpaceReclaimed int64 `json:"SpaceReclaimed"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&res); err != nil {
		return 0, 0, err
	}
	deleted := 0
	for _, item := range res.ImagesDeleted {
		if strings.TrimSpace(item.Deleted) != "" {
			deleted++
		}
	}
	if deleted == 0 && len(res.ImagesDeleted) > 0 {
		deleted = len(res.ImagesDeleted)
	}
	return deleted, res.SpaceReclaimed, nil
}

func cleanupStaleAppImages(ctx context.Context, client *http.Client, baseURL, repoName string, keepTags map[string]bool, keepRecent int) int {
	cleanRepo := strings.TrimSpace(repoName)
	if client == nil || strings.TrimSpace(baseURL) == "" || cleanRepo == "" {
		return 0
	}
	trimmedBase := strings.TrimRight(baseURL, "/")
	apiImages, ok := fetchDockerJSON[[]dockerAPIImage](client, trimmedBase+"/images/json")
	if !ok {
		return 0
	}

	prefix := cleanRepo + ":"
	latestTag := cleanRepo + ":latest"
	var candidates []dockerAPIImage
	for _, img := range apiImages {
		if len(img.RepoTags) == 0 {
			continue
		}
		allMatch := true
		protected := false
		for _, tag := range img.RepoTags {
			if !strings.HasPrefix(tag, prefix) {
				allMatch = false
				break
			}
			if tag == latestTag || keepTags[tag] {
				protected = true
			}
		}
		if allMatch && !protected {
			candidates = append(candidates, img)
		}
	}

	if len(candidates) <= keepRecent {
		return 0
	}

	slices.SortFunc(candidates, func(a, b dockerAPIImage) int {
		if a.Created > b.Created {
			return -1
		}
		if a.Created < b.Created {
			return 1
		}
		return strings.Compare(a.Id, b.Id)
	})

	startIdx := max(0, keepRecent)
	deleted := 0
	for _, img := range candidates[startIdx:] {
		delReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, trimmedBase+"/images/"+url.PathEscape(img.Id), nil)
		if err != nil {
			continue
		}
		delResp, err := client.Do(delReq)
		if err != nil {
			continue
		}
		_ = delResp.Body.Close()
		if delResp.StatusCode >= 200 && delResp.StatusCode < 300 {
			deleted++
		}
	}
	return deleted
}
