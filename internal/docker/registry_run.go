package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// RegistryConfig describes a sanitized container registry credential entry.
type RegistryConfig struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Server          string `json:"server"`
	Username        string `json:"username"`
	HasPassword     bool   `json:"hasPassword"`
	PasswordPreview string `json:"passwordPreview"`
	UpdatedAt       string `json:"updatedAt"`
}

type storedRegistry struct {
	RegistryConfig
	EncryptedPassword string `json:"encryptedPassword"`
}

// PullImageResult summarizes image pull status and Docker Engine stream lines.
type PullImageResult struct {
	Image   string   `json:"image"`
	Tag     string   `json:"tag"`
	Status  string   `json:"status"`
	Lines   []string `json:"lines"`
	Success bool     `json:"success"`
}

// RunContainerRequest configures launching a custom Docker container.
type RunContainerRequest struct {
	Name          string            `json:"name"`
	Image         string            `json:"image"`
	RegistryID    string            `json:"registryId"`
	Cmd           string            `json:"cmd"`
	Ports         []string          `json:"ports"`
	Env           []string          `json:"env"`
	Volumes       []string          `json:"volumes"`
	Network       string            `json:"network"`
	RestartPolicy string            `json:"restartPolicy"`
	MemoryMb      int64             `json:"memoryMb"`
	CPUCores      float64           `json:"cpuCores"`
	Domain        string            `json:"domain"`
	ContainerPort string            `json:"containerPort"`
	EnableSSL     bool              `json:"enableSsl"`
	ForceHTTPS    bool              `json:"forceHttps"`
	Labels        map[string]string `json:"labels"`
}

func resolveRegistriesFilePath() string {
	if custom := strings.TrimSpace(os.Getenv("REGISTRIES_DATA_FILE")); custom != "" {
		return custom
	}
	const defPath = "/data/registries.json"
	if err := os.MkdirAll(filepath.Dir(defPath), 0o750); err == nil {
		return defPath
	}
	return filepath.Join(os.TempDir(), "deploymenthub-registries.json")
}

func (e *Engine) loadRegistriesLocked() {
	path := resolveRegistriesFilePath()
	if e.registriesLoaded && e.registriesLoadedPath == path {
		return
	}
	e.registriesLoaded = true
	e.registriesLoadedPath = path
	e.registries = nil

	raw, err := os.ReadFile(path)
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		return
	}
	var list []storedRegistry
	if err := json.Unmarshal(raw, &list); err == nil {
		e.registries = list
	}
}

func (e *Engine) persistRegistriesLocked() error {
	path := resolveRegistriesFilePath()
	e.registriesLoadedPath = path
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(e.registries, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0o600)
}

func maskSecretPreview(secret string) string {
	tr := strings.TrimSpace(secret)
	if tr == "" {
		return ""
	}
	if len(tr) <= 4 {
		return "****"
	}
	return tr[:2] + "••••" + tr[len(tr)-2:]
}

func normalizeRegistryServer(server string) string {
	s := strings.TrimSpace(server)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimRight(s, "/")
	if s == "" || strings.EqualFold(s, "docker.io") {
		return "https://index.docker.io/v1/"
	}
	return s
}

// ListRegistries returns sanitized private registry credentials (never plaintext secrets).
func (e *Engine) ListRegistries() []RegistryConfig {
	e.registriesMu.Lock()
	e.loadRegistriesLocked()
	out := make([]RegistryConfig, 0, len(e.registries))
	for _, r := range e.registries {
		out = append(out, r.RegistryConfig)
	}
	e.registriesMu.Unlock()
	return out
}

// SaveRegistry adds or updates a private registry credential with AES-256-GCM vault encryption.
func (e *Engine) SaveRegistry(name, server, username, password string) (RegistryConfig, error) {
	cleanName := strings.TrimSpace(name)
	cleanServer := strings.TrimSpace(server)
	cleanUser := strings.TrimSpace(username)
	cleanPass := strings.TrimSpace(password)
	if cleanName == "" {
		cleanName = cleanServer
	}
	if cleanServer == "" {
		cleanServer = "https://index.docker.io/v1/"
	}
	if cleanUser == "" || cleanPass == "" {
		return RegistryConfig{}, errors.New("username and password/token are required")
	}

	encPass, err := e.vault.Encrypt(cleanPass)
	if err != nil {
		return RegistryConfig{}, fmt.Errorf("encrypt registry secret: %w", err)
	}

	item := storedRegistry{
		RegistryConfig: RegistryConfig{
			ID:              "reg-" + shortHex(4),
			Name:            cleanName,
			Server:          normalizeRegistryServer(cleanServer),
			Username:        cleanUser,
			HasPassword:     true,
			PasswordPreview: maskSecretPreview(cleanPass),
			UpdatedAt:       time.Now().UTC().Format(time.RFC3339),
		},
		EncryptedPassword: encPass,
	}

	e.registriesMu.Lock()
	defer e.registriesMu.Unlock()
	e.loadRegistriesLocked()

	updated := false
	for i := range e.registries {
		if strings.EqualFold(e.registries[i].Server, item.Server) && strings.EqualFold(e.registries[i].Username, item.Username) {
			item.ID = e.registries[i].ID
			e.registries[i] = item
			updated = true
			break
		}
	}
	if !updated {
		e.registries = append(e.registries, item)
	}
	if err := e.persistRegistriesLocked(); err != nil {
		return RegistryConfig{}, err
	}
	return item.RegistryConfig, nil
}

// DeleteRegistry removes a saved registry entry by ID.
func (e *Engine) DeleteRegistry(id string) error {
	cleanID := strings.TrimSpace(id)
	if cleanID == "" {
		return errors.New("registry id is required")
	}
	e.registriesMu.Lock()
	defer e.registriesMu.Unlock()
	e.loadRegistriesLocked()

	idx := -1
	for i := range e.registries {
		if e.registries[i].ID == cleanID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("registry %q not found", id)
	}
	e.registries = append(e.registries[:idx], e.registries[idx+1:]...)
	return e.persistRegistriesLocked()
}

func (e *Engine) registryAuthHeaderForImage(imageRef, registryID string) string {
	e.registriesMu.Lock()
	e.loadRegistriesLocked()
	regs := slices.Clone(e.registries)
	e.registriesMu.Unlock()
	if len(regs) == 0 {
		return ""
	}

	var matched *storedRegistry
	if rid := strings.TrimSpace(registryID); rid != "" {
		for i := range regs {
			if regs[i].ID == rid {
				matched = &regs[i]
				break
			}
		}
	}
	if matched == nil {
		host := ""
		if slash := strings.IndexByte(imageRef, '/'); slash > 0 {
			cand := imageRef[:slash]
			if strings.Contains(cand, ".") || strings.Contains(cand, ":") {
				host = strings.ToLower(cand)
			}
		}
		for i := range regs {
			srv := strings.ToLower(regs[i].Server)
			if host != "" && strings.Contains(srv, host) {
				matched = &regs[i]
				break
			}
			if host == "" && strings.Contains(srv, "docker.io") {
				matched = &regs[i]
				break
			}
		}
	}
	if matched == nil || matched.EncryptedPassword == "" {
		return ""
	}
	plainPass, err := e.vault.Decrypt(matched.EncryptedPassword)
	if err != nil {
		return ""
	}
	authJSON, _ := json.Marshal(map[string]string{
		"username":      matched.Username,
		"password":      plainPass,
		"serveraddress": matched.Server,
	})
	return base64.StdEncoding.EncodeToString(authJSON)
}

func splitImageRepoAndTagForPull(raw string) (repo, tag string, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.ContainsAny(trimmed, " \t\n\r") {
		return "", "", errors.New("valid image reference is required (e.g. nginx:alpine)")
	}
	if strings.Contains(trimmed, "@") {
		return trimmed, "", nil
	}
	lastColon := strings.LastIndexByte(trimmed, ':')
	lastSlash := strings.LastIndexByte(trimmed, '/')
	if lastColon > lastSlash {
		return trimmed[:lastColon], trimmed[lastColon+1:], nil
	}
	return trimmed, "latest", nil
}

// PullImage pulls an image from Docker Hub, GHCR, or private registry via POST /images/create.
func (e *Engine) PullImage(ctx context.Context, imageRef, registryID string) (PullImageResult, error) {
	repo, tag, err := splitImageRepoAndTagForPull(imageRef)
	if err != nil {
		return PullImageResult{}, err
	}

	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()

	fullRef := repo
	if tag != "" {
		fullRef += ":" + tag
	}
	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		return PullImageResult{
			Image:   repo,
			Tag:     tag,
			Status:  "Pulled (simulator)",
			Lines:   []string{"Pull complete: " + fullRef},
			Success: true,
		}, nil
	}

	client, baseURL, ok := newDockerHTTPClient(endpoint, 10*time.Minute)
	if !ok {
		return PullImageResult{}, errors.New("docker engine endpoint unreachable")
	}

	q := url.Values{}
	q.Set("fromImage", repo)
	if tag != "" {
		q.Set("tag", tag)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/images/create?"+q.Encode(), nil)
	if err != nil {
		return PullImageResult{}, err
	}
	if authHdr := e.registryAuthHeaderForImage(repo, registryID); authHdr != "" {
		req.Header.Set("X-Registry-Auth", authHdr)
	}

	resp, err := client.Do(req)
	if err != nil {
		return PullImageResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return PullImageResult{}, parseDockerAPIErrorMessage(resp.StatusCode, body)
	}

	var lines []string
	seenStatus := make(map[string]bool)
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 8<<20))
	scanner.Buffer(make([]byte, 0, 16*1024), 512*1024)
	for scanner.Scan() {
		rawLine := strings.TrimSpace(scanner.Text())
		if rawLine == "" {
			continue
		}
		var evt struct {
			Status      string `json:"status"`
			ID          string `json:"id"`
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := json.Unmarshal([]byte(rawLine), &evt); err != nil {
			continue
		}
		if evt.Error != "" || evt.ErrorDetail.Message != "" {
			msg := evt.ErrorDetail.Message
			if msg == "" {
				msg = evt.Error
			}
			return PullImageResult{Image: repo, Tag: tag, Lines: lines}, fmt.Errorf("pull %s failed: %s", fullRef, msg)
		}
		if evt.Status != "" {
			key := evt.Status + ":" + evt.ID
			if evt.Status == "Downloading" || evt.Status == "Extracting" {
				if seenStatus[key] {
					continue
				}
				seenStatus[key] = true
			}
			msg := evt.Status
			if evt.ID != "" {
				msg = evt.ID + ": " + msg
			}
			lines = append(lines, msg)
			if len(lines) > 80 {
				lines = lines[len(lines)-80:]
			}
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return PullImageResult{Image: repo, Tag: tag, Lines: lines}, scanErr
	}

	e.SyncDockerEngine()
	return PullImageResult{
		Image:   repo,
		Tag:     tag,
		Status:  "Pulled " + fullRef,
		Lines:   lines,
		Success: true,
	}, nil
}

func parsePortSpec(raw string) (hostIP, hostPort, containerPortProto string, err error) {
	tr := strings.TrimSpace(raw)
	if tr == "" {
		return "", "", "", errors.New("empty port spec")
	}
	parts := strings.Split(tr, ":")
	switch len(parts) {
	case 1:
		cp := parts[0]
		if !strings.Contains(cp, "/") {
			cp += "/tcp"
		}
		return "0.0.0.0", "", cp, nil
	case 2:
		hp := strings.TrimSpace(parts[0])
		cp := strings.TrimSpace(parts[1])
		if !strings.Contains(cp, "/") {
			cp += "/tcp"
		}
		return "0.0.0.0", hp, cp, nil
	case 3:
		ip := strings.TrimSpace(parts[0])
		if ip == "" {
			ip = "0.0.0.0"
		}
		hp := strings.TrimSpace(parts[1])
		cp := strings.TrimSpace(parts[2])
		if !strings.Contains(cp, "/") {
			cp += "/tcp"
		}
		return ip, hp, cp, nil
	default:
		return "", "", "", fmt.Errorf("invalid port spec %q (expected [ip:]hostPort:containerPort[/proto])", raw)
	}
}

// RunCustomContainer creates, configures (ports/env/volumes/limits/optional Traefik SSL),
// pulls missing images if needed, connects networks, and starts a custom container.
func (e *Engine) RunCustomContainer(ctx context.Context, req RunContainerRequest) (Container, error) {
	image := strings.TrimSpace(req.Image)
	if image == "" {
		return Container{}, errors.New("image is required")
	}
	rawName := strings.TrimSpace(req.Name)
	cname := ""
	if rawName != "" {
		cname = sanitizeSlug(rawName)
		if cname == "" {
			return Container{}, errors.New("invalid container name")
		}
		if IsProtectedSystemContainer(cname) {
			return Container{}, fmt.Errorf("%w: cannot overwrite system container name %q", ErrProtectedContainer, cname)
		}
	} else {
		repo, _, _ := splitImageRepoAndTagForPull(image)
		base := repo
		if idx := strings.LastIndexByte(repo, '/'); idx >= 0 {
			base = repo[idx+1:]
		}
		cname = "dh-" + sanitizeSlug(base) + "-" + shortHex(2)
	}

	exposedPorts := map[string]any{}
	portBindings := map[string][]map[string]string{}
	firstPort := strings.TrimSpace(req.ContainerPort)
	for _, rawPort := range req.Ports {
		if strings.TrimSpace(rawPort) == "" {
			continue
		}
		ip, hp, cpProto, err := parsePortSpec(rawPort)
		if err != nil {
			return Container{}, err
		}
		exposedPorts[cpProto] = map[string]any{}
		if hp != "" {
			portBindings[cpProto] = append(portBindings[cpProto], map[string]string{
				"HostIp":   ip,
				"HostPort": hp,
			})
		}
		if firstPort == "" {
			firstPort, _, _ = strings.Cut(cpProto, "/")
		}
	}
	if firstPort == "" {
		firstPort = "80"
	}

	labels := map[string]string{
		"deploymenthub.custom": "true",
	}
	for k, v := range req.Labels {
		if strings.TrimSpace(k) != "" {
			labels[strings.TrimSpace(k)] = v
		}
	}

	netName := strings.TrimSpace(req.Network)
	cleanDomain := strings.TrimSpace(req.Domain)
	if cleanDomain != "" {
		cfCfg := e.cf.GetSanitizedConfig()
		traefikLabels := buildContainerTraefikLabels(
			cname, image, "custom", "custom", cleanDomain, firstPort, 0,
			req.EnableSSL, req.ForceHTTPS, cfCfg.BaseDomain, cfCfg.TraefikDNS01,
		)
		for k, v := range traefikLabels {
			labels[k] = v
		}
		if netName == "" {
			netName = "deploymenthub_proxy"
		}
	}

	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()

	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		cnt := Container{
			ID:           "cnt-" + shortHex(4),
			Name:         cname,
			Project:      cname,
			StackKey:     inferStackKey(image, cname),
			Image:        image,
			PreviousTags: []string{image},
			Status:       "Running",
			CPUPct:       1.0,
			RAMMb:        32,
			RAMLimitMb:   max(64, int(req.MemoryMb)),
			Ports:        strings.Join(req.Ports, ", "),
			Uptime:       "Up vừa xong",
			Logs:         []string{"[docker] Custom container started: " + image},
		}
		e.mu.Lock()
		e.containers = slices.Insert(e.containers, 0, cnt)
		e.syncVPSRamLocked()
		e.mu.Unlock()
		return cnt, nil
	}

	client, baseURL, ok := newDockerHTTPClient(endpoint, 2*time.Minute)
	if !ok {
		return Container{}, errors.New("docker engine endpoint unreachable")
	}

	hostConfig := map[string]any{}
	if len(portBindings) > 0 {
		hostConfig["PortBindings"] = portBindings
	}
	var cleanBinds []string
	for _, b := range req.Volumes {
		if tr := strings.TrimSpace(b); tr != "" {
			cleanBinds = append(cleanBinds, tr)
		}
	}
	if len(cleanBinds) > 0 {
		hostConfig["Binds"] = cleanBinds
	}
	rp := strings.ToLower(strings.TrimSpace(req.RestartPolicy))
	if rp == "" {
		rp = "unless-stopped"
	}
	rpObj := map[string]any{"Name": rp}
	if rp == "on-failure" {
		rpObj["MaximumRetryCount"] = 5
	}
	hostConfig["RestartPolicy"] = rpObj
	if req.MemoryMb > 0 {
		hostConfig["Memory"] = req.MemoryMb * 1024 * 1024
	}
	if req.CPUCores > 0 {
		hostConfig["NanoCpus"] = int64(math.Round(req.CPUCores * 1e9))
	}

	var cleanEnv []string
	for _, envLine := range req.Env {
		if tr := strings.TrimSpace(envLine); tr != "" {
			cleanEnv = append(cleanEnv, tr)
		}
	}

	payload := map[string]any{
		"Image":        image,
		"Env":          cleanEnv,
		"Labels":       labels,
		"ExposedPorts": exposedPorts,
		"HostConfig":   hostConfig,
	}
	if cmdFields := strings.Fields(strings.TrimSpace(req.Cmd)); len(cmdFields) > 0 {
		payload["Cmd"] = cmdFields
	}
	if netName != "" {
		payload["NetworkingConfig"] = map[string]any{
			"EndpointsConfig": map[string]any{
				netName: map[string]any{},
			},
		}
	}

	createFn := func() (*http.Response, []byte, error) {
		rawBytes, _ := json.Marshal(payload)
		cReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/containers/create?name="+url.QueryEscape(cname), bytes.NewReader(rawBytes))
		if err != nil {
			return nil, nil, err
		}
		cReq.Header.Set("Content-Type", "application/json")
		cResp, err := client.Do(cReq)
		if err != nil {
			return nil, nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(cResp.Body, 1<<20))
		_ = cResp.Body.Close()
		return cResp, body, nil
	}

	cResp, cBody, err := createFn()
	if err != nil {
		return Container{}, err
	}
	// If image does not exist locally yet, pull automatically and retry create.
	if cResp.StatusCode == http.StatusNotFound {
		if _, pullErr := e.PullImage(ctx, image, req.RegistryID); pullErr != nil {
			return Container{}, fmt.Errorf("auto-pull missing image %q: %w", image, pullErr)
		}
		cResp, cBody, err = createFn()
		if err != nil {
			return Container{}, err
		}
	}
	if cResp.StatusCode != http.StatusCreated && cResp.StatusCode != http.StatusOK {
		return Container{}, parseDockerAPIErrorMessage(cResp.StatusCode, cBody)
	}

	var created struct {
		ID string `json:"Id"`
	}
	_ = json.Unmarshal(cBody, &created)
	newID := strings.TrimSpace(created.ID)
	if newID == "" {
		newID = cname
	}

	if err := sendDockerContainerActionStrict(endpoint, newID, "start"); err != nil {
		return Container{}, fmt.Errorf("container created (%s) but start failed: %w", shortDockerID(newID), err)
	}

	e.SyncDockerEngine()
	e.mu.RLock()
	defer e.mu.RUnlock()
	if idx := e.findContainerIndexLocked(shortDockerID(newID)); idx >= 0 {
		return cloneContainer(e.containers[idx]), nil
	}
	if idx := e.findContainerIndexLocked(cname); idx >= 0 {
		return cloneContainer(e.containers[idx]), nil
	}
	return Container{
		ID:        shortDockerID(newID),
		Name:      cname,
		Project:   cname,
		Image:     image,
		Status:    "Running",
		Protected: false,
	}, nil
}
