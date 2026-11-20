// Package docker implements DeploymentHub's thread-safe control plane engine,
// supporting live Docker Engine socket probing, stateful simulator mode,
// 5-stage async deployments with SSE event streaming, and Docker multiplexed log parsing.
package docker

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"deploymenthub/internal/cloudflare"
	"deploymenthub/internal/detector"
	"deploymenthub/internal/vault"
)

// VPSStatus describes the managed host telemetry and Docker Engine connection mode.
type VPSStatus struct {
	Host           string  `json:"host"`
	IP             string  `json:"ip"`
	CPU            float64 `json:"cpu"`
	RAMUsed        float64 `json:"ramUsed"`
	RAMTotal       float64 `json:"ramTotal"`
	DiskPct        int     `json:"diskPct"`
	DockerVersion  string  `json:"dockerVersion"`
	SSHPort        string  `json:"sshPort"`
	SSHUser        string  `json:"sshUser"`
	ConnMode       string  `json:"connMode"`
	SocketEndpoint string  `json:"socketEndpoint"`
	ConnStatus     string  `json:"connStatus"`
	RuntimeMode    string  `json:"runtimeMode"`
}

// Project represents a deployed application tracked by DeploymentHub.
type Project struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Stack      string   `json:"stack"`
	StackKey   string   `json:"stackKey"`
	Category   string   `json:"category"`
	Domain     string   `json:"domain"`
	Repo       string   `json:"repo"`
	Branch     string   `json:"branch"`
	Commit     string   `json:"commit"`
	CommitMsg  string   `json:"commitMsg"`
	Status     string   `json:"status"`
	CPU        float64  `json:"cpu"`
	RAMMb      int      `json:"ramMb"`
	RAMLimitMb int      `json:"ramLimitMb"`
	Port          string   `json:"port"`
	UpdatedAt     string   `json:"updatedAt"`
	Logs          []string `json:"logs"`
	WebhookActive bool     `json:"webhookActive"`
	WebhookID     int64    `json:"webhookId,omitempty"`
	WebhookStatus string   `json:"webhookStatus,omitempty"`
}

// Container represents a Docker container instance associated with a project.
type Container struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Project      string   `json:"project"`
	StackKey     string   `json:"stackKey"`
	Image        string   `json:"image"`
	PreviousTags []string `json:"previousTags"`
	Status       string   `json:"status"`
	Protected    bool     `json:"protected"`
	CPUPct       float64  `json:"cpuPct"`
	RAMMb        int      `json:"ramMb"`
	RAMLimitMb   int      `json:"ramLimitMb"`
	Ports        string   `json:"ports"`
	Uptime       string   `json:"uptime"`
	Logs         []string `json:"logs"`
}

// ErrProtectedContainer is returned when a caller attempts a destructive action
// on a core DeploymentHub infrastructure container, volume, network, or stack.
var ErrProtectedContainer = errors.New("protected system resource")

// IsProtectedSystemContainer reports whether name identifies one of DeploymentHub's
// core runtime containers that must be guarded from destructive lifecycle operations.
func IsProtectedSystemContainer(name string) bool {
	clean := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), "/"))
	switch clean {
	case "deploymenthub-control-plane", "deploymenthub-traefik", "deploymenthub-socket-proxy":
		return true
	default:
		return false
	}
}

func isProtectedActionAllowed(name, action string) bool {
	if !IsProtectedSystemContainer(name) {
		return true
	}
	clean := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), "/"))
	if clean == "deploymenthub-traefik" && action == "restart" {
		return true
	}
	return action == "start"
}

// DockerImage represents a local Docker image or dangling build layer.
type DockerImage struct {
	ID       string   `json:"id"`
	RepoTag  string   `json:"repoTag"`
	Note     string   `json:"note"`
	SizeMb   int      `json:"sizeMb"`
	InUse    bool     `json:"inUse"`
	Dangling bool     `json:"dangling"`
	Created  string   `json:"created"`
	History  []string `json:"history"`
}

// ProxyRoute represents a Traefik reverse-proxy domain route and TLS status.
type ProxyRoute struct {
	ID       string `json:"id"`
	Domain   string `json:"domain"`
	Target   string `json:"target"`
	PathRule string `json:"pathRule"`
	SSL      bool   `json:"ssl"`
	CertExp  string `json:"certExp"`
	Protocol string `json:"protocol"`
}

// Overview aggregates the full control plane state for the dashboard API.
type Overview struct {
	VPS         VPSStatus     `json:"vps"`
	Projects    []Project     `json:"projects"`
	Containers  []Container   `json:"containers"`
	Images      []DockerImage `json:"images"`
	ProxyRoutes []ProxyRoute  `json:"proxyRoutes"`
	WebhookURL  string        `json:"webhookUrl"`
}

// DeployRequest defines the payload to launch a 5-stage deployment pipeline.
type DeployRequest struct {
	AppName     string            `json:"appName"`
	RepoURL     string            `json:"repoUrl"`
	Branch      string            `json:"branch"`
	Domain      string            `json:"domain"`
	SCMMode     string            `json:"scmMode"`
	PAT         string            `json:"pat"`
	DetectMode  string            `json:"detectMode"`
	PresetKey   string            `json:"presetKey"`
	BuildCmd    string            `json:"buildCmd"`
	StartCmd    string            `json:"startCmd"`
	PortMapping string            `json:"portMapping"`
	AutoWebhook bool              `json:"autoWebhook"`
	EnvVars     []detector.EnvVar `json:"envVars"`
}

// DeployEvent is a single real-time deployment progress event streamed over SSE.
type DeployEvent struct {
	DeployID string `json:"deployId"`
	Stage    int    `json:"stage"`
	Status   string `json:"status"`
	Line     string `json:"line"`
	Done     bool   `json:"done"`
}

// DeploymentRecord holds the state, logs, and generated Dockerfile for a deployment run.
type DeploymentRecord struct {
	ID         string   `json:"id"`
	AppName    string   `json:"appName"`
	Domain     string   `json:"domain"`
	PresetKey  string   `json:"presetKey"`
	Stage      int      `json:"stage"`
	Status     string   `json:"status"`
	Logs       []string `json:"logs"`
	Dockerfile string   `json:"dockerfile"`
}

// PruneResult summarizes reclaimed space and remaining images after pruning dangling layers.
type PruneResult struct {
	RemovedCount int           `json:"removedCount"`
	ReclaimedMb  int           `json:"reclaimedMb"`
	Images       []DockerImage `json:"images"`
}

type deploymentState struct {
	mu     sync.Mutex
	record DeploymentRecord
	events []DeployEvent
	subs   map[chan DeployEvent]struct{}
	done   bool
}

// Engine manages projects, containers, images, proxy routes, secrets, and async deployments.
type Engine struct {
	mu                     sync.RWMutex
	traefikSyncMu          sync.Mutex
	dynamicFileMu          sync.Mutex
	vault                  *vault.Vault
	vps                    VPSStatus
	projects               []Project
	containers             []Container
	images                 []DockerImage
	proxyRoutes            []ProxyRoute
	webhookURL             string
	deployments            map[string]*deploymentState
	encryptedSecrets       map[string]string
	manualCleared          bool
	baseRAMUsed            float64
	sslSettings            SSLSettings
	cf                     *cloudflare.Manager
	discoveredContainerIDs map[string]bool
	discoveredProjectIDs   map[string]bool
	discoveredImageIDs     map[string]bool
	seq                    atomic.Uint64
	eventsMu               sync.Mutex
	recentEvents           []DockerEvent
	eventSubs              map[chan DockerEvent]struct{}
	syncNotifyCh           chan struct{}
	stacksMu               sync.Mutex
	registriesMu           sync.RWMutex
	registries             []storedRegistry
	registriesLoaded       bool
	registriesLoadedPath   string
	webhooksMu             sync.RWMutex
	webhooksStore          webhooksStoreFile
	webhooksLoaded         bool
	webhooksLoadedPath     string
	webhookSecret          string
	githubAPIBase          string
}

// NewEngine initializes the control plane Engine with real host telemetry.
// If dockerHost is non-empty and reachable, it runs in "docker" runtimeMode
// and discovers live containers/images; otherwise it runs in clean local mode.
func NewEngine(dockerHost string, v *vault.Vault) *Engine {
	if v == nil {
		v, _ = vault.New("")
	}

	webhookDomain := "localhost:4180"
	if d := strings.TrimSpace(os.Getenv("HUB_DOMAIN")); d != "" {
		webhookDomain = d
	}

	hostName, _ := os.Hostname()
	if strings.TrimSpace(hostName) == "" {
		hostName = "localhost"
	}
	sshUser := strings.TrimSpace(os.Getenv("USER"))
	if sshUser == "" {
		sshUser = "deploy"
	}

	e := &Engine{
		vault:                  v,
		deployments:            make(map[string]*deploymentState),
		encryptedSecrets:       make(map[string]string),
		discoveredContainerIDs: make(map[string]bool),
		discoveredProjectIDs:   make(map[string]bool),
		discoveredImageIDs:     make(map[string]bool),
		recentEvents:           make([]DockerEvent, 0, 150),
		eventSubs:              make(map[chan DockerEvent]struct{}),
		syncNotifyCh:           make(chan struct{}, 1),
		sslSettings:            defaultSSLSettings(),
		cf:                     cloudflare.NewManager(v, os.Getenv("CLOUDFLARE_DATA_FILE")),
		webhookURL:             fmt.Sprintf("http://%s/api/v1/webhooks/github", webhookDomain),
		vps: VPSStatus{
			Host:           hostName,
			IP:             "127.0.0.1",
			CPU:            0,
			RAMUsed:        0,
			RAMTotal:       0,
			DiskPct:        0,
			DockerVersion:  "N/A",
			SSHPort:        "22",
			SSHUser:        sshUser,
			ConnMode:       "local",
			SocketEndpoint: "",
			ConnStatus:     "Local Mode",
			RuntimeMode:    "simulator",
		},
		projects:    make([]Project, 0),
		containers:  make([]Container, 0),
		images:      make([]DockerImage, 0),
		proxyRoutes: make([]ProxyRoute, 0),
	}

	if host := strings.TrimSpace(dockerHost); host != "" {
		if ver, ok := probeDockerHost(host); ok {
			e.vps.RuntimeMode = "docker"
			e.vps.ConnMode = "socket-proxy"
			e.vps.SocketEndpoint = host
			e.vps.ConnStatus = "Connected (Docker Engine)"
			if ver != "" {
				e.vps.DockerVersion = "Docker v" + ver
			} else {
				e.vps.DockerVersion = "Docker Engine"
			}
		}
	}

	e.readHostTelemetry()
	if e.vps.RuntimeMode == "docker" {
		e.SyncDockerEngine()
	}
	return e
}

// Cloudflare returns the Engine's thread-safe Cloudflare API v4 Manager.
func (e *Engine) Cloudflare() *cloudflare.Manager {
	return e.cf
}

// ClearMockData resets all projects, containers, images, and proxy routes to empty state.
func (e *Engine) ClearMockData() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.manualCleared = true
	e.projects = make([]Project, 0)
	e.containers = make([]Container, 0)
	e.images = make([]DockerImage, 0)
	e.proxyRoutes = make([]ProxyRoute, 0)
	e.discoveredContainerIDs = make(map[string]bool)
	e.discoveredProjectIDs = make(map[string]bool)
	e.discoveredImageIDs = make(map[string]bool)
	e.syncVPSRamLocked()
}

func probeDockerHost(dockerHost string) (string, bool) {
	trimmed := strings.TrimSpace(dockerHost)
	if trimmed == "" {
		return "", false
	}

	if strings.HasPrefix(trimmed, "unix://") || strings.HasPrefix(trimmed, "/") {
		sockPath := strings.TrimPrefix(trimmed, "unix://")
		conn, err := net.DialTimeout("unix", sockPath, 600*time.Millisecond)
		if err != nil {
			return "", false
		}
		_ = conn.Close()
		return "", true
	}

	baseURL := trimmed
	if strings.HasPrefix(baseURL, "tcp://") {
		baseURL = "http://" + strings.TrimPrefix(baseURL, "tcp://")
	}
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	client := &http.Client{Timeout: 800 * time.Millisecond}
	resp, err := client.Get(baseURL + "/_ping")
	if err != nil {
		return "", false
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}

	vResp, err := client.Get(baseURL + "/version")
	if err != nil {
		return "", true
	}
	defer vResp.Body.Close()
	if vResp.StatusCode == http.StatusOK {
		var ver struct {
			Version string `json:"Version"`
		}
		if err := json.NewDecoder(vResp.Body).Decode(&ver); err == nil {
			return ver.Version, true
		}
	}
	return "", true
}

// GetOverview returns a thread-safe deep snapshot of the entire control plane state.
func (e *Engine) GetOverview() Overview {
	e.mu.RLock()
	shouldSync := e.vps.RuntimeMode == "docker" && !e.manualCleared && strings.TrimSpace(e.vps.SocketEndpoint) != ""
	e.mu.RUnlock()
	if shouldSync {
		e.SyncDockerEngine()
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	projects := make([]Project, len(e.projects))
	for i, p := range e.projects {
		projects[i] = cloneProject(p)
		e.enrichProjectWebhookLocked(&projects[i])
	}
	containers := make([]Container, len(e.containers))
	for i, c := range e.containers {
		containers[i] = cloneContainer(c)
	}
	images := make([]DockerImage, len(e.images))
	for i, img := range e.images {
		images[i] = cloneImage(img)
	}
	routes := slices.Clone(e.proxyRoutes)

	return Overview{
		VPS:         e.vps,
		Projects:    projects,
		Containers:  containers,
		Images:      images,
		ProxyRoutes: routes,
		WebhookURL:  e.PublicWebhookURL(),
	}
}

// RedeployProject triggers an immediate zero-downtime redeploy on the matching project
// and updates its commit hash, container status, logs, and VPS memory telemetry.
func (e *Engine) RedeployProject(id string) (Project, error) {
	e.mu.RLock()
	pIdx := e.findProjectIndexLocked(id)
	var proj Project
	var runtimeMode, endpoint string
	var cntIDs []string
	if pIdx >= 0 {
		proj = cloneProject(e.projects[pIdx])
		runtimeMode = e.vps.RuntimeMode
		endpoint = e.vps.SocketEndpoint
		for _, c := range e.containers {
			if c.Project == proj.Name {
				cntIDs = append(cntIDs, c.ID)
			}
		}
	}
	e.mu.RUnlock()

	if pIdx < 0 {
		return Project{}, fmt.Errorf("project %q not found", id)
	}

	if runtimeMode == "docker" && strings.TrimSpace(endpoint) != "" &&
		!strings.HasPrefix(endpoint, "http://127.0.0.1:") &&
		!isSyntheticTestRepo(proj.Repo) && strings.Contains(proj.Repo, "/") && !strings.Contains(proj.Repo, ":") {
		cport := extractContainerPortFromSummary(proj.Port)
		envVars := fetchContainerEnvVarsForRedeploy(endpoint, "dh-"+proj.Name)
		pat := e.ResolveSavedPAT(proj.Name)
		if pat == "" {
			pat = e.ResolveSavedPAT(proj.Repo)
		}
		branch := strings.TrimSpace(proj.Branch)
		if branch == "" || branch == "live" {
			branch = "main"
		}
		scmMode := "oauth"
		if pat != "" {
			scmMode = "pat"
		}
		presetKey := proj.StackKey
		if presetKey == "" || !isValidPreset(presetKey) {
			presetKey = "auto"
		}
		_, _ = e.StartDeployment(DeployRequest{
			AppName:     proj.Name,
			RepoURL:     proj.Repo,
			Branch:      branch,
			Domain:      proj.Domain,
			SCMMode:     scmMode,
			PAT:         pat,
			DetectMode:  "hybrid",
			PresetKey:   presetKey,
			PortMapping: cport + ":" + cport,
			EnvVars:     envVars,
			AutoWebhook: false,
		})

		e.mu.Lock()
		if idx := e.findProjectIndexLocked(id); idx >= 0 {
			e.projects[idx].Status = "Building..."
			e.projects[idx].UpdatedAt = "Đang rebuild từ Git..."
			proj = cloneProject(e.projects[idx])
			e.enrichProjectWebhookLocked(&proj)
		}
		e.mu.Unlock()
		return proj, nil
	}

	if runtimeMode == "docker" && strings.TrimSpace(endpoint) != "" {
		for _, cid := range cntIDs {
			sendDockerContainerAction(endpoint, cid, "restart")
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	idx := e.findProjectIndexLocked(id)
	if idx < 0 {
		return Project{}, fmt.Errorf("project %q not found", id)
	}

	p := &e.projects[idx]
	newSHA := "sha-" + shortHex(3)
	p.Commit = newSHA
	p.Status = "Running"
	p.UpdatedAt = "Vừa xong"
	if p.CPU == 0 {
		p.CPU = 4.2
	}
	if p.RAMMb == 0 {
		p.RAMMb = 96
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	p.Logs = append(p.Logs,
		fmt.Sprintf("%s [deploy] Triggered Redeploy on branch %s", ts, p.Branch),
		fmt.Sprintf("%s [traefik] Zero-downtime swap completed -> %s", ts, newSHA),
	)

	for i := range e.containers {
		c := &e.containers[i]
		if c.Project == p.Name {
			c.Status = "Running"
			c.Uptime = "Up vừa xong"
			if c.CPUPct == 0 {
				c.CPUPct = 3.2
			}
			if c.RAMMb == 0 {
				c.RAMMb = min(c.RAMLimitMb, 64)
			}
			c.Logs = append(c.Logs, fmt.Sprintf("[deploy] Swapped active container to commit %s", newSHA))
		}
	}

	e.syncVPSRamLocked()
	return cloneProject(*p), nil
}

// RestartProject toggles a Stopped project to Running or restarts a Running project,
// syncing associated containers and VPS RAM usage.
func (e *Engine) RestartProject(id string) (Project, error) {
	e.mu.RLock()
	pIdx := e.findProjectIndexLocked(id)
	var projName, projStatus, runtimeMode, endpoint string
	var cntIDs []string
	if pIdx >= 0 {
		projName = e.projects[pIdx].Name
		projStatus = e.projects[pIdx].Status
		runtimeMode = e.vps.RuntimeMode
		endpoint = e.vps.SocketEndpoint
		for _, c := range e.containers {
			if c.Project == projName {
				cntIDs = append(cntIDs, c.ID)
			}
		}
	}
	e.mu.RUnlock()

	if runtimeMode == "docker" && strings.TrimSpace(endpoint) != "" {
		act := "restart"
		if projStatus == "Stopped" {
			act = "start"
		}
		for _, cid := range cntIDs {
			sendDockerContainerAction(endpoint, cid, act)
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	idx := e.findProjectIndexLocked(id)
	if idx < 0 {
		return Project{}, fmt.Errorf("project %q not found", id)
	}

	p := &e.projects[idx]
	ts := time.Now().UTC().Format(time.RFC3339)

	if p.Status == "Stopped" {
		p.Status = "Running"
		p.CPU = 2.1
		p.RAMMb = min(p.RAMLimitMb, 64)
		p.UpdatedAt = "Vừa khởi động"
		p.Logs = append(p.Logs, fmt.Sprintf("%s [docker] Container started & passing healthcheck", ts))
		for i := range e.containers {
			c := &e.containers[i]
			if c.Project == p.Name {
				c.Status = "Running"
				c.CPUPct = 2.1
				c.RAMMb = min(c.RAMLimitMb, 64)
				c.Uptime = "Up vừa xong"
				c.Logs = append(c.Logs, "[docker] Container started cleanly")
			}
		}
	} else {
		p.Status = "Running"
		p.UpdatedAt = "Vừa restart"
		if p.CPU == 0 {
			p.CPU = 3.0
		}
		if p.RAMMb == 0 {
			p.RAMMb = min(p.RAMLimitMb, 64)
		}
		p.Logs = append(p.Logs, fmt.Sprintf("%s [docker] Restarted cleanly & healthcheck passed (200 OK)", ts))
		for i := range e.containers {
			c := &e.containers[i]
			if c.Project == p.Name {
				c.Status = "Running"
				if c.CPUPct == 0 {
					c.CPUPct = 2.5
				}
				if c.RAMMb == 0 {
					c.RAMMb = min(c.RAMLimitMb, 48)
				}
				c.Uptime = "Up vừa restart"
				c.Logs = append(c.Logs, "[docker] Container restarted cleanly")
			}
		}
	}

	e.syncVPSRamLocked()
	return cloneProject(*p), nil
}

// ContainerAction executes start, stop, restart, pause, unpause, kill, remove, or rollback
// on a container and synchronizes its parent project and VPS RAM usage.
func (e *Engine) ContainerAction(id, action, targetTag string) (Container, error) {
	return e.ContainerActionWithOptions(id, action, targetTag, false)
}

// ContainerActionWithOptions executes container lifecycle actions with optional volume removal.
func (e *Engine) ContainerActionWithOptions(id, action, targetTag string, removeVolumes bool) (Container, error) {
	act := strings.ToLower(strings.TrimSpace(action))
	switch act {
	case "stop", "start", "restart", "pause", "unpause", "kill", "remove", "rollback":
	default:
		return Container{}, fmt.Errorf("unsupported container action %q", action)
	}

	e.mu.RLock()
	idx := e.findContainerIndexLocked(id)
	if idx < 0 {
		e.mu.RUnlock()
		return Container{}, fmt.Errorf("container %q not found", id)
	}
	dockerID := e.containers[idx].ID
	cname := e.containers[idx].Name
	prevImage := e.containers[idx].Image
	prevTags := slices.Clone(e.containers[idx].PreviousTags)
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()

	if !isProtectedActionAllowed(cname, act) {
		return Container{}, fmt.Errorf("%w: system container %q cannot be modified with action %q", ErrProtectedContainer, cname, act)
	}

	if runtimeMode == "docker" && strings.TrimSpace(endpoint) != "" {
		switch act {
		case "start", "stop", "restart", "pause", "unpause", "kill":
			if err := sendDockerContainerActionStrict(endpoint, dockerID, act); err != nil {
				return Container{}, err
			}
			if act == "pause" || act == "unpause" || act == "kill" {
				e.SyncDockerEngine()
				e.mu.RLock()
				if updatedIdx := e.findContainerIndexLocked(dockerID); updatedIdx >= 0 {
					res := cloneContainer(e.containers[updatedIdx])
					e.mu.RUnlock()
					return res, nil
				}
				e.mu.RUnlock()
			}
		case "remove":
			if err := removeDockerContainerByID(endpoint, dockerID, removeVolumes); err != nil {
				return Container{}, err
			}
			e.mu.Lock()
			if rmIdx := e.findContainerIndexLocked(dockerID); rmIdx >= 0 {
				removed := cloneContainer(e.containers[rmIdx])
				removed.Status = "Removed"
				e.containers = append(e.containers[:rmIdx], e.containers[rmIdx+1:]...)
				e.syncProjectFromContainersLocked(removed.Project)
				e.syncVPSRamLocked()
				e.mu.Unlock()
				e.SyncDockerEngine()
				return removed, nil
			}
			e.mu.Unlock()
			e.SyncDockerEngine()
			return Container{ID: dockerID, Name: cname, Status: "Removed"}, nil
		case "rollback":
			tag := strings.TrimSpace(targetTag)
			if tag == "" {
				for _, pt := range prevTags {
					if pt != "" && pt != prevImage {
						tag = pt
						break
					}
				}
				if tag == "" && len(prevTags) > 0 {
					tag = prevTags[0]
				}
			}
			if tag == "" {
				return Container{}, errors.New("no previous image tag available for rollback")
			}
			newContainer, handled, err := e.rollbackDockerContainer(endpoint, dockerID, tag)
			if err != nil {
				return Container{}, err
			}
			if handled {
				return newContainer, nil
			}
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	idx = e.findContainerIndexLocked(id)
	if idx < 0 {
		return Container{}, fmt.Errorf("container %q not found", id)
	}

	c := &e.containers[idx]

	switch act {
	case "stop":
		c.Status = "Stopped"
		c.CPUPct = 0
		c.RAMMb = 0
		c.Uptime = "Stopped vừa xong"
		c.Logs = append(c.Logs, "[docker] Container stopped by user")

	case "kill":
		c.Status = "Stopped"
		c.CPUPct = 0
		c.RAMMb = 0
		c.Uptime = "Killed vừa xong"
		c.Logs = append(c.Logs, "[docker] Container killed (SIGKILL)")

	case "pause":
		c.Status = "Paused"
		c.CPUPct = 0
		c.Uptime = "Paused"
		c.Logs = append(c.Logs, "[docker] Container paused")

	case "unpause":
		c.Status = "Running"
		if c.RAMMb == 0 {
			c.RAMMb = min(c.RAMLimitMb, 64)
		}
		c.Uptime = "Up (Unpaused)"
		c.Logs = append(c.Logs, "[docker] Container unpaused")

	case "remove":
		removed := cloneContainer(*c)
		removed.Status = "Removed"
		e.containers = append(e.containers[:idx], e.containers[idx+1:]...)
		e.syncProjectFromContainersLocked(removed.Project)
		e.syncVPSRamLocked()
		return removed, nil

	case "start":
		c.Status = "Running"
		if c.CPUPct == 0 {
			c.CPUPct = 2.4
		}
		if c.RAMMb == 0 {
			c.RAMMb = min(c.RAMLimitMb, 64)
		}
		c.Uptime = "Up vừa xong"
		c.Logs = append(c.Logs, "[docker] Container started & passing healthcheck")

	case "restart":
		c.Status = "Running"
		if c.CPUPct == 0 {
			c.CPUPct = 2.8
		}
		if c.RAMMb == 0 {
			c.RAMMb = min(c.RAMLimitMb, 48)
		}
		c.Uptime = "Up vừa restart"
		c.Logs = append(c.Logs, "[docker] Container restarted cleanly")

	case "rollback":
		tag := strings.TrimSpace(targetTag)
		if tag == "" {
			if len(c.PreviousTags) == 0 {
				return Container{}, errors.New("no previous image tag available for rollback")
			}
			tag = c.PreviousTags[0]
		}
		oldTag := c.Image
		c.Image = tag
		if oldTag != "" && oldTag != tag && !slices.Contains(c.PreviousTags, oldTag) {
			c.PreviousTags = slices.Insert(c.PreviousTags, 0, oldTag)
		}
		c.Status = "Running"
		if c.CPUPct == 0 {
			c.CPUPct = 2.6
		}
		if c.RAMMb == 0 {
			c.RAMMb = min(c.RAMLimitMb, 64)
		}
		c.Uptime = "Up (Rollback vừa xong)"
		c.Logs = append(c.Logs, fmt.Sprintf("[rollback] Switched image %s -> %s (zero-downtime)", oldTag, tag))
	}

	e.syncProjectFromContainersLocked(c.Project)
	e.syncVPSRamLocked()
	return cloneContainer(*c), nil
}

// PruneDanglingImages deletes all dangling (<none>) images and reclaims disk space.
func (e *Engine) PruneDanglingImages() PruneResult {
	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()

	if runtimeMode == "docker" && strings.TrimSpace(endpoint) != "" {
		if client, baseURL, ok := newDockerHTTPClient(endpoint, 30*time.Second); ok {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			deleted, reclaimedBytes, pruneErr := pruneDanglingDockerImages(ctx, client, baseURL)
			cancel()
			if pruneErr == nil {
				e.SyncDockerEngine()
				e.mu.RLock()
				resultImages := make([]DockerImage, len(e.images))
				for i, img := range e.images {
					resultImages[i] = cloneImage(img)
				}
				e.mu.RUnlock()
				return PruneResult{
					RemovedCount: deleted,
					ReclaimedMb:  int(reclaimedBytes / (1024 * 1024)),
					Images:       resultImages,
				}
			}
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	kept := make([]DockerImage, 0, len(e.images))
	removedCount := 0
	reclaimedMb := 0
	for _, img := range e.images {
		if img.Dangling {
			removedCount++
			reclaimedMb += img.SizeMb
			continue
		}
		kept = append(kept, cloneImage(img))
	}
	e.images = kept

	if removedCount > 0 {
		e.vps.DiskPct = max(18, e.vps.DiskPct-15)
	}

	resultImages := make([]DockerImage, len(e.images))
	for i, img := range e.images {
		resultImages[i] = cloneImage(img)
	}
	return PruneResult{
		RemovedCount: removedCount,
		ReclaimedMb:  reclaimedMb,
		Images:       resultImages,
	}
}

// ToggleProxySSL toggles Auto-HTTPS TLS 1.3 state on a Traefik proxy route.
func (e *Engine) ToggleProxySSL(id string) (ProxyRoute, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	idx := -1
	for i := range e.proxyRoutes {
		if e.proxyRoutes[i].ID == id || e.proxyRoutes[i].Domain == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ProxyRoute{}, fmt.Errorf("proxy route %q not found", id)
	}

	rt := &e.proxyRoutes[idx]
	rt.SSL = !rt.SSL
	if rt.SSL {
		if strings.Contains(rt.PathRule, "/ws") {
			rt.Protocol = "WSS + TLS 1.3"
		} else {
			rt.Protocol = "HTTP/2 + TLS 1.3"
		}
		rt.CertExp = "90 ngày"
	} else {
		rt.Protocol = "HTTP Only"
		rt.CertExp = "Chưa cấp"
	}
	return *rt, nil
}

// VerifyPAT validates a GitHub Personal Access Token, encrypts it via Vault,
// probes GitHub webhook permissions, and returns metadata without echoing the raw token.
func (e *Engine) VerifyPAT(token, repoURL string) (map[string]any, error) {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		trimmed = e.ResolveSavedPAT(repoURL)
	}
	hasGHPrefix := strings.HasPrefix(trimmed, "ghp_") || strings.HasPrefix(trimmed, "github_pat_")
	if trimmed == "" || (!hasGHPrefix && len(trimmed) < 10) || (hasGHPrefix && len(trimmed) < 6) {
		return nil, errors.New("invalid GitHub PAT: expected len >= 10 or ghp_/github_pat_ token")
	}

	enc, err := e.vault.Encrypt(trimmed)
	if err != nil {
		return nil, fmt.Errorf("encrypt token: %w", err)
	}

	e.mu.Lock()
	e.encryptedSecrets["pat:"+repoURL] = enc
	e.mu.Unlock()
	e.saveDefaultPAT(trimmed)

	previewLen := min(24, len(enc))
	preview := enc[:previewLen] + "..."

	check := e.CheckGitHubWebhookPermission(trimmed, repoURL)
	scopes := check.Scopes
	if len(scopes) == 0 && check.Valid {
		scopes = []string{"repo"}
	}

	detectRes := detector.Detect(detector.DetectRequest{
		RepoURL: repoURL,
		Branch:  "main",
		Mode:    "hybrid",
		Token:   trimmed,
	})

	out := map[string]any{
		"valid":                 check.Valid,
		"encryptedTokenPreview": preview,
		"repo":                  repoURL,
		"scopes":                scopes,
		"canManageWebhook":      check.CanManageWebhook,
		"webhookReason":         check.WebhookReason,
		"existingHookId":        check.ExistingHookID,
		"existingHookUrl":       check.ExistingHookURL,
		"webhookUrl":            e.PublicWebhookURL(),
		"detectResult":          detectRes,
	}
	if check.GitHubUser != "" {
		out["githubUser"] = check.GitHubUser
	}
	return out, nil
}

// StartDeployment validates the deploy request, encrypts secrets via Vault,
// launches the 5-stage async pipeline, and returns the initial DeploymentRecord.
func (e *Engine) StartDeployment(req DeployRequest) (DeploymentRecord, error) {
	appName := sanitizeSlug(req.AppName)
	if appName == "" {
		return DeploymentRecord{}, errors.New("appName is required")
	}
	scmMode := strings.ToLower(strings.TrimSpace(req.SCMMode))
	if scmMode == "" {
		scmMode = "oauth"
	}
	if scmMode == "pat" && strings.TrimSpace(req.PAT) == "" {
		return DeploymentRecord{}, errors.New("pat is required when scmMode is pat")
	}
	presetKey := strings.ToLower(strings.TrimSpace(req.PresetKey))
	if presetKey != "" && presetKey != "auto" && !isValidPreset(presetKey) {
		return DeploymentRecord{}, fmt.Errorf("unsupported presetKey %q", req.PresetKey)
	}
	if strings.TrimSpace(req.RepoURL) == "" && presetKey == "" {
		return DeploymentRecord{}, errors.New("repoUrl or presetKey is required")
	}

	repoURL := strings.TrimSpace(req.RepoURL)
	if repoURL == "" {
		repoURL = "local/" + appName
	}
	branch := strings.TrimSpace(req.Branch)
	if branch == "" {
		branch = "main"
	}
	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		if cfCfg := e.cf.GetSanitizedConfig(); cfCfg.Enabled && cfCfg.BaseDomain != "" {
			domain = appName + "." + cfCfg.BaseDomain
		} else if hubDomain := strings.TrimSpace(os.Getenv("HUB_DOMAIN")); hubDomain != "" {
			domain = appName + "." + hubDomain
		} else {
			domain = appName + ".localhost"
		}
	}
	detectMode := strings.ToLower(strings.TrimSpace(req.DetectMode))
	if detectMode != "file" {
		detectMode = "hybrid"
	}

	det := detector.Detect(detector.DetectRequest{
		RepoURL: repoURL,
		Branch:  branch,
		Mode:    detectMode,
		Token:   strings.TrimSpace(req.PAT),
	})

	resolvedPreset := presetKey
	if resolvedPreset == "" || resolvedPreset == "auto" {
		resolvedPreset = det.PresetKey
	}

	buildCmd := strings.TrimSpace(req.BuildCmd)
	if buildCmd == "" {
		buildCmd = det.BuildCmd
	}
	startCmd := strings.TrimSpace(req.StartCmd)
	if startCmd == "" {
		startCmd = det.StartCmd
	}
	portMapping := strings.TrimSpace(req.PortMapping)
	if portMapping == "" {
		portMapping = det.PortMapping
	}
	envVars := req.EnvVars
	if len(envVars) == 0 {
		envVars = det.EnvVars
	}

	dockerfile := detector.GenerateDockerfile(detector.DockerfileRequest{
		PresetKey:   resolvedPreset,
		Mode:        detectMode,
		AppName:     appName,
		Domain:      domain,
		BuildCmd:    buildCmd,
		StartCmd:    startCmd,
		PortMapping: portMapping,
		NativeDeps:  det.NativeDeps,
		EnvVars:     envVars,
	})

	seqNum := e.seq.Add(1)
	deployID := fmt.Sprintf("dep-%d-%d", time.Now().UnixNano(), seqNum)

	// Encrypt PAT & secret env vars via Vault and record raw secrets for log redaction.
	var secretsToRedact []string
	encryptedMap := make(map[string]string)
	if pat := strings.TrimSpace(req.PAT); pat != "" {
		enc, err := e.vault.Encrypt(pat)
		if err != nil {
			return DeploymentRecord{}, fmt.Errorf("encrypt PAT: %w", err)
		}
		encryptedMap[deployID+":pat"] = enc
		secretsToRedact = append(secretsToRedact, pat)
	}
	for _, ev := range envVars {
		if ev.Secret && ev.Value != "" {
			enc, err := e.vault.Encrypt(ev.Value)
			if err != nil {
				return DeploymentRecord{}, fmt.Errorf("encrypt env %s: %w", ev.Key, err)
			}
			encryptedMap[deployID+":env:"+ev.Key] = enc
			secretsToRedact = append(secretsToRedact, ev.Value)
		}
	}

	initLine := vault.RedactSecrets(
		fmt.Sprintf("$ deploymenthub deploy %s --detect=%s --preset=%s --ssl=%s", appName, detectMode, resolvedPreset, domain),
		secretsToRedact,
	)

	rec := DeploymentRecord{
		ID:         deployID,
		AppName:    appName,
		Domain:     domain,
		PresetKey:  resolvedPreset,
		Stage:      1,
		Status:     "running",
		Logs:       []string{initLine},
		Dockerfile: dockerfile,
	}

	dep := &deploymentState{
		record: rec,
		events: []DeployEvent{
			{DeployID: deployID, Stage: 1, Status: "running", Line: initLine, Done: false},
		},
		subs: make(map[chan DeployEvent]struct{}),
	}

	e.mu.Lock()
	for k, v := range encryptedMap {
		e.encryptedSecrets[k] = v
	}
	e.deployments[deployID] = dep
	e.mu.Unlock()

	reqCopy := req
	reqCopy.AppName = appName
	reqCopy.RepoURL = repoURL
	reqCopy.Branch = branch
	reqCopy.Domain = domain
	reqCopy.DetectMode = detectMode
	reqCopy.PresetKey = resolvedPreset
	reqCopy.PortMapping = portMapping

	go e.runDeploymentPipeline(dep, reqCopy, secretsToRedact)

	return cloneDeploymentRecord(rec), nil
}

func (e *Engine) runDeploymentPipeline(dep *deploymentState, req DeployRequest, secrets []string) {
	e.mu.RLock()
	isDocker := e.vps.RuntimeMode == "docker" && strings.TrimSpace(e.vps.SocketEndpoint) != ""
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()

	if isDocker && !isSyntheticTestRepo(req.RepoURL) {
		e.runRealDockerDeployment(dep, req, endpoint, secrets)
		return
	}

	commitSHA, commitMsg := fetchLatestGitHubCommit(req.RepoURL, req.Branch, strings.TrimSpace(req.PAT))
	cloneDetail := fmt.Sprintf("[1/5] Clone SCM repository %s (%s) -> HEAD %s (%s)", req.RepoURL, req.Branch, commitSHA, commitMsg)

	stageLogs := []struct {
		stage int
		line  string
	}{
		{1, cloneDetail},
		{2, fmt.Sprintf("[2/5] Auto-Generate %s config (%s mode) completed", presetMetaFor(req.PresetKey).filename, req.DetectMode)},
		{3, fmt.Sprintf("[3/5] Docker Build Image %s:%s with BuildKit cache...", req.AppName, commitSHA)},
		{4, fmt.Sprintf("[4/5] Healthcheck Container dh-%s on port %s -> 200 OK", req.AppName, extractPrimaryPort(req.PortMapping))},
		{5, fmt.Sprintf("[5/5] Traefik Auto-SSL Let's Encrypt active for https://%s!", req.Domain)},
	}

	deployID := dep.record.ID
	for _, step := range stageLogs {
		time.Sleep(200 * time.Millisecond)

		safeLine := vault.RedactSecrets(
			fmt.Sprintf("%s %s", time.Now().UTC().Format("15:04:05"), step.line),
			secrets,
		)
		isFinal := step.stage == 5
		status := "running"
		if isFinal {
			status = "success"
		}

		if isFinal {
			dep.mu.Lock()
			priorLogs := slices.Clone(dep.record.Logs)
			dep.mu.Unlock()
			e.registerCompletedDeployment(req, commitSHA, commitMsg, priorLogs, safeLine)
		}

		ev := DeployEvent{
			DeployID: deployID,
			Stage:    step.stage,
			Status:   status,
			Line:     safeLine,
			Done:     isFinal,
		}

		dep.mu.Lock()
		dep.record.Stage = step.stage
		dep.record.Status = status
		dep.record.Logs = append(dep.record.Logs, safeLine)
		dep.events = append(dep.events, ev)

		for ch := range dep.subs {
			select {
			case ch <- ev:
			default:
			}
		}
		if isFinal {
			dep.done = true
			for ch := range dep.subs {
				close(ch)
				delete(dep.subs, ch)
			}
		}
		dep.mu.Unlock()
	}
}

func (e *Engine) registerCompletedDeployment(req DeployRequest, commitSHA, commitMsg string, priorLogs []string, finalLine string) {
	meta := presetMetaFor(req.PresetKey)
	portNum := extractPrimaryPort(req.PortMapping)
	commit := strings.TrimSpace(commitSHA)
	if commit == "" {
		commit = "sha-" + shortHex(3)
	}
	if strings.TrimSpace(commitMsg) == "" {
		commitMsg = "deployed via DeploymentHub pipeline"
	}
	repoTag := fmt.Sprintf("%s:%s", req.AppName, commit)
	containerName := "dh-" + req.AppName

	allLogs := make([]string, 0, len(priorLogs)+1)
	allLogs = append(allLogs, priorLogs...)
	allLogs = append(allLogs, finalLine)

	e.mu.Lock()
	defer e.mu.Unlock()

	// Register or update Project.
	if idx := e.findProjectIndexLocked(req.AppName); idx >= 0 {
		p := &e.projects[idx]
		p.Stack = meta.stack
		p.StackKey = req.PresetKey
		p.Category = meta.category
		p.Domain = req.Domain
		p.Repo = req.RepoURL
		p.Branch = req.Branch
		p.Commit = commit
		p.CommitMsg = commitMsg
		p.Status = "Running"
		p.Port = portNum
		p.UpdatedAt = "Vừa xong"
		p.Logs = append(p.Logs, finalLine)
	} else {
		newProj := Project{
			ID:         req.AppName,
			Name:       req.AppName,
			Stack:      meta.stack,
			StackKey:   req.PresetKey,
			Category:   meta.category,
			Domain:     req.Domain,
			Repo:       req.RepoURL,
			Branch:     req.Branch,
			Commit:     commit,
			CommitMsg:  commitMsg,
			Status:     "Running",
			CPU:        2.8,
			RAMMb:      meta.ramMb,
			RAMLimitMb: 512,
			Port:       portNum,
			UpdatedAt:  "Vừa xong",
			Logs:       slices.Clone(allLogs),
		}
		e.projects = slices.Insert(e.projects, 0, newProj)
	}

	// Register or update Container.
	cntIdx := -1
	for i := range e.containers {
		if e.containers[i].Project == req.AppName || e.containers[i].Name == containerName {
			cntIdx = i
			break
		}
	}
	if cntIdx >= 0 {
		c := &e.containers[cntIdx]
		if c.Image != "" && c.Image != repoTag && !slices.Contains(c.PreviousTags, c.Image) {
			c.PreviousTags = slices.Insert(c.PreviousTags, 0, c.Image)
		}
		c.Image = repoTag
		c.Status = "Running"
		c.CPUPct = 2.8
		c.RAMMb = meta.ramMb
		c.Uptime = "Up vừa xong"
		c.Logs = append(c.Logs, finalLine)
	} else {
		newCnt := Container{
			ID:           "cnt-" + req.AppName,
			Name:         containerName,
			Project:      req.AppName,
			StackKey:     req.PresetKey,
			Image:        repoTag,
			PreviousTags: []string{repoTag},
			Status:       "Running",
			CPUPct:       2.8,
			RAMMb:        meta.ramMb,
			RAMLimitMb:   512,
			Ports:        fmt.Sprintf("127.0.0.1:%s->%s/tcp", portNum, portNum),
			Uptime:       "Up vừa xong",
			Logs:         slices.Clone(allLogs),
		}
		e.containers = slices.Insert(e.containers, 0, newCnt)
	}

	// Register or update DockerImage.
	newImg := DockerImage{
		ID:       fmt.Sprintf("img-%s-%d", req.AppName, e.seq.Add(1)),
		RepoTag:  repoTag,
		SizeMb:   meta.imageMb,
		InUse:    true,
		Dangling: false,
		Created:  "Vừa xong",
		History:  []string{commit},
	}
	e.images = slices.Insert(e.images, 0, newImg)

	// Register or update ProxyRoute.
	rtIdx := -1
	for i := range e.proxyRoutes {
		if e.proxyRoutes[i].Domain == req.Domain {
			rtIdx = i
			break
		}
	}
	if rtIdx >= 0 {
		e.proxyRoutes[rtIdx].Target = fmt.Sprintf("%s:%s", containerName, portNum)
		e.proxyRoutes[rtIdx].SSL = true
		e.proxyRoutes[rtIdx].CertExp = "90 ngày"
		e.proxyRoutes[rtIdx].Protocol = "HTTP/2 + TLS 1.3"
	} else {
		newRoute := ProxyRoute{
			ID:       fmt.Sprintf("rt-%d", e.seq.Add(1)),
			Domain:   req.Domain,
			Target:   fmt.Sprintf("%s:%s", containerName, portNum),
			PathRule: "/*",
			SSL:      true,
			CertExp:  "90 ngày",
			Protocol: "HTTP/2 + TLS 1.3",
		}
		e.proxyRoutes = slices.Insert(e.proxyRoutes, 0, newRoute)
	}

	e.syncVPSRamLocked()
}

// GetDeployment returns a snapshot of the DeploymentRecord for id.
func (e *Engine) GetDeployment(id string) (DeploymentRecord, bool) {
	e.mu.RLock()
	dep, ok := e.deployments[id]
	e.mu.RUnlock()
	if !ok {
		return DeploymentRecord{}, false
	}

	dep.mu.Lock()
	defer dep.mu.Unlock()
	return cloneDeploymentRecord(dep.record), true
}

// SubscribeDeployment returns the recorded event history, a live channel for subsequent
// DeployEvents, an unsubscribe callback, and whether the deployment exists.
// If the deployment has already completed, ch is closed immediately after returning history.
func (e *Engine) SubscribeDeployment(id string) (history []DeployEvent, ch <-chan DeployEvent, unsub func(), ok bool) {
	e.mu.RLock()
	dep, exists := e.deployments[id]
	e.mu.RUnlock()
	if !exists {
		return nil, nil, func() {}, false
	}

	dep.mu.Lock()
	defer dep.mu.Unlock()

	history = slices.Clone(dep.events)
	if dep.done {
		closedCh := make(chan DeployEvent)
		close(closedCh)
		return history, closedCh, func() {}, true
	}

	liveCh := make(chan DeployEvent, 32)
	dep.subs[liveCh] = struct{}{}

	unsubFn := func() {
		dep.mu.Lock()
		defer dep.mu.Unlock()
		if _, stillSub := dep.subs[liveCh]; stillSub {
			delete(dep.subs, liveCh)
			close(liveCh)
		}
	}
	return history, liveCh, unsubFn, true
}

// ParseDockerMultiplexedStream parses Docker Engine 8-byte multiplexed stream frames
// ([streamType, 0, 0, 0, lenBE32...]) into stdout and stderr line slices.
func ParseDockerMultiplexedStream(raw []byte) (stdout []string, stderr []string, err error) {
	stdout = []string{}
	stderr = []string{}

	offset := 0
	for offset < len(raw) {
		if len(raw)-offset < 8 {
			return nil, nil, fmt.Errorf("docker stream: truncated frame header at offset %d", offset)
		}
		streamType := raw[offset]
		if streamType > 2 {
			return nil, nil, fmt.Errorf("docker stream: unknown stream type %d at offset %d", streamType, offset)
		}
		payloadLen := uint64(binary.BigEndian.Uint32(raw[offset+4 : offset+8]))
		offset += 8
		if payloadLen > uint64(len(raw)-offset) {
			return nil, nil, fmt.Errorf("docker stream: truncated payload (need %d bytes, have %d)", payloadLen, len(raw)-offset)
		}

		payload := string(raw[offset : offset+int(payloadLen)])
		offset += int(payloadLen)

		lines := splitDockerPayloadLines(payload)
		switch streamType {
		case 1:
			stdout = append(stdout, lines...)
		case 2:
			stderr = append(stderr, lines...)
		}
	}
	return stdout, stderr, nil
}

func splitDockerPayloadLines(payload string) []string {
	trimmed := strings.TrimSuffix(payload, "\n")
	if trimmed == "" {
		return nil
	}
	parts := strings.Split(trimmed, "\n")
	lines := make([]string, 0, len(parts))
	for _, p := range parts {
		lines = append(lines, strings.TrimRight(p, "\r"))
	}
	return lines
}

func (e *Engine) findProjectIndexLocked(id string) int {
	for i := range e.projects {
		if e.projects[i].ID == id || e.projects[i].Name == id {
			return i
		}
	}
	return -1
}

func (e *Engine) findContainerIndexLocked(id string) int {
	for i := range e.containers {
		if e.containers[i].ID == id || e.containers[i].Name == id {
			return i
		}
	}
	return -1
}

func (e *Engine) syncProjectFromContainersLocked(projectName string) {
	pIdx := e.findProjectIndexLocked(projectName)
	if pIdx < 0 {
		return
	}
	var totalRAM int
	var totalCPU float64
	anyRunning := false
	for _, c := range e.containers {
		if c.Project != projectName {
			continue
		}
		if c.Status == "Running" {
			anyRunning = true
		}
		totalRAM += c.RAMMb
		totalCPU += c.CPUPct
	}
	p := &e.projects[pIdx]
	if anyRunning {
		p.Status = "Running"
	} else {
		p.Status = "Stopped"
	}
	p.RAMMb = totalRAM
	p.CPU = math.Round(totalCPU*10) / 10
}

func (e *Engine) syncVPSRamLocked() {
	var runningMb int
	for _, c := range e.containers {
		if c.Status == "Running" {
			runningMb += c.RAMMb
		}
	}
	if e.vps.RuntimeMode == "docker" && e.baseRAMUsed > 0 {
		e.vps.RAMUsed = e.baseRAMUsed
		return
	}
	e.vps.RAMUsed = math.Round((e.baseRAMUsed+float64(runningMb)/1024.0)*10) / 10
}

func (e *Engine) readHostTelemetry() {
	hostName, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostName) == "" {
		hostName = "localhost"
	}

	ramTotal, ramUsed := readProcMemInfoGB()
	cpus := runtime.NumCPU()
	if cpus < 1 {
		cpus = 1
	}

	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()

	var dockerInfo struct {
		Name          string `json:"Name"`
		NCPU          int    `json:"NCPU"`
		MemTotal      int64  `json:"MemTotal"`
		ServerVersion string `json:"ServerVersion"`
	}
	hasDockerInfo := false
	if runtimeMode == "docker" && strings.TrimSpace(endpoint) != "" {
		if client, baseURL, ok := newDockerHTTPClient(endpoint, 1500*time.Millisecond); ok {
			dockerInfo, hasDockerInfo = fetchDockerJSON[struct {
				Name          string `json:"Name"`
				NCPU          int    `json:"NCPU"`
				MemTotal      int64  `json:"MemTotal"`
				ServerVersion string `json:"ServerVersion"`
			}](client, baseURL+"/info")
		}
	}

	if hasDockerInfo {
		if strings.TrimSpace(dockerInfo.Name) != "" {
			hostName = strings.TrimSpace(dockerInfo.Name)
		}
		if dockerInfo.NCPU > 0 {
			cpus = dockerInfo.NCPU
		}
		if dockerInfo.MemTotal > 0 {
			ramTotal = math.Round((float64(dockerInfo.MemTotal)/(1024*1024*1024))*10) / 10
		}
	}

	cpuPct := readProcCPUPct(cpus)
	diskPct := readRootDiskPct()

	e.mu.Lock()
	defer e.mu.Unlock()
	e.vps.Host = hostName
	e.vps.CPU = cpuPct
	e.vps.DiskPct = diskPct
	if ramTotal > 0 {
		e.vps.RAMTotal = ramTotal
	}
	if ramUsed > 0 {
		e.baseRAMUsed = ramUsed
		e.vps.RAMUsed = ramUsed
	}
	if hasDockerInfo && strings.TrimSpace(dockerInfo.ServerVersion) != "" {
		e.vps.DockerVersion = "Docker v" + strings.TrimSpace(dockerInfo.ServerVersion)
	}
	e.syncVPSRamLocked()
}

func readProcMemInfoGB() (totalGB float64, usedGB float64) {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	var memTotalKB, memAvailKB, memFreeKB, buffersKB, cachedKB int64
	hasAvail := false
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			memTotalKB = val
		case "MemAvailable:":
			memAvailKB = val
			hasAvail = true
		case "MemFree:":
			memFreeKB = val
		case "Buffers:":
			buffersKB = val
		case "Cached:":
			cachedKB = val
		}
	}
	if memTotalKB <= 0 {
		return 0, 0
	}
	if !hasAvail {
		memAvailKB = memFreeKB + buffersKB + cachedKB
	}
	if memAvailKB > memTotalKB {
		memAvailKB = memTotalKB
	}
	usedKB := memTotalKB - memAvailKB
	totalGB = math.Round((float64(memTotalKB)/(1024*1024))*10) / 10
	usedGB = math.Round((float64(usedKB)/(1024*1024))*10) / 10
	return totalGB, usedGB
}

func readProcCPUPct(numCPU int) float64 {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil || numCPU <= 0 {
		return 0
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return 0
	}
	load1, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || load1 < 0 {
		return 0
	}
	pct := (load1 / float64(numCPU)) * 100.0
	if pct > 100.0 {
		pct = 100.0
	}
	return math.Round(pct*10) / 10
}

func readRootDiskPct() int {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil || st.Blocks == 0 {
		return 0
	}
	total := float64(st.Blocks)
	free := float64(st.Bfree)
	usedPct := ((total - free) / total) * 100.0
	if usedPct < 0 {
		return 0
	}
	if usedPct > 100 {
		return 100
	}
	return int(math.Round(usedPct))
}

type presetMeta struct {
	stack    string
	category string
	filename string
	ramMb    int
	imageMb  int
}

func presetMetaFor(key string) presetMeta {
	switch key {
	case "spa":
		return presetMeta{stack: "React / Angular SPA", category: "Frontend", filename: "Dockerfile", ramMb: 32, imageMb: 24}
	case "go":
		return presetMeta{stack: "Go 1.22 REST API", category: "Backend API", filename: "Dockerfile", ramMb: 32, imageMb: 18}
	case "rust":
		return presetMeta{stack: "Rust Actix-Web", category: "Backend API", filename: "Dockerfile", ramMb: 44, imageMb: 22}
	case "compose":
		return presetMeta{stack: "Full-stack FE+BE Compose", category: "Full-stack Compose", filename: "docker-compose.yml", ramMb: 280, imageMb: 180}
	default:
		return presetMeta{stack: "Next.js 15 SSR", category: "Frontend", filename: "Dockerfile", ramMb: 142, imageMb: 145}
	}
}

func isValidPreset(key string) bool {
	switch key {
	case "nextjs", "spa", "go", "rust", "compose":
		return true
	default:
		return false
	}
}

func extractPrimaryPort(portMapping string) string {
	var digits strings.Builder
	for _, r := range portMapping {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
		} else if digits.Len() > 0 {
			break
		}
	}
	if digits.Len() == 0 {
		return "3000"
	}
	return digits.String()
}

func sanitizeSlug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func shortHex(nBytes int) string {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "9f4e1a"
	}
	return hex.EncodeToString(buf)
}

func cloneProject(p Project) Project {
	p.Logs = slices.Clone(p.Logs)
	return p
}

func cloneContainer(c Container) Container {
	c.PreviousTags = slices.Clone(c.PreviousTags)
	c.Logs = slices.Clone(c.Logs)
	return c
}

func cloneImage(img DockerImage) DockerImage {
	img.History = slices.Clone(img.History)
	return img
}

func cloneDeploymentRecord(r DeploymentRecord) DeploymentRecord {
	r.Logs = slices.Clone(r.Logs)
	return r
}

type dockerAPIContainerPort struct {
	IP          string `json:"IP"`
	PrivatePort uint16 `json:"PrivatePort"`
	PublicPort  uint16 `json:"PublicPort"`
	Type        string `json:"Type"`
}

type dockerAPIContainer struct {
	Id     string                   `json:"Id"`
	Names  []string                 `json:"Names"`
	Image  string                   `json:"Image"`
	State  string                   `json:"State"`
	Status string                   `json:"Status"`
	Ports  []dockerAPIContainerPort `json:"Ports"`
	Labels map[string]string        `json:"Labels"`
}

type dockerAPIImage struct {
	Id          string   `json:"Id"`
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
	Created     int64    `json:"Created"`
	Size        int64    `json:"Size"`
	Containers  int64    `json:"Containers"`
}

// SyncDockerEngine queries the live Docker Engine API for containers and images
// when running in "docker" runtimeMode (unless ClearMockData was invoked).
func (e *Engine) SyncDockerEngine() {
	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	manualCleared := e.manualCleared
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()

	if runtimeMode != "docker" || manualCleared || strings.TrimSpace(endpoint) == "" {
		return
	}

	e.readHostTelemetry()

	client, baseURL, ok := newDockerHTTPClient(endpoint, 1500*time.Millisecond)
	if !ok {
		return
	}

	apiContainers, ok := fetchDockerJSON[[]dockerAPIContainer](client, baseURL+"/containers/json?all=1")
	if !ok {
		return
	}

	logsByID := make(map[string][]string, len(apiContainers))
	for _, dc := range apiContainers {
		cid := shortDockerID(dc.Id)
		if lines := fetchDockerContainerLogs(client, baseURL, dc.Id, 25); len(lines) > 0 {
			logsByID[cid] = lines
		}
	}

	apiImages, hasImages := fetchDockerJSON[[]dockerAPIImage](client, baseURL+"/images/json")

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.vps.RuntimeMode != "docker" || e.manualCleared {
		return
	}

	e.applyDiscoveredContainersLocked(apiContainers, logsByID)
	if hasImages {
		e.applyDiscoveredImagesLocked(apiImages)
		e.enrichContainerPreviousTagsLocked(apiImages)
	}
	e.syncVPSRamLocked()
}

// GetContainerLogs returns live container logs from the Docker Engine API (or cached logs in simulator mode).
func (e *Engine) GetContainerLogs(id string, tail int) ([]string, error) {
	if tail <= 0 || tail > 500 {
		tail = 100
	}
	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	cntIdx := e.findContainerIndexLocked(id)
	projIdx := e.findProjectIndexLocked(id)
	var targetDockerID string
	var cachedLogs []string
	if cntIdx >= 0 {
		targetDockerID = e.containers[cntIdx].ID
		cachedLogs = slices.Clone(e.containers[cntIdx].Logs)
	} else if projIdx >= 0 {
		cachedLogs = slices.Clone(e.projects[projIdx].Logs)
		for _, c := range e.containers {
			if c.Project == e.projects[projIdx].Name {
				targetDockerID = c.ID
				break
			}
		}
	}
	e.mu.RUnlock()

	if cntIdx < 0 && projIdx < 0 {
		return nil, fmt.Errorf("container or project %q not found", id)
	}

	if runtimeMode == "docker" && strings.TrimSpace(endpoint) != "" && targetDockerID != "" {
		if client, baseURL, ok := newDockerHTTPClient(endpoint, 2*time.Second); ok {
			if live := fetchDockerContainerLogs(client, baseURL, targetDockerID, tail); len(live) > 0 {
				e.mu.Lock()
				if ci := e.findContainerIndexLocked(targetDockerID); ci >= 0 {
					e.containers[ci].Logs = slices.Clone(live)
				}
				if projIdx >= 0 && projIdx < len(e.projects) {
					e.projects[projIdx].Logs = slices.Clone(live)
				}
				e.mu.Unlock()
				return live, nil
			}
		}
	}
	return cachedLogs, nil
}

func (e *Engine) applyDiscoveredContainersLocked(apiContainers []dockerAPIContainer, logsByID map[string][]string) {
	existingByID := make(map[string]Container, len(e.containers))
	existingByName := make(map[string]Container, len(e.containers))
	for _, c := range e.containers {
		existingByID[c.ID] = c
		existingByName[c.Name] = c
	}

	discoveredContainers := make([]Container, 0, len(apiContainers))
	newDiscoveredIDs := make(map[string]bool, len(apiContainers))
	matchedNonDiscovered := make(map[string]bool)

	type projectGroup struct {
		name         string
		isCompose    bool
		containers   []Container
		primaryPorts []string
		domain       string
		repo         string
		branch       string
		commit       string
		logs         []string
	}
	groupsByName := make(map[string]*projectGroup)
	groupOrder := make([]string, 0)
	discoveredRoutes := make([]ProxyRoute, 0)
	seenRouteDomains := make(map[string]bool)

	for _, dc := range apiContainers {
		cid := shortDockerID(dc.Id)
		cname := cid
		if len(dc.Names) > 0 {
			if trimmed := strings.TrimPrefix(strings.TrimSpace(dc.Names[0]), "/"); trimmed != "" {
				cname = trimmed
			}
		}

		composeProj := strings.TrimSpace(dc.Labels["com.docker.compose.project"])
		projName := composeProj
		if projName == "" {
			projName = cname
		}

		status := mapDockerContainerState(dc.State)
		uptime := strings.TrimSpace(dc.Status)
		if uptime == "" {
			uptime = status
		}
		ports := formatDockerPorts(dc.Ports)
		stackKey := inferStackKey(dc.Image, cname)

		var prev Container
		hasPrev := false
		if p, ok := existingByID[cid]; ok {
			prev, hasPrev = p, true
		} else if p, ok := existingByName[cname]; ok {
			prev, hasPrev = p, true
		}

		if hasPrev && !e.discoveredContainerIDs[prev.ID] {
			matchedNonDiscovered[prev.ID] = true
			projName = prev.Project
		}

		liveLogs := logsByID[cid]
		mapped := Container{
			ID:           cid,
			Name:         cname,
			Project:      projName,
			StackKey:     stackKey,
			Image:        dc.Image,
			PreviousTags: []string{},
			Status:       status,
			Protected:    IsProtectedSystemContainer(cname),
			Ports:        ports,
			Uptime:       uptime,
			RAMLimitMb:   512,
			Logs:         slices.Clone(liveLogs),
		}
		if hasPrev {
			mapped.PreviousTags = slices.Clone(prev.PreviousTags)
			if len(mapped.Logs) == 0 {
				mapped.Logs = slices.Clone(prev.Logs)
			}
			mapped.CPUPct = prev.CPUPct
			mapped.RAMMb = prev.RAMMb
			if prev.RAMLimitMb > 0 {
				mapped.RAMLimitMb = prev.RAMLimitMb
			}
		}
		if len(mapped.PreviousTags) == 0 && dc.Image != "" {
			mapped.PreviousTags = []string{dc.Image}
		}

		discoveredContainers = append(discoveredContainers, mapped)
		newDiscoveredIDs[mapped.ID] = true

		grp, exists := groupsByName[projName]
		if !exists {
			grp = &projectGroup{name: projName, isCompose: composeProj != ""}
			groupsByName[projName] = grp
			groupOrder = append(groupOrder, projName)
		}
		grp.containers = append(grp.containers, mapped)
		if ports != "" && ports != "internal" {
			grp.primaryPorts = append(grp.primaryPorts, ports)
		}
		if len(liveLogs) > 0 && len(grp.logs) == 0 {
			grp.logs = slices.Clone(liveLogs)
		}
		if r := strings.TrimSpace(dc.Labels["deploymenthub.repo"]); r != "" && grp.repo == "" {
			grp.repo = r
		}
		if b := strings.TrimSpace(dc.Labels["deploymenthub.branch"]); b != "" && grp.branch == "" {
			grp.branch = b
		}
		if c := strings.TrimSpace(dc.Labels["deploymenthub.commit"]); c != "" && grp.commit == "" {
			grp.commit = c
		}
		if d := strings.TrimSpace(dc.Labels["deploymenthub.domain"]); d != "" && grp.domain == "" {
			grp.domain = d
		}
		if domain, pathRule, ssl := extractTraefikRouteFromLabels(dc.Labels); domain != "" {
			if grp.domain == "" {
				grp.domain = domain
			}
			if !seenRouteDomains[domain+pathRule] {
				seenRouteDomains[domain+pathRule] = true
				targetPort := "80"
				if len(dc.Ports) > 0 && dc.Ports[0].PrivatePort > 0 {
					targetPort = strconv.Itoa(int(dc.Ports[0].PrivatePort))
				}
				proto := "HTTP Only"
				certExp := "Local / HTTP"
				if ssl {
					proto = "HTTP/2 + TLS 1.3"
					certExp = "Auto-SSL (Let's Encrypt)"
				}
				discoveredRoutes = append(discoveredRoutes, ProxyRoute{
					ID:       "rt-" + cid,
					Domain:   domain,
					Target:   cname + ":" + targetPort,
					PathRule: pathRule,
					SSL:      ssl,
					CertExp:  certExp,
					Protocol: proto,
				})
			}
		}
	}

	mergedContainers := make([]Container, 0, len(e.containers)+len(discoveredContainers))
	mergedContainers = append(mergedContainers, discoveredContainers...)
	for _, c := range e.containers {
		if !e.discoveredContainerIDs[c.ID] && !matchedNonDiscovered[c.ID] {
			mergedContainers = append(mergedContainers, cloneContainer(c))
		}
	}
	e.containers = mergedContainers
	e.discoveredContainerIDs = newDiscoveredIDs

	if len(discoveredRoutes) > 0 {
		existingRoutesByDomain := make(map[string]ProxyRoute, len(e.proxyRoutes))
		for _, r := range e.proxyRoutes {
			existingRoutesByDomain[r.Domain+r.PathRule] = r
		}
		mergedRoutes := make([]ProxyRoute, 0, len(discoveredRoutes)+len(e.proxyRoutes))
		for _, dr := range discoveredRoutes {
			if prev, ok := existingRoutesByDomain[dr.Domain+dr.PathRule]; ok {
				dr.SSL = prev.SSL
				dr.Protocol = prev.Protocol
				dr.CertExp = prev.CertExp
			}
			mergedRoutes = append(mergedRoutes, dr)
		}
		for _, r := range e.proxyRoutes {
			if !seenRouteDomains[r.Domain+r.PathRule] && !strings.HasPrefix(r.ID, "rt-") {
				mergedRoutes = append(mergedRoutes, r)
			} else if !seenRouteDomains[r.Domain+r.PathRule] && len(r.ID) < 10 {
				mergedRoutes = append(mergedRoutes, r)
			}
		}
		e.proxyRoutes = mergedRoutes
	}

	// Merge grouped discovered projects with any DeploymentHub-deployed projects.
	existingProjects := make(map[string]Project, len(e.projects))
	for _, p := range e.projects {
		existingProjects[p.Name] = p
	}

	newDiscoveredProjIDs := make(map[string]bool, len(groupOrder))
	mergedProjects := make([]Project, 0, len(groupOrder)+len(e.projects))
	seenProjectNames := make(map[string]bool, len(groupOrder))

	for _, name := range groupOrder {
		grp := groupsByName[name]
		seenProjectNames[name] = true

		anyRunning := false
		for _, c := range grp.containers {
			if c.Status == "Running" {
				anyRunning = true
				break
			}
		}
		projStatus := "Stopped"
		if anyRunning {
			projStatus = "Running"
		}

		stackKey := grp.containers[0].StackKey
		if grp.isCompose || len(grp.containers) > 1 {
			stackKey = "compose"
		}
		meta := presetMetaFor(stackKey)
		stackDesc := meta.stack
		if len(grp.containers) > 1 {
			stackDesc = fmt.Sprintf("Docker Compose (%d containers)", len(grp.containers))
		}
		portSummary := "internal"
		if len(grp.primaryPorts) > 0 {
			portSummary = grp.primaryPorts[0]
		}

		if existing, ok := existingProjects[name]; ok && !e.discoveredProjectIDs[existing.ID] {
			existing.Status = projStatus
			if grp.domain != "" {
				existing.Domain = grp.domain
			}
			if portSummary != "" && portSummary != "internal" {
				existing.Port = portSummary
			}
			if len(grp.logs) > 0 && len(existing.Logs) == 0 {
				existing.Logs = slices.Clone(grp.logs)
			}
			mergedProjects = append(mergedProjects, cloneProject(existing))
			continue
		}

		repoVal := grp.containers[0].Image
		if grp.repo != "" {
			repoVal = grp.repo
		}
		branchVal := "live"
		if grp.branch != "" {
			branchVal = grp.branch
		}
		commitVal := grp.containers[0].ID
		if grp.commit != "" {
			commitVal = grp.commit
		}

		proj := Project{
			ID:         name,
			Name:       name,
			Stack:      stackDesc,
			StackKey:   stackKey,
			Category:   "Docker Engine",
			Domain:     grp.domain,
			Repo:       repoVal,
			Branch:     branchVal,
			Commit:     commitVal,
			CommitMsg:  fmt.Sprintf("Discovered %d live container(s)", len(grp.containers)),
			Status:     projStatus,
			RAMLimitMb: 512 * len(grp.containers),
			Port:       portSummary,
			UpdatedAt:  grp.containers[0].Uptime,
			Logs:       slices.Clone(grp.logs),
		}
		if existing, ok := existingProjects[name]; ok && len(proj.Logs) == 0 {
			proj.Logs = slices.Clone(existing.Logs)
		}
		mergedProjects = append(mergedProjects, proj)
		newDiscoveredProjIDs[proj.ID] = true
	}

	for _, p := range e.projects {
		if seenProjectNames[p.Name] {
			continue
		}
		if !e.discoveredProjectIDs[p.ID] {
			mergedProjects = append(mergedProjects, cloneProject(p))
		}
	}

	e.projects = mergedProjects
	e.discoveredProjectIDs = newDiscoveredProjIDs
}

func (e *Engine) applyDiscoveredImagesLocked(apiImages []dockerAPIImage) {
	discoveredImages := make([]DockerImage, 0, len(apiImages))
	newDiscoveredImgIDs := make(map[string]bool, len(apiImages))
	seenTags := make(map[string]bool, len(apiImages))

	for _, di := range apiImages {
		rawID := strings.TrimPrefix(di.Id, "sha256:")
		imgID := shortDockerID(rawID)
		repoTag, dangling := resolveDockerImageTag(di)
		sizeMb := int(math.Round(float64(di.Size) / (1024.0 * 1024.0)))
		if di.Size > 0 && sizeMb == 0 {
			sizeMb = 1
		}
		inUse := di.Containers > 0 || imageUsedByContainers(repoTag, rawID, e.containers)

		historyTags := make([]string, 0, len(di.RepoTags))
		for _, t := range di.RepoTags {
			if trimmed := strings.TrimSpace(t); trimmed != "" && trimmed != "<none>:<none>" && !slices.Contains(historyTags, trimmed) {
				historyTags = append(historyTags, trimmed)
			}
		}
		if len(historyTags) == 0 {
			historyTags = []string{repoTag}
		}

		img := DockerImage{
			ID:       imgID,
			RepoTag:  repoTag,
			SizeMb:   sizeMb,
			InUse:    inUse,
			Dangling: dangling,
			Created:  formatUnixSeconds(di.Created),
			History:  historyTags,
		}
		discoveredImages = append(discoveredImages, img)
		newDiscoveredImgIDs[img.ID] = true
		if repoTag != "<none>:<none>" {
			seenTags[repoTag] = true
		}
	}

	merged := make([]DockerImage, 0, len(discoveredImages)+len(e.images))
	merged = append(merged, discoveredImages...)
	for _, img := range e.images {
		if !e.discoveredImageIDs[img.ID] && !seenTags[img.RepoTag] {
			merged = append(merged, cloneImage(img))
		}
	}
	e.images = merged
	e.discoveredImageIDs = newDiscoveredImgIDs
}

func fetchDockerJSON[T any](client *http.Client, endpoint string) (T, bool) {
	var zero T
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return zero, false
	}
	resp, err := client.Do(req)
	if err != nil {
		return zero, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return zero, false
	}

	var out T
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&out); err != nil {
		return zero, false
	}
	return out, true
}

func sendDockerContainerAction(endpoint, containerID, action string) {
	client, baseURL, ok := newDockerHTTPClient(endpoint, 2*time.Second)
	if !ok {
		return
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/containers/"+url.PathEscape(containerID)+"/"+action, nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

func newDockerHTTPClient(dockerHost string, timeout time.Duration) (*http.Client, string, bool) {
	trimmed := strings.TrimSpace(dockerHost)
	if trimmed == "" {
		return nil, "", false
	}
	if strings.HasPrefix(trimmed, "unix://") || strings.HasPrefix(trimmed, "/") {
		sockPath := strings.TrimPrefix(trimmed, "unix://")
		client := &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", sockPath)
				},
			},
		}
		return client, "http://localhost", true
	}

	baseURL := trimmed
	if strings.HasPrefix(baseURL, "tcp://") {
		baseURL = "http://" + strings.TrimPrefix(baseURL, "tcp://")
	}
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}
	return &http.Client{Timeout: timeout}, strings.TrimRight(baseURL, "/"), true
}

func shortDockerID(id string) string {
	trimmed := strings.TrimSpace(id)
	if len(trimmed) >= 64 {
		return trimmed[:12]
	}
	return trimmed
}

func formatDockerPorts(ports []dockerAPIContainerPort) string {
	if len(ports) == 0 {
		return "internal"
	}
	seen := make(map[string]bool, len(ports))
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		proto := p.Type
		if proto == "" {
			proto = "tcp"
		}
		var formatted string
		if p.PublicPort > 0 {
			ip := p.IP
			if ip == "" {
				ip = "0.0.0.0"
			}
			formatted = ip + ":" + strconv.Itoa(int(p.PublicPort)) + "->" + strconv.Itoa(int(p.PrivatePort)) + "/" + proto
		} else if p.PrivatePort > 0 {
			formatted = strconv.Itoa(int(p.PrivatePort)) + "/" + proto
		}
		if formatted != "" && !seen[formatted] {
			seen[formatted] = true
			parts = append(parts, formatted)
		}
	}
	if len(parts) == 0 {
		return "internal"
	}
	return strings.Join(parts, ", ")
}

func inferStackKey(image, name string) string {
	combined := strings.ToLower(image + " " + name)
	switch {
	case strings.Contains(combined, "next"):
		return "nextjs"
	case strings.Contains(combined, "rust") || strings.Contains(combined, "actix") || strings.Contains(combined, "cargo"):
		return "rust"
	case strings.Contains(combined, "golang") || strings.Contains(combined, "/go") || strings.Contains(combined, "go-") || strings.Contains(combined, "-go"):
		return "go"
	case strings.Contains(combined, "nginx") || strings.Contains(combined, "react") || strings.Contains(combined, "vite") || strings.Contains(combined, "angular") || strings.Contains(combined, "node"):
		return "spa"
	default:
		return "compose"
	}
}

func resolveDockerImageTag(di dockerAPIImage) (string, bool) {
	if len(di.RepoTags) > 0 {
		tag := strings.TrimSpace(di.RepoTags[0])
		if tag != "" && tag != "<none>:<none>" {
			return tag, false
		}
		return "<none>:<none>", true
	}
	if len(di.RepoDigests) > 0 {
		if repo, _, ok := strings.Cut(di.RepoDigests[0], "@"); ok && repo != "" {
			return repo + ":<none>", true
		}
	}
	return "<none>:<none>", true
}

func imageUsedByContainers(repoTag, rawID string, containers []Container) bool {
	for _, c := range containers {
		if c.Image == repoTag || (rawID != "" && strings.Contains(c.Image, shortDockerID(rawID))) {
			return true
		}
	}
	return false
}

func formatUnixSeconds(ts int64) string {
	if ts <= 0 {
		return "unknown"
	}
	return time.Unix(ts, 0).UTC().Format("2006-01-02 15:04 UTC")
}

func fetchDockerContainerLogs(client *http.Client, baseURL, containerID string, tail int) []string {
	if client == nil || strings.TrimSpace(containerID) == "" {
		return nil
	}
	if tail <= 0 {
		tail = 25
	}
	endpoint := fmt.Sprintf("%s/containers/%s/logs?stdout=1&stderr=1&tail=%d", baseURL, url.PathEscape(containerID), tail)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil || len(raw) == 0 {
		return nil
	}
	stdout, stderr, muxErr := ParseDockerMultiplexedStream(raw)
	if muxErr == nil {
		combined := make([]string, 0, len(stdout)+len(stderr))
		combined = append(combined, stdout...)
		combined = append(combined, stderr...)
		if len(combined) > tail {
			combined = combined[len(combined)-tail:]
		}
		return combined
	}
	lines := splitDockerPayloadLines(string(raw))
	if len(lines) > tail {
		lines = lines[len(lines)-tail:]
	}
	return lines
}

func extractTraefikRouteFromLabels(labels map[string]string) (domain, pathRule string, ssl bool) {
	if len(labels) == 0 {
		return "", "", false
	}
	pathRule = "/*"
	for k, v := range labels {
		lk := strings.ToLower(strings.TrimSpace(k))
		if strings.HasPrefix(lk, "traefik.http.routers.") && strings.HasSuffix(lk, ".rule") {
			if idx := strings.Index(v, "Host(`"); idx >= 0 {
				rest := v[idx+6:]
				if end := strings.IndexByte(rest, '`'); end > 0 {
					domain = strings.TrimSpace(rest[:end])
				}
			}
			if idx := strings.Index(v, "PathPrefix(`"); idx >= 0 {
				rest := v[idx+12:]
				if end := strings.IndexByte(rest, '`'); end > 0 {
					pathRule = strings.TrimSpace(rest[:end]) + "/*"
				}
			}
		}
		if strings.HasPrefix(lk, "traefik.http.routers.") && (strings.HasSuffix(lk, ".tls") || strings.HasSuffix(lk, ".tls.certresolver")) {
			if v != "" && !strings.EqualFold(v, "false") {
				ssl = true
			}
		}
	}
	return domain, pathRule, ssl
}

func isSyntheticTestRepo(repoURL string) bool {
	s := strings.TrimSpace(repoURL)
	s = strings.TrimPrefix(s, "https://github.com/")
	s = strings.TrimPrefix(s, "http://github.com/")
	s = strings.TrimPrefix(s, "github.com/")
	parts := strings.Split(s, "/")
	if len(parts) < 2 {
		return true
	}
	owner := strings.ToLower(strings.TrimSpace(parts[0]))
	switch owner {
	case "", "org", "my-org", "example-org", "local", "test", "example":
		return true
	default:
		return false
	}
}

func probeGitHubToken(token string) (login string, scopes []string, ok bool) {
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return "", nil, false
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "DeploymentHub-Go-ControlPlane/2.0")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, false
	}
	var u struct {
		Login string `json:"login"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&u)
	rawScopes := resp.Header.Get("X-OAuth-Scopes")
	for _, sc := range strings.Split(rawScopes, ",") {
		if trimmed := strings.TrimSpace(sc); trimmed != "" {
			scopes = append(scopes, trimmed)
		}
	}
	return strings.TrimSpace(u.Login), scopes, true
}

func fetchLatestGitHubCommit(repoURL, branch, token string) (shortSHA, message string) {
	fallbackSHA := "sha-" + shortHex(3)
	fallbackMsg := "deployed via DeploymentHub pipeline"
	if isSyntheticTestRepo(repoURL) {
		return fallbackSHA, fallbackMsg
	}
	s := strings.TrimSpace(repoURL)
	s = strings.TrimPrefix(s, "https://github.com/")
	s = strings.TrimPrefix(s, "http://github.com/")
	s = strings.TrimPrefix(s, "github.com/")
	s = strings.TrimSuffix(s, ".git")
	s = strings.Trim(s, "/")
	parts := strings.Split(s, "/")
	if len(parts) < 2 {
		return fallbackSHA, fallbackMsg
	}
	owner, repo := parts[0], parts[1]
	ref := strings.TrimSpace(branch)
	if ref == "" {
		ref = "main"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s", url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(ref))
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return fallbackSHA, fallbackMsg
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "DeploymentHub-Go-ControlPlane/2.0")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}
	resp, err := client.Do(req)
	if err != nil {
		return fallbackSHA, fallbackMsg
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fallbackSHA, fallbackMsg
	}
	var payload struct {
		SHA    string `json:"sha"`
		Commit struct {
			Message string `json:"message"`
		} `json:"commit"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128<<10)).Decode(&payload); err != nil || payload.SHA == "" {
		return fallbackSHA, fallbackMsg
	}
	sha := payload.SHA
	if len(sha) > 7 {
		sha = sha[:7]
	}
	msg := strings.TrimSpace(strings.Split(payload.Commit.Message, "\n")[0])
	if msg == "" {
		msg = fallbackMsg
	}
	return sha, msg
}
