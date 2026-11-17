// Package docker implements DeploymentHub's thread-safe control plane engine,
// supporting live Docker Engine socket probing, stateful simulator mode,
// 5-stage async deployments with SSE event streaming, and Docker multiplexed log parsing.
package docker

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
	Port       string   `json:"port"`
	UpdatedAt  string   `json:"updatedAt"`
	Logs       []string `json:"logs"`
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
	CPUPct       float64  `json:"cpuPct"`
	RAMMb        int      `json:"ramMb"`
	RAMLimitMb   int      `json:"ramLimitMb"`
	Ports        string   `json:"ports"`
	Uptime       string   `json:"uptime"`
	Logs         []string `json:"logs"`
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
	mu               sync.RWMutex
	vault            *vault.Vault
	vps              VPSStatus
	projects         []Project
	containers       []Container
	images           []DockerImage
	proxyRoutes      []ProxyRoute
	webhookURL       string
	deployments      map[string]*deploymentState
	encryptedSecrets map[string]string
	seq              atomic.Uint64
}

// NewEngine initializes the control plane Engine. If dockerHost is non-empty and reachable,
// it runs in "docker" runtimeMode; otherwise it seeds and runs in stateful "simulator" mode.
func NewEngine(dockerHost string, v *vault.Vault) *Engine {
	if v == nil {
		v, _ = vault.New("")
	}

	e := &Engine{
		vault:            v,
		deployments:      make(map[string]*deploymentState),
		encryptedSecrets: make(map[string]string),
		webhookURL:       "https://hub.anna.dev/api/webhooks/github/wh_9a81f0c2",
		vps: VPSStatus{
			Host:           "vps-sg-01",
			IP:             "103.184.210.12",
			CPU:            24,
			RAMUsed:        3.8,
			RAMTotal:       8.0,
			DiskPct:        42,
			DockerVersion:  "Docker v26.1",
			SSHPort:        "22",
			SSHUser:        "deploy",
			ConnMode:       "socket-proxy",
			SocketEndpoint: "tcp://docker-proxy:2375",
			ConnStatus:     "Connected • 14ms",
			RuntimeMode:    "simulator",
		},
	}

	if host := strings.TrimSpace(dockerHost); host != "" {
		if ver, ok := probeDockerHost(host); ok {
			e.vps.RuntimeMode = "docker"
			e.vps.SocketEndpoint = host
			e.vps.ConnStatus = "Connected (Docker Engine)"
			if ver != "" {
				e.vps.DockerVersion = "Docker v" + ver
			}
		}
	}

	e.seedDefaultState()
	e.syncVPSRamLocked()
	return e
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

func (e *Engine) seedDefaultState() {
	e.projects = []Project{
		{
			ID:         "nextjs-commerce-store",
			Name:       "nextjs-commerce-store",
			Stack:      "Next.js 15 SSR",
			StackKey:   "nextjs",
			Category:   "Frontend",
			Domain:     "store.anna.dev",
			Repo:       "anh-tang/nextjs-commerce-store",
			Branch:     "main",
			Commit:     "sha-8f92a1",
			CommitMsg:  "feat: stripe webhook idempotency",
			Status:     "Running",
			CPU:        6.2,
			RAMMb:      210,
			RAMLimitMb: 512,
			Port:       "3000",
			UpdatedAt:  "4 phút trước",
			Logs: []string{
				"2026-11-14T01:02:11Z [next] ▲ Next.js 15.1.4 (standalone)",
				"2026-11-14T01:02:11Z [next] - Local: http://0.0.0.0:3000",
				"2026-11-14T01:02:12Z [health] GET /api/health 200 OK (3ms)",
				"2026-11-14T01:05:40Z [http] GET /products/pro-plan 200 in 18ms",
				"2026-11-14T01:07:03Z [http] POST /api/checkout 200 in 42ms",
			},
		},
		{
			ID:         "go-payment-gateway",
			Name:       "go-payment-gateway",
			Stack:      "Go 1.22 REST API",
			StackKey:   "go",
			Category:   "Backend API",
			Domain:     "api.anna.dev",
			Repo:       "anh-tang/go-payment-gateway",
			Branch:     "main",
			Commit:     "v1.4.2",
			CommitMsg:  "perf: tune pgx connection pool",
			Status:     "Running",
			CPU:        3.4,
			RAMMb:      28,
			RAMLimitMb: 256,
			Port:       "8080",
			UpdatedAt:  "18 phút trước",
			Logs: []string{
				"2026-11-14T00:50:01Z [go-api] Starting payment-gateway v1.4.2 on :8080",
				"2026-11-14T00:50:01Z [db] Connected PostgreSQL pool (min=4 max=20)",
				"2026-11-14T01:04:12Z [gin] POST /v1/payments/intent 201 (6.1ms)",
				"2026-11-14T01:06:55Z [gin] GET /healthz 200 (0.8ms)",
			},
		},
		{
			ID:         "rust-realtime-engine",
			Name:       "rust-realtime-engine",
			Stack:      "Rust Actix-Web",
			StackKey:   "rust",
			Category:   "Backend API",
			Domain:     "ws.anna.dev",
			Repo:       "anh-tang/rust-realtime-engine",
			Branch:     "feat/ws-cluster",
			Commit:     "c47e12a",
			CommitMsg:  "optimize epoll worker threads",
			Status:     "Building...",
			CPU:        41.0,
			RAMMb:      640,
			RAMLimitMb: 1024,
			Port:       "9000",
			UpdatedAt:  "Đang build Stage 3/5",
			Logs: []string{
				"2026-11-14T01:08:10Z [build] Cloning feat/ws-cluster @ c47e12a",
				"2026-11-14T01:08:14Z [cargo] Downloading crates (actix-web 4.9, tokio 1.41)",
				"2026-11-14T01:08:32Z [cargo] Compiling rust-realtime-engine v0.9.5 (release)",
				"2026-11-14T01:08:51Z [cargo] Linking static musl binary...",
			},
		},
		{
			ID:         "crm-fullstack-monorepo",
			Name:       "crm-fullstack-monorepo",
			Stack:      "Angular 18 FE + Go BE + Postgres",
			StackKey:   "compose",
			Category:   "Full-stack Compose",
			Domain:     "crm.anna.dev",
			Repo:       "anh-tang/crm-fullstack-monorepo",
			Branch:     "production",
			Commit:     "7a20f9c",
			CommitMsg:  "compose: add healthchecks & internal net",
			Status:     "Running",
			CPU:        9.1,
			RAMMb:      480,
			RAMLimitMb: 1024,
			Port:       "80 / 8080",
			UpdatedAt:  "1 giờ trước",
			Logs: []string{
				"2026-11-14T00:12:04Z [compose] Network crm_internal ready",
				"2026-11-14T00:12:06Z [postgres] database system is ready to accept connections",
				"2026-11-14T00:12:08Z [crm-be] Go API listening on :8080",
				"2026-11-14T00:12:09Z [crm-fe] Nginx serving Angular 18 dist on :80",
			},
		},
		{
			ID:         "react-admin-portal",
			Name:       "react-admin-portal",
			Stack:      "React + Vite SPA",
			StackKey:   "spa",
			Category:   "Frontend",
			Domain:     "admin.anna.dev",
			Repo:       "anh-tang/react-admin-portal",
			Branch:     "main",
			Commit:     "91d4e21",
			CommitMsg:  "chore: upgrade vite 5.4 & router",
			Status:     "Stopped",
			CPU:        0,
			RAMMb:      0,
			RAMLimitMb: 128,
			Port:       "80",
			UpdatedAt:  "2 ngày trước",
			Logs: []string{
				"2026-11-12T14:20:01Z [nginx] 1.27.2 worker processes started",
				"2026-11-12T18:05:19Z [docker] Container stopped by user @anh-tang (SIGTERM)",
			},
		},
	}

	e.containers = []Container{
		{
			ID:           "cnt-next",
			Name:         "dh-nextjs-commerce-store",
			Project:      "nextjs-commerce-store",
			StackKey:     "nextjs",
			Image:        "nextjs-commerce:sha-8f92a1",
			PreviousTags: []string{"nextjs-commerce:sha-7c10b4", "nextjs-commerce:sha-60e219"},
			Status:       "Running",
			CPUPct:       6.2,
			RAMMb:        210,
			RAMLimitMb:   512,
			Ports:        "127.0.0.1:3000->3000/tcp",
			Uptime:       "Up 4 phút",
			Logs: []string{
				"[next] ▲ Next.js 15.1.4 Ready in 312ms",
				"[http] GET / 200 12ms",
				"[http] GET /api/cart 200 7ms",
				"[http] POST /api/checkout 200 41ms",
			},
		},
		{
			ID:           "cnt-go",
			Name:         "dh-go-payment-gateway",
			Project:      "go-payment-gateway",
			StackKey:     "go",
			Image:        "go-payment:v1.4.2",
			PreviousTags: []string{"go-payment:v1.4.1", "go-payment:v1.4.0"},
			Status:       "Running",
			CPUPct:       3.4,
			RAMMb:        28,
			RAMLimitMb:   256,
			Ports:        "127.0.0.1:8080->8080/tcp",
			Uptime:       "Up 18 phút",
			Logs: []string{
				"[go] Server listening :8080 (distroless)",
				"[pgx] Pool healthy: 4 idle, 1 active",
				"[http] POST /v1/payments/intent 201 5.9ms",
			},
		},
		{
			ID:           "cnt-rust",
			Name:         "dh-rust-realtime-engine",
			Project:      "rust-realtime-engine",
			StackKey:     "rust",
			Image:        "rust-engine:latest",
			PreviousTags: []string{"rust-engine:v0.9.4", "rust-engine:v0.9.3"},
			Status:       "Running",
			CPUPct:       8.5,
			RAMMb:        44,
			RAMLimitMb:   256,
			Ports:        "127.0.0.1:9000->9000/tcp",
			Uptime:       "Up 3 giờ (Blue-Green active)",
			Logs: []string{
				"[actix] Starting 4 worker threads on 0.0.0.0:9000",
				"[ws] Active WebSocket clients: 312",
				"[ws] Heartbeat latency avg: 1.4ms",
			},
		},
		{
			ID:           "cnt-crm-fe",
			Name:         "dh-crm-fe-angular",
			Project:      "crm-fullstack-monorepo",
			StackKey:     "spa",
			Image:        "crm-fe:7a20f9c",
			PreviousTags: []string{"crm-fe:6d11a0e"},
			Status:       "Running",
			CPUPct:       1.2,
			RAMMb:        18,
			RAMLimitMb:   128,
			Ports:        "crm_net:80/tcp",
			Uptime:       "Up 1 giờ",
			Logs: []string{
				"[nginx] GET /assets/main-B4k1.js 200",
				"[nginx] Proxy /api/* -> http://dh-crm-be-go:8080",
			},
		},
		{
			ID:           "cnt-crm-be",
			Name:         "dh-crm-be-go",
			Project:      "crm-fullstack-monorepo",
			StackKey:     "go",
			Image:        "crm-be:7a20f9c",
			PreviousTags: []string{"crm-be:6d11a0e"},
			Status:       "Running",
			CPUPct:       4.1,
			RAMMb:        62,
			RAMLimitMb:   512,
			Ports:        "crm_net:8080/tcp",
			Uptime:       "Up 1 giờ",
			Logs: []string{
				"[crm-be] Migrated 14 SQL tables cleanly",
				"[crm-be] GET /api/customers 200 (9ms)",
			},
		},
		{
			ID:           "cnt-crm-db",
			Name:         "dh-crm-postgres-16",
			Project:      "crm-fullstack-monorepo",
			StackKey:     "compose",
			Image:        "postgres:16-alpine",
			PreviousTags: []string{"postgres:16.3-alpine"},
			Status:       "Running",
			CPUPct:       3.8,
			RAMMb:        400,
			RAMLimitMb:   1024,
			Ports:        "crm_net:5432/tcp (Internal)",
			Uptime:       "Up 1 giờ",
			Logs: []string{
				"[pg] checkpoint complete: wrote 18 buffers (0.1%)",
				"[pg] autovacuum launcher started",
			},
		},
		{
			ID:           "cnt-react",
			Name:         "dh-react-admin-portal",
			Project:      "react-admin-portal",
			StackKey:     "spa",
			Image:        "react-admin:91d4e21",
			PreviousTags: []string{"react-admin:82a0b12"},
			Status:       "Stopped",
			CPUPct:       0,
			RAMMb:        0,
			RAMLimitMb:   128,
			Ports:        "127.0.0.1:8088->80/tcp",
			Uptime:       "Exited (0) 2 ngày trước",
			Logs: []string{
				"[nginx] graceful shutdown complete",
				"[docker] Container exited with code 0",
			},
		},
	}

	e.images = []DockerImage{
		{ID: "img-next", RepoTag: "nextjs-commerce:sha-8f92a1", SizeMb: 148, InUse: true, Dangling: false, Created: "4 phút trước", History: []string{"sha-8f92a1", "sha-7c10b4", "sha-60e219"}},
		{ID: "img-go", RepoTag: "go-payment:v1.4.2", SizeMb: 19, InUse: true, Dangling: false, Created: "18 phút trước", History: []string{"v1.4.2", "v1.4.1", "v1.4.0"}},
		{ID: "img-rust", RepoTag: "rust-engine:latest", SizeMb: 24, InUse: true, Dangling: false, Created: "3 giờ trước", History: []string{"latest", "v0.9.4", "v0.9.3"}},
		{ID: "img-pg", RepoTag: "postgres:16-alpine", SizeMb: 242, InUse: true, Dangling: false, Created: "6 ngày trước", History: []string{"16-alpine"}},
		{ID: "img-dangle-1", RepoTag: "<none>:<none>", Note: "Dangling Next.js build layer", SizeMb: 640, InUse: false, Dangling: true, Created: "2 giờ trước", History: []string{"<none>"}},
		{ID: "img-dangle-2", RepoTag: "<none>:<none>", Note: "Dangling Rust cargo cache layer", SizeMb: 540, InUse: false, Dangling: true, Created: "1 ngày trước", History: []string{"<none>"}},
	}

	e.proxyRoutes = []ProxyRoute{
		{ID: "rt-1", Domain: "store.anna.dev", Target: "dh-nextjs-commerce-store:3000", PathRule: "/*", SSL: true, CertExp: "84 ngày", Protocol: "HTTP/2 + TLS 1.3"},
		{ID: "rt-2", Domain: "api.anna.dev", Target: "dh-go-payment-gateway:8080", PathRule: "/*", SSL: true, CertExp: "72 ngày", Protocol: "HTTP/2 + TLS 1.3"},
		{ID: "rt-3", Domain: "ws.anna.dev", Target: "dh-rust-realtime-engine:9000", PathRule: "/ws", SSL: true, CertExp: "89 ngày", Protocol: "WSS + TLS 1.3"},
		{ID: "rt-4", Domain: "crm.anna.dev", Target: "FE :80 & /api/* → BE :8080", PathRule: "/ , /api/*", SSL: true, CertExp: "61 ngày", Protocol: "HTTP/2 + TLS 1.3"},
		{ID: "rt-5", Domain: "admin.anna.dev", Target: "dh-react-admin-portal:80", PathRule: "/*", SSL: false, CertExp: "Chưa cấp", Protocol: "HTTP Only"},
	}
}

// GetOverview returns a thread-safe deep snapshot of the entire control plane state.
func (e *Engine) GetOverview() Overview {
	e.mu.RLock()
	defer e.mu.RUnlock()

	projects := make([]Project, len(e.projects))
	for i, p := range e.projects {
		projects[i] = cloneProject(p)
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
		WebhookURL:  e.webhookURL,
	}
}

// RedeployProject triggers an immediate zero-downtime redeploy on the matching project
// and updates its commit hash, container status, logs, and VPS memory telemetry.
func (e *Engine) RedeployProject(id string) (Project, error) {
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

// ContainerAction executes start, stop, restart, or rollback on a container
// and synchronizes its parent project and VPS RAM usage.
func (e *Engine) ContainerAction(id, action, targetTag string) (Container, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	idx := e.findContainerIndexLocked(id)
	if idx < 0 {
		return Container{}, fmt.Errorf("container %q not found", id)
	}

	c := &e.containers[idx]
	act := strings.ToLower(strings.TrimSpace(action))

	switch act {
	case "stop":
		c.Status = "Stopped"
		c.CPUPct = 0
		c.RAMMb = 0
		c.Uptime = "Stopped vừa xong"
		c.Logs = append(c.Logs, "[docker] Container stopped by user")

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

	default:
		return Container{}, fmt.Errorf("unsupported container action %q", action)
	}

	e.syncProjectFromContainersLocked(c.Project)
	e.syncVPSRamLocked()
	return cloneContainer(*c), nil
}

// PruneDanglingImages deletes all dangling (<none>) images and reclaims disk space.
func (e *Engine) PruneDanglingImages() PruneResult {
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
// runs stack detection, and returns metadata without echoing the raw token.
func (e *Engine) VerifyPAT(token, repoURL string) (map[string]any, error) {
	trimmed := strings.TrimSpace(token)
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

	previewLen := min(24, len(enc))
	preview := enc[:previewLen] + "..."

	detectRes := detector.Detect(detector.DetectRequest{
		RepoURL: repoURL,
		Branch:  "main",
		Mode:    "hybrid",
	})

	return map[string]any{
		"valid":                 true,
		"encryptedTokenPreview": preview,
		"repo":                  repoURL,
		"scopes":                []string{"repo", "read:user", "admin:repo_hook"},
		"detectResult":          detectRes,
	}, nil
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
		domain = appName + ".anna.dev"
	}
	detectMode := strings.ToLower(strings.TrimSpace(req.DetectMode))
	if detectMode != "file" {
		detectMode = "hybrid"
	}

	det := detector.Detect(detector.DetectRequest{
		RepoURL: repoURL,
		Branch:  branch,
		Mode:    detectMode,
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
	stageLogs := []struct {
		stage int
		line  string
	}{
		{1, fmt.Sprintf("[1/5] Clone SCM repository %s (%s) cleanly...", req.RepoURL, req.Branch)},
		{2, fmt.Sprintf("[2/5] Auto-Generate %s config (%s mode) completed", presetMetaFor(req.PresetKey).filename, req.DetectMode)},
		{3, fmt.Sprintf("[3/5] Docker Build Image %s:latest with BuildKit cache...", req.AppName)},
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
			e.registerCompletedDeployment(req, priorLogs, safeLine)
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

func (e *Engine) registerCompletedDeployment(req DeployRequest, priorLogs []string, finalLine string) {
	meta := presetMetaFor(req.PresetKey)
	portNum := extractPrimaryPort(req.PortMapping)
	commit := "sha-" + shortHex(3)
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
			CommitMsg:  "deployed via DeploymentHub pipeline",
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
	e.vps.RAMUsed = math.Round((3.04+float64(runningMb)/1024.0)*10) / 10
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
