package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// ContainerStateDetail summarizes live container runtime state from /containers/{id}/json.
type ContainerStateDetail struct {
	Status     string   `json:"status"`
	Running    bool     `json:"running"`
	Paused     bool     `json:"paused"`
	Restarting bool     `json:"restarting"`
	OOMKilled  bool     `json:"oomKilled"`
	Pid        int      `json:"pid"`
	ExitCode   int      `json:"exitCode"`
	StartedAt  string   `json:"startedAt"`
	FinishedAt string   `json:"finishedAt"`
	Health     string   `json:"health"`
	HealthLogs []string `json:"healthLogs"`
}

// ContainerMount describes a bind/volume mount attached to a container.
type ContainerMount struct {
	Type        string `json:"type"`
	Name        string `json:"name,omitempty"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode"`
	RW          bool   `json:"rw"`
}

// ContainerNetworkAttachment describes a container's attachment to a Docker network.
type ContainerNetworkAttachment struct {
	Name      string `json:"name"`
	NetworkID string `json:"networkId"`
	IPAddress string `json:"ipAddress"`
	Gateway   string `json:"gateway"`
	MacAddr   string `json:"macAddress"`
}

// ContainerInspect provides deep inspection details for a Docker container.
type ContainerInspect struct {
	ID            string                       `json:"id"`
	FullID        string                       `json:"fullId"`
	Name          string                       `json:"name"`
	Image         string                       `json:"image"`
	Created       string                       `json:"created"`
	Protected     bool                         `json:"protected"`
	State         ContainerStateDetail         `json:"state"`
	Env           []string                     `json:"env"`
	Cmd           []string                     `json:"cmd"`
	Entrypoint    []string                     `json:"entrypoint"`
	WorkingDir    string                       `json:"workingDir"`
	RestartPolicy string                       `json:"restartPolicy"`
	MemoryLimitMb int64                        `json:"memoryLimitMb"`
	NanoCPUs      int64                        `json:"nanoCpus"`
	CPUCores      float64                      `json:"cpuCores"`
	Ports         string                       `json:"ports"`
	Mounts        []ContainerMount             `json:"mounts"`
	Networks      []ContainerNetworkAttachment `json:"networks"`
	Labels        map[string]string            `json:"labels"`
}

// ContainerStats captures live resource usage metrics for a container.
type ContainerStats struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	CPUPct       float64 `json:"cpuPct"`
	MemoryUsedMb float64 `json:"memoryUsedMb"`
	MemoryLimMb  float64 `json:"memoryLimitMb"`
	MemoryPct    float64 `json:"memoryPct"`
	NetRxBytes   uint64  `json:"netRxBytes"`
	NetTxBytes   uint64  `json:"netTxBytes"`
	BlockReadB   uint64  `json:"blockReadBytes"`
	BlockWriteB  uint64  `json:"blockWriteBytes"`
	PIDs         uint64  `json:"pids"`
	ReadAt       string  `json:"readAt"`
}

// ContainerTop lists running processes inside a container.
type ContainerTop struct {
	ID        string     `json:"id"`
	Titles    []string   `json:"titles"`
	Processes [][]string `json:"processes"`
}

// DiskCategoryUsage breaks down Docker disk usage for one resource type.
type DiskCategoryUsage struct {
	Count            int   `json:"count"`
	ActiveCount      int   `json:"activeCount"`
	TotalBytes       int64 `json:"totalBytes"`
	ReclaimableBytes int64 `json:"reclaimableBytes"`
}

// DockerDiskUsage summarizes /system/df disk usage across images, containers, volumes, and build cache.
type DockerDiskUsage struct {
	Images           DiskCategoryUsage `json:"images"`
	Containers       DiskCategoryUsage `json:"containers"`
	Volumes          DiskCategoryUsage `json:"volumes"`
	BuildCache       DiskCategoryUsage `json:"buildCache"`
	TotalBytes       int64             `json:"totalBytes"`
	ReclaimableBytes int64             `json:"reclaimableBytes"`
	Available        bool              `json:"available"`
}

// ImageHistoryLayer describes one image layer from GET /images/{id}/history.
type ImageHistoryLayer struct {
	ID        string   `json:"id"`
	Created   string   `json:"created"`
	CreatedBy string   `json:"createdBy"`
	SizeBytes int64    `json:"sizeBytes"`
	Comment   string   `json:"comment"`
	Tags      []string `json:"tags"`
}

// BuildCachePruneResult describes reclaimed build cache space.
type BuildCachePruneResult struct {
	CachesDeleted       int   `json:"cachesDeleted"`
	SpaceReclaimedBytes int64 `json:"spaceReclaimedBytes"`
	ReclaimedMb         int   `json:"reclaimedMb"`
}

func mapDockerContainerState(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "running":
		return "Running"
	case "paused":
		return "Paused"
	case "restarting":
		return "Restarting"
	case "created":
		return "Created"
	default:
		return "Stopped"
	}
}

func (e *Engine) enrichContainerPreviousTagsLocked(apiImages []dockerAPIImage) {
	tagsByRepo := make(map[string][]string)
	for _, di := range apiImages {
		for _, tag := range di.RepoTags {
			clean := strings.TrimSpace(tag)
			if clean == "" || clean == "<none>:<none>" {
				continue
			}
			repo, _, ok := splitImageRepoTag(clean)
			if !ok {
				continue
			}
			if !slices.Contains(tagsByRepo[repo], clean) {
				tagsByRepo[repo] = append(tagsByRepo[repo], clean)
			}
		}
	}

	for i := range e.containers {
		c := &e.containers[i]
		repo, _, ok := splitImageRepoTag(c.Image)
		if !ok {
			continue
		}
		related := tagsByRepo[repo]
		if len(related) == 0 {
			continue
		}
		merged := make([]string, 0, len(c.PreviousTags)+len(related))
		for _, t := range c.PreviousTags {
			if t != "" && !slices.Contains(merged, t) {
				merged = append(merged, t)
			}
		}
		for _, t := range related {
			if t != "" && !slices.Contains(merged, t) {
				merged = append(merged, t)
			}
		}
		c.PreviousTags = merged
	}
}

func splitImageRepoTag(imageRef string) (repo string, tag string, ok bool) {
	trimmed := strings.TrimSpace(imageRef)
	if trimmed == "" || strings.Contains(trimmed, "@sha256:") {
		return "", "", false
	}
	lastColon := strings.LastIndexByte(trimmed, ':')
	lastSlash := strings.LastIndexByte(trimmed, '/')
	if lastColon > lastSlash {
		return trimmed[:lastColon], trimmed[lastColon+1:], true
	}
	return trimmed, "latest", true
}

func parseDockerAPIErrorMessage(statusCode int, body []byte) error {
	trimmed := strings.TrimSpace(string(body))
	if trimmed != "" {
		var msg struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(body, &msg); err == nil && strings.TrimSpace(msg.Message) != "" {
			return fmt.Errorf("docker API HTTP %d: %s", statusCode, strings.TrimSpace(msg.Message))
		}
		return fmt.Errorf("docker API HTTP %d: %s", statusCode, trimmed)
	}
	return fmt.Errorf("docker API HTTP %d", statusCode)
}

func sendDockerContainerActionStrict(endpoint, containerID, action string) error {
	timeout := 15 * time.Second
	client, baseURL, ok := newDockerHTTPClient(endpoint, timeout)
	if !ok {
		return errors.New("docker engine endpoint unreachable")
	}
	actionURL := baseURL + "/containers/" + url.PathEscape(containerID) + "/" + action
	if action == "stop" {
		actionURL += "?t=5"
	} else if action == "restart" {
		actionURL += "?t=5"
	}
	req, err := http.NewRequest(http.MethodPost, actionURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Docker returns 204/200 on success and 304 when already started/stopped.
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return parseDockerAPIErrorMessage(resp.StatusCode, body)
}

func removeDockerContainerByID(endpoint, containerID string, removeVolumes bool) error {
	client, baseURL, ok := newDockerHTTPClient(endpoint, 15*time.Second)
	if !ok {
		return errors.New("docker engine endpoint unreachable")
	}
	vFlag := "0"
	if removeVolumes {
		vFlag = "1"
	}
	delURL := fmt.Sprintf("%s/containers/%s?force=1&v=%s", baseURL, url.PathEscape(containerID), vFlag)
	req, err := http.NewRequest(http.MethodDelete, delURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return parseDockerAPIErrorMessage(resp.StatusCode, body)
}

type dockerRawInspect struct {
	ID      string `json:"Id"`
	Name    string `json:"Name"`
	Created string `json:"Created"`
	State   struct {
		Status     string `json:"Status"`
		Running    bool   `json:"Running"`
		Paused     bool   `json:"Paused"`
		Restarting bool   `json:"Restarting"`
		OOMKilled  bool   `json:"OOMKilled"`
		Pid        int    `json:"Pid"`
		ExitCode   int    `json:"ExitCode"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
		Health     *struct {
			Status        string `json:"Status"`
			FailingStreak int    `json:"FailingStreak"`
			Log           []struct {
				Start    string `json:"Start"`
				ExitCode int    `json:"ExitCode"`
				Output   string `json:"Output"`
			} `json:"Log"`
		} `json:"Health"`
	} `json:"State"`
	Config struct {
		Image        string              `json:"Image"`
		Tty          bool                `json:"Tty"`
		Env          []string            `json:"Env"`
		Cmd          []string            `json:"Cmd"`
		Entrypoint   []string            `json:"Entrypoint"`
		WorkingDir   string              `json:"WorkingDir"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
		Labels       map[string]string   `json:"Labels"`
	} `json:"Config"`
	HostConfig      map[string]any `json:"HostConfig"`
	NetworkSettings struct {
		Ports    map[string][]dockerInspectPortBinding `json:"Ports"`
		Networks map[string]struct {
			NetworkID  string `json:"NetworkID"`
			IPAddress  string `json:"IPAddress"`
			Gateway    string `json:"Gateway"`
			MacAddress string `json:"MacAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
	Mounts []ContainerMount `json:"Mounts"`
}

type dockerInspectPortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

func (e *Engine) rollbackDockerContainer(endpoint, dockerID, targetTag string) (Container, bool, error) {
	client, baseURL, ok := newDockerHTTPClient(endpoint, 30*time.Second)
	if !ok {
		return Container{}, false, errors.New("docker engine endpoint unreachable")
	}
	inspectURL := fmt.Sprintf("%s/containers/%s/json", baseURL, url.PathEscape(dockerID))
	inspectReq, _ := http.NewRequest(http.MethodGet, inspectURL, nil)
	inspectResp, err := client.Do(inspectReq)
	if err != nil {
		return Container{}, false, err
	}
	inspectBody, _ := io.ReadAll(io.LimitReader(inspectResp.Body, 4<<20))
	_ = inspectResp.Body.Close()

	// Legacy mock servers in tests don't implement /containers/{id}/json -> fall back cleanly.
	if inspectResp.StatusCode == http.StatusNotFound {
		return Container{}, false, nil
	}
	if inspectResp.StatusCode != http.StatusOK {
		return Container{}, true, parseDockerAPIErrorMessage(inspectResp.StatusCode, inspectBody)
	}

	var raw dockerRawInspect
	if err := json.Unmarshal(inspectBody, &raw); err != nil {
		return Container{}, true, fmt.Errorf("parse container inspect: %w", err)
	}
	cname := strings.TrimPrefix(strings.TrimSpace(raw.Name), "/")
	if IsProtectedSystemContainer(cname) {
		return Container{}, true, fmt.Errorf("%w: system container %q cannot be rolled back", ErrProtectedContainer, cname)
	}

	// Ensure target image exists locally before destroying running container.
	imgCheckReq, _ := http.NewRequest(http.MethodGet, baseURL+"/images/"+url.PathEscape(targetTag)+"/json", nil)
	imgCheckResp, err := client.Do(imgCheckReq)
	if err != nil {
		return Container{}, true, err
	}
	imgBody, _ := io.ReadAll(io.LimitReader(imgCheckResp.Body, 2048))
	_ = imgCheckResp.Body.Close()
	if imgCheckResp.StatusCode != http.StatusOK {
		return Container{}, true, fmt.Errorf("target rollback image %q not found locally (%s)", targetTag, parseDockerAPIErrorMessage(imgCheckResp.StatusCode, imgBody))
	}

	// Stop & remove existing container.
	_ = sendDockerContainerActionStrict(endpoint, dockerID, "stop")
	if err := removeDockerContainerByID(endpoint, dockerID, false); err != nil {
		return Container{}, true, fmt.Errorf("remove container before rollback: %w", err)
	}

	netNames := make([]string, 0, len(raw.NetworkSettings.Networks))
	for netName := range raw.NetworkSettings.Networks {
		if strings.TrimSpace(netName) != "" {
			netNames = append(netNames, netName)
		}
	}
	slices.Sort(netNames)

	createPayload := map[string]any{
		"Image":        targetTag,
		"Env":          raw.Config.Env,
		"Labels":       raw.Config.Labels,
		"ExposedPorts": raw.Config.ExposedPorts,
		"WorkingDir":   raw.Config.WorkingDir,
		"HostConfig":   raw.HostConfig,
	}
	if len(raw.Config.Cmd) > 0 {
		createPayload["Cmd"] = raw.Config.Cmd
	}
	if len(raw.Config.Entrypoint) > 0 {
		createPayload["Entrypoint"] = raw.Config.Entrypoint
	}
	if len(netNames) > 0 {
		createPayload["NetworkingConfig"] = map[string]any{
			"EndpointsConfig": map[string]any{
				netNames[0]: map[string]any{},
			},
		}
	}

	payloadBytes, _ := json.Marshal(createPayload)
	createURL := baseURL + "/containers/create?name=" + url.QueryEscape(cname)
	createReq, _ := http.NewRequest(http.MethodPost, createURL, bytes.NewReader(payloadBytes))
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := client.Do(createReq)
	if err != nil {
		return Container{}, true, err
	}
	createBody, _ := io.ReadAll(io.LimitReader(createResp.Body, 1<<20))
	_ = createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated && createResp.StatusCode != http.StatusOK {
		return Container{}, true, parseDockerAPIErrorMessage(createResp.StatusCode, createBody)
	}
	var created struct {
		ID string `json:"Id"`
	}
	_ = json.Unmarshal(createBody, &created)
	newID := strings.TrimSpace(created.ID)
	if newID == "" {
		newID = cname
	}

	// Attach any additional networks preserved from original container.
	for _, extraNet := range netNames[1:] {
		connBytes, _ := json.Marshal(map[string]string{"Container": newID})
		connReq, _ := http.NewRequest(http.MethodPost, baseURL+"/networks/"+url.PathEscape(extraNet)+"/connect", bytes.NewReader(connBytes))
		connReq.Header.Set("Content-Type", "application/json")
		if connResp, connErr := client.Do(connReq); connErr == nil {
			_ = connResp.Body.Close()
		}
	}

	if err := sendDockerContainerActionStrict(endpoint, newID, "start"); err != nil {
		return Container{}, true, fmt.Errorf("start rolled back container: %w", err)
	}

	e.SyncDockerEngine()
	e.mu.RLock()
	defer e.mu.RUnlock()
	if idx := e.findContainerIndexLocked(shortDockerID(newID)); idx >= 0 {
		return cloneContainer(e.containers[idx]), true, nil
	}
	if idx := e.findContainerIndexLocked(cname); idx >= 0 {
		return cloneContainer(e.containers[idx]), true, nil
	}
	return Container{
		ID:        shortDockerID(newID),
		Name:      cname,
		Project:   cname,
		Image:     targetTag,
		Status:    "Running",
		Protected: IsProtectedSystemContainer(cname),
		Uptime:    "Up (Rollback vừa xong)",
	}, true, nil
}

func (e *Engine) resolveContainerDockerTarget(id string) (runtimeMode, endpoint, dockerID, cname string, err error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	idx := e.findContainerIndexLocked(id)
	if idx >= 0 {
		return e.vps.RuntimeMode, e.vps.SocketEndpoint, e.containers[idx].ID, e.containers[idx].Name, nil
	}
	// Fall back to project ID -> primary container if applicable.
	pIdx := e.findProjectIndexLocked(id)
	if pIdx >= 0 {
		projName := e.projects[pIdx].Name
		for _, c := range e.containers {
			if c.Project == projName {
				return e.vps.RuntimeMode, e.vps.SocketEndpoint, c.ID, c.Name, nil
			}
		}
	}
	return "", "", "", "", fmt.Errorf("container %q not found", id)
}

// InspectContainer returns rich inspection metadata for a container.
func (e *Engine) InspectContainer(id string) (ContainerInspect, error) {
	runtimeMode, endpoint, dockerID, cname, err := e.resolveContainerDockerTarget(id)
	if err != nil {
		return ContainerInspect{}, err
	}

	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		e.mu.RLock()
		defer e.mu.RUnlock()
		idx := e.findContainerIndexLocked(dockerID)
		c := e.containers[idx]
		return ContainerInspect{
			ID:            c.ID,
			FullID:        c.ID,
			Name:          c.Name,
			Image:         c.Image,
			Protected:     IsProtectedSystemContainer(c.Name),
			RestartPolicy: "unless-stopped",
			MemoryLimitMb: int64(c.RAMLimitMb),
			CPUCores:      1,
			Ports:         c.Ports,
			State: ContainerStateDetail{
				Status:  strings.ToLower(c.Status),
				Running: c.Status == "Running",
				Paused:  c.Status == "Paused",
				Health:  "none",
			},
			Env:      []string{},
			Cmd:      []string{},
			Mounts:   []ContainerMount{},
			Networks: []ContainerNetworkAttachment{},
			Labels:   map[string]string{},
		}, nil
	}

	client, baseURL, ok := newDockerHTTPClient(endpoint, 5*time.Second)
	if !ok {
		return ContainerInspect{}, errors.New("docker engine endpoint unreachable")
	}
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/containers/"+url.PathEscape(dockerID)+"/json", nil)
	resp, err := client.Do(req)
	if err != nil {
		return ContainerInspect{}, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ContainerInspect{}, parseDockerAPIErrorMessage(resp.StatusCode, body)
	}

	var raw dockerRawInspect
	if err := json.Unmarshal(body, &raw); err != nil {
		return ContainerInspect{}, fmt.Errorf("decode inspect: %w", err)
	}

	name := strings.TrimPrefix(strings.TrimSpace(raw.Name), "/")
	if name == "" {
		name = cname
	}
	imageRef := raw.Config.Image
	if imageRef == "" {
		e.mu.RLock()
		if idx := e.findContainerIndexLocked(dockerID); idx >= 0 {
			imageRef = e.containers[idx].Image
		}
		e.mu.RUnlock()
	}

	healthStatus := "none"
	healthLogs := []string{}
	if raw.State.Health != nil {
		if raw.State.Health.Status != "" {
			healthStatus = raw.State.Health.Status
		}
		start := max(0, len(raw.State.Health.Log)-5)
		for _, hl := range raw.State.Health.Log[start:] {
			out := strings.TrimSpace(hl.Output)
			if len(out) > 220 {
				out = out[:220] + "..."
			}
			healthLogs = append(healthLogs, fmt.Sprintf("[exit %d] %s", hl.ExitCode, out))
		}
	}

	var memBytes, nanoCPUs int64
	restartPolicy := "no"
	if v, ok := raw.HostConfig["Memory"].(float64); ok && v > 0 {
		memBytes = int64(v)
	}
	if v, ok := raw.HostConfig["NanoCpus"].(float64); ok && v > 0 {
		nanoCPUs = int64(v)
	}
	if rp, ok := raw.HostConfig["RestartPolicy"].(map[string]any); ok {
		if rname, ok := rp["Name"].(string); ok && rname != "" {
			restartPolicy = rname
		}
	}

	nets := make([]ContainerNetworkAttachment, 0, len(raw.NetworkSettings.Networks))
	for netName, info := range raw.NetworkSettings.Networks {
		nets = append(nets, ContainerNetworkAttachment{
			Name:      netName,
			NetworkID: shortDockerID(info.NetworkID),
			IPAddress: info.IPAddress,
			Gateway:   info.Gateway,
			MacAddr:   info.MacAddress,
		})
	}
	slices.SortFunc(nets, func(a, b ContainerNetworkAttachment) int {
		return strings.Compare(a.Name, b.Name)
	})

	ports := formatInspectPorts(raw.NetworkSettings.Ports)
	mounts := raw.Mounts
	if mounts == nil {
		mounts = []ContainerMount{}
	}
	labels := raw.Config.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	env := raw.Config.Env
	if env == nil {
		env = []string{}
	}

	return ContainerInspect{
		ID:         shortDockerID(raw.ID),
		FullID:     raw.ID,
		Name:       name,
		Image:      imageRef,
		Created:    raw.Created,
		Protected:  IsProtectedSystemContainer(name),
		State: ContainerStateDetail{
			Status:     raw.State.Status,
			Running:    raw.State.Running,
			Paused:     raw.State.Paused,
			Restarting: raw.State.Restarting,
			OOMKilled:  raw.State.OOMKilled,
			Pid:        raw.State.Pid,
			ExitCode:   raw.State.ExitCode,
			StartedAt:  raw.State.StartedAt,
			FinishedAt: raw.State.FinishedAt,
			Health:     healthStatus,
			HealthLogs: healthLogs,
		},
		Env:           env,
		Cmd:           slices.Clone(raw.Config.Cmd),
		Entrypoint:    slices.Clone(raw.Config.Entrypoint),
		WorkingDir:    raw.Config.WorkingDir,
		RestartPolicy: restartPolicy,
		MemoryLimitMb: memBytes / (1024 * 1024),
		NanoCPUs:      nanoCPUs,
		CPUCores:      math.Round((float64(nanoCPUs)/1e9)*100) / 100,
		Ports:         ports,
		Mounts:        mounts,
		Networks:      nets,
		Labels:        labels,
	}, nil
}

func formatInspectPorts(ports map[string][]dockerInspectPortBinding) string {
	if len(ports) == 0 {
		return "internal"
	}
	var out []string
	for containerPort, bindings := range ports {
		if len(bindings) == 0 {
			out = append(out, containerPort)
			continue
		}
		for _, b := range bindings {
			ip := b.HostIP
			if ip == "" {
				ip = "0.0.0.0"
			}
			if b.HostPort != "" {
				out = append(out, ip+":"+b.HostPort+"->"+containerPort)
			} else {
				out = append(out, containerPort)
			}
		}
	}
	slices.Sort(out)
	return strings.Join(out, ", ")
}

type dockerRawStats struct {
	Read     string `json:"read"`
	CPUStats struct {
		CPUUsage struct {
			TotalUsage  uint64   `json:"total_usage"`
			PercpuUsage []uint64 `json:"percpu_usage"`
		} `json:"cpu_usage"`
		SystemCPUUsage uint64 `json:"system_cpu_usage"`
		OnlineCPUs     uint32 `json:"online_cpus"`
	} `json:"cpu_stats"`
	PreCPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemCPUUsage uint64 `json:"system_cpu_usage"`
	} `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64            `json:"usage"`
		Limit uint64            `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
	Networks map[string]struct {
		RxBytes uint64 `json:"rx_bytes"`
		TxBytes uint64 `json:"tx_bytes"`
	} `json:"networks"`
	BlkioStats struct {
		IoServiceBytesRecursive []struct {
			Op    string `json:"op"`
			Value uint64 `json:"value"`
		} `json:"io_service_bytes_recursive"`
	} `json:"blkio_stats"`
	PidsStats struct {
		Current uint64 `json:"current"`
	} `json:"pids_stats"`
}

func computeContainerStats(id, name string, raw dockerRawStats) ContainerStats {
	var cpuPct float64
	if raw.CPUStats.CPUUsage.TotalUsage > raw.PreCPUStats.CPUUsage.TotalUsage &&
		raw.CPUStats.SystemCPUUsage > raw.PreCPUStats.SystemCPUUsage {
		cpuDelta := float64(raw.CPUStats.CPUUsage.TotalUsage - raw.PreCPUStats.CPUUsage.TotalUsage)
		sysDelta := float64(raw.CPUStats.SystemCPUUsage - raw.PreCPUStats.SystemCPUUsage)
		online := float64(raw.CPUStats.OnlineCPUs)
		if online <= 0 {
			online = float64(len(raw.CPUStats.CPUUsage.PercpuUsage))
		}
		if online <= 0 {
			online = 1
		}
		cpuPct = (cpuDelta / sysDelta) * online * 100.0
	}
	cpuPct = math.Round(cpuPct*100) / 100

	cacheBytes := raw.MemoryStats.Stats["inactive_file"]
	if cacheBytes == 0 {
		cacheBytes = raw.MemoryStats.Stats["cache"]
	}
	usedBytes := raw.MemoryStats.Usage
	if usedBytes > cacheBytes {
		usedBytes -= cacheBytes
	}
	usedMb := math.Round((float64(usedBytes)/(1024*1024))*10) / 10
	limitMb := math.Round((float64(raw.MemoryStats.Limit)/(1024*1024))*10) / 10
	var memPct float64
	if limitMb > 0 {
		memPct = math.Round((usedMb/limitMb)*1000) / 10
	}

	var rx, tx uint64
	for _, n := range raw.Networks {
		rx += n.RxBytes
		tx += n.TxBytes
	}

	var blkRead, blkWrite uint64
	for _, entry := range raw.BlkioStats.IoServiceBytesRecursive {
		switch strings.ToLower(entry.Op) {
		case "read":
			blkRead += entry.Value
		case "write":
			blkWrite += entry.Value
		}
	}

	return ContainerStats{
		ID:           id,
		Name:         name,
		CPUPct:       cpuPct,
		MemoryUsedMb: usedMb,
		MemoryLimMb:  limitMb,
		MemoryPct:    memPct,
		NetRxBytes:   rx,
		NetTxBytes:   tx,
		BlockReadB:   blkRead,
		BlockWriteB:  blkWrite,
		PIDs:         raw.PidsStats.Current,
		ReadAt:       raw.Read,
	}
}

// GetContainerStats queries single-shot real resource metrics for a container.
func (e *Engine) GetContainerStats(id string) (ContainerStats, error) {
	runtimeMode, endpoint, dockerID, cname, err := e.resolveContainerDockerTarget(id)
	if err != nil {
		return ContainerStats{}, err
	}

	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		e.mu.RLock()
		defer e.mu.RUnlock()
		c := e.containers[e.findContainerIndexLocked(dockerID)]
		lim := float64(max(1, c.RAMLimitMb))
		return ContainerStats{
			ID:           c.ID,
			Name:         c.Name,
			CPUPct:       c.CPUPct,
			MemoryUsedMb: float64(c.RAMMb),
			MemoryLimMb:  lim,
			MemoryPct:    math.Round((float64(c.RAMMb)/lim)*1000) / 10,
			PIDs:         1,
			ReadAt:       time.Now().UTC().Format(time.RFC3339),
		}, nil
	}

	client, baseURL, ok := newDockerHTTPClient(endpoint, 5*time.Second)
	if !ok {
		return ContainerStats{}, errors.New("docker engine endpoint unreachable")
	}
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/containers/"+url.PathEscape(dockerID)+"/stats?stream=false", nil)
	resp, err := client.Do(req)
	if err != nil {
		return ContainerStats{}, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ContainerStats{}, parseDockerAPIErrorMessage(resp.StatusCode, body)
	}

	var raw dockerRawStats
	if err := json.Unmarshal(body, &raw); err != nil {
		return ContainerStats{}, fmt.Errorf("decode stats: %w", err)
	}
	st := computeContainerStats(dockerID, cname, raw)

	e.mu.Lock()
	if idx := e.findContainerIndexLocked(dockerID); idx >= 0 {
		e.containers[idx].CPUPct = math.Round(st.CPUPct*10) / 10
		e.containers[idx].RAMMb = int(math.Round(st.MemoryUsedMb))
		if st.MemoryLimMb > 0 && st.MemoryLimMb <= 65536 {
			e.containers[idx].RAMLimitMb = int(math.Round(st.MemoryLimMb))
		}
		e.syncProjectFromContainersLocked(e.containers[idx].Project)
	}
	e.mu.Unlock()
	return st, nil
}

// GetAllRunningContainerStats concurrently fetches stats for all running containers.
func (e *Engine) GetAllRunningContainerStats() map[string]ContainerStats {
	e.mu.RLock()
	targets := make([]Container, 0, len(e.containers))
	for _, c := range e.containers {
		if c.Status == "Running" {
			targets = append(targets, cloneContainer(c))
		}
	}
	e.mu.RUnlock()

	results := make(map[string]ContainerStats, len(targets))
	var resMu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)

	for _, c := range targets {
		wg.Add(1)
		go func(cnt Container) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if st, err := e.GetContainerStats(cnt.ID); err == nil {
				resMu.Lock()
				results[cnt.ID] = st
				resMu.Unlock()
			}
		}(c)
	}
	wg.Wait()
	return results
}

// GetContainerTop returns active OS processes running inside a container.
func (e *Engine) GetContainerTop(id string) (ContainerTop, error) {
	runtimeMode, endpoint, dockerID, _, err := e.resolveContainerDockerTarget(id)
	if err != nil {
		return ContainerTop{}, err
	}
	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		return ContainerTop{
			ID:        dockerID,
			Titles:    []string{"PID", "USER", "TIME", "COMMAND"},
			Processes: [][]string{{"1", "root", "0:01", "app-server"}},
		}, nil
	}

	client, baseURL, ok := newDockerHTTPClient(endpoint, 5*time.Second)
	if !ok {
		return ContainerTop{}, errors.New("docker engine endpoint unreachable")
	}
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/containers/"+url.PathEscape(dockerID)+"/top", nil)
	resp, err := client.Do(req)
	if err != nil {
		return ContainerTop{}, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ContainerTop{}, parseDockerAPIErrorMessage(resp.StatusCode, body)
	}
	var out struct {
		Titles    []string   `json:"Titles"`
		Processes [][]string `json:"Processes"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return ContainerTop{}, fmt.Errorf("decode top: %w", err)
	}
	return ContainerTop{
		ID:        dockerID,
		Titles:    out.Titles,
		Processes: out.Processes,
	}, nil
}

// UpdateContainerResources hot-updates Memory, CPU quota, and RestartPolicy on a container.
func (e *Engine) UpdateContainerResources(id string, memoryMb int64, cpuCores float64, restartPolicy string) error {
	runtimeMode, endpoint, dockerID, cname, err := e.resolveContainerDockerTarget(id)
	if err != nil {
		return err
	}
	if IsProtectedSystemContainer(cname) {
		return fmt.Errorf("%w: system container %q resource limits are managed by compose", ErrProtectedContainer, cname)
	}
	if memoryMb < 0 || memoryMb > 262144 {
		return errors.New("memoryMb must be between 0 and 262144 MB")
	}
	if cpuCores < 0 || cpuCores > 128 {
		return errors.New("cpuCores must be between 0 and 128")
	}
	rp := strings.ToLower(strings.TrimSpace(restartPolicy))
	switch rp {
	case "", "no", "always", "unless-stopped", "on-failure":
	default:
		return fmt.Errorf("unsupported restartPolicy %q", restartPolicy)
	}

	if runtimeMode == "docker" && strings.TrimSpace(endpoint) != "" {
		client, baseURL, ok := newDockerHTTPClient(endpoint, 10*time.Second)
		if !ok {
			return errors.New("docker engine endpoint unreachable")
		}
		payload := map[string]any{}
		if memoryMb > 0 {
			memBytes := memoryMb * 1024 * 1024
			payload["Memory"] = memBytes
			payload["MemorySwap"] = memBytes * 2
		} else {
			payload["Memory"] = int64(0)
			payload["MemorySwap"] = int64(0)
		}
		if cpuCores > 0 {
			payload["NanoCpus"] = int64(math.Round(cpuCores * 1e9))
		} else {
			payload["NanoCpus"] = int64(0)
		}
		if rp != "" {
			rpMap := map[string]any{"Name": rp}
			if rp == "on-failure" {
				rpMap["MaximumRetryCount"] = 5
			}
			payload["RestartPolicy"] = rpMap
		}
		rawBytes, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/containers/"+url.PathEscape(dockerID)+"/update", bytes.NewReader(rawBytes))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return parseDockerAPIErrorMessage(resp.StatusCode, respBody)
		}
	}

	if memoryMb > 0 {
		e.mu.Lock()
		if idx := e.findContainerIndexLocked(dockerID); idx >= 0 {
			e.containers[idx].RAMLimitMb = int(memoryMb)
			e.syncProjectFromContainersLocked(e.containers[idx].Project)
		}
		e.mu.Unlock()
	}
	return nil
}

// StreamContainerLogs follows live stdout/stderr logs from a container until ctx ends or onLine returns false.
func (e *Engine) StreamContainerLogs(ctx context.Context, id string, tail int, timestamps bool, onLine func(stream, line string) bool) error {
	if tail <= 0 || tail > 2000 {
		tail = 200
	}
	runtimeMode, endpoint, dockerID, _, err := e.resolveContainerDockerTarget(id)
	if err != nil {
		return err
	}

	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		logs, _ := e.GetContainerLogs(dockerID, tail)
		for _, line := range logs {
			if !onLine("stdout", line) {
				return nil
			}
		}
		return nil
	}

	ttyMode := detectContainerTTY(endpoint, dockerID)
	client, baseURL, ok := newDockerHTTPClient(endpoint, 0)
	if !ok {
		return errors.New("docker engine endpoint unreachable")
	}
	tsFlag := "0"
	if timestamps {
		tsFlag = "1"
	}
	streamURL := fmt.Sprintf("%s/containers/%s/logs?follow=1&stdout=1&stderr=1&tail=%d&timestamps=%s",
		baseURL, url.PathEscape(dockerID), tail, tsFlag)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, streamURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return parseDockerAPIErrorMessage(resp.StatusCode, body)
	}

	return readDockerLogStream(resp.Body, ttyMode, onLine)
}

// detectContainerTTY returns 1 if Config.Tty=true, 0 if Config.Tty=false, or -1 if unknown.
func detectContainerTTY(endpoint, dockerID string) int {
	client, baseURL, ok := newDockerHTTPClient(endpoint, 2*time.Second)
	if !ok {
		return -1
	}
	req, err := http.NewRequest(http.MethodGet, baseURL+"/containers/"+url.PathEscape(dockerID)+"/json", nil)
	if err != nil {
		return -1
	}
	resp, err := client.Do(req)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return -1
	}
	var meta struct {
		Config struct {
			Tty bool `json:"Tty"`
		} `json:"Config"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&meta); err != nil {
		return -1
	}
	if meta.Config.Tty {
		return 1
	}
	return 0
}

func readDockerLogStream(body io.Reader, ttyMode int, onLine func(stream, line string) bool) error {
	br := bufio.NewReaderSize(body, 32*1024)
	isMultiplexed := ttyMode == 0
	if ttyMode < 0 {
		peek, err := br.Peek(8)
		if err != nil && len(peek) == 0 {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		isMultiplexed = len(peek) == 8 && (peek[0] == 1 || peek[0] == 2 || peek[0] == 0) &&
			peek[1] == 0 && peek[2] == 0 && peek[3] == 0
	}

	if !isMultiplexed {
		scanner := bufio.NewScanner(br)
		scanner.Buffer(make([]byte, 0, 16*1024), 512*1024)
		for scanner.Scan() {
			if !onLine("stdout", strings.TrimRight(scanner.Text(), "\r")) {
				return nil
			}
		}
		return scanner.Err()
	}

	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(br, hdr); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		streamName := "stdout"
		if hdr[0] == 2 {
			streamName = "stderr"
		}
		frameLen := binary.BigEndian.Uint32(hdr[4:8])
		if frameLen == 0 {
			continue
		}
		if frameLen > 16<<20 {
			return fmt.Errorf("docker log frame too large (%d bytes)", frameLen)
		}
		payload := make([]byte, frameLen)
		if _, err := io.ReadFull(br, payload); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				for _, line := range splitDockerPayloadLines(string(payload)) {
					_ = onLine(streamName, line)
				}
				return nil
			}
			return err
		}
		for _, line := range splitDockerPayloadLines(string(payload)) {
			if !onLine(streamName, line) {
				return nil
			}
		}
	}
}

// DownloadContainerLogs fetches recent container logs formatted as downloadable plain text.
func (e *Engine) DownloadContainerLogs(ctx context.Context, id string, tail int, timestamps bool) (string, string, error) {
	if tail <= 0 || tail > 5000 {
		tail = 1000
	}
	runtimeMode, endpoint, dockerID, cname, err := e.resolveContainerDockerTarget(id)
	if err != nil {
		return "", "", err
	}
	if cname == "" {
		cname = dockerID
	}

	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		logs, _ := e.GetContainerLogs(dockerID, tail)
		return cname, strings.Join(logs, "\n") + "\n", nil
	}

	client, baseURL, ok := newDockerHTTPClient(endpoint, 15*time.Second)
	if !ok {
		return "", "", errors.New("docker engine endpoint unreachable")
	}
	tsFlag := "0"
	if timestamps {
		tsFlag = "1"
	}
	dlURL := fmt.Sprintf("%s/containers/%s/logs?stdout=1&stderr=1&tail=%d&timestamps=%s",
		baseURL, url.PathEscape(dockerID), tail, tsFlag)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dlURL, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", "", parseDockerAPIErrorMessage(resp.StatusCode, body)
	}

	var buf strings.Builder
	_ = readDockerLogStream(resp.Body, detectContainerTTY(endpoint, dockerID), func(_ string, line string) bool {
		buf.WriteString(line)
		buf.WriteByte('\n')
		return true
	})
	return cname, buf.String(), nil
}

// GetSystemDiskUsage queries Docker Engine GET /system/df for accurate storage breakdown.
func (e *Engine) GetSystemDiskUsage() (DockerDiskUsage, error) {
	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	imagesCopy := slices.Clone(e.images)
	containersCopy := slices.Clone(e.containers)
	e.mu.RUnlock()

	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		var imgTotal, imgReclaim int64
		for _, img := range imagesCopy {
			b := int64(img.SizeMb) * 1024 * 1024
			imgTotal += b
			if !img.InUse {
				imgReclaim += b
			}
		}
		return DockerDiskUsage{
			Available: true,
			Images: DiskCategoryUsage{
				Count:            len(imagesCopy),
				ActiveCount:      len(imagesCopy),
				TotalBytes:       imgTotal,
				ReclaimableBytes: imgReclaim,
			},
			Containers: DiskCategoryUsage{
				Count: len(containersCopy),
			},
			TotalBytes:       imgTotal,
			ReclaimableBytes: imgReclaim,
		}, nil
	}

	client, baseURL, ok := newDockerHTTPClient(endpoint, 10*time.Second)
	if !ok {
		return DockerDiskUsage{}, errors.New("docker engine endpoint unreachable")
	}
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/system/df", nil)
	resp, err := client.Do(req)
	if err != nil {
		return DockerDiskUsage{}, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return DockerDiskUsage{}, parseDockerAPIErrorMessage(resp.StatusCode, body)
	}

	var raw struct {
		LayersSize int64 `json:"LayersSize"`
		Images     []struct {
			Size       int64 `json:"Size"`
			SharedSize int64 `json:"SharedSize"`
			Containers int64 `json:"Containers"`
		} `json:"Images"`
		Containers []struct {
			SizeRw int64  `json:"SizeRw"`
			State  string `json:"State"`
		} `json:"Containers"`
		Volumes []struct {
			UsageData struct {
				Size     int64 `json:"Size"`
				RefCount int64 `json:"RefCount"`
			} `json:"UsageData"`
		} `json:"Volumes"`
		BuildCache []struct {
			Size  int64 `json:"Size"`
			InUse bool  `json:"InUse"`
		} `json:"BuildCache"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return DockerDiskUsage{}, fmt.Errorf("decode system/df: %w", err)
	}

	var du DockerDiskUsage
	du.Available = true

	du.Images.Count = len(raw.Images)
	var uniqueImgTotal int64
	for _, img := range raw.Images {
		unique := img.Size - img.SharedSize
		if unique < 0 {
			unique = img.Size
		}
		uniqueImgTotal += img.Size
		if img.Containers > 0 {
			du.Images.ActiveCount++
		} else {
			du.Images.ReclaimableBytes += img.Size
		}
	}
	if raw.LayersSize > 0 {
		du.Images.TotalBytes = raw.LayersSize
		if du.Images.ReclaimableBytes > raw.LayersSize {
			du.Images.ReclaimableBytes = raw.LayersSize
		}
	} else {
		du.Images.TotalBytes = uniqueImgTotal
	}

	du.Containers.Count = len(raw.Containers)
	for _, c := range raw.Containers {
		if c.SizeRw > 0 {
			du.Containers.TotalBytes += c.SizeRw
			if !strings.EqualFold(c.State, "running") {
				du.Containers.ReclaimableBytes += c.SizeRw
			}
		}
		if strings.EqualFold(c.State, "running") {
			du.Containers.ActiveCount++
		}
	}

	du.Volumes.Count = len(raw.Volumes)
	for _, v := range raw.Volumes {
		sz := v.UsageData.Size
		if sz < 0 {
			sz = 0
		}
		du.Volumes.TotalBytes += sz
		if v.UsageData.RefCount > 0 {
			du.Volumes.ActiveCount++
		} else {
			du.Volumes.ReclaimableBytes += sz
		}
	}

	du.BuildCache.Count = len(raw.BuildCache)
	for _, bc := range raw.BuildCache {
		if bc.Size > 0 {
			du.BuildCache.TotalBytes += bc.Size
			if bc.InUse {
				du.BuildCache.ActiveCount++
			} else {
				du.BuildCache.ReclaimableBytes += bc.Size
			}
		} else if bc.InUse {
			du.BuildCache.ActiveCount++
		}
	}

	du.TotalBytes = du.Images.TotalBytes + du.Containers.TotalBytes + du.Volumes.TotalBytes + du.BuildCache.TotalBytes
	du.ReclaimableBytes = du.Images.ReclaimableBytes + du.Containers.ReclaimableBytes + du.Volumes.ReclaimableBytes + du.BuildCache.ReclaimableBytes
	return du, nil
}

// RemoveImage deletes a local Docker image unless it belongs to a protected system container.
func (e *Engine) RemoveImage(id string, force bool) error {
	cleanID := strings.TrimSpace(id)
	if cleanID == "" {
		return errors.New("image id is required")
	}

	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	var targetImg *DockerImage
	for i := range e.images {
		if e.images[i].ID == cleanID || e.images[i].RepoTag == cleanID {
			imgCopy := cloneImage(e.images[i])
			targetImg = &imgCopy
			break
		}
	}
	for _, c := range e.containers {
		if !c.Protected {
			continue
		}
		if targetImg != nil && (c.Image == targetImg.RepoTag || slices.Contains(targetImg.History, c.Image) || strings.Contains(c.Image, targetImg.ID)) {
			e.mu.RUnlock()
			return fmt.Errorf("%w: image %q is used by protected system container %q", ErrProtectedContainer, targetImg.RepoTag, c.Name)
		}
		if c.Image == cleanID {
			e.mu.RUnlock()
			return fmt.Errorf("%w: image %q is used by protected system container %q", ErrProtectedContainer, cleanID, c.Name)
		}
	}
	e.mu.RUnlock()

	if runtimeMode == "docker" && strings.TrimSpace(endpoint) != "" {
		client, baseURL, ok := newDockerHTTPClient(endpoint, 15*time.Second)
		if !ok {
			return errors.New("docker engine endpoint unreachable")
		}
		forceParam := "0"
		if force {
			forceParam = "1"
		}
		delURL := fmt.Sprintf("%s/images/%s?force=%s", baseURL, url.PathEscape(cleanID), forceParam)
		req, _ := http.NewRequest(http.MethodDelete, delURL, nil)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return parseDockerAPIErrorMessage(resp.StatusCode, body)
		}
		e.SyncDockerEngine()
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	for i, img := range e.images {
		if img.ID == cleanID || img.RepoTag == cleanID {
			e.images = append(e.images[:i], e.images[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("image %q not found", id)
}

// GetImageHistory retrieves layer history from Docker Engine GET /images/{id}/history.
func (e *Engine) GetImageHistory(id string) ([]ImageHistoryLayer, error) {
	cleanID := strings.TrimSpace(id)
	if cleanID == "" {
		return nil, errors.New("image id is required")
	}

	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	var simImg *DockerImage
	for i := range e.images {
		if e.images[i].ID == cleanID || e.images[i].RepoTag == cleanID {
			cp := cloneImage(e.images[i])
			simImg = &cp
			break
		}
	}
	e.mu.RUnlock()

	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		if simImg == nil {
			return nil, fmt.Errorf("image %q not found", id)
		}
		return []ImageHistoryLayer{
			{
				ID:        simImg.ID,
				Created:   simImg.Created,
				CreatedBy: "/bin/sh -c #(nop) CMD [\"/server\"]",
				SizeBytes: int64(simImg.SizeMb) * 1024 * 1024,
				Tags:      simImg.History,
			},
		}, nil
	}

	client, baseURL, ok := newDockerHTTPClient(endpoint, 10*time.Second)
	if !ok {
		return nil, errors.New("docker engine endpoint unreachable")
	}
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/images/"+url.PathEscape(cleanID)+"/history", nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, parseDockerAPIErrorMessage(resp.StatusCode, body)
	}

	var raw []struct {
		ID        string   `json:"Id"`
		Created   int64    `json:"Created"`
		CreatedBy string   `json:"CreatedBy"`
		Size      int64    `json:"Size"`
		Comment   string   `json:"Comment"`
		Tags      []string `json:"Tags"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode image history: %w", err)
	}
	layers := make([]ImageHistoryLayer, 0, len(raw))
	for _, r := range raw {
		layerID := strings.TrimPrefix(strings.TrimSpace(r.ID), "sha256:")
		if len(layerID) > 12 {
			layerID = layerID[:12]
		}
		if layerID == "" {
			layerID = "<missing>"
		}
		layers = append(layers, ImageHistoryLayer{
			ID:        layerID,
			Created:   formatUnixSeconds(r.Created),
			CreatedBy: r.CreatedBy,
			SizeBytes: r.Size,
			Comment:   r.Comment,
			Tags:      r.Tags,
		})
	}
	return layers, nil
}

// PruneImages deletes dangling images or all unused images when all=true.
func (e *Engine) PruneImages(all bool) PruneResult {
	if !all {
		return e.PruneDanglingImages()
	}

	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()

	if runtimeMode == "docker" && strings.TrimSpace(endpoint) != "" {
		if client, baseURL, ok := newDockerHTTPClient(endpoint, 30*time.Second); ok {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			deleted, reclaimedBytes, pruneErr := pruneDockerImagesWithFilter(ctx, client, baseURL, `{"dangling":["false"]}`)
			d2, r2, err2 := pruneDanglingDockerImages(ctx, client, baseURL)
			cancel()
			if pruneErr == nil || err2 == nil {
				e.SyncDockerEngine()
				e.mu.RLock()
				resultImages := make([]DockerImage, len(e.images))
				for i, img := range e.images {
					resultImages[i] = cloneImage(img)
				}
				e.mu.RUnlock()
				return PruneResult{
					RemovedCount: deleted + d2,
					ReclaimedMb:  int((reclaimedBytes + r2) / (1024 * 1024)),
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
		if !img.InUse {
			removedCount++
			reclaimedMb += img.SizeMb
			continue
		}
		kept = append(kept, cloneImage(img))
	}
	e.images = kept
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

func pruneDockerImagesWithFilter(ctx context.Context, client *http.Client, baseURL, filterJSON string) (int, int64, error) {
	pruneURL := strings.TrimRight(baseURL, "/") + "/images/prune?filters=" + url.QueryEscape(filterJSON)
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

// PruneBuildCache clears unused Docker Builder cache via POST /build/prune.
func (e *Engine) PruneBuildCache(all bool) (BuildCachePruneResult, error) {
	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()

	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		return BuildCachePruneResult{CachesDeleted: 0, SpaceReclaimedBytes: 0, ReclaimedMb: 0}, nil
	}
	client, baseURL, ok := newDockerHTTPClient(endpoint, 30*time.Second)
	if !ok {
		return BuildCachePruneResult{}, errors.New("docker engine endpoint unreachable")
	}
	pruneURL := baseURL + "/build/prune"
	if all {
		pruneURL += "?all=true"
	}
	req, _ := http.NewRequest(http.MethodPost, pruneURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		return BuildCachePruneResult{}, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return BuildCachePruneResult{}, parseDockerAPIErrorMessage(resp.StatusCode, body)
	}
	var res struct {
		CachesDeleted  []string `json:"CachesDeleted"`
		SpaceReclaimed int64    `json:"SpaceReclaimed"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return BuildCachePruneResult{}, fmt.Errorf("decode build/prune: %w", err)
	}
	return BuildCachePruneResult{
		CachesDeleted:       len(res.CachesDeleted),
		SpaceReclaimedBytes: res.SpaceReclaimed,
		ReclaimedMb:         int(res.SpaceReclaimed / (1024 * 1024)),
	}, nil
}
