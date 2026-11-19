package docker

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// DockerVolume describes a Docker Engine persistent volume and its container references.
type DockerVolume struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Scope      string            `json:"scope"`
	Mountpoint string            `json:"mountpoint"`
	CreatedAt  string            `json:"createdAt"`
	SizeBytes  int64             `json:"sizeBytes"`
	RefCount   int64             `json:"refCount"`
	InUseBy    []string          `json:"inUseBy"`
	Protected  bool              `json:"protected"`
	Labels     map[string]string `json:"labels"`
}

// NetworkAttachedContainer describes a container connected to a Docker network.
type NetworkAttachedContainer struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	IPv4 string `json:"ipv4"`
	Mac  string `json:"macAddress"`
}

// DockerNetwork describes a Docker network with subnet/gateway and attached containers.
type DockerNetwork struct {
	ID         string                     `json:"id"`
	FullID     string                     `json:"fullId"`
	Name       string                     `json:"name"`
	Driver     string                     `json:"driver"`
	Scope      string                     `json:"scope"`
	Internal   bool                       `json:"internal"`
	Subnet     string                     `json:"subnet"`
	Gateway    string                     `json:"gateway"`
	Created    string                     `json:"created"`
	Protected  bool                       `json:"protected"`
	Containers []NetworkAttachedContainer `json:"containers"`
	Labels     map[string]string          `json:"labels"`
}

// PruneResourcesResult summarizes deleted volumes or networks and reclaimed bytes.
type PruneResourcesResult struct {
	Removed        []string `json:"removed"`
	RemovedCount   int      `json:"removedCount"`
	ReclaimedBytes int64    `json:"reclaimedBytes"`
}

func isStaticProtectedVolume(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "hub_data", "letsencrypt_certs", "traefik_dynamic",
		"deployment-hub_hub_data", "deployment-hub_letsencrypt_certs", "deployment-hub_traefik_dynamic":
		return true
	default:
		return false
	}
}

func isStaticProtectedNetwork(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "bridge", "host", "none", "deploymenthub_proxy", "hub_internal",
		"deployment-hub_hub_internal", "deployment-hub_default":
		return true
	default:
		return false
	}
}

func (e *Engine) inspectProtectedMountsAndNetworks(client *http.Client, baseURL string) (protVols map[string]bool, protNets map[string]bool) {
	protVols = make(map[string]bool)
	protNets = make(map[string]bool)
	e.mu.RLock()
	var sysIDs []string
	for _, c := range e.containers {
		if c.Protected || IsProtectedSystemContainer(c.Name) {
			sysIDs = append(sysIDs, c.ID)
		}
	}
	e.mu.RUnlock()

	for _, cid := range sysIDs {
		req, err := http.NewRequest(http.MethodGet, baseURL+"/containers/"+url.PathEscape(cid)+"/json", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode == http.StatusOK {
			var raw dockerRawInspect
			if json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&raw) == nil {
				for _, m := range raw.Mounts {
					if m.Name != "" {
						protVols[strings.ToLower(strings.TrimSpace(m.Name))] = true
					}
				}
				for netName := range raw.NetworkSettings.Networks {
					if netName != "" {
						protNets[strings.ToLower(strings.TrimSpace(netName))] = true
					}
				}
			}
		}
		_ = resp.Body.Close()
	}
	return protVols, protNets
}

// ListVolumes returns all Docker volumes with attached container info, sizes (best-effort), and system protection flags.
func (e *Engine) ListVolumes() ([]DockerVolume, error) {
	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()

	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		return []DockerVolume{}, nil
	}
	client, baseURL, ok := newDockerHTTPClient(endpoint, 10*time.Second)
	if !ok {
		return nil, errors.New("docker engine endpoint unreachable")
	}

	req, _ := http.NewRequest(http.MethodGet, baseURL+"/volumes", nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, parseDockerAPIErrorMessage(resp.StatusCode, body)
	}

	var volResp struct {
		Volumes []struct {
			Name       string            `json:"Name"`
			Driver     string            `json:"Driver"`
			Scope      string            `json:"Scope"`
			Mountpoint string            `json:"Mountpoint"`
			CreatedAt  string            `json:"CreatedAt"`
			Labels     map[string]string `json:"Labels"`
			UsageData  *struct {
				Size     int64 `json:"Size"`
				RefCount int64 `json:"RefCount"`
			} `json:"UsageData"`
		} `json:"Volumes"`
	}
	if err := json.Unmarshal(body, &volResp); err != nil {
		return nil, fmt.Errorf("decode volumes: %w", err)
	}

	// Best-effort /system/df for accurate volume byte sizes.
	sizeByVol := make(map[string]int64)
	refByVol := make(map[string]int64)
	if dfReq, err := http.NewRequest(http.MethodGet, baseURL+"/system/df", nil); err == nil {
		if dfResp, err := client.Do(dfReq); err == nil {
			if dfResp.StatusCode == http.StatusOK {
				var dfRaw struct {
					Volumes []struct {
						Name      string `json:"Name"`
						UsageData struct {
							Size     int64 `json:"Size"`
							RefCount int64 `json:"RefCount"`
						} `json:"UsageData"`
					} `json:"Volumes"`
				}
				if json.NewDecoder(io.LimitReader(dfResp.Body, 4<<20)).Decode(&dfRaw) == nil {
					for _, dv := range dfRaw.Volumes {
						sizeByVol[dv.Name] = dv.UsageData.Size
						refByVol[dv.Name] = dv.UsageData.RefCount
					}
				}
			}
			_ = dfResp.Body.Close()
		}
	}

	// Correlate container mounts from /containers/json?all=1.
	usedByVol := make(map[string][]string)
	protVols, _ := e.inspectProtectedMountsAndNetworks(client, baseURL)
	if cReq, err := http.NewRequest(http.MethodGet, baseURL+"/containers/json?all=1", nil); err == nil {
		if cResp, err := client.Do(cReq); err == nil {
			if cResp.StatusCode == http.StatusOK {
				var apiCnts []struct {
					Id     string   `json:"Id"`
					Names  []string `json:"Names"`
					Mounts []struct {
						Name string `json:"Name"`
					} `json:"Mounts"`
				}
				if json.NewDecoder(io.LimitReader(cResp.Body, 4<<20)).Decode(&apiCnts) == nil {
					for _, dc := range apiCnts {
						cname := shortDockerID(dc.Id)
						if len(dc.Names) > 0 {
							if tr := strings.TrimPrefix(strings.TrimSpace(dc.Names[0]), "/"); tr != "" {
								cname = tr
							}
						}
						isSys := IsProtectedSystemContainer(cname)
						for _, m := range dc.Mounts {
							if m.Name == "" {
								continue
							}
							if !slices.Contains(usedByVol[m.Name], cname) {
								usedByVol[m.Name] = append(usedByVol[m.Name], cname)
							}
							if isSys {
								protVols[strings.ToLower(strings.TrimSpace(m.Name))] = true
							}
						}
					}
				}
			}
			_ = cResp.Body.Close()
		}
	}

	out := make([]DockerVolume, 0, len(volResp.Volumes))
	for _, v := range volResp.Volumes {
		sz := sizeByVol[v.Name]
		ref := refByVol[v.Name]
		if v.UsageData != nil {
			if sz == 0 && v.UsageData.Size > 0 {
				sz = v.UsageData.Size
			}
			if ref == 0 && v.UsageData.RefCount > 0 {
				ref = v.UsageData.RefCount
			}
		}
		inUse := usedByVol[v.Name]
		if inUse == nil {
			inUse = []string{}
		}
		if ref == 0 && len(inUse) > 0 {
			ref = int64(len(inUse))
		}
		labels := v.Labels
		if labels == nil {
			labels = map[string]string{}
		}
		prot := isStaticProtectedVolume(v.Name) || protVols[strings.ToLower(strings.TrimSpace(v.Name))]
		out = append(out, DockerVolume{
			Name:       v.Name,
			Driver:     v.Driver,
			Scope:      v.Scope,
			Mountpoint: v.Mountpoint,
			CreatedAt:  v.CreatedAt,
			SizeBytes:  max(int64(0), sz),
			RefCount:   ref,
			InUseBy:    inUse,
			Protected:  prot,
			Labels:     labels,
		})
	}
	slices.SortFunc(out, func(a, b DockerVolume) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out, nil
}

// CreateVolume creates a named Docker volume via POST /volumes/create.
func (e *Engine) CreateVolume(name, driver string, labels map[string]string) (DockerVolume, error) {
	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return DockerVolume{}, errors.New("volume name is required")
	}
	if strings.ContainsAny(cleanName, "/\\ \t\n") {
		return DockerVolume{}, errors.New("invalid volume name")
	}
	drv := strings.TrimSpace(driver)
	if drv == "" {
		drv = "local"
	}

	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()

	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		return DockerVolume{Name: cleanName, Driver: drv, Scope: "local", InUseBy: []string{}, Labels: labels}, nil
	}
	client, baseURL, ok := newDockerHTTPClient(endpoint, 10*time.Second)
	if !ok {
		return DockerVolume{}, errors.New("docker engine endpoint unreachable")
	}
	payload := map[string]any{
		"Name":   cleanName,
		"Driver": drv,
	}
	if len(labels) > 0 {
		payload["Labels"] = labels
	}
	rawBytes, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/volumes/create", bytes.NewReader(rawBytes))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return DockerVolume{}, err
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return DockerVolume{}, parseDockerAPIErrorMessage(resp.StatusCode, respBody)
	}
	var created struct {
		Name       string            `json:"Name"`
		Driver     string            `json:"Driver"`
		Scope      string            `json:"Scope"`
		Mountpoint string            `json:"Mountpoint"`
		CreatedAt  string            `json:"CreatedAt"`
		Labels     map[string]string `json:"Labels"`
	}
	_ = json.Unmarshal(respBody, &created)
	if created.Labels == nil {
		created.Labels = map[string]string{}
	}
	return DockerVolume{
		Name:       created.Name,
		Driver:     created.Driver,
		Scope:      created.Scope,
		Mountpoint: created.Mountpoint,
		CreatedAt:  created.CreatedAt,
		InUseBy:    []string{},
		Labels:     created.Labels,
	}, nil
}

// RemoveVolume deletes an unused, non-protected Docker volume.
func (e *Engine) RemoveVolume(name string, force bool) error {
	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return errors.New("volume name is required")
	}
	if isStaticProtectedVolume(cleanName) {
		return fmt.Errorf("%w: system volume %q cannot be deleted", ErrProtectedContainer, cleanName)
	}

	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()

	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		return nil
	}
	client, baseURL, ok := newDockerHTTPClient(endpoint, 15*time.Second)
	if !ok {
		return errors.New("docker engine endpoint unreachable")
	}
	protVols, _ := e.inspectProtectedMountsAndNetworks(client, baseURL)
	if protVols[strings.ToLower(cleanName)] {
		return fmt.Errorf("%w: volume %q is mounted by a protected system container", ErrProtectedContainer, cleanName)
	}

	f := "0"
	if force {
		f = "1"
	}
	req, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/volumes/%s?force=%s", baseURL, url.PathEscape(cleanName), f), nil)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return parseDockerAPIErrorMessage(resp.StatusCode, body)
	}
	return nil
}

// PruneVolumes deletes all unused anonymous/unreferenced volumes via POST /volumes/prune.
func (e *Engine) PruneVolumes() (PruneResourcesResult, error) {
	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()

	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		return PruneResourcesResult{Removed: []string{}}, nil
	}
	client, baseURL, ok := newDockerHTTPClient(endpoint, 30*time.Second)
	if !ok {
		return PruneResourcesResult{}, errors.New("docker engine endpoint unreachable")
	}
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/volumes/prune", nil)
	resp, err := client.Do(req)
	if err != nil {
		return PruneResourcesResult{}, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return PruneResourcesResult{}, parseDockerAPIErrorMessage(resp.StatusCode, body)
	}
	var res struct {
		VolumesDeleted []string `json:"VolumesDeleted"`
		SpaceReclaimed int64    `json:"SpaceReclaimed"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return PruneResourcesResult{}, fmt.Errorf("decode volumes/prune: %w", err)
	}
	if res.VolumesDeleted == nil {
		res.VolumesDeleted = []string{}
	}
	return PruneResourcesResult{
		Removed:        res.VolumesDeleted,
		RemovedCount:   len(res.VolumesDeleted),
		ReclaimedBytes: res.SpaceReclaimed,
	}, nil
}

// BackupVolumeTarGz streams a gzip-compressed tar archive of volume contents using a temporary read-only container.
func (e *Engine) BackupVolumeTarGz(ctx context.Context, volumeName string, w io.Writer) error {
	cleanName := strings.TrimSpace(volumeName)
	if cleanName == "" {
		return errors.New("volume name is required")
	}

	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()

	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		return errors.New("volume backup requires live Docker Engine mode")
	}

	client, baseURL, ok := newDockerHTTPClient(endpoint, 10*time.Minute)
	if !ok {
		return errors.New("docker engine endpoint unreachable")
	}

	// Verify volume exists first.
	vReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/volumes/"+url.PathEscape(cleanName), nil)
	vResp, err := client.Do(vReq)
	if err != nil {
		return err
	}
	vBody, _ := io.ReadAll(io.LimitReader(vResp.Body, 4096))
	_ = vResp.Body.Close()
	if vResp.StatusCode != http.StatusOK {
		return parseDockerAPIErrorMessage(vResp.StatusCode, vBody)
	}

	helperName := "dh-vol-backup-" + shortHex(4)
	createPayload, _ := json.Marshal(map[string]any{
		"Image": "alpine:3.20",
		"Cmd":   []string{"sleep", "60"},
		"HostConfig": map[string]any{
			"Binds": []string{cleanName + ":/vol:ro"},
		},
	})
	cReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/containers/create?name="+url.QueryEscape(helperName), bytes.NewReader(createPayload))
	cReq.Header.Set("Content-Type", "application/json")
	cResp, err := client.Do(cReq)
	if err != nil {
		return err
	}
	cBody, _ := io.ReadAll(io.LimitReader(cResp.Body, 4096))
	_ = cResp.Body.Close()
	if cResp.StatusCode != http.StatusCreated && cResp.StatusCode != http.StatusOK {
		return parseDockerAPIErrorMessage(cResp.StatusCode, cBody)
	}
	var created struct {
		ID string `json:"Id"`
	}
	_ = json.Unmarshal(cBody, &created)
	tmpID := strings.TrimSpace(created.ID)
	if tmpID == "" {
		tmpID = helperName
	}

	defer func() {
		delReq, err := http.NewRequest(http.MethodDelete, baseURL+"/containers/"+url.PathEscape(tmpID)+"?force=1", nil)
		if err == nil {
			if delResp, err := client.Do(delReq); err == nil {
				_ = delResp.Body.Close()
			}
		}
	}()

	archReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/containers/"+url.PathEscape(tmpID)+"/archive?path=/vol", nil)
	archResp, err := client.Do(archReq)
	if err != nil {
		return err
	}
	defer archResp.Body.Close()
	if archResp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(archResp.Body, 4096))
		return parseDockerAPIErrorMessage(archResp.StatusCode, errBody)
	}

	gz := gzip.NewWriter(w)
	if _, err := io.Copy(gz, archResp.Body); err != nil {
		_ = gz.Close()
		return err
	}
	return gz.Close()
}

// ListNetworks lists all Docker networks with IPAM subnet/gateway, attached containers, and protection flags.
func (e *Engine) ListNetworks() ([]DockerNetwork, error) {
	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()

	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		return []DockerNetwork{}, nil
	}
	client, baseURL, ok := newDockerHTTPClient(endpoint, 10*time.Second)
	if !ok {
		return nil, errors.New("docker engine endpoint unreachable")
	}

	_, protNets := e.inspectProtectedMountsAndNetworks(client, baseURL)

	req, _ := http.NewRequest(http.MethodGet, baseURL+"/networks", nil)
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
		ID       string            `json:"Id"`
		Name     string            `json:"Name"`
		Driver   string            `json:"Driver"`
		Scope    string            `json:"Scope"`
		Internal bool              `json:"Internal"`
		Created  string            `json:"Created"`
		Labels   map[string]string `json:"Labels"`
		IPAM     struct {
			Config []struct {
				Subnet  string `json:"Subnet"`
				Gateway string `json:"Gateway"`
			} `json:"Config"`
		} `json:"IPAM"`
		Containers map[string]struct {
			Name        string `json:"Name"`
			IPv4Address string `json:"IPv4Address"`
			MacAddress  string `json:"MacAddress"`
		} `json:"Containers"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode networks: %w", err)
	}

	out := make([]DockerNetwork, 0, len(raw))
	for _, n := range raw {
		subnet, gw := "", ""
		if len(n.IPAM.Config) > 0 {
			subnet = n.IPAM.Config[0].Subnet
			gw = n.IPAM.Config[0].Gateway
		}
		cnts := make([]NetworkAttachedContainer, 0, len(n.Containers))
		for cid, cinfo := range n.Containers {
			cnts = append(cnts, NetworkAttachedContainer{
				ID:   shortDockerID(cid),
				Name: cinfo.Name,
				IPv4: cinfo.IPv4Address,
				Mac:  cinfo.MacAddress,
			})
		}
		slices.SortFunc(cnts, func(a, b NetworkAttachedContainer) int {
			return strings.Compare(a.Name, b.Name)
		})
		labels := n.Labels
		if labels == nil {
			labels = map[string]string{}
		}
		prot := isStaticProtectedNetwork(n.Name) || protNets[strings.ToLower(strings.TrimSpace(n.Name))]
		out = append(out, DockerNetwork{
			ID:         shortDockerID(n.ID),
			FullID:     n.ID,
			Name:       n.Name,
			Driver:     n.Driver,
			Scope:      n.Scope,
			Internal:   n.Internal,
			Subnet:     subnet,
			Gateway:    gw,
			Created:    n.Created,
			Protected:  prot,
			Containers: cnts,
			Labels:     labels,
		})
	}
	slices.SortFunc(out, func(a, b DockerNetwork) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out, nil
}

// CreateNetwork creates a Docker network with optional IPAM subnet/gateway and internal isolation.
func (e *Engine) CreateNetwork(name, driver, subnet, gateway string, internal bool) (DockerNetwork, error) {
	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return DockerNetwork{}, errors.New("network name is required")
	}
	drv := strings.TrimSpace(driver)
	if drv == "" {
		drv = "bridge"
	}

	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()

	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		return DockerNetwork{ID: "net-" + shortHex(4), Name: cleanName, Driver: drv, Internal: internal, Subnet: subnet, Gateway: gateway, Containers: []NetworkAttachedContainer{}}, nil
	}

	client, baseURL, ok := newDockerHTTPClient(endpoint, 10*time.Second)
	if !ok {
		return DockerNetwork{}, errors.New("docker engine endpoint unreachable")
	}

	payload := map[string]any{
		"Name":           cleanName,
		"Driver":         drv,
		"Internal":       internal,
		"CheckDuplicate": true,
	}
	if strings.TrimSpace(subnet) != "" {
		cfg := map[string]string{"Subnet": strings.TrimSpace(subnet)}
		if strings.TrimSpace(gateway) != "" {
			cfg["Gateway"] = strings.TrimSpace(gateway)
		}
		payload["IPAM"] = map[string]any{
			"Driver": "default",
			"Config": []map[string]string{cfg},
		}
	}
	rawBytes, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/networks/create", bytes.NewReader(rawBytes))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return DockerNetwork{}, err
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return DockerNetwork{}, parseDockerAPIErrorMessage(resp.StatusCode, respBody)
	}
	var res struct {
		ID string `json:"Id"`
	}
	_ = json.Unmarshal(respBody, &res)
	return DockerNetwork{
		ID:         shortDockerID(res.ID),
		FullID:     res.ID,
		Name:       cleanName,
		Driver:     drv,
		Internal:   internal,
		Subnet:     strings.TrimSpace(subnet),
		Gateway:    strings.TrimSpace(gateway),
		Containers: []NetworkAttachedContainer{},
		Labels:     map[string]string{},
	}, nil
}

// RemoveNetwork deletes a non-protected Docker network.
func (e *Engine) RemoveNetwork(id string) error {
	cleanID := strings.TrimSpace(id)
	if cleanID == "" {
		return errors.New("network id is required")
	}

	nets, err := e.ListNetworks()
	if err == nil {
		for _, n := range nets {
			if (n.ID == cleanID || n.FullID == cleanID || n.Name == cleanID) && n.Protected {
				return fmt.Errorf("%w: system network %q cannot be deleted", ErrProtectedContainer, n.Name)
			}
		}
	}

	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()
	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		return nil
	}

	client, baseURL, ok := newDockerHTTPClient(endpoint, 10*time.Second)
	if !ok {
		return errors.New("docker engine endpoint unreachable")
	}
	req, _ := http.NewRequest(http.MethodDelete, baseURL+"/networks/"+url.PathEscape(cleanID), nil)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return parseDockerAPIErrorMessage(resp.StatusCode, body)
	}
	return nil
}

// ConnectNetwork attaches a container to a Docker network via POST /networks/{id}/connect.
func (e *Engine) ConnectNetwork(networkID, containerID string) error {
	nid := strings.TrimSpace(networkID)
	cid := strings.TrimSpace(containerID)
	if nid == "" || cid == "" {
		return errors.New("networkId and containerId are required")
	}

	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()
	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		return nil
	}

	client, baseURL, ok := newDockerHTTPClient(endpoint, 10*time.Second)
	if !ok {
		return errors.New("docker engine endpoint unreachable")
	}
	payload, _ := json.Marshal(map[string]string{"Container": cid})
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/networks/"+url.PathEscape(nid)+"/connect", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return parseDockerAPIErrorMessage(resp.StatusCode, body)
	}
	return nil
}

// DisconnectNetwork detaches a container from a network, guarding core system container links.
func (e *Engine) DisconnectNetwork(networkID, containerID string, force bool) error {
	nid := strings.TrimSpace(networkID)
	cid := strings.TrimSpace(containerID)
	if nid == "" || cid == "" {
		return errors.New("networkId and containerId are required")
	}

	e.mu.RLock()
	var cname string
	if idx := e.findContainerIndexLocked(cid); idx >= 0 {
		cname = e.containers[idx].Name
	}
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()
	if IsProtectedSystemContainer(cname) || IsProtectedSystemContainer(cid) {
		return fmt.Errorf("%w: cannot disconnect protected system container %q", ErrProtectedContainer, cid)
	}
	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		return nil
	}

	client, baseURL, ok := newDockerHTTPClient(endpoint, 10*time.Second)
	if !ok {
		return errors.New("docker engine endpoint unreachable")
	}
	payload, _ := json.Marshal(map[string]any{"Container": cid, "Force": force})
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/networks/"+url.PathEscape(nid)+"/disconnect", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return parseDockerAPIErrorMessage(resp.StatusCode, body)
	}
	return nil
}

// PruneNetworks deletes all unused Docker networks via POST /networks/prune.
func (e *Engine) PruneNetworks() (PruneResourcesResult, error) {
	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()

	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		return PruneResourcesResult{Removed: []string{}}, nil
	}
	client, baseURL, ok := newDockerHTTPClient(endpoint, 30*time.Second)
	if !ok {
		return PruneResourcesResult{}, errors.New("docker engine endpoint unreachable")
	}
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/networks/prune", nil)
	resp, err := client.Do(req)
	if err != nil {
		return PruneResourcesResult{}, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return PruneResourcesResult{}, parseDockerAPIErrorMessage(resp.StatusCode, body)
	}
	var res struct {
		NetworksDeleted []string `json:"NetworksDeleted"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return PruneResourcesResult{}, fmt.Errorf("decode networks/prune: %w", err)
	}
	if res.NetworksDeleted == nil {
		res.NetworksDeleted = []string{}
	}
	return PruneResourcesResult{
		Removed:      res.NetworksDeleted,
		RemovedCount: len(res.NetworksDeleted),
	}, nil
}
