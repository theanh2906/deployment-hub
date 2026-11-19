package docker

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func buildMuxFrame(stream byte, payload string) []byte {
	hdr := make([]byte, 8)
	hdr[0] = stream
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(payload)))
	return append(hdr, []byte(payload)...)
}

func TestDockerDeepControlCheckpoint1(t *testing.T) {
	var mu sync.Mutex
	cntState := "running"
	cntImage := "myapp:v2"
	updatedMem := int64(0)
	updatedNanoCPUs := int64(0)
	deletedImageID := ""
	removedContainer := false
	buildPruned := false
	createdRollbackPayload := map[string]any{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/_ping":
			_, _ = w.Write([]byte("OK"))
		case r.URL.Path == "/version":
			_ = json.NewEncoder(w).Encode(map[string]string{"Version": "29.1.3"})
		case r.URL.Path == "/info":
			_ = json.NewEncoder(w).Encode(map[string]any{"Name": "cp1-host", "NCPU": 4, "MemTotal": int64(8) << 30, "ServerVersion": "29.1.3"})
		case r.URL.Path == "/containers/json":
			if removedContainer {
				_ = json.NewEncoder(w).Encode([]map[string]any{})
				return
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"Id":     "sys1111111111111",
					"Names":  []string{"/deploymenthub-traefik"},
					"Image":  "traefik:v3.6",
					"State":  "running",
					"Status": "Up 1h",
					"Ports":  []map[string]any{{"IP": "0.0.0.0", "PrivatePort": 443, "PublicPort": 443, "Type": "tcp"}},
					"Labels": map[string]string{},
				},
				{
					"Id":     "app2222222222222",
					"Names":  []string{"/dh-myapp"},
					"Image":  cntImage,
					"State":  cntState,
					"Status": "Up 5m",
					"Ports":  []map[string]any{{"IP": "0.0.0.0", "PrivatePort": 8080, "PublicPort": 4201, "Type": "tcp"}},
					"Labels": map[string]string{"env": "prod"},
				},
			})
		case r.URL.Path == "/images/json":
			imgs := []map[string]any{
				{"Id": "sha256:aaa111", "RepoTags": []string{"myapp:v2"}, "Size": 32 << 20, "Containers": 1, "Created": 1700000200},
				{"Id": "sha256:bbb222", "RepoTags": []string{"myapp:v1"}, "Size": 30 << 20, "Containers": 0, "Created": 1700000100},
				{"Id": "sha256:ccc333", "RepoTags": []string{"traefik:v3.6"}, "Size": 250 << 20, "Containers": 1, "Created": 1700000000},
			}
			if deletedImageID == "" {
				imgs = append(imgs, map[string]any{"Id": "sha256:ddd444", "RepoTags": []string{"unused:old"}, "Size": 40 << 20, "Containers": 0, "Created": 1699999000})
			}
			_ = json.NewEncoder(w).Encode(imgs)
		case r.Method == http.MethodPost && r.URL.Path == "/containers/app2222222222222/pause":
			cntState = "paused"
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/containers/app2222222222222/unpause":
			cntState = "running"
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/containers/app2222222222222/stop":
			cntState = "exited"
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/containers/app2222222222222/start":
			cntState = "running"
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/containers/app2222222222222/kill":
			cntState = "exited"
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/containers/sys1111111111111/restart":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/containers/app2222222222222/json":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Id":      "app2222222222222",
				"Name":    "/dh-myapp",
				"Created": "2026-11-19T10:00:00Z",
				"State": map[string]any{
					"Status": "running", "Running": true, "Pid": 1234,
					"Health": map[string]any{"Status": "healthy", "Log": []map[string]any{{"ExitCode": 0, "Output": "OK"}}},
				},
				"Config": map[string]any{
					"Image":        cntImage,
					"Tty":          false,
					"Env":          []string{"PORT=8080", "API_SECRET=super"},
					"Cmd":          []string{"/server"},
					"WorkingDir":   "/app",
					"ExposedPorts": map[string]any{"8080/tcp": map[string]any{}},
					"Labels":       map[string]string{"env": "prod"},
				},
				"HostConfig": map[string]any{
					"Memory":        512 << 20,
					"NanoCpus":      1000000000,
					"RestartPolicy": map[string]any{"Name": "unless-stopped"},
				},
				"NetworkSettings": map[string]any{
					"Ports":    map[string]any{"8080/tcp": []map[string]any{{"HostIp": "0.0.0.0", "HostPort": "4201"}}},
					"Networks": map[string]any{"deploymenthub_proxy": map[string]any{"NetworkID": "net1", "IPAddress": "172.18.0.5", "Gateway": "172.18.0.1"}},
				},
				"Mounts": []map[string]any{{"Type": "volume", "Name": "app_vol", "Source": "/var/lib/docker/volumes/app_vol", "Destination": "/data", "Mode": "rw", "RW": true}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/containers/app2222222222222/stats":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"read": "2026-11-19T11:00:00Z",
				"cpu_stats": map[string]any{
					"cpu_usage":        map[string]any{"total_usage": 200000000, "percpu_usage": []uint64{100000000, 100000000}},
					"system_cpu_usage": 10000000000,
					"online_cpus":      2,
				},
				"precpu_stats": map[string]any{
					"cpu_usage":        map[string]any{"total_usage": 100000000},
					"system_cpu_usage": 9000000000,
				},
				"memory_stats": map[string]any{
					"usage": 128 << 20,
					"limit": 512 << 20,
					"stats": map[string]any{"inactive_file": 28 << 20},
				},
				"networks":   map[string]any{"eth0": map[string]any{"rx_bytes": 1024, "tx_bytes": 2048}},
				"blkio_stats": map[string]any{"io_service_bytes_recursive": []map[string]any{{"op": "Read", "value": 4096}, {"op": "Write", "value": 8192}}},
				"pids_stats": map[string]any{"current": 7},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/containers/app2222222222222/top":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Titles":    []string{"PID", "USER", "TIME", "COMMAND"},
				"Processes": [][]string{{"1", "hub", "0:03", "/server"}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/containers/app2222222222222/update":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if v, ok := body["Memory"].(float64); ok {
				updatedMem = int64(v)
			}
			if v, ok := body["NanoCpus"].(float64); ok {
				updatedNanoCPUs = int64(v)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"Warnings": []string{}})
		case r.Method == http.MethodGet && r.URL.Path == "/containers/app2222222222222/logs":
			var buf bytes.Buffer
			buf.Write(buildMuxFrame(1, "stdout line one\n"))
			buf.Write(buildMuxFrame(2, "stderr line two\n"))
			_, _ = w.Write(buf.Bytes())
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/images/") && strings.HasSuffix(r.URL.Path, "/json"):
			_ = json.NewEncoder(w).Encode(map[string]any{"Id": "sha256:bbb222"})
		case r.Method == http.MethodDelete && r.URL.Path == "/containers/app2222222222222":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/containers/create":
			_ = json.NewDecoder(r.Body).Decode(&createdRollbackPayload)
			if img, _ := createdRollbackPayload["Image"].(string); img != "" {
				cntImage = img
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"Id": "app2222222222222"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/connect"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/system/df":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"LayersSize": int64(312 << 20),
				"Images": []map[string]any{
					{"Size": int64(32 << 20), "SharedSize": 0, "Containers": 1},
					{"Size": int64(40 << 20), "SharedSize": 0, "Containers": 0},
				},
				"Containers": []map[string]any{
					{"SizeRw": int64(5 << 20), "State": "running"},
					{"SizeRw": int64(10 << 20), "State": "exited"},
				},
				"Volumes": []map[string]any{
					{"UsageData": map[string]any{"Size": int64(100 << 20), "RefCount": 1}},
				},
				"BuildCache": []map[string]any{
					{"Size": int64(64 << 20), "InUse": false},
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/images/sha256%3Addd444/history" || r.Method == http.MethodGet && r.URL.Path == "/images/ddd444/history":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"Id": "sha256:1234567890abcdef", "Created": 1700000000, "CreatedBy": "ADD app /app", "Size": 1024000, "Tags": []string{"unused:old"}},
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/images/ddd444":
			deletedImageID = "ddd444"
			_ = json.NewEncoder(w).Encode([]map[string]any{{"Deleted": "sha256:ddd444"}})
		case r.Method == http.MethodPost && r.URL.Path == "/build/prune":
			buildPruned = true
			_ = json.NewEncoder(w).Encode(map[string]any{"CachesDeleted": []string{"c1", "c2"}, "SpaceReclaimed": int64(64 << 20)})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	eng := newTestEngine(t, srv.URL)
	ov := eng.GetOverview()
	if len(ov.Containers) != 2 {
		t.Fatalf("expected 2 discovered containers, got %d", len(ov.Containers))
	}

	// Verify system protection
	if _, err := eng.ContainerAction("sys1111111111111", "stop", ""); !errors.Is(err, ErrProtectedContainer) {
		t.Fatalf("expected ErrProtectedContainer on system stop, got %v", err)
	}
	if _, err := eng.ContainerAction("sys1111111111111", "restart", ""); err != nil {
		t.Fatalf("expected traefik restart allowed, got %v", err)
	}
	if err := eng.RemoveImage("traefik:v3.6", false); !errors.Is(err, ErrProtectedContainer) {
		t.Fatalf("expected ErrProtectedContainer deleting system image, got %v", err)
	}

	// Pause & Unpause
	paused, err := eng.ContainerAction("app2222222222222", "pause", "")
	if err != nil || paused.Status != "Paused" {
		t.Fatalf("expected Paused status, got %+v err=%v", paused, err)
	}
	unpaused, err := eng.ContainerAction("app2222222222222", "unpause", "")
	if err != nil || unpaused.Status != "Running" {
		t.Fatalf("expected Running after unpause, got %+v err=%v", unpaused, err)
	}

	// Deep Inspect
	ins, err := eng.InspectContainer("app2222222222222")
	if err != nil || ins.State.Health != "healthy" || len(ins.Env) != 2 || len(ins.Mounts) != 1 || len(ins.Networks) != 1 {
		t.Fatalf("unexpected inspect output: %+v err=%v", ins, err)
	}

	// Live Stats calculation: cpuDelta=1e8, sysDelta=1e9, online=2 -> 20% CPU; mem=100MB/512MB
	st, err := eng.GetContainerStats("app2222222222222")
	if err != nil || st.CPUPct != 20.0 || st.MemoryUsedMb != 100.0 || st.PIDs != 7 {
		t.Fatalf("unexpected container stats: %+v err=%v", st, err)
	}

	// Container Top
	top, err := eng.GetContainerTop("app2222222222222")
	if err != nil || len(top.Processes) != 1 {
		t.Fatalf("unexpected top output: %+v err=%v", top, err)
	}

	// Hot Resource Limits Update
	if err := eng.UpdateContainerResources("app2222222222222", 1024, 1.5, "always"); err != nil {
		t.Fatalf("UpdateContainerResources failed: %v", err)
	}
	if updatedMem != 1024<<20 || updatedNanoCPUs != 1500000000 {
		t.Fatalf("unexpected updated resources: mem=%d cpu=%d", updatedMem, updatedNanoCPUs)
	}

	// Streaming & downloading logs
	var streamed []string
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := eng.StreamContainerLogs(ctx, "app2222222222222", 50, true, func(stream, line string) bool {
		streamed = append(streamed, stream+":"+line)
		return true
	}); err != nil {
		t.Fatalf("StreamContainerLogs failed: %v", err)
	}
	if len(streamed) != 2 || streamed[0] != "stdout:stdout line one" || streamed[1] != "stderr:stderr line two" {
		t.Fatalf("unexpected streamed log lines: %+v", streamed)
	}
	cname, dlText, err := eng.DownloadContainerLogs(ctx, "app2222222222222", 100, false)
	if err != nil || cname != "dh-myapp" || !strings.Contains(dlText, "stderr line two") {
		t.Fatalf("DownloadContainerLogs unexpected: cname=%q err=%v text=%q", cname, err, dlText)
	}

	// Real Rollback via inspect + recreate + start
	rb, err := eng.ContainerAction("app2222222222222", "rollback", "myapp:v1")
	if err != nil || rb.Image != "myapp:v1" {
		t.Fatalf("real rollback failed: %+v err=%v", rb, err)
	}
	if createdRollbackPayload["Image"] != "myapp:v1" {
		t.Fatalf("expected rollback recreate payload Image=myapp:v1, got %v", createdRollbackPayload["Image"])
	}

	// Disk Usage & Image History & Image Delete & Build Cache Prune
	df, err := eng.GetSystemDiskUsage()
	if err != nil || !df.Available || df.BuildCache.ReclaimableBytes != 64<<20 {
		t.Fatalf("unexpected system df: %+v err=%v", df, err)
	}
	hist, err := eng.GetImageHistory("ddd444")
	if err != nil || len(hist) != 1 || hist[0].CreatedBy != "ADD app /app" {
		t.Fatalf("unexpected image history: %+v err=%v", hist, err)
	}
	if err := eng.RemoveImage("ddd444", false); err != nil || deletedImageID != "ddd444" {
		t.Fatalf("RemoveImage failed: err=%v deleted=%q", err, deletedImageID)
	}
	bcRes, err := eng.PruneBuildCache(true)
	if err != nil || !buildPruned || bcRes.CachesDeleted != 2 || bcRes.ReclaimedMb != 64 {
		t.Fatalf("PruneBuildCache failed: %+v err=%v", bcRes, err)
	}
}
