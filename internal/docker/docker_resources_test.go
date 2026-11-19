package docker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDockerVolumesNetworksAndEventsCheckpoint2(t *testing.T) {
	var mu sync.Mutex
	createdVol := ""
	deletedVol := ""
	createdNet := ""
	deletedNet := ""
	connectedCid := ""
	disconnectedCid := ""
	prunedVols := false
	prunedNets := false

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	data := []byte("backup-content-ok")
	_ = tw.WriteHeader(&tar.Header{Name: "vol/hello.txt", Mode: 0o644, Size: int64(len(data))})
	_, _ = tw.Write(data)
	_ = tw.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/_ping":
			_, _ = w.Write([]byte("OK"))
		case r.URL.Path == "/version":
			_ = json.NewEncoder(w).Encode(map[string]string{"Version": "29.1.3"})
		case r.URL.Path == "/info":
			_ = json.NewEncoder(w).Encode(map[string]any{"Name": "cp2-node", "NCPU": 4, "MemTotal": int64(8) << 30, "ServerVersion": "29.1.3"})
		case r.URL.Path == "/containers/json":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"Id": "sys001", "Names": []string{"/deploymenthub-control-plane"}, "Image": "hub:latest",
					"State": "running", "Status": "Up 1h", "Labels": map[string]string{},
					"Mounts": []map[string]any{{"Name": "hub_data"}},
				},
				{
					"Id": "app001", "Names": []string{"/dh-portfolio"}, "Image": "portfolio:latest",
					"State": "running", "Status": "Up 1h", "Labels": map[string]string{},
					"Mounts": []map[string]any{{"Name": "app_vol"}},
				},
			})
		case r.URL.Path == "/containers/sys001/json":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Id": "sys001", "Name": "/deploymenthub-control-plane",
				"NetworkSettings": map[string]any{"Networks": map[string]any{"hub_internal": map[string]any{}}},
				"Mounts":          []map[string]any{{"Name": "hub_data"}},
			})
		case r.URL.Path == "/images/json":
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		case r.URL.Path == "/system/df":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Volumes": []map[string]any{
					{"Name": "app_vol", "UsageData": map[string]any{"Size": int64(12 << 20), "RefCount": 1}},
					{"Name": "hub_data", "UsageData": map[string]any{"Size": int64(4 << 20), "RefCount": 1}},
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/volumes":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Volumes": []map[string]any{
					{"Name": "hub_data", "Driver": "local", "Scope": "local", "Mountpoint": "/var/lib/docker/volumes/hub_data/_data"},
					{"Name": "app_vol", "Driver": "local", "Scope": "local", "Mountpoint": "/var/lib/docker/volumes/app_vol/_data"},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/volumes/create":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			createdVol, _ = body["Name"].(string)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"Name": createdVol, "Driver": "local", "Scope": "local"})
		case r.Method == http.MethodDelete && r.URL.Path == "/volumes/app_vol":
			deletedVol = "app_vol"
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/volumes/prune":
			prunedVols = true
			_ = json.NewEncoder(w).Encode(map[string]any{"VolumesDeleted": []string{"orphan_v1"}, "SpaceReclaimed": int64(8 << 20)})
		case r.Method == http.MethodGet && r.URL.Path == "/volumes/app_vol":
			_ = json.NewEncoder(w).Encode(map[string]any{"Name": "app_vol", "Driver": "local"})
		case r.Method == http.MethodPost && r.URL.Path == "/containers/create":
			_ = json.NewEncoder(w).Encode(map[string]any{"Id": "tmp-backup-1"})
		case r.Method == http.MethodGet && r.URL.Path == "/containers/tmp-backup-1/archive":
			_, _ = w.Write(tarBuf.Bytes())
		case r.Method == http.MethodDelete && r.URL.Path == "/containers/tmp-backup-1":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/networks":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"Id": "net_sys", "Name": "hub_internal", "Driver": "bridge", "Scope": "local", "Internal": true,
					"IPAM":       map[string]any{"Config": []map[string]any{{"Subnet": "172.20.0.0/16", "Gateway": "172.20.0.1"}}},
					"Containers": map[string]any{"sys001": map[string]any{"Name": "deploymenthub-control-plane", "IPv4Address": "172.20.0.2/16"}},
				},
				{
					"Id": "net_usr", "Name": "custom_net", "Driver": "bridge", "Scope": "local", "Internal": false,
					"IPAM":       map[string]any{"Config": []map[string]any{{"Subnet": "172.25.0.0/16", "Gateway": "172.25.0.1"}}},
					"Containers": map[string]any{},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/networks/create":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			createdNet, _ = body["Name"].(string)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"Id": "net_new_1"})
		case r.Method == http.MethodPost && r.URL.Path == "/networks/net_usr/connect":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			connectedCid = body["Container"]
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/networks/net_usr/disconnect":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			disconnectedCid, _ = body["Container"].(string)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && r.URL.Path == "/networks/net_usr":
			deletedNet = "net_usr"
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/networks/prune":
			prunedNets = true
			_ = json.NewEncoder(w).Encode(map[string]any{"NetworksDeleted": []string{"stale_net"}})
		case r.Method == http.MethodGet && r.URL.Path == "/events":
			_, _ = w.Write([]byte(`{"Type":"container","Action":"start","Actor":{"ID":"app001","Attributes":{"name":"dh-portfolio"}},"time":1700000500}` + "\n"))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	eng := newTestEngine(t, srv.URL)

	// Volumes tests
	vols, err := eng.ListVolumes()
	if err != nil || len(vols) != 2 {
		t.Fatalf("ListVolumes failed: %+v err=%v", vols, err)
	}
	if !vols[1].Protected || vols[1].Name != "hub_data" {
		t.Fatalf("expected hub_data protected, got %+v", vols)
	}
	if err := eng.RemoveVolume("hub_data", false); !errors.Is(err, ErrProtectedContainer) {
		t.Fatalf("expected ErrProtectedContainer deleting hub_data, got %v", err)
	}
	if _, err := eng.CreateVolume("new_vol", "local", nil); err != nil || createdVol != "new_vol" {
		t.Fatalf("CreateVolume failed: err=%v created=%q", err, createdVol)
	}
	if err := eng.RemoveVolume("app_vol", false); err != nil || deletedVol != "app_vol" {
		t.Fatalf("RemoveVolume failed: err=%v deleted=%q", err, deletedVol)
	}
	prVolRes, err := eng.PruneVolumes()
	if err != nil || !prunedVols || prVolRes.RemovedCount != 1 {
		t.Fatalf("PruneVolumes failed: %+v err=%v", prVolRes, err)
	}

	// Backup .tar.gz verification
	var gzOut bytes.Buffer
	if err := eng.BackupVolumeTarGz(context.Background(), "app_vol", &gzOut); err != nil {
		t.Fatalf("BackupVolumeTarGz failed: %v", err)
	}
	gr, err := gzip.NewReader(&gzOut)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	tr := tar.NewReader(gr)
	hdr, err := tr.Next()
	if err != nil || hdr.Name != "vol/hello.txt" {
		t.Fatalf("expected tar entry vol/hello.txt, got %+v err=%v", hdr, err)
	}
	readBytes, _ := io.ReadAll(tr)
	_ = gr.Close()
	if string(readBytes) != "backup-content-ok" {
		t.Fatalf("unexpected backed up bytes: %q", string(readBytes))
	}

	// Networks tests
	nets, err := eng.ListNetworks()
	if err != nil || len(nets) != 2 {
		t.Fatalf("ListNetworks failed: %+v err=%v", nets, err)
	}
	if err := eng.RemoveNetwork("net_sys"); !errors.Is(err, ErrProtectedContainer) {
		t.Fatalf("expected ErrProtectedContainer deleting hub_internal, got %v", err)
	}
	if err := eng.DisconnectNetwork("net_sys", "sys001", false); !errors.Is(err, ErrProtectedContainer) {
		t.Fatalf("expected ErrProtectedContainer disconnecting sys001, got %v", err)
	}
	if _, err := eng.CreateNetwork("new_bridge", "bridge", "172.30.0.0/16", "172.30.0.1", true); err != nil || createdNet != "new_bridge" {
		t.Fatalf("CreateNetwork failed: err=%v created=%q", err, createdNet)
	}
	if err := eng.ConnectNetwork("net_usr", "app001"); err != nil || connectedCid != "app001" {
		t.Fatalf("ConnectNetwork failed: err=%v cid=%q", err, connectedCid)
	}
	if err := eng.DisconnectNetwork("net_usr", "app001", false); err != nil || disconnectedCid != "app001" {
		t.Fatalf("DisconnectNetwork failed: err=%v cid=%q", err, disconnectedCid)
	}
	if err := eng.RemoveNetwork("net_usr"); err != nil || deletedNet != "net_usr" {
		t.Fatalf("RemoveNetwork failed: err=%v deleted=%q", err, deletedNet)
	}
	prNetRes, err := eng.PruneNetworks()
	if err != nil || !prunedNets || prNetRes.RemovedCount != 1 {
		t.Fatalf("PruneNetworks failed: %+v err=%v", prNetRes, err)
	}

	// Realtime Docker Events watcher & ring buffer + subscriber test
	hist, ch, unsub := eng.SubscribeDockerEvents()
	defer unsub()
	if len(hist) != 0 {
		t.Fatalf("expected empty initial events history, got %d", len(hist))
	}
	wCtx, wCancel := context.WithCancel(context.Background())
	defer wCancel()
	go eng.StartDockerEventWatcher(wCtx)

	select {
	case ev := <-ch:
		if ev.Type != "container" || ev.Action != "start" || ev.ActorName != "dh-portfolio" {
			t.Fatalf("unexpected docker event: %+v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for parsed Docker /events notification")
	}
	if recent := eng.GetRecentDockerEvents(); len(recent) == 0 || !strings.Contains(recent[0].ActorName, "portfolio") {
		t.Fatalf("expected event cached in GetRecentDockerEvents, got %+v", recent)
	}
}
