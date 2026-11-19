package docker

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func dialTestWS(t *testing.T, httpURL, origin string) (net.Conn, *bufio.Reader) {
	t.Helper()
	u, err := url.Parse(httpURL)
	if err != nil {
		t.Fatalf("parse ws url: %v", err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("tcp dial %s: %v", u.Host, err)
	}
	reqStr := "GET " + u.RequestURI() + " HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n"
	if origin != "" {
		reqStr += "Origin: " + origin + "\r\n"
	}
	reqStr += "\r\n"
	if _, err := io.WriteString(conn, reqStr); err != nil {
		_ = conn.Close()
		t.Fatalf("write ws handshake: %v", err)
	}
	br := bufio.NewReader(conn)
	var lines []string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			t.Fatalf("read ws response headers: %v", err)
		}
		tr := strings.TrimRight(line, "\r\n")
		if tr == "" {
			break
		}
		lines = append(lines, tr)
	}
	joined := strings.Join(lines, "\n")
	if len(lines) == 0 || !strings.Contains(lines[0], "101") {
		_ = conn.Close()
		t.Fatalf("expected 101 Switching Protocols, got:\n%s", joined)
	}
	if !strings.Contains(joined, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") {
		_ = conn.Close()
		t.Fatalf("unexpected Sec-WebSocket-Accept in headers:\n%s", joined)
	}
	return conn, br
}

func writeMaskedWSClientFrame(t *testing.T, conn net.Conn, opcode byte, payload []byte) {
	t.Helper()
	var hdr [2]byte
	hdr[0] = 0x80 | opcode
	n := len(payload)
	if n >= 126 {
		t.Fatalf("helper supports small test payloads (<126), got %d", n)
	}
	hdr[1] = 0x80 | byte(n)
	var mask [4]byte
	_, _ = rand.Read(mask[:])
	masked := make([]byte, n)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := conn.Write(hdr[:]); err != nil {
		t.Fatalf("write ws header: %v", err)
	}
	if _, err := conn.Write(mask[:]); err != nil {
		t.Fatalf("write ws mask: %v", err)
	}
	if n > 0 {
		if _, err := conn.Write(masked); err != nil {
			t.Fatalf("write ws payload: %v", err)
		}
	}
}

func readServerWSFrame(t *testing.T, br *bufio.Reader) (byte, []byte) {
	t.Helper()
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			t.Fatalf("read ws server frame header: %v", err)
		}
		op := hdr[0] & 0x0F
		plen := uint64(hdr[1] & 0x7F)
		switch plen {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(br, ext[:]); err != nil {
				t.Fatalf("read ext16: %v", err)
			}
			plen = uint64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(br, ext[:]); err != nil {
				t.Fatalf("read ext64: %v", err)
			}
			plen = binary.BigEndian.Uint64(ext[:])
		}
		payload := make([]byte, plen)
		if plen > 0 {
			if _, err := io.ReadFull(br, payload); err != nil {
				t.Fatalf("read ws payload: %v", err)
			}
		}
		if op == wsOpPing {
			continue
		}
		return op, payload
	}
}

func TestWebSocketAcceptAndExecTerminalBridgeCheckpoint3(t *testing.T) {
	if got := computeWebSocketAccept("dGhlIHNhbXBsZSBub25jZQ=="); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("RFC 6455 Sec-WebSocket-Accept mismatch: %q", got)
	}

	var mu sync.Mutex
	var resizeCalls []string
	dockerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/_ping":
			_, _ = w.Write([]byte("OK"))
		case r.URL.Path == "/version":
			_ = json.NewEncoder(w).Encode(map[string]string{"Version": "29.1.3"})
		case r.URL.Path == "/info":
			_ = json.NewEncoder(w).Encode(map[string]any{"Name": "ws-host", "NCPU": 2, "MemTotal": int64(4) << 30, "ServerVersion": "29.1.3"})
		case r.URL.Path == "/containers/json":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"Id": "app1111111111111", "Names": []string{"/dh-shell-app"}, "Image": "alpine:3.20", "State": "running", "Status": "Up 1m"},
				{"Id": "prx2222222222222", "Names": []string{"/deploymenthub-socket-proxy"}, "Image": "tecnativa/docker-socket-proxy:latest", "State": "running", "Status": "Up 1m"},
			})
		case r.URL.Path == "/images/json":
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		case r.Method == http.MethodPost && r.URL.Path == "/containers/app1111111111111/exec":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"Id": "exec123"})
		case r.Method == http.MethodPost && r.URL.Path == "/exec/exec123/resize":
			mu.Lock()
			resizeCalls = append(resizeCalls, r.URL.RawQuery)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/exec/exec123/start":
			_, _ = io.ReadAll(r.Body)
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "no hijack", http.StatusInternalServerError)
				return
			}
			conn, brw, err := hj.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = io.WriteString(conn, "HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
			_, _ = io.WriteString(conn, "root@dh-shell-app:/# ")
			_, _ = io.Copy(conn, brw)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer dockerSrv.Close()

	eng := newTestEngine(t, dockerSrv.URL)

	hubSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/exec/")
		eng.HandleContainerExecWS(w, r, id)
	}))
	defer hubSrv.Close()

	// 1. Cross-Origin CSWSH request must be rejected with 403
	reqCSWSH, _ := http.NewRequest(http.MethodGet, hubSrv.URL+"/exec/app1111111111111?shell=sh", nil)
	reqCSWSH.Header.Set("Connection", "Upgrade")
	reqCSWSH.Header.Set("Upgrade", "websocket")
	reqCSWSH.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	reqCSWSH.Header.Set("Origin", "https://evil.example")
	respCSWSH, err := http.DefaultClient.Do(reqCSWSH)
	if err != nil {
		t.Fatalf("cswsh request error: %v", err)
	}
	_ = respCSWSH.Body.Close()
	if respCSWSH.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on cross-origin WS, got %d", respCSWSH.StatusCode)
	}

	// 2. Socket proxy container exec must be rejected with 403
	reqProxy, _ := http.NewRequest(http.MethodGet, hubSrv.URL+"/exec/prx2222222222222?shell=sh", nil)
	reqProxy.Header.Set("Connection", "Upgrade")
	reqProxy.Header.Set("Upgrade", "websocket")
	reqProxy.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	respProxy, err := http.DefaultClient.Do(reqProxy)
	if err != nil {
		t.Fatalf("proxy exec request error: %v", err)
	}
	_ = respProxy.Body.Close()
	if respProxy.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on socket-proxy exec, got %d", respProxy.StatusCode)
	}

	// 3. Full bidirectional WebSocket PTY bridge + TTY resize check
	conn, br := dialTestWS(t, hubSrv.URL+"/exec/app1111111111111?shell=sh&cols=80&rows=24", hubSrv.URL)
	defer conn.Close()

	op, banner := readServerWSFrame(t, br)
	if op != wsOpText || !strings.Contains(string(banner), "root@dh-shell-app") {
		t.Fatalf("expected PTY banner frame, got op=%d payload=%q", op, string(banner))
	}

	writeMaskedWSClientFrame(t, conn, wsOpText, []byte("id\n"))
	op2, echo := readServerWSFrame(t, br)
	if op2 != wsOpText || string(echo) != "id\n" {
		t.Fatalf("expected echoed stdin frame, got op=%d payload=%q", op2, string(echo))
	}

	writeMaskedWSClientFrame(t, conn, wsOpText, []byte(`{"type":"resize","cols":120,"rows":40}`))
	writeMaskedWSClientFrame(t, conn, wsOpText, []byte("pwd\n"))
	op3, echo2 := readServerWSFrame(t, br)
	if op3 != wsOpText || string(echo2) != "pwd\n" {
		t.Fatalf("expected second stdin frame after resize, got op=%d payload=%q", op3, string(echo2))
	}

	mu.Lock()
	defer mu.Unlock()
	foundInitial := false
	foundDynamic := false
	for _, q := range resizeCalls {
		if q == "h=24&w=80" {
			foundInitial = true
		}
		if q == "h=40&w=120" {
			foundDynamic = true
		}
	}
	if !foundInitial || !foundDynamic {
		t.Fatalf("expected initial h=24&w=80 and dynamic h=40&w=120 resize calls, got %v", resizeCalls)
	}
}
