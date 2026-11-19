package docker

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	wsOpCont   byte = 0x0
	wsOpText   byte = 0x1
	wsOpBinary byte = 0x2
	wsOpClose  byte = 0x8
	wsOpPing   byte = 0x9
	wsOpPong   byte = 0xA
)

func computeWebSocketAccept(key string) string {
	h := sha1.New()
	_, _ = io.WriteString(h, strings.TrimSpace(key)+wsGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func validateWebSocketOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	expectedHost := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if expectedHost == "" {
		expectedHost = strings.TrimSpace(r.Host)
	}
	if comma := strings.IndexByte(expectedHost, ','); comma >= 0 {
		expectedHost = strings.TrimSpace(expectedHost[:comma])
	}
	return strings.EqualFold(stripHostPort(u.Host), stripHostPort(expectedHost))
}

func stripHostPort(hostPort string) string {
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		return h
	}
	return hostPort
}

func headerHasToken(hdrVal, token string) bool {
	for _, part := range strings.Split(hdrVal, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

type wsConn struct {
	conn    net.Conn
	br      *bufio.Reader
	writeMu sync.Mutex
	closed  bool
}

func upgradeHTTPToWebSocket(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return nil, errors.New("websocket requires GET")
	}
	if !headerHasToken(r.Header.Get("Connection"), "upgrade") || !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		http.Error(w, "websocket upgrade required", http.StatusUpgradeRequired)
		return nil, errors.New("missing websocket upgrade headers")
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, errors.New("missing Sec-WebSocket-Key")
	}
	if !validateWebSocketOrigin(r) {
		http.Error(w, "cross-origin websocket forbidden", http.StatusForbidden)
		return nil, errors.New("origin mismatch")
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return nil, errors.New("http.Hijacker unsupported")
	}
	netConn, brw, err := hijacker.Hijack()
	if err != nil {
		return nil, fmt.Errorf("hijack connection: %w", err)
	}

	accept := computeWebSocketAccept(key)
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := netConn.Write([]byte(resp)); err != nil {
		_ = netConn.Close()
		return nil, fmt.Errorf("write 101 handshake: %w", err)
	}
	if err := netConn.SetDeadline(time.Time{}); err != nil {
		// Ignore on mock connections without deadline support.
	}
	return &wsConn{
		conn: netConn,
		br:   brw.Reader,
	}, nil
}

func (wc *wsConn) writeFrame(opcode byte, payload []byte) error {
	wc.writeMu.Lock()
	defer wc.writeMu.Unlock()
	if wc.closed {
		return net.ErrClosed
	}

	var header [10]byte
	header[0] = 0x80 | (opcode & 0x0F)
	n := len(payload)
	hdrLen := 2
	switch {
	case n < 126:
		header[1] = byte(n)
	case n <= 65535:
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:4], uint16(n))
		hdrLen = 4
	default:
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:10], uint64(n))
		hdrLen = 10
	}

	if _, err := wc.conn.Write(header[:hdrLen]); err != nil {
		return err
	}
	if n > 0 {
		if _, err := wc.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func (wc *wsConn) Close() error {
	wc.writeMu.Lock()
	if wc.closed {
		wc.writeMu.Unlock()
		return nil
	}
	_ = wc.writeCloseFrameLocked(1000, "closed")
	wc.closed = true
	wc.writeMu.Unlock()
	return wc.conn.Close()
}

func (wc *wsConn) writeCloseFrameLocked(code uint16, reason string) error {
	buf := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(buf[:2], code)
	copy(buf[2:], reason)
	var hdr [2]byte
	hdr[0] = 0x80 | wsOpClose
	hdr[1] = byte(min(125, len(buf)))
	if _, err := wc.conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := wc.conn.Write(buf[:hdr[1]])
	return err
}

func (wc *wsConn) readMessage() (byte, []byte, error) {
	var msgBuf bytes.Buffer
	var firstOp byte
	hasFirst := false

	for {
		var hdr [2]byte
		if _, err := io.ReadFull(wc.br, hdr[:]); err != nil {
			return 0, nil, err
		}
		fin := (hdr[0] & 0x80) != 0
		opcode := hdr[0] & 0x0F
		masked := (hdr[1] & 0x80) != 0
		payloadLen := uint64(hdr[1] & 0x7F)

		switch payloadLen {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(wc.br, ext[:]); err != nil {
				return 0, nil, err
			}
			payloadLen = uint64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(wc.br, ext[:]); err != nil {
				return 0, nil, err
			}
			payloadLen = binary.BigEndian.Uint64(ext[:])
		}
		if payloadLen > 1<<20 {
			return 0, nil, errors.New("websocket frame too large")
		}

		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(wc.br, maskKey[:]); err != nil {
				return 0, nil, err
			}
		}

		payload := make([]byte, payloadLen)
		if payloadLen > 0 {
			if _, err := io.ReadFull(wc.br, payload); err != nil {
				return 0, nil, err
			}
			if masked {
				for i := range payload {
					payload[i] ^= maskKey[i%4]
				}
			}
		}

		// Control frames may be interleaved inside fragmented messages.
		switch opcode {
		case wsOpPing:
			_ = wc.writeFrame(wsOpPong, payload)
			continue
		case wsOpPong:
			continue
		case wsOpClose:
			return wsOpClose, payload, io.EOF
		}

		if !hasFirst {
			firstOp = opcode
			hasFirst = true
		}
		msgBuf.Write(payload)
		if fin {
			return firstOp, msgBuf.Bytes(), nil
		}
	}
}

func dialDockerRawConn(dockerHost string) (net.Conn, error) {
	trimmed := strings.TrimSpace(dockerHost)
	if trimmed == "" {
		return nil, errors.New("docker endpoint missing")
	}
	if strings.HasPrefix(trimmed, "unix://") || strings.HasPrefix(trimmed, "/") {
		return net.DialTimeout("unix", strings.TrimPrefix(trimmed, "unix://"), 5*time.Second)
	}
	addr := strings.TrimPrefix(trimmed, "tcp://")
	addr = strings.TrimPrefix(addr, "http://")
	addr = strings.TrimPrefix(addr, "https://")
	addr = strings.TrimRight(addr, "/")
	if !strings.Contains(addr, ":") {
		addr += ":2375"
	}
	return net.DialTimeout("tcp", addr, 5*time.Second)
}

func buildExecShellCmd(shellParam string) []string {
	switch strings.ToLower(strings.TrimSpace(shellParam)) {
	case "sh", "/bin/sh":
		return []string{"/bin/sh"}
	case "ash", "/bin/ash":
		return []string{"/bin/ash"}
	case "bash", "/bin/bash":
		return []string{"/bin/bash"}
	default:
		return []string{"/bin/sh", "-c", "if command -v bash >/dev/null 2>&1; then exec bash; else exec sh; fi"}
	}
}

// HandleContainerExecWS bridges a browser RFC 6455 WebSocket connection directly
// to an interactive Docker Engine TTY exec session via hijacked TCP upgrade.
func (e *Engine) HandleContainerExecWS(w http.ResponseWriter, r *http.Request, id string) {
	if !validateWebSocketOrigin(r) {
		writeErrorJSON(w, http.StatusForbidden, "cross-origin websocket forbidden")
		return
	}
	runtimeMode, endpoint, dockerID, cname, err := e.resolveContainerDockerTarget(id)
	if err != nil {
		writeErrorJSON(w, http.StatusNotFound, err.Error())
		return
	}
	if strings.EqualFold(strings.TrimPrefix(cname, "/"), "deploymenthub-socket-proxy") {
		writeErrorJSON(w, http.StatusForbidden, "exec into deploymenthub-socket-proxy is forbidden")
		return
	}
	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		writeErrorJSON(w, http.StatusBadRequest, "interactive shell requires live Docker Engine connection")
		return
	}

	client, baseURL, ok := newDockerHTTPClient(endpoint, 10*time.Second)
	if !ok {
		writeErrorJSON(w, http.StatusBadGateway, "docker engine unreachable")
		return
	}

	// 1. Create Docker Exec instance before upgrading WebSocket so errors return normal HTTP JSON.
	execCmd := buildExecShellCmd(r.URL.Query().Get("shell"))
	execCreatePayload, _ := json.Marshal(map[string]any{
		"AttachStdin":  true,
		"AttachStdout": true,
		"AttachStderr": true,
		"Tty":          true,
		"Cmd":          execCmd,
		"Env":          []string{"TERM=xterm-256color"},
	})
	execReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, baseURL+"/containers/"+url.PathEscape(dockerID)+"/exec", bytes.NewReader(execCreatePayload))
	if err != nil {
		writeErrorJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	execReq.Header.Set("Content-Type", "application/json")
	execResp, err := client.Do(execReq)
	if err != nil {
		writeErrorJSON(w, http.StatusBadGateway, err.Error())
		return
	}
	execBody, _ := io.ReadAll(io.LimitReader(execResp.Body, 4096))
	_ = execResp.Body.Close()
	if execResp.StatusCode != http.StatusCreated && execResp.StatusCode != http.StatusOK {
		writeErrorJSON(w, http.StatusBadRequest, parseDockerAPIErrorMessage(execResp.StatusCode, execBody).Error())
		return
	}
	var createdExec struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(execBody, &createdExec); err != nil || strings.TrimSpace(createdExec.ID) == "" {
		writeErrorJSON(w, http.StatusBadGateway, "docker returned invalid exec ID")
		return
	}
	execID := strings.TrimSpace(createdExec.ID)

	// 2. Dial raw TCP/Unix connection and send /exec/{id}/start Upgrade: tcp BEFORE upgrading WS.
	dockerConn, err := dialDockerRawConn(endpoint)
	if err != nil {
		writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("dial docker exec stream: %v", err))
		return
	}

	startBody := `{"Detach":false,"Tty":true}`
	rawHTTP := fmt.Sprintf("POST /exec/%s/start HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: %d\r\n\r\n%s",
		url.PathEscape(execID), len(startBody), startBody)
	if _, err := io.WriteString(dockerConn, rawHTTP); err != nil {
		_ = dockerConn.Close()
		writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("write exec/start upgrade: %v", err))
		return
	}

	dockerReader := bufio.NewReaderSize(dockerConn, 16*1024)
	tp := textproto.NewReader(dockerReader)
	statusLine, err := tp.ReadLine()
	if err != nil {
		_ = dockerConn.Close()
		writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("read exec/start status: %v", err))
		return
	}
	if _, err := tp.ReadMIMEHeader(); err != nil {
		_ = dockerConn.Close()
		writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("read exec/start headers: %v", err))
		return
	}
	if !strings.Contains(statusLine, "101") && !strings.Contains(statusLine, "200") {
		_ = dockerConn.Close()
		writeErrorJSON(w, http.StatusBadGateway, "docker exec/start rejected: "+statusLine)
		return
	}

	// 3. Upgrade browser connection to RFC 6455 WebSocket.
	ws, err := upgradeHTTPToWebSocket(w, r)
	if err != nil {
		_ = dockerConn.Close()
		return
	}
	defer ws.Close()
	defer dockerConn.Close()

	// Send initial resize if cols/rows passed in query params.
	if cols := strings.TrimSpace(r.URL.Query().Get("cols")); cols != "" {
		if rows := strings.TrimSpace(r.URL.Query().Get("rows")); rows != "" {
			resizeDockerExec(endpoint, execID, cols, rows)
		}
	}

	doneCh := make(chan struct{})
	var closeOnce sync.Once
	signalDone := func() {
		closeOnce.Do(func() {
			close(doneCh)
			_ = dockerConn.Close()
			_ = ws.Close()
		})
	}

	// 25s Ping keepalive keeps Cloudflare/Traefik WS connections alive cleanly.
	go func() {
		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-doneCh:
				return
			case <-r.Context().Done():
				signalDone()
				return
			case <-ticker.C:
				if err := ws.writeFrame(wsOpPing, []byte("keepalive")); err != nil {
					signalDone()
					return
				}
			}
		}
	}()

	// Pump Docker PTY stdout -> WebSocket using the exact dockerReader to preserve buffered prompt bytes.
	go func() {
		defer signalDone()
		buf := make([]byte, 4096)
		for {
			n, readErr := dockerReader.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				op := wsOpBinary
				if utf8.Valid(chunk) {
					op = wsOpText
				}
				if err := ws.writeFrame(op, chunk); err != nil {
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}()

	// Pump WebSocket client frames -> Docker PTY stdin (or resize REST call).
	for {
		op, payload, readErr := ws.readMessage()
		if readErr != nil {
			signalDone()
			return
		}
		if op != wsOpText && op != wsOpBinary {
			continue
		}
		if len(payload) == 0 {
			continue
		}
		if op == wsOpText && bytes.HasPrefix(bytes.TrimSpace(payload), []byte(`{"type":"resize"`)) {
			var rsz struct {
				Type string `json:"type"`
				Cols int    `json:"cols"`
				Rows int    `json:"rows"`
			}
			if json.Unmarshal(payload, &rsz) == nil && rsz.Type == "resize" && rsz.Cols > 0 && rsz.Rows > 0 {
				resizeDockerExec(endpoint, execID, fmt.Sprintf("%d", rsz.Cols), fmt.Sprintf("%d", rsz.Rows))
				continue
			}
		}
		if _, err := dockerConn.Write(payload); err != nil {
			signalDone()
			return
		}
	}
}

func resizeDockerExec(endpoint, execID, cols, rows string) {
	client, baseURL, ok := newDockerHTTPClient(endpoint, 2*time.Second)
	if !ok {
		return
	}
	rszURL := fmt.Sprintf("%s/exec/%s/resize?h=%s&w=%s",
		baseURL, url.PathEscape(execID), url.QueryEscape(rows), url.QueryEscape(cols))
	req, err := http.NewRequest(http.MethodPost, rszURL, nil)
	if err != nil {
		return
	}
	if resp, err := client.Do(req); err == nil {
		_ = resp.Body.Close()
	}
}

func writeErrorJSON(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
