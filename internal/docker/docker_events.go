package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

// DockerEvent represents a real-time lifecycle event streamed from Docker Engine GET /events.
type DockerEvent struct {
	Type      string            `json:"type"`
	Action    string            `json:"action"`
	ActorID   string            `json:"actorId"`
	ActorName string            `json:"actorName"`
	Attributes map[string]string `json:"attributes,omitempty"`
	TimeUnix  int64             `json:"timeUnix"`
	Timestamp string            `json:"timestamp"`
}

func (e *Engine) ensureEventsInit() {
	e.eventsMu.Lock()
	defer e.eventsMu.Unlock()
	if e.eventSubs == nil {
		e.eventSubs = make(map[chan DockerEvent]struct{})
	}
	if e.syncNotifyCh == nil {
		e.syncNotifyCh = make(chan struct{}, 1)
	}
}

func (e *Engine) RecordDockerEvent(ev DockerEvent) {
	if ev.Timestamp == "" {
		if ev.TimeUnix > 0 {
			ev.Timestamp = time.Unix(ev.TimeUnix, 0).UTC().Format(time.RFC3339)
		} else {
			ev.TimeUnix = time.Now().Unix()
			ev.Timestamp = time.Now().UTC().Format(time.RFC3339)
		}
	}
	e.ensureEventsInit()

	e.eventsMu.Lock()
	e.recentEvents = append(e.recentEvents, ev)
	if len(e.recentEvents) > 150 {
		e.recentEvents = slices.Clone(e.recentEvents[len(e.recentEvents)-150:])
	}
	for ch := range e.eventSubs {
		select {
		case ch <- ev:
		default:
		}
	}
	e.eventsMu.Unlock()
}

// GetRecentDockerEvents returns up to the most recent 150 Docker lifecycle events (newest last).
func (e *Engine) GetRecentDockerEvents() []DockerEvent {
	e.ensureEventsInit()
	e.eventsMu.Lock()
	defer e.eventsMu.Unlock()
	return slices.Clone(e.recentEvents)
}

// SubscribeDockerEvents returns recent cached events and a live channel of new DockerEvents.
func (e *Engine) SubscribeDockerEvents() (history []DockerEvent, ch <-chan DockerEvent, unsub func()) {
	e.ensureEventsInit()
	liveCh := make(chan DockerEvent, 64)

	e.eventsMu.Lock()
	history = slices.Clone(e.recentEvents)
	e.eventSubs[liveCh] = struct{}{}
	e.eventsMu.Unlock()

	unsubFn := func() {
		e.eventsMu.Lock()
		defer e.eventsMu.Unlock()
		if _, ok := e.eventSubs[liveCh]; ok {
			delete(e.eventSubs, liveCh)
			close(liveCh)
		}
	}
	return history, liveCh, unsubFn
}

func parseRawDockerEvent(rawLine []byte) (DockerEvent, bool) {
	var raw struct {
		Type   string `json:"Type"`
		Action string `json:"Action"`
		ID     string `json:"id"`
		Time   int64  `json:"time"`
		Actor  struct {
			ID         string            `json:"ID"`
			Attributes map[string]string `json:"Attributes"`
		} `json:"Actor"`
	}
	if err := json.Unmarshal(rawLine, &raw); err != nil {
		return DockerEvent{}, false
	}
	if raw.Type == "" && raw.Action == "" {
		return DockerEvent{}, false
	}
	actorID := strings.TrimSpace(raw.Actor.ID)
	if actorID == "" {
		actorID = strings.TrimSpace(raw.ID)
	}
	actorID = shortDockerID(actorID)

	actorName := strings.TrimSpace(raw.Actor.Attributes["name"])
	if actorName == "" {
		actorName = strings.TrimSpace(raw.Actor.Attributes["image"])
	}
	if actorName == "" {
		actorName = actorID
	}

	tsUnix := raw.Time
	if tsUnix <= 0 {
		tsUnix = time.Now().Unix()
	}
	return DockerEvent{
		Type:       raw.Type,
		Action:     raw.Action,
		ActorID:    actorID,
		ActorName:  actorName,
		Attributes: raw.Actor.Attributes,
		TimeUnix:   tsUnix,
		Timestamp:  time.Unix(tsUnix, 0).UTC().Format(time.RFC3339),
	}, true
}

func shouldTriggerSyncForDockerEvent(ev DockerEvent) bool {
	switch ev.Type {
	case "container":
		switch strings.ToLower(strings.Split(ev.Action, ":")[0]) {
		case "start", "stop", "die", "kill", "pause", "unpause", "create", "destroy", "rename", "restart", "update", "oom":
			return true
		}
	case "image":
		switch strings.ToLower(strings.Split(ev.Action, ":")[0]) {
		case "pull", "delete", "prune", "tag", "untag":
			return true
		}
	case "network", "volume":
		return true
	}
	return false
}

// StartDockerEventWatcher subscribes to Docker Engine GET /events in the background
// with exponential backoff, publishing live events and debouncing SyncDockerEngine calls.
func (e *Engine) StartDockerEventWatcher(ctx context.Context) {
	e.ensureEventsInit()

	// Dedicated debouncer goroutine: syncs at most once per 1000ms burst.
	go func() {
		var timer *time.Timer
		var timerCh <-chan time.Time
		for {
			select {
			case <-ctx.Done():
				if timer != nil {
					timer.Stop()
				}
				return
			case <-e.syncNotifyCh:
				if timer == nil {
					timer = time.NewTimer(600 * time.Millisecond)
					timerCh = timer.C
				}
			case <-timerCh:
				timer = nil
				timerCh = nil
				e.SyncDockerEngine()
			}
		}
	}()

	backoff := 1 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		e.mu.RLock()
		runtimeMode := e.vps.RuntimeMode
		endpoint := e.vps.SocketEndpoint
		e.mu.RUnlock()

		if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
				continue
			}
		}

		client, baseURL, ok := newDockerHTTPClient(endpoint, 0)
		if !ok {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				backoff = min(5*time.Second, backoff*2)
				continue
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/events", nil)
		if err != nil {
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				backoff = min(5*time.Second, backoff*2)
				continue
			}
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				backoff = min(5*time.Second, backoff*2)
				continue
			}
		}

		backoff = 1 * time.Second
		scanner := bufio.NewScanner(io.LimitReader(resp.Body, 1<<30))
		scanner.Buffer(make([]byte, 0, 16*1024), 512*1024)
		for scanner.Scan() {
			if ctx.Err() != nil {
				break
			}
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			ev, valid := parseRawDockerEvent(line)
			if !valid {
				continue
			}
			e.RecordDockerEvent(ev)
			if shouldTriggerSyncForDockerEvent(ev) {
				select {
				case e.syncNotifyCh <- struct{}{}:
				default:
				}
			}
		}
		_ = resp.Body.Close()

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}
