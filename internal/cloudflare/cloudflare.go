// Package cloudflare implements a native Go Cloudflare REST API v4 client,
// AES-256-GCM encrypted token persistence, DNS record management,
// Zone SSL/TLS mode enforcement, and VPS public IPv4 auto-detection.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"deploymenthub/internal/vault"
)

const defaultCloudflareAPIBase = "https://api.cloudflare.com/client/v4"

// Config captures persisted Cloudflare integration settings.
// EncryptedToken is always omitted from API responses via GetSanitizedConfig().
type Config struct {
	Enabled          bool   `json:"enabled"`
	EncryptedToken   string `json:"encryptedToken,omitempty"`
	TokenPreview     string `json:"tokenPreview"`
	ZoneID           string `json:"zoneId"`
	BaseDomain       string `json:"baseDomain"`
	ServerIP         string `json:"serverIp"`
	DefaultProxied   bool   `json:"defaultProxied"`
	WildcardEnabled  bool   `json:"wildcardEnabled"`
	WildcardRecordID string `json:"wildcardRecordId,omitempty"`
	SSLMode          string `json:"sslMode"`
	TraefikDNS01     bool   `json:"traefikDns01"`
	HubDomain        string `json:"hubDomain,omitempty"`
	UpdatedAt        string `json:"updatedAt,omitempty"`
}

// Zone describes a Cloudflare DNS Zone returned by GET /zones.
type Zone struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	NameServers []string `json:"nameServers"`
}

// DNSRecord represents a Cloudflare Zone DNS record.
type DNSRecord struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Name       string `json:"name"`
	Content    string `json:"content"`
	TTL        int    `json:"ttl"`
	Proxied    bool   `json:"proxied"`
	ModifiedOn string `json:"modifiedOn,omitempty"`
}

// Manager provides thread-safe Cloudflare API v4 operations and encrypted persistence.
type Manager struct {
	mu           sync.RWMutex
	dnsMu        sync.Mutex
	vault        *vault.Vault
	dataFilePath string
	apiBaseURL   string
	httpClient   *http.Client
	cfg          Config
	cachedPubIP  string
}

type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfEnvelope[T any] struct {
	Success  bool         `json:"success"`
	Errors   []cfAPIError `json:"errors"`
	Messages []any        `json:"messages"`
	Result   T            `json:"result"`
}

// NewManager initializes a Cloudflare Manager and loads any persisted state from dataFile.
func NewManager(v *vault.Vault, dataFile string) *Manager {
	if v == nil {
		v, _ = vault.New("")
	}
	trimmedPath := strings.TrimSpace(dataFile)
	if trimmedPath == "" {
		trimmedPath = strings.TrimSpace(os.Getenv("CLOUDFLARE_DATA_FILE"))
	}
	m := &Manager{
		vault:        v,
		dataFilePath: trimmedPath,
		apiBaseURL:   defaultCloudflareAPIBase,
		httpClient:   &http.Client{Timeout: 12 * time.Second},
	}
	if envIP := strings.TrimSpace(os.Getenv("VPS_PUBLIC_IP")); net.ParseIP(envIP) != nil {
		m.cachedPubIP = envIP
	}
	m.loadFromDisk()
	return m
}

// SetAPIBaseURL overrides the Cloudflare API v4 base URL (used in tests).
func (m *Manager) SetAPIBaseURL(baseURL string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/"); trimmed != "" {
		m.apiBaseURL = trimmed
	}
}

// GetSanitizedConfig returns a copy of Config with EncryptedToken cleared.
func (m *Manager) GetSanitizedConfig() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := m.cfg
	out.EncryptedToken = ""
	return out
}

// GetDecryptedToken decrypts and returns the stored Cloudflare API token.
func (m *Manager) GetDecryptedToken() (string, error) {
	m.mu.RLock()
	enc := m.cfg.EncryptedToken
	m.mu.RUnlock()
	if strings.TrimSpace(enc) == "" {
		return "", errors.New("cloudflare is not connected")
	}
	return m.vault.Decrypt(enc)
}

// VerifyAndListZones validates a Cloudflare API token against GET /zones.
func (m *Manager) VerifyAndListZones(token string) ([]Zone, error) {
	cleanToken := strings.TrimSpace(token)
	if cleanToken == "" {
		return nil, errors.New("cloudflare API token is required")
	}

	type rawZone struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Status      string   `json:"status"`
		NameServers []string `json:"name_servers"`
	}
	rawZones, err := doCFRequest[[]rawZone](m, http.MethodGet, "/zones?per_page=50", cleanToken, nil)
	if err != nil {
		return nil, err
	}

	zones := make([]Zone, 0, len(rawZones))
	for _, rz := range rawZones {
		zones = append(zones, Zone{
			ID:          strings.TrimSpace(rz.ID),
			Name:        strings.ToLower(strings.TrimSpace(rz.Name)),
			Status:      strings.TrimSpace(rz.Status),
			NameServers: rz.NameServers,
		})
	}
	return zones, nil
}

// Connect verifies the Cloudflare API token, selects the target Zone, reads SSL settings & wildcard status,
// encrypts the token with AES-256-GCM, persists Config, and returns sanitized Config + Zones.
func (m *Manager) Connect(token, zoneID, baseDomain, serverIP string, defaultProxied bool) (Config, []Zone, error) {
	cleanToken := strings.TrimSpace(token)
	if cleanToken == "" {
		existing, err := m.GetDecryptedToken()
		if err != nil || existing == "" {
			return Config{}, nil, errors.New("cloudflare API token is required")
		}
		cleanToken = existing
	}

	zones, err := m.VerifyAndListZones(cleanToken)
	if err != nil {
		return Config{}, nil, err
	}
	if len(zones) == 0 {
		return Config{}, nil, errors.New("no Cloudflare zones found for this API token")
	}

	chosen, ok := pickTargetZone(zones, zoneID, baseDomain)
	if !ok {
		return Config{}, nil, fmt.Errorf("requested zone %q/%q not found in token scope", zoneID, baseDomain)
	}

	resolvedIP := strings.TrimSpace(serverIP)
	if net.ParseIP(resolvedIP) == nil {
		resolvedIP = m.DetectPublicIPv4()
	}

	encToken, err := m.vault.Encrypt(cleanToken)
	if err != nil {
		return Config{}, nil, fmt.Errorf("encrypt cloudflare token: %w", err)
	}

	sslMode := ""
	if mode, sslErr := m.fetchSSLMode(cleanToken, chosen.ID); sslErr == nil {
		sslMode = mode
	}

	wildcardEnabled := false
	wildcardRecID := ""
	if recs, recErr := m.fetchDNSRecords(cleanToken, chosen.ID); recErr == nil {
		wildcardTarget := "*." + chosen.Name
		for _, r := range recs {
			if r.Type == "A" && strings.EqualFold(r.Name, wildcardTarget) {
				wildcardEnabled = true
				wildcardRecID = r.ID
				break
			}
		}
	}

	previewLen := min(24, len(encToken))
	preview := encToken[:previewLen] + "..."

	m.mu.Lock()
	prevDNS01 := m.cfg.TraefikDNS01
	prevHub := m.cfg.HubDomain
	m.cfg = Config{
		Enabled:          true,
		EncryptedToken:   encToken,
		TokenPreview:     preview,
		ZoneID:           chosen.ID,
		BaseDomain:       chosen.Name,
		ServerIP:         resolvedIP,
		DefaultProxied:   defaultProxied,
		WildcardEnabled:  wildcardEnabled,
		WildcardRecordID: wildcardRecID,
		SSLMode:          sslMode,
		TraefikDNS01:     prevDNS01,
		HubDomain:        prevHub,
		UpdatedAt:        time.Now().UTC().Format(time.RFC3339),
	}
	m.persistLocked()
	sanitized := m.cfg
	sanitized.EncryptedToken = ""
	m.mu.Unlock()

	return sanitized, zones, nil
}

// Disconnect clears the Cloudflare configuration and removes/truncates persisted state.
func (m *Manager) Disconnect() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = Config{}
	if m.dataFilePath != "" {
		if err := os.Remove(m.dataFilePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// ListDNSRecords lists DNS records in the currently connected Cloudflare zone.
func (m *Manager) ListDNSRecords() ([]DNSRecord, error) {
	token, zoneID, _, err := m.authContext()
	if err != nil {
		return nil, err
	}
	return m.fetchDNSRecords(token, zoneID)
}

// UpsertARecord creates or updates an A record in the connected Cloudflare zone.
// Passing name="*" or "*.<baseDomain>" targets the wildcard record.
func (m *Manager) UpsertARecord(fqdn, ip string, proxied bool) (DNSRecord, error) {
	m.dnsMu.Lock()
	defer m.dnsMu.Unlock()

	token, zoneID, baseDomain, err := m.authContext()
	if err != nil {
		return DNSRecord{}, err
	}

	targetName := normalizeRecordName(fqdn, baseDomain)
	if targetName == "" {
		return DNSRecord{}, errors.New("DNS record name is required")
	}

	targetIP := strings.TrimSpace(ip)
	if net.ParseIP(targetIP) == nil {
		targetIP = m.GetSanitizedConfig().ServerIP
	}
	if net.ParseIP(targetIP) == nil {
		targetIP = m.DetectPublicIPv4()
	}
	if net.ParseIP(targetIP) == nil {
		return DNSRecord{}, errors.New("valid public IPv4 address is required for A record")
	}

	existing, err := m.fetchDNSRecordsByNameAndType(token, zoneID, targetName, "A")
	if err != nil {
		return DNSRecord{}, err
	}

	var rec DNSRecord
	if len(existing) > 0 && existing[0].Content == targetIP && existing[0].Proxied == proxied {
		rec = existing[0]
	} else {
		payload := map[string]any{
			"type":    "A",
			"name":    targetName,
			"content": targetIP,
			"ttl":     1,
			"proxied": proxied,
		}

		type rawRecord struct {
			ID         string `json:"id"`
			Type       string `json:"type"`
			Name       string `json:"name"`
			Content    string `json:"content"`
			TTL        int    `json:"ttl"`
			Proxied    bool   `json:"proxied"`
			ModifiedOn string `json:"modified_on"`
		}

		var saved rawRecord
		if len(existing) > 0 {
			path := fmt.Sprintf("/zones/%s/dns_records/%s", url.PathEscape(zoneID), url.PathEscape(existing[0].ID))
			saved, err = doCFRequest[rawRecord](m, http.MethodPut, path, token, payload)
		} else {
			path := fmt.Sprintf("/zones/%s/dns_records", url.PathEscape(zoneID))
			saved, err = doCFRequest[rawRecord](m, http.MethodPost, path, token, payload)
		}
		if err != nil {
			return DNSRecord{}, err
		}

		rec = DNSRecord{
			ID:         saved.ID,
			Type:       saved.Type,
			Name:       saved.Name,
			Content:    saved.Content,
			TTL:        saved.TTL,
			Proxied:    saved.Proxied,
			ModifiedOn: saved.ModifiedOn,
		}
	}

	if strings.EqualFold(rec.Name, "*."+baseDomain) {
		m.mu.Lock()
		m.cfg.WildcardEnabled = true
		m.cfg.WildcardRecordID = rec.ID
		m.cfg.DefaultProxied = rec.Proxied
		m.cfg.ServerIP = rec.Content
		m.cfg.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		m.persistLocked()
		m.mu.Unlock()
	}

	return rec, nil
}

// DeleteDNSRecord deletes a DNS record by ID from the connected Cloudflare zone.
func (m *Manager) DeleteDNSRecord(recordID string) error {
	m.dnsMu.Lock()
	defer m.dnsMu.Unlock()

	cleanID := strings.TrimSpace(recordID)
	if cleanID == "" {
		return errors.New("recordId is required")
	}
	token, zoneID, _, err := m.authContext()
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/zones/%s/dns_records/%s", url.PathEscape(zoneID), url.PathEscape(cleanID))
	_, err = doCFRequest[map[string]any](m, http.MethodDelete, path, token, nil)
	if err != nil {
		return err
	}

	m.mu.Lock()
	if m.cfg.WildcardRecordID == cleanID {
		m.cfg.WildcardEnabled = false
		m.cfg.WildcardRecordID = ""
		m.cfg.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		m.persistLocked()
	}
	m.mu.Unlock()
	return nil
}

// GetSSLMode fetches the Zone SSL/TLS encryption mode from Cloudflare ("off", "flexible", "full", "strict").
func (m *Manager) GetSSLMode() (string, error) {
	token, zoneID, _, err := m.authContext()
	if err != nil {
		return "", err
	}
	mode, err := m.fetchSSLMode(token, zoneID)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	m.cfg.SSLMode = mode
	m.persistLocked()
	m.mu.Unlock()
	return mode, nil
}

// SetSSLMode updates the Cloudflare Zone SSL/TLS encryption mode (e.g. "strict").
func (m *Manager) SetSSLMode(mode string) (string, error) {
	m.dnsMu.Lock()
	defer m.dnsMu.Unlock()

	normalized := strings.ToLower(strings.TrimSpace(mode))
	switch normalized {
	case "off", "flexible", "full", "strict":
	default:
		return "", fmt.Errorf("invalid SSL mode %q (expected off, flexible, full, or strict)", mode)
	}
	token, zoneID, _, err := m.authContext()
	if err != nil {
		return "", err
	}
	path := fmt.Sprintf("/zones/%s/settings/ssl", url.PathEscape(zoneID))
	res, err := doCFRequest[struct {
		Value string `json:"value"`
	}](m, http.MethodPatch, path, token, map[string]string{"value": normalized})
	if err != nil {
		return "", err
	}

	m.mu.Lock()
	m.cfg.SSLMode = res.Value
	m.cfg.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	m.persistLocked()
	m.mu.Unlock()
	return res.Value, nil
}

// SetTraefikDNS01Status records whether Traefik has Cloudflare DNS-01 active.
func (m *Manager) SetTraefikDNS01Status(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.TraefikDNS01 = enabled
	m.cfg.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	m.persistLocked()
}

// SetHubDomain persists the configured custom Cloudflare domain for DeploymentHub UI.
func (m *Manager) SetHubDomain(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.HubDomain = strings.TrimSpace(domain)
	m.cfg.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	m.persistLocked()
}

// DetectPublicIPv4 resolves and caches the host VPS public IPv4 address.
func (m *Manager) DetectPublicIPv4() string {
	m.mu.RLock()
	if net.ParseIP(m.cachedPubIP) != nil {
		ip := m.cachedPubIP
		m.mu.RUnlock()
		return ip
	}
	m.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()

	client := &http.Client{Timeout: 2500 * time.Millisecond}

	// 1. Try Cloudflare trace endpoint
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://1.1.1.1/cdn-cgi/trace", nil); err == nil {
		if resp, err := client.Do(req); err == nil {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			for _, line := range strings.Split(string(raw), "\n") {
				if ipStr, ok := strings.CutPrefix(strings.TrimSpace(line), "ip="); ok {
					if ip := net.ParseIP(strings.TrimSpace(ipStr)); ip != nil && ip.To4() != nil {
						m.cachePublicIP(ip.String())
						return ip.String()
					}
				}
			}
		}
	}

	// 2. Fallback to api.ipify.org
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil); err == nil {
		if resp, err := client.Do(req); err == nil {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			_ = resp.Body.Close()
			if ip := net.ParseIP(strings.TrimSpace(string(raw))); ip != nil && ip.To4() != nil {
				m.cachePublicIP(ip.String())
				return ip.String()
			}
		}
	}

	return ""
}

func (m *Manager) cachePublicIP(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cachedPubIP = ip
}

func (m *Manager) authContext() (token, zoneID, baseDomain string, err error) {
	m.mu.RLock()
	enabled := m.cfg.Enabled
	enc := m.cfg.EncryptedToken
	zoneID = m.cfg.ZoneID
	baseDomain = m.cfg.BaseDomain
	m.mu.RUnlock()

	if !enabled || strings.TrimSpace(enc) == "" || strings.TrimSpace(zoneID) == "" {
		return "", "", "", errors.New("cloudflare is not connected")
	}
	tok, err := m.vault.Decrypt(enc)
	if err != nil {
		return "", "", "", fmt.Errorf("decrypt cloudflare token: %w", err)
	}
	return tok, zoneID, baseDomain, nil
}

func (m *Manager) clientAndBase() (*http.Client, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.httpClient, m.apiBaseURL
}

func (m *Manager) fetchSSLMode(token, zoneID string) (string, error) {
	path := fmt.Sprintf("/zones/%s/settings/ssl", url.PathEscape(zoneID))
	res, err := doCFRequest[struct {
		Value string `json:"value"`
	}](m, http.MethodGet, path, token, nil)
	if err != nil {
		return "", err
	}
	return res.Value, nil
}

func (m *Manager) fetchDNSRecords(token, zoneID string) ([]DNSRecord, error) {
	path := fmt.Sprintf("/zones/%s/dns_records?per_page=100", url.PathEscape(zoneID))
	return m.fetchDNSRecordsPath(token, path)
}

func (m *Manager) fetchDNSRecordsByNameAndType(token, zoneID, fqdn, recType string) ([]DNSRecord, error) {
	q := url.Values{}
	q.Set("type", recType)
	q.Set("name", fqdn)
	path := fmt.Sprintf("/zones/%s/dns_records?%s", url.PathEscape(zoneID), q.Encode())
	return m.fetchDNSRecordsPath(token, path)
}

func (m *Manager) fetchDNSRecordsPath(token, path string) ([]DNSRecord, error) {
	type rawRecord struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Name       string `json:"name"`
		Content    string `json:"content"`
		TTL        int    `json:"ttl"`
		Proxied    bool   `json:"proxied"`
		ModifiedOn string `json:"modified_on"`
	}
	raw, err := doCFRequest[[]rawRecord](m, http.MethodGet, path, token, nil)
	if err != nil {
		return nil, err
	}
	out := make([]DNSRecord, 0, len(raw))
	for _, r := range raw {
		out = append(out, DNSRecord{
			ID:         r.ID,
			Type:       r.Type,
			Name:       r.Name,
			Content:    r.Content,
			TTL:        r.TTL,
			Proxied:    r.Proxied,
			ModifiedOn: r.ModifiedOn,
		})
	}
	return out, nil
}

func (m *Manager) loadFromDisk() {
	if m.dataFilePath == "" {
		return
	}
	raw, err := os.ReadFile(m.dataFilePath)
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		return
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return
	}
	if cfg.ServerIP != "" && m.cachedPubIP == "" && net.ParseIP(cfg.ServerIP) != nil {
		m.cachedPubIP = cfg.ServerIP
	}
	m.cfg = cfg
}

func (m *Manager) persistLocked() {
	if m.dataFilePath == "" {
		return
	}
	dir := filepath.Dir(m.dataFilePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	data, err := json.MarshalIndent(m.cfg, "", "  ")
	if err != nil {
		return
	}
	tmp := m.dataFilePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, m.dataFilePath)
}

func doCFRequest[T any](m *Manager, method, path, token string, body any) (T, error) {
	var zero T
	client, baseURL := m.clientAndBase()
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return zero, err
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, baseURL+path, bodyReader)
	if err != nil {
		return zero, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return zero, fmt.Errorf("cloudflare API request failed: %w", err)
	}
	defer resp.Body.Close()

	rawBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return zero, err
	}

	var env cfEnvelope[T]
	if err := json.Unmarshal(rawBytes, &env); err != nil {
		return zero, fmt.Errorf("cloudflare API HTTP %d invalid JSON: %w", resp.StatusCode, err)
	}

	if !env.Success || resp.StatusCode >= 400 {
		if len(env.Errors) > 0 {
			msgs := make([]string, 0, len(env.Errors))
			for _, e := range env.Errors {
				msgs = append(msgs, fmt.Sprintf("%s (code %d)", e.Message, e.Code))
			}
			return zero, fmt.Errorf("cloudflare API error: %s", strings.Join(msgs, "; "))
		}
		return zero, fmt.Errorf("cloudflare API failed with HTTP %d", resp.StatusCode)
	}
	return env.Result, nil
}

func pickTargetZone(zones []Zone, zoneID, baseDomain string) (Zone, bool) {
	wantID := strings.TrimSpace(zoneID)
	wantDomain := strings.ToLower(strings.TrimSpace(baseDomain))
	if wantID != "" {
		for _, z := range zones {
			if z.ID == wantID {
				return z, true
			}
		}
		return Zone{}, false
	}
	if wantDomain != "" {
		for _, z := range zones {
			if z.Name == wantDomain || strings.HasSuffix(wantDomain, "."+z.Name) {
				return z, true
			}
		}
		return Zone{}, false
	}
	for _, z := range zones {
		if strings.EqualFold(z.Status, "active") {
			return z, true
		}
	}
	if len(zones) > 0 {
		return zones[0], true
	}
	return Zone{}, false
}

func normalizeRecordName(fqdn, baseDomain string) string {
	clean := strings.ToLower(strings.TrimSpace(fqdn))
	base := strings.ToLower(strings.TrimSpace(baseDomain))
	clean = strings.TrimSuffix(clean, ".")
	if clean == "" || base == "" {
		return clean
	}
	if clean == "@" || clean == base {
		return base
	}
	if clean == "*" {
		return "*." + base
	}
	if strings.HasSuffix(clean, "."+base) {
		return clean
	}
	if !strings.Contains(clean, ".") {
		return clean + "." + base
	}
	return clean
}
