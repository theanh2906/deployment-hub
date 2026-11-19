package docker

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ErrOperationInProgress is returned when a conflicting Traefik/SSL operation is already running.
var ErrOperationInProgress = errors.New("another Traefik/SSL configuration operation is already in progress")

// SSLSettings holds global ACME / Let's Encrypt configuration for Traefik reverse proxy routes.
type SSLSettings struct {
	Provider          string `json:"provider"`
	ACMEEmail         string `json:"acmeEmail"`
	ChallengeType     string `json:"challengeType"`
	AutoRedirectHTTPS bool   `json:"autoRedirectHttps"`
	WildcardDomain    string `json:"wildcardDomain"`
}

// CertProbeResult reports real DNS resolution and live X.509 certificate inspection from Traefik.
type CertProbeResult struct {
	Domain            string   `json:"domain"`
	DNSResolved       bool     `json:"dnsResolved"`
	DNSIPs            []string `json:"dnsIps"`
	TLSActive         bool     `json:"tlsActive"`
	TrustedLetEncrypt bool     `json:"trustedLetsEncrypt"`
	Issuer            string   `json:"issuer"`
	Subject           string   `json:"subject"`
	NotBefore         string   `json:"notBefore"`
	NotAfter          string   `json:"notAfter"`
	DaysRemaining     int      `json:"daysRemaining"`
	Protocol          string   `json:"protocol"`
	StatusLabel       string   `json:"statusLabel"`
}

func defaultSSLSettings() SSLSettings {
	email := strings.TrimSpace(os.Getenv("ACME_EMAIL"))
	if email == "" {
		email = "theanh2906@gmail.com"
	}
	return SSLSettings{
		Provider:          "letsencrypt",
		ACMEEmail:         email,
		ChallengeType:     "HTTP-01 (:80) + TLS-ALPN-01 (:443)",
		AutoRedirectHTTPS: false,
		WildcardDomain:    "sslip.io",
	}
}

func isPublicACMEDomain(domain string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" || d == "localhost" || strings.HasSuffix(d, ".localhost") || strings.HasSuffix(d, ".local") {
		return false
	}
	// Bare IP address is not valid for Let's Encrypt ACME; *.sslip.io or *.nip.io is valid.
	if net.ParseIP(d) != nil {
		return false
	}
	if ipv4SuffixRegexp.MatchString(d) && !strings.HasSuffix(d, ".sslip.io") && !strings.HasSuffix(d, ".nip.io") {
		return false
	}
	return strings.Contains(d, ".")
}

func isUnderBaseDomain(domain, baseDomain string) (under bool, isWildcardEligible bool) {
	d := strings.ToLower(strings.TrimSpace(domain))
	b := strings.ToLower(strings.TrimSpace(baseDomain))
	if d == "" || b == "" {
		return false, false
	}
	if d == b {
		return true, true
	}
	suffix := "." + b
	if !strings.HasSuffix(d, suffix) {
		return false, false
	}
	sub := strings.TrimSuffix(d, suffix)
	// Single-level subdomain (*.bennasolutions.com) is covered by the wildcard cert;
	// deeper multi-level subdomains (a.b.bennasolutions.com) get a dedicated DNS-01 SAN.
	return true, sub != "" && !strings.Contains(sub, ".")
}

func buildContainerTraefikLabels(
	appName, repoURL, branch, commitSHA, publicDomain, containerPort string,
	hostPort int,
	enableSSL, forceHTTPS bool,
	cfBaseDomain string,
	useCFDNS01 bool,
) map[string]string {
	cleanDomain := strings.TrimSpace(publicDomain)
	if cleanDomain == "" {
		cleanDomain = appName + ".localhost"
	}

	rawAlias := ""
	if strings.HasSuffix(strings.ToLower(cleanDomain), ".sslip.io") {
		rawAlias = strings.TrimSuffix(cleanDomain, ".sslip.io")
	} else if strings.HasSuffix(strings.ToLower(cleanDomain), ".nip.io") {
		rawAlias = strings.TrimSuffix(cleanDomain, ".nip.io")
	}

	httpRule := fmt.Sprintf("Host(`%s`)", cleanDomain)
	if rawAlias != "" && rawAlias != cleanDomain {
		httpRule = fmt.Sprintf("Host(`%s`) || Host(`%s`)", cleanDomain, rawAlias)
	}

	labels := map[string]string{
		"com.docker.compose.project": appName,
		"deploymenthub.managed":      "true",
		"deploymenthub.app":          appName,
		"deploymenthub.repo":         repoURL,
		"deploymenthub.branch":       branch,
		"deploymenthub.commit":       commitSHA,
		"deploymenthub.domain":       cleanDomain,
		"deploymenthub.host_port":    strconv.Itoa(hostPort),
		"deploymenthub.force_https":  strconv.FormatBool(forceHTTPS),
		"traefik.enable":             "true",
		"traefik.docker.network":     "deploymenthub_proxy",
		fmt.Sprintf("traefik.http.routers.%s.rule", appName):                      httpRule,
		fmt.Sprintf("traefik.http.routers.%s.entrypoints", appName):               "web",
		fmt.Sprintf("traefik.http.services.%s.loadbalancer.server.port", appName): containerPort,
	}

	if enableSSL {
		tlsRule := fmt.Sprintf("Host(`%s`)", cleanDomain)
		labels[fmt.Sprintf("traefik.http.routers.%s-tls.rule", appName)] = tlsRule
		labels[fmt.Sprintf("traefik.http.routers.%s-tls.entrypoints", appName)] = "websecure"
		labels[fmt.Sprintf("traefik.http.routers.%s-tls.tls", appName)] = "true"

		underCF, wildcardEligible := isUnderBaseDomain(cleanDomain, cfBaseDomain)
		if useCFDNS01 && underCF {
			labels[fmt.Sprintf("traefik.http.routers.%s-tls.tls.certresolver", appName)] = "cloudflare"
			if wildcardEligible {
				cleanBase := strings.ToLower(strings.TrimSpace(cfBaseDomain))
				labels[fmt.Sprintf("traefik.http.routers.%s-tls.tls.domains[0].main", appName)] = cleanBase
				labels[fmt.Sprintf("traefik.http.routers.%s-tls.tls.domains[0].sans", appName)] = "*." + cleanBase
			}
		} else if isPublicACMEDomain(cleanDomain) {
			labels[fmt.Sprintf("traefik.http.routers.%s-tls.tls.certresolver", appName)] = "letsencrypt"
		}
		if forceHTTPS {
			mwName := appName + "-redirect-https"
			labels[fmt.Sprintf("traefik.http.middlewares.%s.redirectscheme.scheme", mwName)] = "https"
			labels[fmt.Sprintf("traefik.http.middlewares.%s.redirectscheme.permanent", mwName)] = "true"
			labels[fmt.Sprintf("traefik.http.routers.%s.middlewares", appName)] = mwName
		}
	}

	return labels
}

// ProbeDomainSSL performs real DNS lookup + live TLS handshake inspection against Traefik.
func ProbeDomainSSL(domain string) CertProbeResult {
	cleanDomain := strings.TrimSpace(domain)
	res := CertProbeResult{
		Domain:      cleanDomain,
		DNSIPs:      []string{},
		StatusLabel: "Chưa kiểm tra",
	}
	if cleanDomain == "" {
		res.StatusLabel = "Chưa cấu hình domain"
		return res
	}

	// 1. Real DNS lookup with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	if ips, err := net.DefaultResolver.LookupHost(ctx, cleanDomain); err == nil && len(ips) > 0 {
		res.DNSResolved = true
		res.DNSIPs = ips
	}

	// 2. Live TLS dial against Traefik (service DNS inside Docker network, or loopback)
	dialTargets := []string{"deploymenthub-traefik:443", "127.0.0.1:443"}
	var tlsConn *tls.Conn
	for _, target := range dialTargets {
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 2500 * time.Millisecond},
			"tcp",
			target,
			&tls.Config{
				ServerName:         cleanDomain,
				InsecureSkipVerify: true, // Inspect certificate chain even if default self-signed cert
			},
		)
		if err == nil {
			tlsConn = conn
			break
		}
	}

	if tlsConn == nil {
		if res.DNSResolved {
			res.StatusLabel = "DNS OK • Chờ mở cổng :443"
		} else {
			res.StatusLabel = "Chưa trỏ DNS / Cổng :443 chưa sẵn sàng"
		}
		return res
	}
	defer tlsConn.Close()

	cs := tlsConn.ConnectionState()
	res.TLSActive = true
	res.Protocol = tlsVersionName(cs.Version)

	if len(cs.PeerCertificates) > 0 {
		cert := cs.PeerCertificates[0]
		issuer := strings.TrimSpace(cert.Issuer.CommonName)
		if issuer == "" && len(cert.Issuer.Organization) > 0 {
			issuer = strings.Join(cert.Issuer.Organization, ", ")
		}
		res.Issuer = issuer
		res.Subject = strings.TrimSpace(cert.Subject.CommonName)
		res.NotBefore = cert.NotBefore.UTC().Format("2006-01-02")
		res.NotAfter = cert.NotAfter.UTC().Format("2006-01-02")
		res.DaysRemaining = int(time.Until(cert.NotAfter).Hours() / 24)

		lowerIssuer := strings.ToLower(issuer + " " + strings.Join(cert.Issuer.Organization, " "))
		lowerSubj := strings.ToLower(res.Subject)
		if strings.Contains(lowerIssuer, "let's encrypt") || strings.Contains(lowerIssuer, "r3") || strings.Contains(lowerIssuer, "e5") || strings.Contains(lowerIssuer, "e6") || strings.Contains(lowerIssuer, "r10") || strings.Contains(lowerIssuer, "r11") {
			res.TrustedLetEncrypt = true
			res.StatusLabel = fmt.Sprintf("Let's Encrypt Active (%s • còn %d ngày)", issuer, res.DaysRemaining)
		} else if strings.Contains(lowerSubj, "traefik default cert") || strings.Contains(lowerIssuer, "traefik") {
			res.TrustedLetEncrypt = false
			res.StatusLabel = "Traefik Default Cert (ACME đang chờ DNS/HTTP-01 challenge)"
		} else {
			res.StatusLabel = fmt.Sprintf("TLS Active (%s)", issuer)
		}
	} else {
		res.StatusLabel = "TLS Active"
	}
	return res
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	default:
		return "TLS"
	}
}

func triggerTraefikACMEWarmup(domain string) {
	if !isPublicACMEDomain(domain) {
		return
	}
	// Performing a TLS handshake with SNI prompts Traefik's ACME resolver to issue the Let's Encrypt cert.
	for i := 0; i < 3; i++ {
		res := ProbeDomainSSL(domain)
		if res.TrustedLetEncrypt {
			return
		}
		time.Sleep(1500 * time.Millisecond)
	}
}

// GetSSLOverview returns global Let's Encrypt settings plus live DNS/X.509 probe data per route.
func (e *Engine) GetSSLOverview() map[string]any {
	e.mu.RLock()
	settings := e.sslSettings
	routes := make([]ProxyRoute, len(e.proxyRoutes))
	copy(routes, e.proxyRoutes)
	e.mu.RUnlock()

	probes := make([]CertProbeResult, 0, len(routes))
	seen := make(map[string]bool)
	for _, rt := range routes {
		d := strings.TrimSpace(rt.Domain)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		probes = append(probes, ProbeDomainSSL(d))
	}

	return map[string]any{
		"settings": settings,
		"probes":   probes,
	}
}

// UpdateSSLSettings updates Let's Encrypt / ACME preferences on the engine.
func (e *Engine) UpdateSSLSettings(acmeEmail, wildcardDomain string, autoRedirect bool) SSLSettings {
	e.mu.Lock()
	defer e.mu.Unlock()
	if trimmed := strings.TrimSpace(acmeEmail); trimmed != "" {
		e.sslSettings.ACMEEmail = trimmed
	}
	if w := strings.TrimSpace(wildcardDomain); w != "" {
		e.sslSettings.WildcardDomain = w
	}
	e.sslSettings.AutoRedirectHTTPS = autoRedirect
	return e.sslSettings
}

type dockerContainerInspect struct {
	Id     string `json:"Id"`
	Name   string `json:"Name"`
	Image  string `json:"Image"`
	Config struct {
		Image        string            `json:"Image"`
		Cmd          []string          `json:"Cmd"`
		Env          []string          `json:"Env"`
		Labels       map[string]string `json:"Labels"`
		ExposedPorts map[string]any    `json:"ExposedPorts"`
	} `json:"Config"`
	HostConfig struct {
		Binds         []string                       `json:"Binds"`
		PortBindings  map[string][]map[string]string `json:"PortBindings"`
		RestartPolicy map[string]any                 `json:"RestartPolicy"`
		NetworkMode   string                         `json:"NetworkMode"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]any `json:"Networks"`
	} `json:"NetworkSettings"`
}

func traefikDynamicDir() string {
	if d := strings.TrimSpace(os.Getenv("TRAEFIK_DYNAMIC_DIR")); d != "" {
		return d
	}
	return "/data/traefik-dynamic"
}

// SyncTraefikCloudflareDNS01 configures deploymenthub-traefik with CF_DNS_API_TOKEN and
// the Cloudflare ACME DNS-01 challenge resolver, preserving all networks, ports, and volumes.
func (e *Engine) SyncTraefikCloudflareDNS01(cfToken, acmeEmail, baseDomain string) error {
	if !e.traefikSyncMu.TryLock() {
		return ErrOperationInProgress
	}
	defer e.traefikSyncMu.Unlock()

	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	defaultEmail := e.sslSettings.ACMEEmail
	e.mu.RUnlock()

	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		if e.cf != nil {
			e.cf.SetTraefikDNS01Status(true)
		}
		return nil
	}

	email := strings.TrimSpace(acmeEmail)
	if email == "" {
		email = defaultEmail
	}
	if email == "" {
		email = "theanh2906@gmail.com"
	}

	desiredFlags := map[string]string{
		"--providers.file.directory":                                  "/etc/traefik/dynamic",
		"--providers.file.watch":                                      "true",
		"--certificatesresolvers.cloudflare.acme.dnschallenge":        "true",
		"--certificatesresolvers.cloudflare.acme.dnschallenge.provider": "cloudflare",
		"--certificatesresolvers.cloudflare.acme.dnschallenge.resolvers": "1.1.1.1:53,8.8.8.8:53",
		"--certificatesresolvers.cloudflare.acme.email":               email,
		"--certificatesresolvers.cloudflare.acme.storage":             "/letsencrypt/acme.json",
	}

	client, baseURL, ok := newDockerHTTPClient(endpoint, 45*time.Second)
	if !ok {
		return errors.New("docker engine client unavailable")
	}

	inspectData, hasInspect := fetchDockerJSON[dockerContainerInspect](client, baseURL+"/containers/deploymenthub-traefik/json")
	if !hasInspect {
		return errors.New("failed to inspect deploymenthub-traefik container")
	}

	if traefikConfigMatches(inspectData.Config.Env, inspectData.Config.Cmd, cfToken, desiredFlags) {
		if cleanBase := strings.ToLower(strings.TrimSpace(baseDomain)); cleanBase != "" {
			_ = e.writeWildcardWarmupDynamicConfig(cleanBase)
		}
		if e.cf != nil {
			e.cf.SetTraefikDNS01Status(true)
		}
		return nil
	}

	// Update env with CF_DNS_API_TOKEN
	newEnv := make([]string, 0, len(inspectData.Config.Env)+1)
	for _, kv := range inspectData.Config.Env {
		if strings.HasPrefix(kv, "CF_DNS_API_TOKEN=") {
			continue
		}
		newEnv = append(newEnv, kv)
	}
	newEnv = append(newEnv, "CF_DNS_API_TOKEN="+strings.TrimSpace(cfToken))

	// Update Cmd flags idempotently with cloudflare DNS-01 resolver + dynamic file provider
	newCmd := mergeTraefikCmdFlags(inspectData.Config.Cmd, desiredFlags)

	netMode := inspectData.HostConfig.NetworkMode
	if netMode == "" {
		netMode = "deploymenthub_proxy"
	}
	extraNetworks := make([]string, 0, len(inspectData.NetworkSettings.Networks))
	for netName := range inspectData.NetworkSettings.Networks {
		if netName != "" && netName != netMode {
			extraNetworks = append(extraNetworks, netName)
		}
	}
	slices.Sort(extraNetworks)

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	removeExistingDockerContainer(ctx, client, baseURL, "deploymenthub-traefik")

	imageName := inspectData.Config.Image
	if imageName == "" {
		imageName = inspectData.Image
	}

	createPayload := map[string]any{
		"Image":        imageName,
		"Cmd":          newCmd,
		"Env":          newEnv,
		"Labels":       inspectData.Config.Labels,
		"ExposedPorts": inspectData.Config.ExposedPorts,
		"HostConfig": map[string]any{
			"Binds":         inspectData.HostConfig.Binds,
			"PortBindings":  inspectData.HostConfig.PortBindings,
			"RestartPolicy": map[string]any{"Name": "unless-stopped"},
			"NetworkMode":   netMode,
		},
	}

	bodyBytes, _ := json.Marshal(createPayload)
	createReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/containers/create?name=deploymenthub-traefik", bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := client.Do(createReq)
	if err != nil {
		return fmt.Errorf("recreate traefik: %w", err)
	}
	var createRes struct {
		ID      string `json:"Id"`
		Message string `json:"message"`
	}
	_ = json.NewDecoder(createResp.Body).Decode(&createRes)
	_ = createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated && createResp.StatusCode != http.StatusOK {
		return fmt.Errorf("recreate deploymenthub-traefik failed (HTTP %d): %s", createResp.StatusCode, createRes.Message)
	}

	// Re-attach all other Docker networks (such as deployment-hub_hub_internal) before starting
	for _, netName := range extraNetworks {
		connBody, _ := json.Marshal(map[string]any{"Container": createRes.ID})
		connReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/networks/"+url.PathEscape(netName)+"/connect", bytes.NewReader(connBody))
		if err == nil {
			connReq.Header.Set("Content-Type", "application/json")
			if resp, err := client.Do(connReq); err == nil {
				_ = resp.Body.Close()
			}
		}
	}

	startReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/containers/"+url.PathEscape(createRes.ID)+"/start", nil)
	startResp, err := client.Do(startReq)
	if err != nil {
		return fmt.Errorf("start traefik: %w", err)
	}
	defer startResp.Body.Close()
	if startResp.StatusCode != http.StatusNoContent && startResp.StatusCode != http.StatusOK && startResp.StatusCode != http.StatusNotModified {
		errBody, _ := io.ReadAll(io.LimitReader(startResp.Body, 4096))
		return fmt.Errorf("start deploymenthub-traefik failed (HTTP %d): %s", startResp.StatusCode, strings.TrimSpace(string(errBody)))
	}

	// Write a dynamic router file requesting the wildcard certificate immediately on Traefik
	if cleanBase := strings.ToLower(strings.TrimSpace(baseDomain)); cleanBase != "" {
		_ = e.writeWildcardWarmupDynamicConfig(cleanBase)
		go triggerTraefikACMEWarmup("*." + cleanBase)
	}

	if e.cf != nil {
		e.cf.SetTraefikDNS01Status(true)
	}
	return nil
}

func traefikConfigMatches(existingEnv, existingCmd []string, wantToken string, wantFlags map[string]string) bool {
	wantEnv := "CF_DNS_API_TOKEN=" + strings.TrimSpace(wantToken)
	foundToken := false
	for _, kv := range existingEnv {
		if kv == wantEnv {
			foundToken = true
			break
		}
	}
	if !foundToken {
		return false
	}

	actualFlags := make(map[string]string, len(existingCmd))
	for _, arg := range existingCmd {
		if k, v, ok := strings.Cut(arg, "="); ok {
			actualFlags[k] = v
		}
	}
	for k, wantVal := range wantFlags {
		if gotVal, ok := actualFlags[k]; !ok || gotVal != wantVal {
			return false
		}
	}
	return true
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, data) {
		return nil
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func mergeTraefikCmdFlags(existing []string, desired map[string]string) []string {
	out := make([]string, 0, len(existing)+len(desired))
	seen := make(map[string]bool, len(desired))
	for _, arg := range existing {
		key, _, _ := strings.Cut(arg, "=")
		if newVal, override := desired[key]; override {
			if !seen[key] {
				out = append(out, key+"="+newVal)
				seen[key] = true
			}
			continue
		}
		out = append(out, arg)
	}
	keys := make([]string, 0, len(desired))
	for k := range desired {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		out = append(out, k+"="+desired[k])
	}
	return out
}

func (e *Engine) writeWildcardWarmupDynamicConfig(baseDomain string) error {
	e.dynamicFileMu.Lock()
	defer e.dynamicFileMu.Unlock()

	dir := traefikDynamicDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// Traefik dynamic file to define TLS options; wildcard SANs are requested when a router references it,
	// or via the hub-domain / app routers using certResolver cloudflare.
	cfgPath := filepath.Join(dir, "cloudflare-wildcard.yml")
	content := fmt.Sprintf(`# Managed by DeploymentHub for %s
tls:
  stores:
    default:
      defaultGeneratedCert:
        resolver: cloudflare
        domain:
          main: "%s"
          sans:
            - "*.%s"
`, baseDomain, baseDomain, baseDomain)
	return writeFileAtomic(cfgPath, []byte(content), 0o644)
}

// ConfigureHubDomain writes a dynamic Traefik route for the DeploymentHub control plane UI itself
// (e.g. hub.bennasolutions.com) without restarting the control-plane container.
func (e *Engine) ConfigureHubDomain(hubDomain string, useCFDNS01 bool, baseDomain string) error {
	cleanDomain := strings.ToLower(strings.TrimSpace(hubDomain))
	if cleanDomain == "" {
		return errors.New("hub domain is required")
	}

	resolver := "letsencrypt"
	tlsDomainsBlock := ""
	underCF, wildcardEligible := isUnderBaseDomain(cleanDomain, baseDomain)
	if useCFDNS01 && underCF {
		resolver = "cloudflare"
		if wildcardEligible {
			cleanBase := strings.ToLower(strings.TrimSpace(baseDomain))
			tlsDomainsBlock = fmt.Sprintf(`
        domains:
          - main: "%s"
            sans:
              - "*.%s"`, cleanBase, cleanBase)
		}
	}

	yml := fmt.Sprintf(`# Managed by DeploymentHub (Control Plane Route)
http:
  routers:
    deploymenthub-custom-http:
      rule: "Host(`+"`%s`"+`)"
      entryPoints:
        - web
      service: deploymenthub-control-plane-svc
    deploymenthub-custom-https:
      rule: "Host(`+"`%s`"+`)"
      entryPoints:
        - websecure
      tls:
        certResolver: %s%s
      service: deploymenthub-control-plane-svc
  services:
    deploymenthub-control-plane-svc:
      loadBalancer:
        servers:
          - url: "http://deploymenthub-control-plane:4180"
`, cleanDomain, cleanDomain, resolver, tlsDomainsBlock)

	e.dynamicFileMu.Lock()
	dir := traefikDynamicDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		e.dynamicFileMu.Unlock()
		return fmt.Errorf("create traefik dynamic dir: %w", err)
	}
	err := writeFileAtomic(filepath.Join(dir, "hub-domain.yml"), []byte(yml), 0o644)
	e.dynamicFileMu.Unlock()
	if err != nil {
		return fmt.Errorf("write hub-domain.yml: %w", err)
	}
	if e.cf != nil {
		e.cf.SetHubDomain(cleanDomain)
	}
	return nil
}

// ConfigureProjectSSL updates domain & Let's Encrypt SSL configuration for a project.
func (e *Engine) ConfigureProjectSSL(projectID, newDomain string, enableSSL, forceHTTPS bool) (Project, CertProbeResult, error) {
	return e.ConfigureProjectSSLWithOptions(projectID, newDomain, enableSSL, forceHTTPS, false, false)
}

// ConfigureProjectSSLWithOptions updates domain & SSL configuration for a project and optionally
// upserts an explicit Cloudflare DNS A record + Orange Cloud proxy status.
func (e *Engine) ConfigureProjectSSLWithOptions(projectID, newDomain string, enableSSL, forceHTTPS, syncCFDNS, cfProxied bool) (Project, CertProbeResult, error) {
	e.mu.RLock()
	pIdx := e.findProjectIndexLocked(projectID)
	if pIdx < 0 {
		e.mu.RUnlock()
		return Project{}, CertProbeResult{}, fmt.Errorf("project %q not found", projectID)
	}
	proj := cloneProject(e.projects[pIdx])
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	var containerIDs []string
	var primaryContainer Container
	for _, c := range e.containers {
		if c.Project == proj.Name {
			if primaryContainer.ID == "" {
				primaryContainer = c
			}
			containerIDs = append(containerIDs, c.ID)
		}
	}
	e.mu.RUnlock()

	normalizedDomain := normalizePublicDomain(newDomain)
	if strings.TrimSpace(newDomain) == "" {
		normalizedDomain = normalizePublicDomain(proj.Domain)
	}

	var cfBaseDomain string
	var useCFDNS01 bool
	var serverIP string
	if e.cf != nil {
		cfCfg := e.cf.GetSanitizedConfig()
		if cfCfg.Enabled {
			cfBaseDomain = cfCfg.BaseDomain
			useCFDNS01 = cfCfg.TraefikDNS01
			serverIP = cfCfg.ServerIP
			if syncCFDNS {
				if _, err := e.cf.UpsertARecord(normalizedDomain, serverIP, cfProxied); err != nil {
					return Project{}, CertProbeResult{}, fmt.Errorf("cloudflare DNS sync: %w", err)
				}
			}
		}
	}

	if runtimeMode == "docker" && strings.TrimSpace(endpoint) != "" && len(containerIDs) > 0 {
		client, baseURL, ok := newDockerHTTPClient(endpoint, 30*time.Second)
		if ok && !strings.HasPrefix(primaryContainer.ID, "cnt-") {
			inspectData, hasInspect := fetchDockerJSON[dockerContainerInspect](client, baseURL+"/containers/"+url.PathEscape(primaryContainer.ID)+"/json")
			if hasInspect {
				// Do not recreate deploymenthub-control-plane itself
				cname := strings.TrimPrefix(inspectData.Name, "/")
				if cname != "deploymenthub-control-plane" && cname != "deploymenthub-traefik" && cname != "deploymenthub-socket-proxy" {
					if err := recreateContainerWithSSL(client, baseURL, inspectData, proj, normalizedDomain, enableSSL, forceHTTPS, cfBaseDomain, useCFDNS01); err != nil {
						return Project{}, CertProbeResult{}, err
					}
				}
			}
		}
	}

	// Update in-memory routes & project state immediately as well
	e.mu.Lock()
	if idx := e.findProjectIndexLocked(projectID); idx >= 0 {
		e.projects[idx].Domain = normalizedDomain
		e.projects[idx].UpdatedAt = "Vừa cấu hình SSL"
		ts := time.Now().UTC().Format("15:04:05")
		e.projects[idx].Logs = append(e.projects[idx].Logs,
			fmt.Sprintf("%s [traefik/ssl] Configured domain=%s letsencrypt=%v forceHTTPS=%v", ts, normalizedDomain, enableSSL, forceHTTPS),
		)
		proj = cloneProject(e.projects[idx])
	}

	updatedRoute := false
	for i := range e.proxyRoutes {
		rt := &e.proxyRoutes[i]
		if rt.Domain == proj.Domain || strings.Contains(rt.Target, proj.Name) || rt.Domain == newDomain || rt.Domain == normalizedDomain {
			rt.Domain = normalizedDomain
			rt.SSL = enableSSL
			if enableSSL {
				rt.Protocol = "HTTP/2 + TLS 1.3"
				rt.CertExp = "Let's Encrypt (ACME)"
			} else {
				rt.Protocol = "HTTP Only"
				rt.CertExp = "Tắt SSL"
			}
			updatedRoute = true
			break
		}
	}
	if !updatedRoute && normalizedDomain != "" {
		proto := "HTTP Only"
		certExp := "Tắt SSL"
		if enableSSL {
			proto = "HTTP/2 + TLS 1.3"
			certExp = "Let's Encrypt (ACME)"
		}
		targetName := "dh-" + proj.Name
		if primaryContainer.Name != "" {
			targetName = primaryContainer.Name
		}
		e.proxyRoutes = append(e.proxyRoutes, ProxyRoute{
			ID:       fmt.Sprintf("rt-%d", e.seq.Add(1)),
			Domain:   normalizedDomain,
			Target:   targetName + ":80",
			PathRule: "/*",
			SSL:      enableSSL,
			CertExp:  certExp,
			Protocol: proto,
		})
	}
	e.mu.Unlock()

	if runtimeMode == "docker" {
		if enableSSL {
			triggerTraefikACMEWarmup(normalizedDomain)
		}
		e.SyncDockerEngine()
	}

	probe := ProbeDomainSSL(normalizedDomain)

	// Update route CertExp if Probe verified trusted Let's Encrypt cert
	if probe.TrustedLetEncrypt {
		e.mu.Lock()
		for i := range e.proxyRoutes {
			if e.proxyRoutes[i].Domain == normalizedDomain {
				e.proxyRoutes[i].CertExp = fmt.Sprintf("Let's Encrypt (%dd)", probe.DaysRemaining)
			}
		}
		e.mu.Unlock()
	}

	e.mu.RLock()
	if idx := e.findProjectIndexLocked(projectID); idx >= 0 {
		proj = cloneProject(e.projects[idx])
	}
	e.mu.RUnlock()

	return proj, probe, nil
}

func recreateContainerWithSSL(
	client *http.Client,
	baseURL string,
	inspect dockerContainerInspect,
	proj Project,
	newDomain string,
	enableSSL, forceHTTPS bool,
	cfBaseDomain string,
	useCFDNS01 bool,
) error {
	cname := strings.TrimPrefix(inspect.Name, "/")
	if cname == "" {
		return errors.New("container name is empty")
	}
	appName := sanitizeSlug(proj.Name)
	if appName == "" {
		appName = strings.TrimPrefix(cname, "dh-")
	}

	containerPort := "80"
	for pKey := range inspect.Config.ExposedPorts {
		if num, _, ok := strings.Cut(pKey, "/"); ok && num != "" {
			containerPort = num
			break
		}
	}

	hostPort := 4201
	if hp, err := strconv.Atoi(strings.TrimSpace(inspect.Config.Labels["deploymenthub.host_port"])); err == nil && hp > 0 {
		hostPort = hp
	} else {
		for _, bindings := range inspect.HostConfig.PortBindings {
			if len(bindings) > 0 {
				if hp, err := strconv.Atoi(bindings[0]["HostPort"]); err == nil && hp > 0 {
					hostPort = hp
					break
				}
			}
		}
	}

	newLabels := buildContainerTraefikLabels(
		appName,
		proj.Repo,
		proj.Branch,
		proj.Commit,
		newDomain,
		containerPort,
		hostPort,
		enableSSL,
		forceHTTPS,
		cfBaseDomain,
		useCFDNS01,
	)

	// Preserve non-traefik custom labels if any
	for k, v := range inspect.Config.Labels {
		lk := strings.ToLower(k)
		if !strings.HasPrefix(lk, "traefik.") && !strings.HasPrefix(lk, "deploymenthub.") {
			if _, exists := newLabels[k]; !exists {
				newLabels[k] = v
			}
		}
	}

	imageName := inspect.Config.Image
	if imageName == "" {
		imageName = inspect.Image
	}
	netMode := inspect.HostConfig.NetworkMode
	if netMode == "" {
		netMode = "deploymenthub_proxy"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	removeExistingDockerContainer(ctx, client, baseURL, cname)

	createPayload := map[string]any{
		"Image":        imageName,
		"Env":          inspect.Config.Env,
		"Labels":       newLabels,
		"ExposedPorts": inspect.Config.ExposedPorts,
		"HostConfig": map[string]any{
			"PortBindings":  inspect.HostConfig.PortBindings,
			"RestartPolicy": map[string]any{"Name": "unless-stopped"},
			"NetworkMode":   netMode,
		},
	}

	bodyBytes, _ := json.Marshal(createPayload)
	createReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/containers/create?name="+url.QueryEscape(cname), bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := client.Do(createReq)
	if err != nil {
		return fmt.Errorf("create container: %w", err)
	}
	var createRes struct {
		ID      string `json:"Id"`
		Message string `json:"message"`
	}
	_ = json.NewDecoder(createResp.Body).Decode(&createRes)
	_ = createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated && createResp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker create %s failed (HTTP %d): %s", cname, createResp.StatusCode, createRes.Message)
	}

	startReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/containers/"+url.PathEscape(createRes.ID)+"/start", nil)
	startResp, err := client.Do(startReq)
	if err != nil {
		return fmt.Errorf("start container: %w", err)
	}
	defer startResp.Body.Close()
	if startResp.StatusCode != http.StatusNoContent && startResp.StatusCode != http.StatusOK && startResp.StatusCode != http.StatusNotModified {
		errBody, _ := io.ReadAll(io.LimitReader(startResp.Body, 4096))
		return fmt.Errorf("docker start %s failed (HTTP %d): %s", cname, startResp.StatusCode, strings.TrimSpace(string(errBody)))
	}
	return nil
}
