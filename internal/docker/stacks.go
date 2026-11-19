package docker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

var stackNameRegexp = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,48}$`)

// ComposeStack summarizes a managed or live Docker Compose stack.
type ComposeStack struct {
	Name          string   `json:"name"`
	Status        string   `json:"status"`
	Services      int      `json:"services"`
	Running       int      `json:"running"`
	Managed       bool     `json:"managed"`
	Protected     bool     `json:"protected"`
	HasEnv        bool     `json:"hasEnv"`
	ContainerIDs  []string `json:"containerIds"`
	ContainerList []string `json:"containers"`
	UpdatedAt     string   `json:"updatedAt"`
}

// StackEnvEntry represents one masked environment variable stored inside env.enc.
type StackEnvEntry struct {
	Key      string `json:"key"`
	HasValue bool   `json:"hasValue"`
	Preview  string `json:"preview"`
}

// ComposeStackDetail includes compose YAML content and masked env metadata for editing.
type ComposeStackDetail struct {
	ComposeStack
	ComposeYAML string          `json:"composeYaml"`
	EnvEntries  []StackEnvEntry `json:"envEntries"`
}

// StackActionResult captures real docker compose command stdout/stderr output.
type StackActionResult struct {
	Stack   string `json:"stack"`
	Action  string `json:"action"`
	Output  string `json:"output"`
	Success bool   `json:"success"`
}

// ServiceTemplate describes a 1-click self-hostable DB/infrastructure Compose stack.
type ServiceTemplate struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	DefaultName string `json:"defaultName"`
	Ports       string `json:"ports"`
	ComposeYAML string `json:"composeYaml"`
	EnvText     string `json:"envText"`
}

func isProtectedStackName(name string) bool {
	clean := strings.ToLower(strings.TrimSpace(name))
	return clean == "deployment-hub" || clean == "deploymenthub"
}

func validateStackName(raw string) (string, error) {
	clean := strings.ToLower(strings.TrimSpace(raw))
	if !stackNameRegexp.MatchString(clean) {
		return "", errors.New("stack name must match ^[a-z0-9][a-z0-9_-]{0,48}$")
	}
	return clean, nil
}

func resolveStacksDir() string {
	if custom := strings.TrimSpace(os.Getenv("STACKS_DIR")); custom != "" {
		if err := os.MkdirAll(custom, 0o750); err == nil {
			return custom
		}
	}
	const defaultDir = "/data/stacks"
	if err := os.MkdirAll(defaultDir, 0o750); err == nil {
		return defaultDir
	}
	fallback := filepath.Join(os.TempDir(), "deploymenthub-stacks")
	_ = os.MkdirAll(fallback, 0o750)
	return fallback
}

func randomStackPassword(nBytes int) string {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "dh_s3cure_" + shortHex(8)
	}
	return hex.EncodeToString(buf)
}

func parseEnvEntries(envText string) []StackEnvEntry {
	lines := strings.Split(envText, "\n")
	out := make([]StackEnvEntry, 0, len(lines))
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		val := strings.TrimSpace(v)
		preview := "(empty)"
		if val != "" {
			preview = "••••••••"
		}
		out = append(out, StackEnvEntry{
			Key:      key,
			HasValue: val != "",
			Preview:  preview,
		})
	}
	return out
}

func (e *Engine) mergeStackEnv(stackDir, incomingEnv string) (string, error) {
	encPath := filepath.Join(stackDir, "env.enc")
	existingPlain := ""
	if rawEnc, err := os.ReadFile(encPath); err == nil && len(bytes.TrimSpace(rawEnc)) > 0 {
		if dec, decErr := e.vault.Decrypt(strings.TrimSpace(string(rawEnc))); decErr == nil {
			existingPlain = dec
		}
	}
	if strings.TrimSpace(incomingEnv) == "" {
		return existingPlain, nil
	}

	// Preserve existing secret when caller sends "KEY=••••••••" or "KEY=__KEEP__".
	existingMap := make(map[string]string)
	for _, line := range strings.Split(existingPlain, "\n") {
		tr := strings.TrimSpace(line)
		if tr == "" || strings.HasPrefix(tr, "#") {
			continue
		}
		if k, v, ok := strings.Cut(tr, "="); ok {
			existingMap[strings.TrimSpace(k)] = v
		}
	}

	var mergedLines []string
	for _, raw := range strings.Split(incomingEnv, "\n") {
		tr := strings.TrimSpace(raw)
		if tr == "" {
			continue
		}
		if strings.HasPrefix(tr, "#") {
			mergedLines = append(mergedLines, tr)
			continue
		}
		k, v, ok := strings.Cut(tr, "=")
		if !ok {
			continue
		}
		key := strings.TrimSpace(k)
		val := strings.TrimSpace(v)
		if (val == "••••••••" || val == "__KEEP__" || val == "***") && existingMap[key] != "" {
			val = existingMap[key]
		}
		mergedLines = append(mergedLines, key+"="+val)
	}
	return strings.Join(mergedLines, "\n"), nil
}

// ListStacks combines managed /data/stacks/* directories with live container compose project labels.
func (e *Engine) ListStacks() ([]ComposeStack, error) {
	stacksMap := make(map[string]*ComposeStack)
	stacksDir := resolveStacksDir()

	if entries, err := os.ReadDir(stacksDir); err == nil {
		for _, ent := range entries {
			if !ent.IsDir() {
				continue
			}
			name := ent.Name()
			sdir := filepath.Join(stacksDir, name)
			composePath := filepath.Join(sdir, "docker-compose.yml")
			info, statErr := os.Stat(composePath)
			if statErr != nil {
				continue
			}
			_, hasEnvErr := os.Stat(filepath.Join(sdir, "env.enc"))
			stacksMap[name] = &ComposeStack{
				Name:          name,
				Status:        "Stopped",
				Managed:       true,
				Protected:     isProtectedStackName(name),
				HasEnv:        hasEnvErr == nil,
				ContainerIDs:  []string{},
				ContainerList: []string{},
				UpdatedAt:     info.ModTime().UTC().Format(time.RFC3339),
			}
		}
	}

	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	localContainers := slices.Clone(e.containers)
	e.mu.RUnlock()

	usedDockerAPI := false
	if runtimeMode == "docker" && strings.TrimSpace(endpoint) != "" {
		if client, baseURL, ok := newDockerHTTPClient(endpoint, 5*time.Second); ok {
			if apiContainers, ok := fetchDockerJSON[[]dockerAPIContainer](client, baseURL+"/containers/json?all=1"); ok {
				usedDockerAPI = true
				for _, dc := range apiContainers {
					proj := strings.TrimSpace(dc.Labels["com.docker.compose.project"])
					if proj == "" {
						continue
					}
					cid := shortDockerID(dc.Id)
					cname := cid
					if len(dc.Names) > 0 {
						if tr := strings.TrimPrefix(strings.TrimSpace(dc.Names[0]), "/"); tr != "" {
							cname = tr
						}
					}
					st, ok := stacksMap[proj]
					if !ok {
						st = &ComposeStack{
							Name:          proj,
							Status:        "Stopped",
							Managed:       false,
							Protected:     isProtectedStackName(proj),
							ContainerIDs:  []string{},
							ContainerList: []string{},
						}
						stacksMap[proj] = st
					}
					st.Services++
					if strings.EqualFold(dc.State, "running") {
						st.Running++
					}
					st.ContainerIDs = append(st.ContainerIDs, cid)
					st.ContainerList = append(st.ContainerList, cname)
				}
			}
		}
	}

	if !usedDockerAPI {
		for _, c := range localContainers {
			if c.Project == "" {
				continue
			}
			st, ok := stacksMap[c.Project]
			if !ok {
				st = &ComposeStack{
					Name:          c.Project,
					Status:        "Stopped",
					Managed:       false,
					Protected:     isProtectedStackName(c.Project),
					ContainerIDs:  []string{},
					ContainerList: []string{},
				}
				stacksMap[c.Project] = st
			}
			st.Services++
			if c.Status == "Running" {
				st.Running++
			}
			st.ContainerIDs = append(st.ContainerIDs, c.ID)
			st.ContainerList = append(st.ContainerList, c.Name)
		}
	}

	out := make([]ComposeStack, 0, len(stacksMap))
	for _, st := range stacksMap {
		if st.Services > 0 && st.Running == st.Services {
			st.Status = "Running"
		} else if st.Running > 0 {
			st.Status = fmt.Sprintf("Partial (%d/%d)", st.Running, st.Services)
		} else {
			st.Status = "Stopped"
		}
		out = append(out, *st)
	}
	slices.SortFunc(out, func(a, b ComposeStack) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out, nil
}

// GetStackDetail returns the saved compose YAML, masked env keys, and live status for a stack.
func (e *Engine) GetStackDetail(rawName string) (ComposeStackDetail, error) {
	name, err := validateStackName(rawName)
	if err != nil {
		return ComposeStackDetail{}, err
	}
	stacks, err := e.ListStacks()
	if err != nil {
		return ComposeStackDetail{}, err
	}
	var summary *ComposeStack
	for i := range stacks {
		if stacks[i].Name == name {
			cp := stacks[i]
			summary = &cp
			break
		}
	}
	if summary == nil {
		return ComposeStackDetail{}, fmt.Errorf("stack %q not found", name)
	}

	detail := ComposeStackDetail{
		ComposeStack: *summary,
		EnvEntries:   []StackEnvEntry{},
	}
	sdir := filepath.Join(resolveStacksDir(), name)
	if rawYAML, err := os.ReadFile(filepath.Join(sdir, "docker-compose.yml")); err == nil {
		detail.ComposeYAML = string(rawYAML)
	}
	if rawEnc, err := os.ReadFile(filepath.Join(sdir, "env.enc")); err == nil && len(bytes.TrimSpace(rawEnc)) > 0 {
		if dec, decErr := e.vault.Decrypt(strings.TrimSpace(string(rawEnc))); decErr == nil {
			detail.EnvEntries = parseEnvEntries(dec)
		}
	}
	return detail, nil
}

// DeployStack writes compose YAML & vault-encrypted env.enc, then executes `docker compose up -d`.
func (e *Engine) DeployStack(ctx context.Context, rawName, composeYAML, envText string) (StackActionResult, error) {
	name, err := validateStackName(rawName)
	if err != nil {
		return StackActionResult{}, err
	}
	if isProtectedStackName(name) {
		return StackActionResult{}, fmt.Errorf("%w: system stack %q cannot be modified", ErrProtectedContainer, name)
	}
	if strings.TrimSpace(composeYAML) == "" {
		return StackActionResult{}, errors.New("composeYaml is required")
	}

	e.stacksMu.Lock()
	defer e.stacksMu.Unlock()

	sdir := filepath.Join(resolveStacksDir(), name)
	if err := os.MkdirAll(sdir, 0o750); err != nil {
		return StackActionResult{}, fmt.Errorf("create stack directory: %w", err)
	}

	composePath := filepath.Join(sdir, "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte(composeYAML), 0o600); err != nil {
		return StackActionResult{}, fmt.Errorf("write docker-compose.yml: %w", err)
	}

	mergedEnv, err := e.mergeStackEnv(sdir, envText)
	if err != nil {
		return StackActionResult{}, err
	}
	encPath := filepath.Join(sdir, "env.enc")
	if strings.TrimSpace(mergedEnv) != "" {
		sealed, err := e.vault.Encrypt(mergedEnv)
		if err != nil {
			return StackActionResult{}, fmt.Errorf("encrypt stack env: %w", err)
		}
		if err := os.WriteFile(encPath, []byte(sealed), 0o600); err != nil {
			return StackActionResult{}, fmt.Errorf("write env.enc: %w", err)
		}
	}

	out, runErr := e.runDockerComposeCmd(ctx, sdir, name, mergedEnv, "up", "-d", "--remove-orphans")
	e.SyncDockerEngine()
	if runErr != nil {
		return StackActionResult{Stack: name, Action: "up", Output: out, Success: false}, runErr
	}
	return StackActionResult{Stack: name, Action: "up", Output: out, Success: true}, nil
}

// StackAction runs lifecycle commands (up, start, stop, restart, pull, down, logs) on a Compose stack.
func (e *Engine) StackAction(ctx context.Context, rawName, action string) (StackActionResult, error) {
	name, err := validateStackName(rawName)
	if err != nil {
		return StackActionResult{}, err
	}
	act := strings.ToLower(strings.TrimSpace(action))
	switch act {
	case "up", "start", "stop", "restart", "pull", "down", "logs":
	default:
		return StackActionResult{}, fmt.Errorf("unsupported stack action %q", action)
	}

	if isProtectedStackName(name) && act != "logs" {
		return StackActionResult{}, fmt.Errorf("%w: system stack %q cannot execute %q", ErrProtectedContainer, name, act)
	}

	e.stacksMu.Lock()
	defer e.stacksMu.Unlock()

	sdir := filepath.Join(resolveStacksDir(), name)
	composePath := filepath.Join(sdir, "docker-compose.yml")
	if _, statErr := os.Stat(composePath); statErr != nil {
		// Unmanaged compose stack discovered solely via container labels: use container API actions cleanly.
		if act == "start" || act == "stop" || act == "restart" {
			return e.runUnmanagedStackContainerAction(name, act)
		}
		return StackActionResult{}, fmt.Errorf("managed stack compose file for %q not found", name)
	}

	envPlain := ""
	if rawEnc, err := os.ReadFile(filepath.Join(sdir, "env.enc")); err == nil && len(bytes.TrimSpace(rawEnc)) > 0 {
		if dec, decErr := e.vault.Decrypt(strings.TrimSpace(string(rawEnc))); decErr == nil {
			envPlain = dec
		}
	}

	var args []string
	switch act {
	case "up":
		args = []string{"up", "-d", "--remove-orphans"}
	case "logs":
		args = []string{"logs", "--no-color", "--tail=120"}
	default:
		args = []string{act}
	}

	out, runErr := e.runDockerComposeCmd(ctx, sdir, name, envPlain, args...)
	if act != "logs" {
		e.SyncDockerEngine()
	}
	if runErr != nil {
		return StackActionResult{Stack: name, Action: act, Output: out, Success: false}, runErr
	}
	return StackActionResult{Stack: name, Action: act, Output: out, Success: true}, nil
}

// DeleteStack runs `docker compose down` and deletes the managed stack directory.
func (e *Engine) DeleteStack(ctx context.Context, rawName string, removeVolumes bool) (StackActionResult, error) {
	name, err := validateStackName(rawName)
	if err != nil {
		return StackActionResult{}, err
	}
	if isProtectedStackName(name) {
		return StackActionResult{}, fmt.Errorf("%w: system stack %q cannot be deleted", ErrProtectedContainer, name)
	}

	e.stacksMu.Lock()
	defer e.stacksMu.Unlock()

	sdir := filepath.Join(resolveStacksDir(), name)
	composePath := filepath.Join(sdir, "docker-compose.yml")
	out := ""
	if _, statErr := os.Stat(composePath); statErr == nil {
		args := []string{"down", "--remove-orphans"}
		if removeVolumes {
			args = append(args, "--volumes")
		}
		envPlain := ""
		if rawEnc, err := os.ReadFile(filepath.Join(sdir, "env.enc")); err == nil && len(bytes.TrimSpace(rawEnc)) > 0 {
			if dec, decErr := e.vault.Decrypt(strings.TrimSpace(string(rawEnc))); decErr == nil {
				envPlain = dec
			}
		}
		var runErr error
		out, runErr = e.runDockerComposeCmd(ctx, sdir, name, envPlain, args...)
		if runErr != nil {
			return StackActionResult{Stack: name, Action: "delete", Output: out, Success: false}, runErr
		}
	}
	_ = os.RemoveAll(sdir)
	e.SyncDockerEngine()
	return StackActionResult{Stack: name, Action: "delete", Output: out, Success: true}, nil
}

func (e *Engine) runUnmanagedStackContainerAction(stackName, action string) (StackActionResult, error) {
	e.mu.RLock()
	endpoint := e.vps.SocketEndpoint
	var ids []string
	for _, c := range e.containers {
		if strings.EqualFold(c.Project, stackName) && !c.Protected {
			ids = append(ids, c.ID)
		}
	}
	e.mu.RUnlock()

	if len(ids) == 0 {
		return StackActionResult{}, fmt.Errorf("no containers found for stack %q", stackName)
	}
	for _, cid := range ids {
		if _, err := e.ContainerAction(cid, action, ""); err != nil {
			return StackActionResult{Stack: stackName, Action: action}, err
		}
	}
	_ = endpoint
	return StackActionResult{
		Stack:   stackName,
		Action:  action,
		Output:  fmt.Sprintf("Executed %s on %d container(s) in %s", action, len(ids), stackName),
		Success: true,
	}, nil
}

func (e *Engine) runDockerComposeCmd(ctx context.Context, stackDir, projectName, envPlain string, composeArgs ...string) (string, error) {
	e.mu.RLock()
	runtimeMode := e.vps.RuntimeMode
	endpoint := e.vps.SocketEndpoint
	e.mu.RUnlock()

	if runtimeMode != "docker" || strings.TrimSpace(endpoint) == "" {
		return fmt.Sprintf("[simulator] docker compose -p %s %s", projectName, strings.Join(composeArgs, " ")), nil
	}

	args := []string{"compose", "-p", projectName, "-f", filepath.Join(stackDir, "docker-compose.yml")}
	if strings.TrimSpace(envPlain) != "" {
		tmpEnv, err := os.CreateTemp("", "dh-compose-env-*")
		if err != nil {
			return "", fmt.Errorf("create temp env file: %w", err)
		}
		tmpEnvPath := tmpEnv.Name()
		_, writeErr := tmpEnv.WriteString(envPlain + "\n")
		_ = tmpEnv.Chmod(0o600)
		_ = tmpEnv.Close()
		defer os.Remove(tmpEnvPath)
		if writeErr != nil {
			return "", writeErr
		}
		args = append(args, "--env-file", tmpEnvPath)
	}
	args = append(args, composeArgs...)

	if ctx == nil {
		ctx = context.Background()
	}
	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// Support mock/override DOCKER_COMPOSE_BIN in tests while defaulting to real `docker`.
	bin := "docker"
	if custom := strings.TrimSpace(os.Getenv("DOCKER_COMPOSE_BIN")); custom != "" {
		bin = custom
	}

	cmd := exec.CommandContext(cmdCtx, bin, args...)
	cmd.Dir = stackDir
	cmd.Env = append(os.Environ(),
		"DOCKER_HOST="+endpoint,
		"DOCKER_CONFIG=/tmp/.docker",
		"COMPOSE_PROJECT_NAME="+projectName,
	)
	outBytes, err := cmd.CombinedOutput()
	out := string(outBytes)
	if err != nil {
		return out, fmt.Errorf("docker %s failed: %w\n%s", strings.Join(composeArgs, " "), err, strings.TrimSpace(out))
	}
	return out, nil
}

// GetServiceTemplates returns ready-to-deploy 1-Click DB & Infrastructure templates
// with unique CSPRNG passwords generated per invocation.
func (e *Engine) GetServiceTemplates() []ServiceTemplate {
	pgPass := randomStackPassword(12)
	mysqlRoot := randomStackPassword(12)
	mysqlPass := randomStackPassword(12)
	redisPass := randomStackPassword(12)
	mongoPass := randomStackPassword(12)
	minioPass := randomStackPassword(12)
	natsToken := randomStackPassword(12)

	return []ServiceTemplate{
		{
			Key:         "postgres16",
			Name:        "PostgreSQL 16 Alpine",
			Category:    "Database",
			Description: "Relational DB tối ưu bộ nhớ kèm Healthcheck & Volume bền vững.",
			DefaultName: "postgres-db",
			Ports:       "5432/tcp (internal / localhost)",
			ComposeYAML: `services:
  postgres:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-appuser}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB:-appdb}
    ports:
      - "127.0.0.1:5432:5432"
    volumes:
      - pg_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-appuser}"]
      interval: 10s
      timeout: 5s
      retries: 5
volumes:
  pg_data:
`,
			EnvText: fmt.Sprintf("POSTGRES_USER=appuser\nPOSTGRES_PASSWORD=%s\nPOSTGRES_DB=appdb\n", pgPass),
		},
		{
			Key:         "redis7",
			Name:        "Redis 7 Alpine",
			Category:    "Cache / Queue",
			Description: "In-memory Cache & Pub/Sub kèm AOF persistence + RequirePass bảo mật.",
			DefaultName: "redis-cache",
			Ports:       "6379/tcp (localhost)",
			ComposeYAML: `services:
  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: ["sh", "-c", "redis-server --appendonly yes --requirepass \"$$REDIS_PASSWORD\""]
    environment:
      REDIS_PASSWORD: ${REDIS_PASSWORD}
    ports:
      - "127.0.0.1:6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5
volumes:
  redis_data:
`,
			EnvText: fmt.Sprintf("REDIS_PASSWORD=%s\n", redisPass),
		},
		{
			Key:         "mysql8",
			Name:        "MySQL 8.4 LTS",
			Category:    "Database",
			Description: "MySQL server production với UTF8MB4 mặc định & persistent volume.",
			DefaultName: "mysql-db",
			Ports:       "3306/tcp (localhost)",
			ComposeYAML: `services:
  mysql:
    image: mysql:8.4
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}
      MYSQL_DATABASE: ${MYSQL_DATABASE:-appdb}
      MYSQL_USER: ${MYSQL_USER:-appuser}
      MYSQL_PASSWORD: ${MYSQL_PASSWORD}
    ports:
      - "127.0.0.1:3306:3306"
    volumes:
      - mysql_data:/var/lib/mysql
volumes:
  mysql_data:
`,
			EnvText: fmt.Sprintf("MYSQL_ROOT_PASSWORD=%s\nMYSQL_DATABASE=appdb\nMYSQL_USER=appuser\nMYSQL_PASSWORD=%s\n", mysqlRoot, mysqlPass),
		},
		{
			Key:         "mongodb7",
			Name:        "MongoDB 7",
			Category:    "NoSQL",
			Description: "Document database với root auth & wiredTiger persistent storage.",
			DefaultName: "mongo-db",
			Ports:       "27017/tcp (localhost)",
			ComposeYAML: `services:
  mongodb:
    image: mongo:7
    restart: unless-stopped
    environment:
      MONGO_INITDB_ROOT_USERNAME: ${MONGO_USER:-root}
      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_PASSWORD}
    ports:
      - "127.0.0.1:27017:27017"
    volumes:
      - mongo_data:/data/db
volumes:
  mongo_data:
`,
			EnvText: fmt.Sprintf("MONGO_USER=root\nMONGO_PASSWORD=%s\n", mongoPass),
		},
		{
			Key:         "minio",
			Name:        "MinIO S3 Storage",
			Category:    "Object Storage",
			Description: "Self-hosted S3 compatible Object Storage + Web Console quản trị file.",
			DefaultName: "minio-s3",
			Ports:       "9000 (API) / 9001 (Console)",
			ComposeYAML: `services:
  minio:
    image: minio/minio:latest
    restart: unless-stopped
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: ${MINIO_ROOT_USER:-minioadmin}
      MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD}
    ports:
      - "127.0.0.1:9000:9000"
      - "127.0.0.1:9001:9001"
    volumes:
      - minio_data:/data
volumes:
  minio_data:
`,
			EnvText: fmt.Sprintf("MINIO_ROOT_USER=minioadmin\nMINIO_ROOT_PASSWORD=%s\n", minioPass),
		},
		{
			Key:         "nats",
			Name:        "NATS JetStream",
			Category:    "Messaging",
			Description: "Ultra-fast NATS JetStream broker kèm monitoring HTTP :8222 & auth token.",
			DefaultName: "nats-jetstream",
			Ports:       "4222 / 8222",
			ComposeYAML: `services:
  nats:
    image: nats:2.10-alpine
    restart: unless-stopped
    command: ["-js", "-sd", "/data", "-m", "8222", "--auth", "${NATS_TOKEN}"]
    ports:
      - "127.0.0.1:4222:4222"
      - "127.0.0.1:8222:8222"
    volumes:
      - nats_data:/data
volumes:
  nats_data:
`,
			EnvText: fmt.Sprintf("NATS_TOKEN=%s\n", natsToken),
		},
	}
}
