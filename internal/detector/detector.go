// Package detector implements two-tier polyglot stack detection,
// production Dockerfile / docker-compose generation, metadata-only LLM prompt
// construction, and build failure diagnostics.
package detector

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// EnvVar represents an environment variable detected or configured for a deployment.
type EnvVar struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Secret bool   `json:"secret"`
}

// DetectRequest defines the inputs for Tier 1 (file/manifest) and Tier 2 (hybrid AI) detection.
type DetectRequest struct {
	RepoURL     string   `json:"repoUrl"`
	Branch      string   `json:"branch"`
	Mode        string   `json:"mode"`
	Token       string   `json:"token,omitempty"`
	Files       []string `json:"files,omitempty"`
	PackageJSON string   `json:"packageJson,omitempty"`
	EnvExample  string   `json:"envExample,omitempty"`
	LocalDir    string   `json:"localDir,omitempty"`
}

// DetectResult captures detected stack metadata, commands, native dependencies, and generated config.
type DetectResult struct {
	PresetKey      string   `json:"presetKey"`
	StackLabel     string   `json:"stackLabel"`
	Confidence     int      `json:"confidence"`
	ScanDurationMs int      `json:"scanDurationMs"`
	Mode           string   `json:"mode"`
	DetectedFiles  []string `json:"detectedFiles"`
	Strategy       string   `json:"strategy"`
	Insight        string   `json:"insight"`
	NativeDeps     []string `json:"nativeDeps"`
	BuildCmd       string   `json:"buildCmd"`
	StartCmd       string   `json:"startCmd"`
	PortMapping    string   `json:"portMapping"`
	Filename       string   `json:"filename"`
	Footprint      string   `json:"footprint"`
	EnvVars        []EnvVar `json:"envVars"`
	Dockerfile     string   `json:"dockerfile"`
}

// DockerfileRequest defines inputs for generating a multi-stage Dockerfile or docker-compose.yml.
type DockerfileRequest struct {
	PresetKey   string   `json:"presetKey"`
	Mode        string   `json:"mode"`
	AppName     string   `json:"appName"`
	Domain      string   `json:"domain"`
	BuildCmd    string   `json:"buildCmd"`
	StartCmd    string   `json:"startCmd"`
	PortMapping string   `json:"portMapping"`
	NativeDeps  []string `json:"nativeDeps,omitempty"`
	EnvVars     []EnvVar `json:"envVars,omitempty"`
}

// BuildDoctorResult describes a root cause diagnosis and fix diff for failed builds.
type BuildDoctorResult struct {
	RootCause   string `json:"rootCause"`
	Suggestion  string `json:"suggestion"`
	DiffPreview string `json:"diffPreview"`
}

type presetTemplate struct {
	Key         string
	Label       string
	Strategy    string
	BuildCmd    string
	StartCmd    string
	PortMapping string
	Filename    string
	Footprint   string
	EnvVars     []EnvVar
	DefaultDeps []string
	MarkerFiles []string
	FileInsight string
}

var presetCatalog = map[string]presetTemplate{
	"nextjs": {
		Key:         "nextjs",
		Label:       "Next.js",
		Strategy:    "Auto-detected package.json (next 15.x) -> Multi-stage Node 20 Alpine with output: 'standalone'",
		BuildCmd:    "npm ci && npm run build",
		StartCmd:    "node .next/standalone/server.js",
		PortMapping: "3000 -> 443 (HTTPS)",
		Filename:    "Dockerfile",
		Footprint:   "~145 MB",
		EnvVars: []EnvVar{
			{Key: "NODE_ENV", Value: "production", Secret: false},
			{Key: "PORT", Value: "3000", Secret: false},
			{Key: "NEXT_PUBLIC_API_URL", Value: "/api", Secret: false},
			{Key: "AUTH_SECRET", Value: "", Secret: true},
		},
		DefaultDeps: []string{"openssl", "libc6-compat"},
		MarkerFiles: []string{"package.json (next 15)", "pnpm-lock.yaml", "next.config.mjs", "prisma/schema.prisma", ".env.example"},
		FileInsight: "Rule-based: Matched package.json + next.config -> Next.js Standalone (~145 MB).",
	},
	"spa": {
		Key:         "spa",
		Label:       "React / Angular",
		Strategy:    "Auto-detected Vite / Angular CLI -> Multi-stage Node Build + Nginx Alpine Static (~24 MB)",
		BuildCmd:    "npm ci && npm run build",
		StartCmd:    `nginx -g "daemon off;"`,
		PortMapping: "80 -> 443 (HTTPS)",
		Filename:    "Dockerfile",
		Footprint:   "~24 MB",
		EnvVars: []EnvVar{
			{Key: "NODE_ENV", Value: "production", Secret: false},
			{Key: "VITE_API_BASE", Value: "/api/v1", Secret: false},
			{Key: "NGINX_SPA_FALLBACK", Value: "try_files $uri /index.html", Secret: false},
		},
		DefaultDeps: []string{"brotli"},
		MarkerFiles: []string{"package.json", "vite.config.ts", "package-lock.json", ".env.example"},
		FileInsight: "Rule-based: Matched package.json + SPA config -> Nginx Static Runner (~24 MB).",
	},
	"go": {
		Key:         "go",
		Label:       "Go API",
		Strategy:    "Auto-detected go.mod -> Static CGO_ENABLED=0 Binary + Distroless (~18 MB)",
		BuildCmd:    `CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/server ./cmd/api`,
		StartCmd:    "/server",
		PortMapping: "8080 -> 443 (HTTPS)",
		Filename:    "Dockerfile",
		Footprint:   "~18 MB",
		EnvVars: []EnvVar{
			{Key: "GO_ENV", Value: "production", Secret: false},
			{Key: "PORT", Value: "8080", Secret: false},
			{Key: "DATABASE_URL", Value: "", Secret: true},
			{Key: "JWT_SIGNING_KEY", Value: "", Secret: true},
		},
		DefaultDeps: []string{"ca-certificates"},
		MarkerFiles: []string{"go.mod", "go.sum", "cmd/api/main.go", ".env.example"},
		FileInsight: "Rule-based: Matched go.mod -> Go Static Binary + Distroless (~18 MB).",
	},
	"rust": {
		Key:         "rust",
		Label:       "Rust API",
		Strategy:    "Auto-detected Cargo.toml -> Cargo Release Build + Alpine Minimal (~22 MB)",
		BuildCmd:    "cargo build --release --locked",
		StartCmd:    "./target/release/api-engine",
		PortMapping: "9000 -> 443 (HTTPS / WSS)",
		Filename:    "Dockerfile",
		Footprint:   "~22 MB",
		EnvVars: []EnvVar{
			{Key: "RUST_LOG", Value: "info,actix_web=info", Secret: false},
			{Key: "BIND_ADDR", Value: "0.0.0.0:9000", Secret: false},
			{Key: "REDIS_URL", Value: "", Secret: true},
		},
		DefaultDeps: []string{"pkg-config", "musl-dev", "openssl-dev"},
		MarkerFiles: []string{"Cargo.toml", "Cargo.lock", "src/main.rs", ".env.example"},
		FileInsight: "Rule-based: Matched Cargo.toml -> Rust Release Binary + Alpine (~22 MB).",
	},
	"compose": {
		Key:         "compose",
		Label:       "FE+BE Compose",
		Strategy:    "Auto-detected /frontend + /backend -> Multi-service Docker Compose + Internal Network",
		BuildCmd:    "docker compose build --parallel",
		StartCmd:    "docker compose up -d --remove-orphans",
		PortMapping: "FE :80 + BE :8080 (/api/*) + DB :5432",
		Filename:    "docker-compose.yml",
		Footprint:   "3 Services",
		EnvVars: []EnvVar{
			{Key: "COMPOSE_PROJECT_NAME", Value: "fullstack-app", Secret: false},
			{Key: "POSTGRES_USER", Value: "app_admin", Secret: false},
			{Key: "POSTGRES_PASSWORD", Value: "", Secret: true},
			{Key: "API_INTERNAL_URL", Value: "http://backend:8080", Secret: false},
		},
		DefaultDeps: []string{},
		MarkerFiles: []string{"apps/web/package.json", "apps/api/go.mod", "docker-compose.yml", ".env.example"},
		FileInsight: "Rule-based: Matched monorepo FE+BE manifests -> Full-stack Compose (3 Services).",
	},
}

var portNumRegexp = regexp.MustCompile(`\d+`)

// Detect performs Tier 1 deterministic File & Manifest scanning and, when req.Mode == "hybrid",
// Tier 2 Smart Analyzer enrichment (native OS deps, .env.example sync, healthcheck & caching hints).
func Detect(req DetectRequest) DetectResult {
	start := time.Now()

	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode != "hybrid" {
		mode = "file"
	}

	scannedFiles := slices.Clone(req.Files)
	pkgJSON := req.PackageJSON
	envExample := req.EnvExample
	extraManifestText := ""

	fromRepoURLOnly := false

	if dir := strings.TrimSpace(req.LocalDir); dir != "" {
		dirFiles, dirPkg, dirEnv, dirManifests := scanLocalDirectory(dir)
		if len(dirFiles) > 0 {
			scannedFiles = dirFiles
		}
		if strings.TrimSpace(pkgJSON) == "" && dirPkg != "" {
			pkgJSON = dirPkg
		}
		if strings.TrimSpace(envExample) == "" && dirEnv != "" {
			envExample = dirEnv
		}
		extraManifestText = dirManifests
	} else if len(scannedFiles) == 0 && strings.TrimSpace(pkgJSON) == "" && strings.TrimSpace(req.RepoURL) != "" {
		if ghFiles, ghPkg, ghEnv, ghManifests, ok := scanRemoteGitHubRepo(req.RepoURL, req.Branch, req.Token); ok {
			scannedFiles = ghFiles
			if strings.TrimSpace(pkgJSON) == "" && ghPkg != "" {
				pkgJSON = ghPkg
			}
			if strings.TrimSpace(envExample) == "" && ghEnv != "" {
				envExample = ghEnv
			}
			extraManifestText = ghManifests
		}
	}

	presetKey := ""
	matchedByManifest := false

	if len(scannedFiles) > 0 || strings.TrimSpace(pkgJSON) != "" {
		presetKey, matchedByManifest = detectFromFilesAndManifest(scannedFiles, pkgJSON)
	}
	if presetKey == "" {
		presetKey = inferPresetFromRepoURL(req.RepoURL)
		if len(scannedFiles) == 0 && strings.TrimSpace(pkgJSON) == "" {
			fromRepoURLOnly = true
		}
	}

	tpl, ok := presetCatalog[presetKey]
	if !ok {
		tpl = presetCatalog["nextjs"]
	}

	detectedFiles := pickDetectedFiles(scannedFiles, pkgJSON, envExample, tpl, fromRepoURLOnly)

	buildCmd := tpl.BuildCmd
	startCmd := tpl.StartCmd
	if tpl.Key == "go" {
		if cmdEntry := findGoCmdEntrypoint(scannedFiles); cmdEntry != "" {
			buildCmd = fmt.Sprintf(`CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/server %s`, cmdEntry)
		} else if hasFileExact(scannedFiles, "main.go") && !hasPrefixFile(scannedFiles, "cmd/") {
			buildCmd = `CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/server .`
		}
	}
	if tpl.Key == "spa" && (hasFileBase(scannedFiles, "angular.json") || strings.Contains(strings.ToLower(pkgJSON), `"@angular/core"`)) {
		tpl.Label = "Angular SPA"
	}

	envVars := slices.Clone(tpl.EnvVars)
	nativeDeps := []string{}
	insight := tpl.FileInsight

	confidence := 94
	if fromRepoURLOnly || !matchedByManifest {
		confidence = 86
	}

	if mode == "hybrid" {
		if fromRepoURLOnly || !matchedByManifest {
			confidence = 92
		} else {
			confidence = 99
		}

		nativeDeps = detectNativeDeps(tpl.Key, scannedFiles, pkgJSON, extraManifestText, fromRepoURLOnly)

		var extractedKeys []string
		if strings.TrimSpace(envExample) != "" {
			parsedEnv := parseEnvExample(envExample)
			extractedKeys = make([]string, 0, len(parsedEnv))
			for _, ev := range parsedEnv {
				extractedKeys = append(extractedKeys, ev.Key)
			}
			envVars = mergeEnvVars(envVars, parsedEnv)
		}

		insight = buildHybridInsight(tpl.Key, nativeDeps, extractedKeys)
	}

	appName := deriveAppName(req.RepoURL, req.LocalDir, tpl.Key)
	domain := appName + ".localhost"

	dockerfile := GenerateDockerfile(DockerfileRequest{
		PresetKey:   tpl.Key,
		Mode:        mode,
		AppName:     appName,
		Domain:      domain,
		BuildCmd:    buildCmd,
		StartCmd:    startCmd,
		PortMapping: tpl.PortMapping,
		NativeDeps:  nativeDeps,
		EnvVars:     envVars,
	})

	durMs := int(time.Since(start).Milliseconds())
	if durMs < 1 {
		durMs = 1
	}

	return DetectResult{
		PresetKey:      tpl.Key,
		StackLabel:     tpl.Label,
		Confidence:     confidence,
		ScanDurationMs: durMs,
		Mode:           mode,
		DetectedFiles:  nonNilStrings(detectedFiles),
		Strategy:       tpl.Strategy,
		Insight:        insight,
		NativeDeps:     nonNilStrings(nativeDeps),
		BuildCmd:       buildCmd,
		StartCmd:       startCmd,
		PortMapping:    tpl.PortMapping,
		Filename:       tpl.Filename,
		Footprint:      tpl.Footprint,
		EnvVars:        nonNilEnvVars(envVars),
		Dockerfile:     dockerfile,
	}
}

// GenerateDockerfile creates a multi-stage production Dockerfile or docker-compose.yml
// with optional native OS dependencies and HEALTHCHECK instructions.
func GenerateDockerfile(req DockerfileRequest) string {
	presetKey := normalizePresetKey(req.PresetKey)
	tpl := presetCatalog[presetKey]

	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	modeTag := "File Heuristic Rule-based"
	if mode == "hybrid" {
		modeTag = "Hybrid File + AI Assist"
	}

	appName := sanitizeSlug(req.AppName)
	if appName == "" {
		appName = "deploymenthub-app"
	}
	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		domain = appName + ".localhost"
	}

	buildCmd := strings.TrimSpace(req.BuildCmd)
	if buildCmd == "" {
		buildCmd = tpl.BuildCmd
	}
	startCmd := strings.TrimSpace(req.StartCmd)
	if startCmd == "" {
		startCmd = tpl.StartCmd
	}
	portMapping := strings.TrimSpace(req.PortMapping)
	if portMapping == "" {
		portMapping = tpl.PortMapping
	}
	portNum := extractPrimaryPort(portMapping, defaultPortForPreset(presetKey))
	deps := uniqueNonEmpty(req.NativeDeps)

	envLines := formatDockerEnvLines(req.EnvVars)

	switch presetKey {
	case "nextjs":
		var b strings.Builder
		fmt.Fprintf(&b, "# Auto-generated by DeploymentHub (%s - Next.js Standalone)\n", modeTag)
		b.WriteString("FROM node:20-alpine AS builder\n")
		b.WriteString("WORKDIR /app\n")
		b.WriteString("COPY package*.json ./\n")
		b.WriteString("RUN npm ci\n")
		b.WriteString("COPY . .\n")
		fmt.Fprintf(&b, "RUN %s\n", buildCmd)
		b.WriteString("RUN mkdir -p /app/public\n\n")

		b.WriteString("FROM node:20-alpine AS runner\n")
		b.WriteString("WORKDIR /app\n")
		if len(deps) > 0 {
			fmt.Fprintf(&b, "# Native OS dependencies\nRUN apk add --no-cache %s\n", strings.Join(deps, " "))
		}
		if envLines != "" {
			b.WriteString(envLines + "\n")
		} else {
			b.WriteString("ENV NODE_ENV=\"production\"\n")
		}
		b.WriteString("COPY --from=builder /app/public ./public\n")
		b.WriteString("COPY --from=builder /app/.next/standalone ./\n")
		b.WriteString("COPY --from=builder /app/.next/static ./.next/static\n")
		fmt.Fprintf(&b, "EXPOSE %s\n", portNum)
		fmt.Fprintf(&b, "HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD wget -qO- http://127.0.0.1:%s/api/health || exit 1\n", portNum)
		b.WriteString(`CMD ["node", "server.js"]`)
		return b.String()

	case "spa":
		var b strings.Builder
		fmt.Fprintf(&b, "# Auto-generated by DeploymentHub (%s - SPA Static + Nginx)\n", modeTag)
		b.WriteString("FROM node:20-alpine AS builder\n")
		b.WriteString("WORKDIR /app\n")
		b.WriteString("COPY package*.json ./\n")
		b.WriteString("RUN npm ci\n")
		b.WriteString("COPY . .\n")
		fmt.Fprintf(&b, "RUN %s\n\n", buildCmd)

		b.WriteString("FROM nginx:1.27-alpine\n")
		if len(deps) > 0 {
			fmt.Fprintf(&b, "RUN apk add --no-cache %s\n", strings.Join(deps, " "))
		}
		if envLines != "" {
			b.WriteString(envLines + "\n")
		} else {
			b.WriteString("ENV NODE_ENV=\"production\"\n")
		}
		b.WriteString("COPY --from=builder /app/dist /usr/share/nginx/html\n")
		fmt.Fprintf(&b, "EXPOSE %s\n", portNum)
		fmt.Fprintf(&b, "HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD wget -qO- http://127.0.0.1:%s/ || exit 1\n", portNum)
		b.WriteString(`CMD ["nginx", "-g", "daemon off;"]`)
		return b.String()

	case "go":
		var b strings.Builder
		fmt.Fprintf(&b, "# Auto-generated by DeploymentHub (%s - Go Static Binary)\n", modeTag)
		b.WriteString("FROM golang:1.22-alpine AS builder\n")
		b.WriteString("WORKDIR /src\n")
		builderDeps := mergeUniqueStrings([]string{"ca-certificates"}, deps)
		fmt.Fprintf(&b, "RUN apk add --no-cache %s\n", strings.Join(builderDeps, " "))
		b.WriteString("COPY go.mod go.sum* ./\n")
		b.WriteString("RUN go mod download\n")
		b.WriteString("COPY . .\n")
		fmt.Fprintf(&b, "RUN %s\n\n", buildCmd)

		b.WriteString("FROM gcr.io/distroless/static-debian12\n")
		b.WriteString("COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/\n")
		if envLines != "" {
			b.WriteString(envLines + "\n")
		} else {
			fmt.Fprintf(&b, "ENV PORT=\"%s\"\n", portNum)
		}
		b.WriteString("COPY --from=builder /out/server /server\n")
		fmt.Fprintf(&b, "EXPOSE %s\n", portNum)
		b.WriteString(`HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["/server", "--health"]` + "\n")
		fmt.Fprintf(&b, `ENTRYPOINT ["%s"]`, startCmd)
		return b.String()

	case "rust":
		var b strings.Builder
		fmt.Fprintf(&b, "# Auto-generated by DeploymentHub (%s - Rust Release Binary)\n", modeTag)
		b.WriteString("FROM rust:1.80-alpine AS builder\n")
		b.WriteString("WORKDIR /app\n")
		builderDeps := deps
		if len(builderDeps) == 0 {
			builderDeps = []string{"musl-dev"}
		}
		fmt.Fprintf(&b, "RUN apk add --no-cache %s\n", strings.Join(builderDeps, " "))
		b.WriteString("COPY . .\n")
		fmt.Fprintf(&b, "RUN %s\n\n", buildCmd)

		b.WriteString("FROM alpine:3.20\n")
		runtimeDeps := []string{"ca-certificates"}
		if slices.Contains(deps, "openssl") || slices.Contains(deps, "openssl-dev") {
			runtimeDeps = append(runtimeDeps, "openssl")
		}
		fmt.Fprintf(&b, "RUN apk add --no-cache %s\n", strings.Join(runtimeDeps, " "))
		if envLines != "" {
			b.WriteString(envLines + "\n")
		} else {
			b.WriteString("ENV RUST_LOG=\"info\"\n")
		}
		b.WriteString("COPY --from=builder /app/target/release/api-engine /usr/local/bin/api-engine\n")
		fmt.Fprintf(&b, "EXPOSE %s\n", portNum)
		fmt.Fprintf(&b, "HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD wget -qO- http://127.0.0.1:%s/ready || exit 1\n", portNum)
		b.WriteString(`CMD ["api-engine"]`)
		return b.String()

	default: // compose
		var envBlock strings.Builder
		if len(req.EnvVars) == 0 {
			envBlock.WriteString("      - PORT=8080\n")
		} else {
			for _, ev := range req.EnvVars {
				k := strings.TrimSpace(ev.Key)
				if k == "" {
					continue
				}
				val := ev.Value
				if ev.Secret {
					val = "***"
				}
				fmt.Fprintf(&envBlock, "      - %s=%s\n", k, val)
			}
			if envBlock.Len() == 0 {
				envBlock.WriteString("      - PORT=8080\n")
			}
		}

		var b strings.Builder
		fmt.Fprintf(&b, "# Auto-generated by DeploymentHub (%s - Full-stack Compose)\n", modeTag)
		b.WriteString("services:\n")
		b.WriteString("  frontend:\n")
		b.WriteString("    build: ./apps/web\n")
		b.WriteString("    networks: [internal-net]\n")
		b.WriteString("    healthcheck:\n")
		b.WriteString(`      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:80/ || exit 1"]` + "\n")
		b.WriteString("      interval: 15s\n")
		fmt.Fprintf(&b, "    labels: [\"traefik.http.routers.%s-fe.rule=Host(`%s`)\"]\n\n", appName, domain)

		b.WriteString("  backend:\n")
		b.WriteString("    build: ./apps/api\n")
		b.WriteString("    depends_on:\n")
		b.WriteString("      postgres:\n")
		b.WriteString("        condition: service_healthy\n")
		b.WriteString("    environment:\n")
		b.WriteString(envBlock.String())
		b.WriteString("    networks: [internal-net]\n")
		b.WriteString("    healthcheck:\n")
		b.WriteString(`      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:8080/health || exit 1"]` + "\n")
		b.WriteString("      interval: 15s\n")
		fmt.Fprintf(&b, "    labels: [\"traefik.http.routers.%s-be.rule=Host(`%s`) && PathPrefix(`/api`)\"]\n\n", appName, domain)

		b.WriteString("  postgres:\n")
		b.WriteString("    image: postgres:16-alpine\n")
		b.WriteString("    volumes: [\"pg_data:/var/lib/postgresql/data\"]\n")
		b.WriteString("    healthcheck:\n")
		b.WriteString(`      test: ["CMD-SHELL", "pg_isready -U postgres"]` + "\n")
		b.WriteString("      interval: 5s\n")
		b.WriteString("    restart: unless-stopped\n")
		b.WriteString("    networks: [internal-net]\n\n")

		b.WriteString("networks:\n")
		b.WriteString("  internal-net:\n")
		b.WriteString("volumes:\n")
		b.WriteString("  pg_data:")
		return b.String()
	}
}

// BuildMetadataPrompt builds a <= 2KB metadata-only prompt suitable for LLM assist.
// It strictly excludes .ts, .tsx, .js, .go, .rs, and .py source files and caps tailLogs to the last 50 lines.
func BuildMetadataPrompt(tree []string, manifestName, manifestContent, envExample string, tailLogs []string) string {
	const maxBytes = 2048

	filteredTree := make([]string, 0, len(tree))
	for _, entry := range tree {
		clean := strings.TrimSpace(entry)
		if clean == "" || isExcludedSourceFile(clean) {
			continue
		}
		filteredTree = append(filteredTree, clean)
		if len(filteredTree) >= 35 {
			break
		}
	}

	if len(tailLogs) > 50 {
		tailLogs = tailLogs[len(tailLogs)-50:]
	}

	envKeys := make([]string, 0)
	for _, ev := range parseEnvExample(envExample) {
		envKeys = append(envKeys, ev.Key)
	}

	safeManifest := truncateUTF8(strings.TrimSpace(manifestContent), 650)
	treeSection := truncateUTF8(strings.Join(filteredTree, "\n"), 450)
	envSection := truncateUTF8(strings.Join(envKeys, ", "), 220)
	logsSection := truncateUTF8(strings.Join(tailLogs, "\n"), 550)

	assemble := func(m, t, e, l string) string {
		var b strings.Builder
		b.WriteString("DeploymentHub Metadata Prompt\n")
		if t != "" {
			b.WriteString("FILES:\n")
			b.WriteString(t)
			b.WriteString("\n")
		}
		if manifestName != "" || m != "" {
			fmt.Fprintf(&b, "MANIFEST (%s):\n%s\n", strings.TrimSpace(manifestName), m)
		}
		if e != "" {
			fmt.Fprintf(&b, "ENV_KEYS: %s\n", e)
		}
		if l != "" {
			b.WriteString("TAIL_LOGS:\n")
			b.WriteString(l)
		}
		return strings.TrimSpace(b.String())
	}

	prompt := assemble(safeManifest, treeSection, envSection, logsSection)
	if len(prompt) <= maxBytes {
		return prompt
	}

	// Tighten sections gracefully before falling back to hard UTF-8 byte cap.
	prompt = assemble(
		truncateUTF8(safeManifest, 400),
		truncateUTF8(treeSection, 300),
		truncateUTF8(envSection, 150),
		truncateUTF8(logsSection, 350),
	)
	if len(prompt) <= maxBytes {
		return prompt
	}
	return truncateUTF8(prompt, maxBytes)
}

// DiagnoseBuildFailure inspects build/runtime tail logs and returns a structured root cause,
// actionable fix suggestion, and unified diff preview.
func DiagnoseBuildFailure(tailLogs []string) BuildDoctorResult {
	joined := strings.ToLower(strings.Join(tailLogs, "\n"))

	switch {
	case isOOMFailure(joined):
		return BuildDoctorResult{
			RootCause:  "Build container killed by OOM Killer (Exit Code 137) due to memory exhaustion during bundling/compilation.",
			Suggestion: "Cap Node heap via NODE_OPTIONS=\"--max-old-space-size=1536\" or allocate >= 2GB RAM/swap for the build stage.",
			DiffPreview: strings.Join([]string{
				"--- a/Dockerfile",
				"+++ b/Dockerfile",
				"@@ -3,6 +3,7 @@",
				" WORKDIR /app",
				"+ENV NODE_OPTIONS=\"--max-old-space-size=1536\"",
				" COPY package*.json ./",
				" RUN npm ci",
			}, "\n"),
		}

	case strings.Contains(joined, "openssl") ||
		strings.Contains(joined, "libssl") ||
		strings.Contains(joined, "libc6-compat") ||
		strings.Contains(joined, "libcrypto") ||
		strings.Contains(joined, "error loading shared library") ||
		(strings.Contains(joined, "prisma") && (strings.Contains(joined, "error") || strings.Contains(joined, "failed") || strings.Contains(joined, "missing"))):
		return BuildDoctorResult{
			RootCause:  "Missing Alpine native shared libraries (openssl / libc6-compat) required by Prisma or native Node addons.",
			Suggestion: "Install openssl and libc6-compat in the Alpine runner/builder stage via apk add --no-cache.",
			DiffPreview: strings.Join([]string{
				"--- a/Dockerfile",
				"+++ b/Dockerfile",
				"@@ -8,6 +8,7 @@",
				" FROM node:20-alpine AS runner",
				" WORKDIR /app",
				"+RUN apk add --no-cache openssl libc6-compat",
				" COPY --from=builder /app/.next/standalone ./",
			}, "\n"),
		}

	case isAngularDistBrowserFailure(joined):
		return BuildDoctorResult{
			RootCause:  "Angular 17+ application builder outputs static files to dist/<app>/browser instead of dist/.",
			Suggestion: "Update the Dockerfile COPY instruction to copy from /app/dist/<app>/browser into /usr/share/nginx/html.",
			DiffPreview: strings.Join([]string{
				"--- a/Dockerfile",
				"+++ b/Dockerfile",
				"@@ -7,5 +7,5 @@",
				" FROM nginx:1.27-alpine",
				"-COPY --from=builder /app/dist /usr/share/nginx/html",
				"+COPY --from=builder /app/dist/<app>/browser /usr/share/nginx/html",
				" EXPOSE 80",
			}, "\n"),
		}

	case strings.Contains(joined, "cgo") ||
		strings.Contains(joined, "cgo_enabled") ||
		strings.Contains(joined, "cannot find -l") ||
		strings.Contains(joined, "libsqlite") ||
		strings.Contains(joined, `"gcc"`):
		return BuildDoctorResult{
			RootCause:  "Go CGO compilation failed because C toolchain (gcc/musl-dev) is absent or CGO binary is incompatible with distroless.",
			Suggestion: "Disable CGO with CGO_ENABLED=0 GOOS=linux for a static binary, or install gcc musl-dev in the builder stage.",
			DiffPreview: strings.Join([]string{
				"--- a/Dockerfile",
				"+++ b/Dockerfile",
				"@@ -4,5 +4,5 @@",
				" COPY . .",
				"-RUN go build -o /out/server ./cmd/api",
				"+RUN CGO_ENABLED=0 GOOS=linux go build -ldflags=\"-s -w\" -o /out/server ./cmd/api",
				" FROM gcr.io/distroless/static-debian12",
			}, "\n"),
		}

	default:
		lastErr := "Build exited with non-zero status"
		for i := len(tailLogs) - 1; i >= 0; i-- {
			if t := strings.TrimSpace(tailLogs[i]); t != "" {
				lastErr = t
				break
			}
		}
		return BuildDoctorResult{
			RootCause:  "Unclassified build failure: " + truncateUTF8(lastErr, 180),
			Suggestion: "Inspect full builder stage output, verify lockfile integrity, and enable BuildKit --no-cache retry.",
			DiffPreview: strings.Join([]string{
				"--- a/Dockerfile",
				"+++ b/Dockerfile",
				"@@ -1,3 +1,4 @@",
				" # Retry with clean dependency cache and verbose diagnostics",
				"+ENV CI=true",
			}, "\n"),
		}
	}
}

func scanLocalDirectory(dir string) (files []string, pkgJSON, envExample, extraManifests string) {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil, "", "", ""
	}

	skipDirs := map[string]bool{
		".git":         true,
		"node_modules": true,
		"target":       true,
		".next":        true,
		"dist":         true,
		"vendor":       true,
		".turbo":       true,
	}

	var extra strings.Builder
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil || rel == "." {
			return nil
		}
		norm := filepath.ToSlash(rel)
		depth := strings.Count(norm, "/")

		if d.IsDir() {
			if skipDirs[d.Name()] || depth >= 2 {
				return filepath.SkipDir
			}
			return nil
		}
		if depth > 2 {
			return nil
		}

		files = append(files, norm)
		lowerBase := strings.ToLower(d.Name())
		switch lowerBase {
		case "package.json":
			if pkgJSON == "" || norm == "package.json" {
				if data, err := os.ReadFile(path); err == nil {
					pkgJSON = string(data)
				}
			} else if data, err := os.ReadFile(path); err == nil {
				extra.Write(data)
				extra.WriteByte('\n')
			}
		case ".env.example", ".env.sample", ".env.template":
			if envExample == "" {
				if data, err := os.ReadFile(path); err == nil {
					envExample = string(data)
				}
			}
		case "cargo.toml", "go.mod", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml":
			if data, err := os.ReadFile(path); err == nil {
				extra.Write(data)
				extra.WriteByte('\n')
			}
		}
		return nil
	})

	slices.Sort(files)
	return files, pkgJSON, envExample, extra.String()
}

func detectFromFilesAndManifest(files []string, pkgJSON string) (presetKey string, matched bool) {
	lowerFiles := make([]string, len(files))
	for i, f := range files {
		lowerFiles[i] = strings.ToLower(filepath.ToSlash(strings.TrimSpace(f)))
	}

	hasAnyBase := func(names ...string) bool {
		for _, lf := range lowerFiles {
			base := filepath.Base(lf)
			for _, n := range names {
				if base == n {
					return true
				}
			}
		}
		return false
	}

	hasSubPathSuffix := func(suffixes ...string) bool {
		for _, lf := range lowerFiles {
			for _, s := range suffixes {
				if strings.HasSuffix(lf, s) && strings.Contains(lf, "/") {
					return true
				}
			}
		}
		return false
	}

	hasFE := hasSubPathSuffix("/package.json") && (hasAnyPathFragment(lowerFiles, "frontend", "apps/web", "client", "web/"))
	hasBE := (hasSubPathSuffix("/go.mod", "/cargo.toml", "/requirements.txt", "/pyproject.toml") ||
		(hasSubPathSuffix("/package.json") && hasAnyPathFragment(lowerFiles, "backend", "apps/api", "server", "api/")))
	if hasFE && hasBE {
		return "compose", true
	}

	hasRootManifest := hasFileExact(lowerFiles, "go.mod") || hasFileExact(lowerFiles, "cargo.toml") || hasFileExact(lowerFiles, "package.json")
	if !hasRootManifest && hasAnyBase("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml") {
		return "compose", true
	}

	if hasAnyBase("cargo.toml", "cargo.lock") {
		return "rust", true
	}
	if hasAnyBase("go.mod", "go.sum") {
		return "go", true
	}
	if hasAnyBase("next.config.js", "next.config.mjs", "next.config.ts") {
		return "nextjs", true
	}

	pkgDeps := parsePackageDeps(pkgJSON)
	if _, hasNext := pkgDeps["next"]; hasNext || strings.Contains(strings.ToLower(pkgJSON), `"next"`) {
		return "nextjs", true
	}

	if hasAnyBase("angular.json", "vite.config.ts", "vite.config.js", "vite.config.mjs") {
		return "spa", true
	}
	for _, spaPkg := range []string{"@angular/core", "react", "vite", "vue", "svelte"} {
		if _, ok := pkgDeps[spaPkg]; ok {
			return "spa", true
		}
	}
	lowerPkg := strings.ToLower(pkgJSON)
	if strings.Contains(lowerPkg, `"react"`) || strings.Contains(lowerPkg, `"@angular/core"`) || strings.Contains(lowerPkg, `"vite"`) {
		return "spa", true
	}

	if hasAnyBase("package.json") || strings.TrimSpace(pkgJSON) != "" {
		return "spa", true
	}

	return "", false
}

func inferPresetFromRepoURL(repoURL string) string {
	lower := strings.ToLower(strings.TrimSpace(repoURL))
	if lower == "" {
		return "nextjs"
	}

	tokens := strings.FieldsFunc(lower, func(r rune) bool {
		return r == '/' || r == '-' || r == '_' || r == '.' || r == ':' || r == ' '
	})
	hasToken := func(candidates ...string) bool {
		for _, tok := range tokens {
			if slices.Contains(candidates, tok) {
				return true
			}
		}
		return false
	}

	switch {
	case hasToken("compose", "monorepo", "fullstack", "crm") || strings.Contains(lower, "compose") || strings.Contains(lower, "monorepo"):
		return "compose"
	case hasToken("rust", "cargo", "actix", "axum") || strings.Contains(lower, "rust"):
		return "rust"
	case hasToken("go", "golang", "gin", "fiber") || strings.Contains(lower, "golang"):
		return "go"
	case hasToken("angular", "react", "vite", "spa", "vue", "svelte"):
		return "spa"
	case hasToken("next", "nextjs"):
		return "nextjs"
	default:
		return "nextjs"
	}
}

func detectNativeDeps(presetKey string, files []string, pkgJSON, extraManifests string, fromRepoURLOnly bool) []string {
	if fromRepoURLOnly {
		return slices.Clone(presetCatalog[presetKey].DefaultDeps)
	}

	var deps []string
	pkgDeps := parsePackageDeps(pkgJSON)
	combinedLower := strings.ToLower(pkgJSON + "\n" + extraManifests + "\n" + strings.Join(files, "\n"))

	_, hasPrismaPkg := pkgDeps["prisma"]
	_, hasPrismaClient := pkgDeps["@prisma/client"]
	if hasPrismaPkg || hasPrismaClient || strings.Contains(combinedLower, "prisma") {
		deps = append(deps, "openssl", "libc6-compat")
	}

	_, hasSharp := pkgDeps["sharp"]
	if hasSharp || strings.Contains(combinedLower, `"sharp"`) {
		deps = append(deps, "vips-dev", "libc6-compat")
	}

	_, hasFFmpeg1 := pkgDeps["fluent-ffmpeg"]
	_, hasFFmpeg2 := pkgDeps["ffmpeg-static"]
	_, hasFFmpeg3 := pkgDeps["@ffmpeg-installer/ffmpeg"]
	if hasFFmpeg1 || hasFFmpeg2 || hasFFmpeg3 || strings.Contains(combinedLower, "ffmpeg") {
		deps = append(deps, "ffmpeg")
	}

	if presetKey == "rust" {
		deps = append(deps, "pkg-config", "musl-dev")
		if strings.Contains(combinedLower, "openssl") || strings.Contains(combinedLower, "reqwest") || strings.Contains(combinedLower, "actix") {
			deps = append(deps, "openssl-dev")
		}
	}

	if presetKey == "go" && len(deps) == 0 {
		deps = append(deps, "ca-certificates")
	}

	return uniqueNonEmpty(deps)
}

func parsePackageDeps(pkgJSON string) map[string]string {
	result := make(map[string]string)
	if strings.TrimSpace(pkgJSON) == "" {
		return result
	}
	var parsed struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal([]byte(pkgJSON), &parsed); err != nil {
		return result
	}
	for k, v := range parsed.Dependencies {
		result[strings.ToLower(k)] = v
	}
	for k, v := range parsed.DevDependencies {
		result[strings.ToLower(k)] = v
	}
	return result
}

func parseEnvExample(raw string) []EnvVar {
	var vars []EnvVar
	seen := make(map[string]bool)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		idx := strings.IndexByte(line, '=')
		var key, val string
		if idx < 0 {
			key = strings.TrimSpace(line)
		} else {
			key = strings.TrimSpace(line[:idx])
			val = strings.TrimSpace(line[idx+1:])
			val = strings.Trim(val, `"'`)
		}
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		vars = append(vars, EnvVar{
			Key:    key,
			Value:  val,
			Secret: isLikelySecretKey(key),
		})
	}
	return vars
}

func mergeEnvVars(base, extra []EnvVar) []EnvVar {
	out := make([]EnvVar, 0, len(base)+len(extra))
	indexByKey := make(map[string]int, len(base))
	for _, ev := range base {
		indexByKey[ev.Key] = len(out)
		out = append(out, ev)
	}
	for _, ev := range extra {
		if idx, exists := indexByKey[ev.Key]; exists {
			if ev.Value != "" {
				out[idx].Value = ev.Value
			}
			out[idx].Secret = out[idx].Secret || ev.Secret
			continue
		}
		indexByKey[ev.Key] = len(out)
		out = append(out, ev)
	}
	return out
}

func isLikelySecretKey(key string) bool {
	upper := strings.ToUpper(key)
	for _, marker := range []string{"SECRET", "TOKEN", "PASSWORD", "PASS", "PRIVATE", "API_KEY", "AUTH", "DATABASE_URL", "REDIS_URL", "JWT", "DSN"} {
		if strings.Contains(upper, marker) {
			return true
		}
	}
	return strings.HasSuffix(upper, "_KEY")
}

func buildHybridInsight(presetKey string, nativeDeps, envKeys []string) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("AI Hybrid [%s]:", presetCatalog[presetKey].Label))
	if len(nativeDeps) > 0 {
		parts = append(parts, fmt.Sprintf("injected native OS packages (%s)", strings.Join(nativeDeps, ", ")))
	}
	if len(envKeys) > 0 {
		parts = append(parts, fmt.Sprintf("synced %d key(s) from .env.example (%s)", len(envKeys), strings.Join(envKeys, ", ")))
	}
	parts = append(parts, "added container HEALTHCHECK + multi-stage layer caching optimization.")
	return strings.Join(parts, " ")
}

func pickDetectedFiles(files []string, pkgJSON, envExample string, tpl presetTemplate, fromRepoURLOnly bool) []string {
	if fromRepoURLOnly {
		return slices.Clone(tpl.MarkerFiles)
	}
	out := make([]string, 0, len(files)+2)
	seen := make(map[string]bool)
	for _, f := range files {
		if f != "" && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	if strings.TrimSpace(pkgJSON) != "" && !seen["package.json"] {
		seen["package.json"] = true
		out = append(out, "package.json")
	}
	if strings.TrimSpace(envExample) != "" && !seen[".env.example"] {
		seen[".env.example"] = true
		out = append(out, ".env.example")
	}
	if len(out) == 0 {
		return slices.Clone(tpl.MarkerFiles)
	}
	if len(out) > 12 {
		return out[:12]
	}
	return out
}

func deriveAppName(repoURL, localDir, fallbackPreset string) string {
	if raw := strings.TrimSpace(repoURL); raw != "" {
		raw = strings.TrimSuffix(raw, "/")
		raw = strings.TrimSuffix(raw, ".git")
		parts := strings.Split(raw, "/")
		if last := sanitizeSlug(parts[len(parts)-1]); last != "" {
			return last
		}
	}
	if dir := strings.TrimSpace(localDir); dir != "" {
		if base := sanitizeSlug(filepath.Base(dir)); base != "" && base != "." {
			return base
		}
	}
	return fallbackPreset + "-app"
}

func sanitizeSlug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func normalizePresetKey(key string) string {
	k := strings.ToLower(strings.TrimSpace(key))
	if _, ok := presetCatalog[k]; ok {
		return k
	}
	return "nextjs"
}

func defaultPortForPreset(preset string) string {
	switch preset {
	case "spa":
		return "80"
	case "go", "compose":
		return "8080"
	case "rust":
		return "9000"
	default:
		return "3000"
	}
}

func extractPrimaryPort(portMapping, fallback string) string {
	m := portNumRegexp.FindString(portMapping)
	if m == "" {
		return fallback
	}
	if p, err := strconv.Atoi(m); err != nil || p <= 0 || p > 65535 {
		return fallback
	}
	return m
}

func formatDockerEnvLines(envVars []EnvVar) string {
	lines := make([]string, 0, len(envVars))
	for _, ev := range envVars {
		k := strings.TrimSpace(ev.Key)
		if k == "" {
			continue
		}
		val := ev.Value
		if ev.Secret {
			val = "***"
		}
		lines = append(lines, fmt.Sprintf(`ENV %s="%s"`, k, strings.ReplaceAll(val, `"`, `\"`)))
	}
	return strings.Join(lines, "\n")
}

func isExcludedSourceFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(strings.TrimSpace(path)))
	switch ext {
	case ".ts", ".tsx", ".js", ".go", ".rs", ".py":
		return true
	default:
		return false
	}
}

func isOOMFailure(joined string) bool {
	if strings.Contains(joined, "exit code 137") ||
		strings.Contains(joined, "exit status 137") ||
		strings.Contains(joined, "out of memory") ||
		strings.Contains(joined, "oom") ||
		strings.Contains(joined, "killed") {
		return true
	}
	for _, tok := range strings.Fields(joined) {
		if strings.Trim(tok, "()[]:;,.") == "137" {
			return true
		}
	}
	return false
}

func isAngularDistBrowserFailure(joined string) bool {
	if strings.Contains(joined, "angular") && strings.Contains(joined, "dist") {
		return true
	}
	if strings.Contains(joined, "/browser") && strings.Contains(joined, "dist") {
		return true
	}
	if strings.Contains(joined, "/app/dist") &&
		(strings.Contains(joined, "no such file") || strings.Contains(joined, "not found") || strings.Contains(joined, "enoent")) {
		return true
	}
	return false
}

func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	if maxBytes <= 0 {
		return ""
	}
	cut := maxBytes
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut]
}

func hasAnyPathFragment(files []string, fragments ...string) bool {
	for _, f := range files {
		for _, frag := range fragments {
			if strings.Contains(f, frag) {
				return true
			}
		}
	}
	return false
}

func hasFileExact(files []string, target string) bool {
	t := strings.ToLower(target)
	for _, f := range files {
		if strings.ToLower(filepath.ToSlash(f)) == t {
			return true
		}
	}
	return false
}

func hasFileBase(files []string, base string) bool {
	b := strings.ToLower(base)
	for _, f := range files {
		if strings.ToLower(filepath.Base(f)) == b {
			return true
		}
	}
	return false
}

func hasPrefixFile(files []string, prefix string) bool {
	p := strings.ToLower(prefix)
	for _, f := range files {
		if strings.HasPrefix(strings.ToLower(filepath.ToSlash(f)), p) {
			return true
		}
	}
	return false
}

func findGoCmdEntrypoint(files []string) string {
	for _, f := range files {
		norm := filepath.ToSlash(strings.TrimSpace(f))
		lower := strings.ToLower(norm)
		if strings.HasPrefix(lower, "cmd/") && strings.HasSuffix(lower, "/main.go") {
			dir := filepath.ToSlash(filepath.Dir(norm))
			return "./" + dir
		}
	}
	return ""
}

func uniqueNonEmpty(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func mergeUniqueStrings(a, b []string) []string {
	combined := make([]string, 0, len(a)+len(b))
	combined = append(combined, a...)
	combined = append(combined, b...)
	return uniqueNonEmpty(combined)
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func nonNilEnvVars(in []EnvVar) []EnvVar {
	if in == nil {
		return []EnvVar{}
	}
	return in
}
