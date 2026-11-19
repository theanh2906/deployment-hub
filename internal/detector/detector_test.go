package detector

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDetectRepoURLInferenceAndModes(t *testing.T) {
	cases := []struct {
		repo string
		want string
	}{
		{"example-org/next-dashboard", "nextjs"},
		{"example-org/angular-portal", "spa"},
		{"https://github.com/example-org/go-api-service.git", "go"},
		{"example-org/rust-matcher", "rust"},
		{"example-org/ecommerce-monorepo", "compose"},
	}

	for _, tc := range cases {
		res := Detect(DetectRequest{RepoURL: tc.repo, Branch: "main", Mode: "file"})
		if res.PresetKey != tc.want {
			t.Errorf("Detect(%q) preset = %q, want %q", tc.repo, res.PresetKey, tc.want)
		}
		if res.Mode != "file" {
			t.Errorf("expected file mode, got %q", res.Mode)
		}
		if res.Dockerfile == "" || !strings.Contains(res.Dockerfile, "HEALTHCHECK") && !strings.Contains(res.Dockerfile, "healthcheck:") {
			t.Errorf("expected generated config with healthcheck for %q", tc.repo)
		}
	}
}

func TestDetectHybridEnrichmentNativeDepsAndEnvExample(t *testing.T) {
	pkg := `{
	  "name": "commerce-web",
	  "dependencies": {
	    "next": "15.1.4",
	    "@prisma/client": "6.0.0",
	    "sharp": "0.33.5",
	    "fluent-ffmpeg": "2.1.3"
	  }
	}`
	envEx := `
# Sample env
DATABASE_URL=postgres://user:pass@db:5432/app
STRIPE_SECRET_KEY=sk_test_example
PUBLIC_SITE_NAME=DeploymentHub
`

	res := Detect(DetectRequest{
		RepoURL:     "https://github.com/org/storefront",
		Branch:      "main",
		Mode:        "hybrid",
		Files:       []string{"package.json", "next.config.mjs", "prisma/schema.prisma", ".env.example"},
		PackageJSON: pkg,
		EnvExample:  envEx,
	})

	if res.PresetKey != "nextjs" {
		t.Fatalf("expected nextjs preset, got %q", res.PresetKey)
	}
	if res.Confidence < 95 {
		t.Fatalf("expected high confidence in hybrid mode, got %d", res.Confidence)
	}
	for _, wantDep := range []string{"openssl", "vips-dev", "ffmpeg"} {
		if !slices.Contains(res.NativeDeps, wantDep) {
			t.Errorf("expected nativeDep %q in %v", wantDep, res.NativeDeps)
		}
		if !strings.Contains(res.Dockerfile, wantDep) {
			t.Errorf("expected Dockerfile to inject nativeDep %q", wantDep)
		}
	}

	envMap := map[string]EnvVar{}
	for _, ev := range res.EnvVars {
		envMap[ev.Key] = ev
	}
	for _, key := range []string{"DATABASE_URL", "STRIPE_SECRET_KEY", "PUBLIC_SITE_NAME"} {
		if _, ok := envMap[key]; !ok {
			t.Errorf("expected env key %q from .env.example to be extracted", key)
		}
	}
	if !envMap["STRIPE_SECRET_KEY"].Secret {
		t.Errorf("expected STRIPE_SECRET_KEY to be flagged secret")
	}
	if strings.Contains(res.Dockerfile, "sk_test_example") {
		t.Errorf("secret env value should be masked in Dockerfile preview")
	}
}

func TestDetectLocalDirDepthLimit(t *testing.T) {
	tmp := t.TempDir()

	// Depth 0 and 1 files should be detected; depth 3 should be ignored.
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte("module example.com/svc\ngo 1.22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "cmd", "api"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "cmd", "api", "main.go"), []byte("package main\nfunc main(){}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "a", "b", "c"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "a", "b", "c", "Cargo.toml"), []byte("[package]\nname=\"ignored\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res := Detect(DetectRequest{LocalDir: tmp, Mode: "hybrid"})
	if res.PresetKey != "go" {
		t.Fatalf("expected go preset (depth 3 Cargo.toml must be ignored), got %q (files: %v)", res.PresetKey, res.DetectedFiles)
	}
	if slices.Contains(res.DetectedFiles, "a/b/c/Cargo.toml") {
		t.Fatalf("depth > 2 file should not be scanned: %v", res.DetectedFiles)
	}
}

func TestGenerateDockerfileAllStacks(t *testing.T) {
	stacks := []struct {
		preset   string
		contains []string
	}{
		{"nextjs", []string{"FROM node:20-alpine AS builder", ".next/standalone", ".next/static", "./public", "HEALTHCHECK", "vips-dev"}},
		{"spa", []string{"FROM nginx:1.27-alpine", "/usr/share/nginx/html", "HEALTHCHECK"}},
		{"go", []string{"CGO_ENABLED=0", "gcr.io/distroless/static-debian12", "HEALTHCHECK"}},
		{"rust", []string{"FROM rust:1.80-alpine AS builder", "FROM alpine:3.20", "pkg-config", "musl-dev", "HEALTHCHECK"}},
		{"compose", []string{"services:", "internal-net", "postgres:16-alpine", "traefik.http.routers.crm-fe.rule", "healthcheck:"}},
	}

	for _, st := range stacks {
		out := GenerateDockerfile(DockerfileRequest{
			PresetKey:  st.preset,
			Mode:       "hybrid",
			AppName:    "crm",
			Domain:     "crm.localhost",
			NativeDeps: []string{"vips-dev", "pkg-config", "musl-dev"},
		})
		for _, needle := range st.contains {
			if !strings.Contains(out, needle) {
				t.Errorf("preset %q Dockerfile missing %q\nOutput:\n%s", st.preset, needle, out)
			}
		}
	}
}

func TestBuildMetadataPromptExcludesSourceFilesAndCapsSize(t *testing.T) {
	tree := []string{
		"package.json",
		"next.config.mjs",
		"prisma/schema.prisma",
		"src/index.ts",
		"src/App.tsx",
		"scripts/helper.js",
		"cmd/api/main.go",
		"src/lib.rs",
		"ml/train.py",
	}

	logs := make([]string, 80)
	for i := range logs {
		logs[i] = strings.Repeat("log-line-", 8) + string(rune('a'+(i%26)))
	}
	manifest := strings.Repeat(`{"dep":"x"},`, 150)

	prompt := BuildMetadataPrompt(tree, "package.json", manifest, "API_SECRET=topsecret\nPORT=3000", logs)
	if len(prompt) > 2048 {
		t.Fatalf("prompt exceeded 2048 bytes: got %d", len(prompt))
	}
	for _, forbidden := range []string{"src/index.ts", "src/App.tsx", "scripts/helper.js", "cmd/api/main.go", "src/lib.rs", "ml/train.py", "topsecret"} {
		if strings.Contains(prompt, forbidden) {
			t.Errorf("prompt leaked forbidden item %q:\n%s", forbidden, prompt)
		}
	}
	if !strings.Contains(prompt, "package.json") || !strings.Contains(prompt, "prisma/schema.prisma") {
		t.Errorf("prompt missing expected metadata files:\n%s", prompt)
	}
}

func TestDiagnoseBuildFailure(t *testing.T) {
	cases := []struct {
		name      string
		logs      []string
		wantCause string
		wantDiff  string
	}{
		{
			name:      "oom_137",
			logs:      []string{"npm run build", "Killed", "The command '/bin/sh -c npm run build' returned a non-zero code: 137"},
			wantCause: "137",
			wantDiff:  "NODE_OPTIONS",
		},
		{
			name:      "missing_openssl",
			logs:      []string{"Error: PrismaClientInitializationError: Unable to require libquery_engine: libssl.so.1.1 missing openssl"},
			wantCause: "openssl",
			wantDiff:  "libc6-compat",
		},
		{
			name:      "angular_browser_dist",
			logs:      []string{"Angular application build succeeded", "COPY failed: file not found in build context: /app/dist"},
			wantCause: "browser",
			wantDiff:  "/app/dist/<app>/browser",
		},
		{
			name:      "go_cgo",
			logs:      []string{`# cgo: C compiler "gcc" not found: exec: "gcc": executable file not found`},
			wantCause: "CGO",
			wantDiff:  "CGO_ENABLED=0",
		},
	}

	for _, tc := range cases {
		res := DiagnoseBuildFailure(tc.logs)
		if !strings.Contains(strings.ToLower(res.RootCause), strings.ToLower(tc.wantCause)) {
			t.Errorf("%s: RootCause %q does not mention %q", tc.name, res.RootCause, tc.wantCause)
		}
		if !strings.Contains(res.DiffPreview, tc.wantDiff) {
			t.Errorf("%s: DiffPreview %q does not contain %q", tc.name, res.DiffPreview, tc.wantDiff)
		}
		if res.Suggestion == "" {
			t.Errorf("%s: expected non-empty Suggestion", tc.name)
		}
	}
}
