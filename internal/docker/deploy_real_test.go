package docker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"deploymenthub/internal/detector"
)

func TestReadExistingRepoDockerfile(t *testing.T) {
	// Missing Dockerfile
	emptyDir := t.TempDir()
	if _, _, ok := readExistingRepoDockerfile(emptyDir); ok {
		t.Fatal("expected ok=false when Dockerfile does not exist")
	}

	// Invalid Dockerfile without FROM instruction
	invalidDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(invalidDir, "Dockerfile"), []byte("# comment only\nRUN echo hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := readExistingRepoDockerfile(invalidDir); ok {
		t.Fatal("expected ok=false when Dockerfile lacks FROM instruction")
	}

	// Valid multi-stage Dockerfile with EXPOSE 3000
	validDir := t.TempDir()
	df3000 := "# Multi-stage build\nFROM node:22-alpine AS builder\nWORKDIR /app\nRUN npm run build\nFROM node:22-alpine AS runner\nEXPOSE 3000\nCMD [\"node\", \"server.js\"]\n"
	if err := os.WriteFile(filepath.Join(validDir, "Dockerfile"), []byte(df3000), 0o644); err != nil {
		t.Fatal(err)
	}
	gotContent, gotPort, ok := readExistingRepoDockerfile(validDir)
	if !ok || gotContent != df3000 || gotPort != "3000" {
		t.Fatalf("unexpected result for EXPOSE 3000: ok=%v port=%q", ok, gotPort)
	}

	// Valid Dockerfile with EXPOSE 8080/tcp overriding earlier EXPOSE 80
	tcpDir := t.TempDir()
	df8080 := "FROM golang:1.22-alpine\nEXPOSE 80\nEXPOSE 8080/tcp\nCMD [\"/server\"]\n"
	if err := os.WriteFile(filepath.Join(tcpDir, "Dockerfile"), []byte(df8080), 0o644); err != nil {
		t.Fatal(err)
	}
	gotContent2, gotPort2, ok2 := readExistingRepoDockerfile(tcpDir)
	if !ok2 || gotContent2 != df8080 || gotPort2 != "8080" {
		t.Fatalf("unexpected result for EXPOSE 8080/tcp: ok=%v port=%q", ok2, gotPort2)
	}
}

func TestBuildResilientRuntimeDockerfileNextjsStandaloneCopiesAssets(t *testing.T) {
	workDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(workDir, "package.json"), []byte(`{"name":"studio","dependencies":{"next":"15.4.9"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	dockerfile, _ := buildResilientRuntimeDockerfile(workDir, DeployRequest{
		AppName:   "flow-studio",
		PresetKey: "nextjs",
	}, detector.DetectResult{PresetKey: "nextjs"}, "3000")

	for _, want := range []string{
		".next/standalone/.next/static",
		".next/standalone/public",
		"node .next/standalone/server.js",
	} {
		if !strings.Contains(dockerfile, want) {
			t.Fatalf("expected Next.js runtime Dockerfile to contain %q, got:\n%s", want, dockerfile)
		}
	}
}
