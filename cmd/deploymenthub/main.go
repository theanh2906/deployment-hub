// Command deploymenthub launches the DeploymentHub control plane HTTP server,
// serving the embedded web UI and REST/SSE APIs.
package main

import (
	"context"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"deploymenthub/internal/docker"
	"deploymenthub/internal/mah"
	"deploymenthub/internal/server"
	"deploymenthub/internal/vault"
	"deploymenthub/web"
)

func main() {
	if (len(os.Args) > 1 && os.Args[1] == "mcp") || strings.EqualFold(strings.TrimSpace(os.Getenv("MCP_TRANSPORT")), "stdio") {
		mcpAPIURL := firstNonEmptyEnv("MAH_MCP_API_URL", "MAH_API_URL", "http://127.0.0.1:4180")
		mcpToken := firstNonEmptyEnv("MAH_API_KEY", "MAH_API_TOKEN", "")
		if err := mah.RunMCPStdio(mcpAPIURL, mcpToken, os.Stdin, os.Stdout); err != nil {
			log.Fatalf("[fatal] MCP stdio server error: %v", err)
		}
		return
	}

	port := envOrDefault("PORT", "4180")
	dockerHost := strings.TrimSpace(os.Getenv("DOCKER_HOST"))
	masterKey := os.Getenv("HUB_MASTER_KEY")
	webhookSecret := strings.TrimSpace(os.Getenv("GITHUB_WEBHOOK_SECRET"))
	if webhookSecret == "" {
		webhookSecret = "deploymenthub-dev-webhook-secret"
		log.Println("[warn] GITHUB_WEBHOOK_SECRET not set; using default development webhook secret")
	}

	v, err := vault.New(masterKey)
	if err != nil {
		log.Fatalf("[fatal] failed to initialize crypto vault: %v", err)
	}

	engine := docker.NewEngine(dockerHost, v)
	overview := engine.GetOverview()

	var webFS fs.FS = web.StaticFS
	if webDir := strings.TrimSpace(os.Getenv("WEB_DIR")); webDir != "" {
		webFS = os.DirFS(webDir)
		log.Printf("[info] serving web UI from disk directory: %s", webDir)
	}

	addr := ":" + strings.TrimPrefix(port, ":")
	srv := &http.Server{
		Addr:              addr,
		Handler:           server.New(engine, v, webhookSecret, webFS),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("[info] DeploymentHub Control Plane listening on http://127.0.0.1%s (mode=%s, docker=%s)",
			addr, overview.VPS.RuntimeMode, overview.VPS.DockerVersion)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[fatal] HTTP server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("[info] shutting down DeploymentHub gracefully...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[warn] graceful shutdown error: %v", err)
	}
}

func envOrDefault(key, fallback string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return fallback
}

func firstNonEmptyEnv(keysAndFallback ...string) string {
	if len(keysAndFallback) == 0 {
		return ""
	}
	for _, key := range keysAndFallback[:len(keysAndFallback)-1] {
		if val := strings.TrimSpace(os.Getenv(key)); val != "" {
			return val
		}
	}
	return keysAndFallback[len(keysAndFallback)-1]
}
