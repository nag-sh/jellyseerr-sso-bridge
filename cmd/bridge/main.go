package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nag-sh/jellyseerr-sso-bridge/internal/config"
	"github.com/nag-sh/jellyseerr-sso-bridge/internal/handlers"
	"github.com/nag-sh/jellyseerr-sso-bridge/internal/jellyfin"
	"github.com/nag-sh/jellyseerr-sso-bridge/internal/jellyseerr"
	"github.com/nag-sh/jellyseerr-sso-bridge/internal/oidc"
	"github.com/nag-sh/jellyseerr-sso-bridge/internal/session"
)

var version = "dev"

func main() {
	// Setup structured logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	slog.Info("starting jellyseerr-sso-bridge", "version", version)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Initialize OIDC client
	ctx := context.Background()
	oidcClient, err := oidc.NewClient(ctx, cfg.OIDC)
	if err != nil {
		slog.Error("failed to initialize OIDC client", "error", err)
		os.Exit(1)
	}

	// Initialize Jellyfin client
	jellyfinClient := jellyfin.NewClient(cfg.Jellyfin)

	// Initialize Jellyseerr client
	jellyseerrClient := jellyseerr.NewClient(cfg.Jellyseerr)

	// Initialize session manager
	sessionMgr := session.NewManager(cfg.Session)

	// Create handler
	handler := handlers.New(handlers.Config{
		OIDCClient:       oidcClient,
		JellyfinClient:   jellyfinClient,
		JellyseerrClient: jellyseerrClient,
		SessionManager:   sessionMgr,
		ExternalURL:      cfg.Bridge.ExternalURL,
		CookieDomain:     cfg.Bridge.CookieDomain,
	})

	// Setup routes
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handler.Health)
	mux.HandleFunc("GET /ready", handler.Ready)
	mux.HandleFunc("GET /auth/check", handler.Check)
	mux.HandleFunc("GET /login", handler.Login)
	mux.HandleFunc("GET /callback", handler.Callback)
	mux.HandleFunc("GET /logout", handler.Logout)
	mux.HandleFunc("POST /logout", handler.Logout)

	// Create server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Bridge.Port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		slog.Info("server listening", "port", cfg.Bridge.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("server forced to shutdown", "error", err)
	}

	slog.Info("server stopped")
}

