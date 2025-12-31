package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/nag-sh/jellyseerr-sso-bridge/internal/jellyfin"
	"github.com/nag-sh/jellyseerr-sso-bridge/internal/jellyseerr"
	"github.com/nag-sh/jellyseerr-sso-bridge/internal/oidc"
	"github.com/nag-sh/jellyseerr-sso-bridge/internal/session"
)

// Config holds handler configuration
type Config struct {
	OIDCClient       *oidc.Client
	JellyfinClient   *jellyfin.Client
	JellyseerrClient *jellyseerr.Client
	SessionManager   *session.Manager
	ExternalURL      string
	CookieDomain     string
}

// Handler handles HTTP requests
type Handler struct {
	oidc       *oidc.Client
	jellyfin   *jellyfin.Client
	jellyseerr *jellyseerr.Client
	session    *session.Manager
	extURL     string
	cookieDomain string
}

// New creates a new handler
func New(cfg Config) *Handler {
	return &Handler{
		oidc:         cfg.OIDCClient,
		jellyfin:     cfg.JellyfinClient,
		jellyseerr:   cfg.JellyseerrClient,
		session:      cfg.SessionManager,
		extURL:       cfg.ExternalURL,
		cookieDomain: cfg.CookieDomain,
	}
}

// Health handles health check requests
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Ready handles readiness check requests
func (h *Handler) Ready(w http.ResponseWriter, r *http.Request) {
	// Check Jellyfin connectivity
	if err := h.jellyfin.Ping(); err != nil {
		slog.Error("jellyfin not ready", "error", err)
		http.Error(w, "jellyfin not ready", http.StatusServiceUnavailable)
		return
	}

	// Check Jellyseerr connectivity
	if err := h.jellyseerr.Ping(); err != nil {
		slog.Error("jellyseerr not ready", "error", err)
		http.Error(w, "jellyseerr not ready", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Check handles forwardAuth check requests from Traefik
func (h *Handler) Check(w http.ResponseWriter, r *http.Request) {
	// Validate session
	sessionData, err := h.session.ValidateRequest(r)
	if err != nil {
		slog.Debug("session validation failed", "error", err)
		
		// Get the original URL from X-Forwarded headers
		originalURL := getOriginalURL(r)
		loginURL := h.buildLoginURL(originalURL)
		
		// Return 302 redirect to login page
		// Browsers follow 3xx redirects, not 401 with Location header
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Session is valid - set headers for downstream
	w.Header().Set("X-Forwarded-User", sessionData.Username)
	w.Header().Set("X-Jellyfin-User-Id", sessionData.JellyfinUserID)
	w.WriteHeader(http.StatusOK)
}

// Login initiates the OIDC login flow
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	returnURL := r.URL.Query().Get("return_url")
	if returnURL == "" {
		returnURL = r.Header.Get("X-Forwarded-Uri")
	}
	if returnURL == "" {
		returnURL = "/"
	}

	// Generate auth URL
	authURL, _, err := h.oidc.AuthCodeURL(returnURL)
	if err != nil {
		slog.Error("failed to generate auth URL", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	slog.Info("redirecting to OIDC provider", "return_url", returnURL)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// Callback handles the OIDC callback
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		slog.Error("no code in callback")
		http.Error(w, "No authorization code", http.StatusBadRequest)
		return
	}

	// Exchange code for claims
	claims, err := h.oidc.Exchange(ctx, code, state)
	if err != nil {
		slog.Error("failed to exchange code", "error", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	slog.Info("OIDC authentication successful", 
		"username", claims.PreferredUsername,
		"email", claims.Email)

	// Look up Jellyfin user by username
	jellyfinUser, err := h.jellyfin.GetUserByName(claims.PreferredUsername)
	if err != nil {
		slog.Error("jellyfin user not found", 
			"username", claims.PreferredUsername,
			"error", err)
		http.Error(w, fmt.Sprintf(
			"Jellyfin user '%s' not found. Please login to Jellyfin first to create your account.",
			claims.PreferredUsername), http.StatusForbidden)
		return
	}

	slog.Info("found jellyfin user", 
		"jellyfin_id", jellyfinUser.ID,
		"name", jellyfinUser.Name)

	// Find or import user in Jellyseerr
	jellyseerrUser, err := h.jellyseerr.GetUserByJellyfinID(jellyfinUser.ID)
	if err != nil {
		slog.Info("user not in jellyseerr, triggering import", 
			"jellyfin_id", jellyfinUser.ID)
		
		// Trigger import of specific Jellyfin user
		if err := h.jellyseerr.ImportJellyfinUser(jellyfinUser.ID); err != nil {
			slog.Error("failed to import jellyfin user", "error", err)
		}

		// Wait a moment for import to complete
		time.Sleep(2 * time.Second)

		// Try again
		jellyseerrUser, err = h.jellyseerr.GetUserByJellyfinID(jellyfinUser.ID)
		if err != nil {
			slog.Error("user still not found after import", "error", err)
			http.Error(w, "Failed to import user into Jellyseerr. Please try again.", 
				http.StatusInternalServerError)
			return
		}
	}

	slog.Info("found jellyseerr user", 
		"jellyseerr_id", jellyseerrUser.ID,
		"jellyfin_id", jellyseerrUser.JellyfinUserID)

	// Create a Jellyseerr session by temporarily enabling password auth
	// and using a temp password to login
	tempPassword := fmt.Sprintf("sso-bridge-%d-%s", time.Now().UnixNano(), jellyfinUser.ID[:8])
	
	// Step 1: Enable default auth provider for the user
	if err := h.jellyfin.SetUserAuthProvider(jellyfinUser.ID, jellyfin.DefaultAuthProvider); err != nil {
		slog.Error("failed to set auth provider", "error", err)
		http.Error(w, "Failed to configure authentication. Please try again.", 
			http.StatusInternalServerError)
		return
	}
	
	// Step 2: Set a temporary password
	if err := h.jellyfin.SetUserPassword(jellyfinUser.ID, tempPassword); err != nil {
		slog.Error("failed to set temp password", "error", err)
		http.Error(w, "Failed to configure authentication. Please try again.", 
			http.StatusInternalServerError)
		return
	}
	
	// Step 3: Login to Jellyseerr with the temp password
	jellyseerrCookie, err := h.jellyseerr.LoginWithJellyfin(claims.PreferredUsername, tempPassword)
	if err != nil {
		slog.Error("failed to login to jellyseerr", "error", err)
		http.Error(w, "Failed to create Jellyseerr session. Please try again.", 
			http.StatusInternalServerError)
		return
	}
	
	slog.Info("created jellyseerr session", "username", claims.PreferredUsername)

	// Create bridge session (for forwardAuth validation)
	sessionData := session.SessionData{
		UserID:         jellyseerrUser.ID,
		JellyfinUserID: jellyfinUser.ID,
		Username:       claims.PreferredUsername,
		Email:          claims.Email,
	}
	bridgeSessionCookie := h.session.Create(sessionData, h.cookieDomain)
	http.SetCookie(w, bridgeSessionCookie)
	
	// Set the Jellyseerr session cookie
	// Adjust the cookie for the proper domain
	jellyseerrCookie.Domain = h.cookieDomain
	jellyseerrCookie.Path = "/"
	jellyseerrCookie.Secure = true
	jellyseerrCookie.SameSite = http.SameSiteLaxMode
	http.SetCookie(w, jellyseerrCookie)

	// Get return URL from state
	stateData, err := oidc.DecodeState(state)
	if err != nil {
		slog.Warn("failed to decode state, using default return URL", "error", err)
		stateData = &oidc.StateData{ReturnURL: "/"}
	}

	returnURL := stateData.ReturnURL
	if returnURL == "" || returnURL == "/" {
		// Default to Jellyseerr home
		returnURL = "/"
	}

	slog.Info("authentication complete, redirecting", 
		"return_url", returnURL,
		"username", claims.PreferredUsername)

	http.Redirect(w, r, returnURL, http.StatusFound)
}

// Logout handles logout requests
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	// Clear the session cookie
	clearCookie := h.session.ClearCookie(h.cookieDomain)
	http.SetCookie(w, clearCookie)

	// Redirect to the return URL or home
	returnURL := r.URL.Query().Get("return_url")
	if returnURL == "" {
		returnURL = "/"
	}

	http.Redirect(w, r, returnURL, http.StatusFound)
}

func (h *Handler) buildLoginURL(returnURL string) string {
	loginURL, _ := url.Parse(h.extURL + "/login")
	q := loginURL.Query()
	q.Set("return_url", returnURL)
	loginURL.RawQuery = q.Encode()
	return loginURL.String()
}

func getOriginalURL(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "https"
	}

	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}

	uri := r.Header.Get("X-Forwarded-Uri")
	if uri == "" {
		uri = r.URL.RequestURI()
	}

	return scheme + "://" + host + uri
}

