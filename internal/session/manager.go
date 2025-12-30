package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nag-sh/jellyseerr-sso-bridge/internal/config"
)

const (
	// CookieName is the name of the bridge session cookie
	CookieName = "jellyseerr_sso_session"
)

// Manager handles session creation and validation
type Manager struct {
	secret []byte
	ttl    time.Duration
}

// SessionData holds the data stored in the session
type SessionData struct {
	UserID          int    `json:"uid"`
	JellyfinUserID  string `json:"jfid"`
	Username        string `json:"u"`
	Email           string `json:"e"`
	ExpiresAt       int64  `json:"exp"`
}

// NewManager creates a new session manager
func NewManager(cfg config.SessionConfig) *Manager {
	return &Manager{
		secret: []byte(cfg.Secret),
		ttl:    cfg.TTL,
	}
}

// Create creates a new session cookie
func (m *Manager) Create(data SessionData, domain string) *http.Cookie {
	data.ExpiresAt = time.Now().Add(m.ttl).Unix()

	// Encode session data
	dataJSON, _ := json.Marshal(data)
	dataB64 := base64.URLEncoding.EncodeToString(dataJSON)

	// Create signature
	sig := m.sign(dataB64)

	// Cookie value is data.signature
	value := dataB64 + "." + sig

	return &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		Domain:   domain,
		Expires:  time.Unix(data.ExpiresAt, 0),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// Validate validates a session cookie and returns the session data
func (m *Manager) Validate(cookie *http.Cookie) (*SessionData, error) {
	if cookie == nil {
		return nil, fmt.Errorf("no cookie provided")
	}

	// Split value into data and signature
	value := cookie.Value
	var dataB64, sig string
	for i := len(value) - 1; i >= 0; i-- {
		if value[i] == '.' {
			dataB64 = value[:i]
			sig = value[i+1:]
			break
		}
	}

	if dataB64 == "" || sig == "" {
		return nil, fmt.Errorf("invalid cookie format")
	}

	// Verify signature
	expectedSig := m.sign(dataB64)
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode data
	dataJSON, err := base64.URLEncoding.DecodeString(dataB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode data: %w", err)
	}

	var data SessionData
	if err := json.Unmarshal(dataJSON, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data: %w", err)
	}

	// Check expiration
	if time.Now().Unix() > data.ExpiresAt {
		return nil, fmt.Errorf("session expired")
	}

	return &data, nil
}

// ValidateRequest extracts and validates the session from a request
func (m *Manager) ValidateRequest(r *http.Request) (*SessionData, error) {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return nil, fmt.Errorf("no session cookie: %w", err)
	}
	return m.Validate(cookie)
}

// ClearCookie creates a cookie that clears the session
func (m *Manager) ClearCookie(domain string) *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		Domain:   domain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

func (m *Manager) sign(data string) string {
	h := hmac.New(sha256.New, m.secret)
	h.Write([]byte(data))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

