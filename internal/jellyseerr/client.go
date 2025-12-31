package jellyseerr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/nag-sh/jellyseerr-sso-bridge/internal/config"
)

// Client handles Jellyseerr API interactions
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// User represents a Jellyseerr user
type User struct {
	ID              int       `json:"id"`
	Email           string    `json:"email"`
	PlexUsername    string    `json:"plexUsername,omitempty"`
	JellyfinUserID  string    `json:"jellyfinUserId,omitempty"`
	JellyfinUsername string   `json:"jellyfinUsername,omitempty"`
	Username        string    `json:"username,omitempty"`
	UserType        int       `json:"userType"`
	Permissions     int       `json:"permissions"`
	Avatar          string    `json:"avatar,omitempty"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

// UserType constants
const (
	UserTypePlex     = 1
	UserTypeLocal    = 2
	UserTypeJellyfin = 3
)

// UsersResponse represents the paginated users response
type UsersResponse struct {
	PageInfo PageInfo `json:"pageInfo"`
	Results  []User   `json:"results"`
}

// PageInfo represents pagination info
type PageInfo struct {
	Pages   int `json:"pages"`
	Page    int `json:"page"`
	Results int `json:"results"`
}

// NewClient creates a new Jellyseerr API client
func NewClient(cfg config.JellyseerrConfig) *Client {
	return &Client{
		baseURL: cfg.URL,
		apiKey:  cfg.APIKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetUsers retrieves all users from Jellyseerr
func (c *Client) GetUsers() ([]User, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/api/v1/user?take=100", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jellyseerr API error: %d - %s", resp.StatusCode, string(body))
	}

	var usersResp UsersResponse
	if err := json.NewDecoder(resp.Body).Decode(&usersResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return usersResp.Results, nil
}

// GetUserByJellyfinID finds a user by their Jellyfin user ID
func (c *Client) GetUserByJellyfinID(jellyfinUserID string) (*User, error) {
	users, err := c.GetUsers()
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		if user.JellyfinUserID == jellyfinUserID {
			return &user, nil
		}
	}

	return nil, fmt.Errorf("user not found with jellyfin ID: %s", jellyfinUserID)
}

// GetUserByID retrieves a specific user by ID
func (c *Client) GetUserByID(userID int) (*User, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/user/%d", c.baseURL, userID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("user not found: %d", userID)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jellyseerr API error: %d - %s", resp.StatusCode, string(body))
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &user, nil
}

// ImportJellyfinUser triggers Jellyseerr to import a specific user from Jellyfin
func (c *Client) ImportJellyfinUser(jellyfinUserID string) error {
	// Jellyseerr expects an array of user IDs
	reqBody := map[string]interface{}{
		"jellyfinUserIds": []string{jellyfinUserID},
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", c.baseURL+"/api/v1/user/import-from-jellyfin", bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("jellyseerr API error: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}

// AuthResponse represents the response from auth endpoints
type AuthResponse struct {
	ID              int    `json:"id"`
	Email           string `json:"email"`
	PlexToken       string `json:"plexToken,omitempty"`
	JellyfinAuthToken string `json:"jellyfinAuthToken,omitempty"`
}

// LoginAsUser creates a session for a specific user (admin API)
// This uses the admin functionality to get auth tokens for a user
func (c *Client) LoginAsUser(userID int) (*http.Cookie, error) {
	// First, get the user's details
	user, err := c.GetUserByID(userID)
	if err != nil {
		return nil, err
	}

	// Use admin endpoint to create a session token
	// Note: This requires admin API key and Jellyseerr >= 1.7
	reqBody := map[string]interface{}{
		"userId": user.ID,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", c.baseURL+"/api/v1/auth/me", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Extract the session cookie from response
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "connect.sid" {
			return cookie, nil
		}
	}

	return nil, fmt.Errorf("no session cookie in response")
}

// Ping checks if Jellyseerr is reachable
func (c *Client) Ping() error {
	req, err := http.NewRequest("GET", c.baseURL+"/api/v1/status", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to reach jellyseerr: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jellyseerr returned status: %d", resp.StatusCode)
	}

	return nil
}

func (c *Client) setHeaders(req *http.Request) {
	if c.apiKey != "" {
		req.Header.Set("X-Api-Key", c.apiKey)
	}
	req.Header.Set("Accept", "application/json")
}

