package jellyfin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/nag-sh/jellyseerr-sso-bridge/internal/config"
)

// Client handles Jellyfin API interactions
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// User represents a Jellyfin user
type User struct {
	ID                  string    `json:"Id"`
	Name                string    `json:"Name"`
	ServerID            string    `json:"ServerId"`
	HasPassword         bool      `json:"HasPassword"`
	HasConfiguredPassword bool    `json:"HasConfiguredPassword"`
	EnableAutoLogin     bool      `json:"EnableAutoLogin"`
	LastLoginDate       time.Time `json:"LastLoginDate"`
	LastActivityDate    time.Time `json:"LastActivityDate"`
}

// NewClient creates a new Jellyfin API client
func NewClient(cfg config.JellyfinConfig) *Client {
	return &Client{
		baseURL: cfg.URL,
		apiKey:  cfg.APIKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetUsers retrieves all users from Jellyfin
func (c *Client) GetUsers() ([]User, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/Users", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Emby-Token", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jellyfin API error: %d - %s", resp.StatusCode, string(body))
	}

	var users []User
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return users, nil
}

// GetUserByName finds a user by their username
func (c *Client) GetUserByName(username string) (*User, error) {
	users, err := c.GetUsers()
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		if user.Name == username {
			return &user, nil
		}
	}

	return nil, fmt.Errorf("user not found: %s", username)
}

// GetUserByID retrieves a specific user by ID
func (c *Client) GetUserByID(userID string) (*User, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/Users/"+userID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Emby-Token", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("user not found: %s", userID)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jellyfin API error: %d - %s", resp.StatusCode, string(body))
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &user, nil
}

// Ping checks if Jellyfin is reachable
func (c *Client) Ping() error {
	req, err := http.NewRequest("GET", c.baseURL+"/System/Info/Public", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to reach jellyfin: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jellyfin returned status: %d", resp.StatusCode)
	}

	return nil
}

