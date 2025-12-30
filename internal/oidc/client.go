package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/nag-sh/jellyseerr-sso-bridge/internal/config"
	"golang.org/x/oauth2"
)

// Client handles OIDC authentication
type Client struct {
	provider    *oidc.Provider
	oauth2Cfg   oauth2.Config
	verifier    *oidc.IDTokenVerifier
}

// Claims represents the claims extracted from the ID token
type Claims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	Groups            []string `json:"groups"`
}

// StateData holds data encoded in the OAuth state parameter
type StateData struct {
	Nonce     string `json:"n"`
	ReturnURL string `json:"r"`
}

// NewClient creates a new OIDC client
func NewClient(ctx context.Context, cfg config.OIDCConfig) (*Client, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	oauth2Cfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       append([]string{oidc.ScopeOpenID}, cfg.Scopes...),
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	return &Client{
		provider:  provider,
		oauth2Cfg: oauth2Cfg,
		verifier:  verifier,
	}, nil
}

// AuthCodeURL generates an authorization URL with state
func (c *Client) AuthCodeURL(returnURL string) (string, string, error) {
	nonce, err := generateNonce()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	stateData := StateData{
		Nonce:     nonce,
		ReturnURL: returnURL,
	}

	stateJSON, err := json.Marshal(stateData)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal state: %w", err)
	}

	state := base64.URLEncoding.EncodeToString(stateJSON)
	url := c.oauth2Cfg.AuthCodeURL(state, oidc.Nonce(nonce))

	return url, state, nil
}

// Exchange exchanges an authorization code for tokens and extracts claims
func (c *Client) Exchange(ctx context.Context, code, state string) (*Claims, error) {
	// Decode state to get nonce
	stateJSON, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		return nil, fmt.Errorf("failed to decode state: %w", err)
	}

	var stateData StateData
	if err := json.Unmarshal(stateJSON, &stateData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}

	// Exchange code for token
	token, err := c.oauth2Cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		// Debug: log what we got
		fmt.Printf("DEBUG: token.Extra keys: %+v\n", token)
		return nil, fmt.Errorf("no id_token in response")
	}
	
	// Debug: log first 100 chars of ID token
	if len(rawIDToken) > 100 {
		fmt.Printf("DEBUG: id_token (first 100 chars): %s...\n", rawIDToken[:100])
	} else {
		fmt.Printf("DEBUG: id_token: %s\n", rawIDToken)
	}

	// Verify ID token
	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify id_token: %w", err)
	}

	// Verify nonce
	if idToken.Nonce != stateData.Nonce {
		return nil, fmt.Errorf("nonce mismatch")
	}

	// Extract claims
	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	return &claims, nil
}

// DecodeState decodes the state parameter to extract the return URL
func DecodeState(state string) (*StateData, error) {
	stateJSON, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		return nil, fmt.Errorf("failed to decode state: %w", err)
	}

	var stateData StateData
	if err := json.Unmarshal(stateJSON, &stateData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}

	return &stateData, nil
}

func generateNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

