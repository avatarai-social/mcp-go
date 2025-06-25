package transport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// OAuthConfig holds the OAuth configuration for the client
type OAuthConfig struct {
	// ClientID is the OAuth client ID
	ClientID string
	// ClientSecret is the OAuth client secret (for confidential clients)
	ClientSecret string
	// ClientType is the type of client (public, confidential)
	ClientType string
	// RedirectURI is the redirect URI for the OAuth flow
	RedirectURI string
	// Scopes is the list of OAuth scopes to request
	Scopes []string
	// TokenStore is the storage for OAuth tokens
	TokenStore TokenStore
	// AuthServerMetadataURL is the URL to the OAuth server metadata
	// If empty, the client will attempt to discover it from the base URL
	AuthServerMetadataURL string
	// PKCEEnabled enables PKCE for the OAuth flow (recommended for public clients)
	PKCEEnabled bool
	// FIXME: @zsw
	// AuthorizationURL is the URL to the OAuth authorization endpoint
	AuthorizationURL string
	// TokenURL is the URL to the OAuth token endpoint
	TokenURL string
	// UserInfoURL is the URL to the OAuth user info endpoint
	UserInfoURL string
}

// TokenStore is an interface for storing and retrieving OAuth tokens
type TokenStore interface {
	// GetToken returns the current token
	GetToken() (*Token, error)
	// SaveToken saves a token
	SaveToken(token *Token) error
}

// Token represents an OAuth token
type Token struct {
	// AccessToken is the OAuth access token
	AccessToken string `json:"access_token"`
	// TokenType is the type of token (usually "Bearer")
	TokenType string `json:"token_type"`
	// RefreshToken is the OAuth refresh token
	RefreshToken string `json:"refresh_token,omitempty"`
	// ExpiresIn is the number of seconds until the token expires
	ExpiresIn int64 `json:"expires_in,omitempty"`
	// Scope is the scope of the token
	Scope string `json:"scope,omitempty"`
	// ExpiresAt is the time when the token expires
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// IsExpired returns true if the token is expired
func (t *Token) IsExpired() bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(t.ExpiresAt)
}

// MemoryTokenStore is a simple in-memory token store
type MemoryTokenStore struct {
	token *Token
	mu    sync.RWMutex
}

// NewMemoryTokenStore creates a new in-memory token store
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{}
}

// GetToken returns the current token
func (s *MemoryTokenStore) GetToken() (*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.token == nil {
		return nil, errors.New("no token available")
	}
	return s.token, nil
}

// SaveToken saves a token
func (s *MemoryTokenStore) SaveToken(token *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = token
	return nil
}

// AuthServerMetadata represents the OAuth 2.0 Authorization Server Metadata
type AuthServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	JwksURI                           string   `json:"jwks_uri,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}

// OAuthHandler handles OAuth authentication for HTTP requests
type OAuthHandler struct {
	config           OAuthConfig
	httpClient       *http.Client
	serverMetadata   *AuthServerMetadata
	metadataFetchErr error
	metadataOnce     sync.Once
	baseURL          string
	expectedState    string // Expected state value for CSRF protection
}

// NewOAuthHandler creates a new OAuth handler
func NewOAuthHandler(config OAuthConfig) *OAuthHandler {
	if config.TokenStore == nil {
		config.TokenStore = NewMemoryTokenStore()
	}

	return &OAuthHandler{
		config:     config,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// GetAuthorizationHeader returns the Authorization header value for a request
func (h *OAuthHandler) GetAuthorizationHeader(ctx context.Context) (string, error) {
	token, err := h.getValidToken(ctx)
	if err != nil {
		return "", err
	}

	// Some auth implementations are strict about token type
	tokenType := token.TokenType
	if tokenType == "bearer" {
		tokenType = "Bearer"
	}

	return fmt.Sprintf("%s %s", tokenType, token.AccessToken), nil
}

// getValidToken returns a valid token, refreshing if necessary
func (h *OAuthHandler) getValidToken(ctx context.Context) (*Token, error) {
	token, err := h.config.TokenStore.GetToken()
	if err == nil && !token.IsExpired() && token.AccessToken != "" {
		return token, nil
	}

	// If we have a refresh token, try to use it
	if err == nil && token.RefreshToken != "" {
		newToken, err := h.refreshToken(ctx, token.RefreshToken)
		if err == nil {
			return newToken, nil
		}
		// If refresh fails, continue to authorization flow
	}

	// We need to get a new token through the authorization flow
	return nil, ErrOAuthAuthorizationRequired
}

// refreshToken refreshes an OAuth token
func (h *OAuthHandler) refreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	metadata, err := h.getServerMetadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get server metadata: %w", err)
	}

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", h.config.ClientID)
	if h.config.ClientSecret != "" {
		data.Set("client_secret", h.config.ClientSecret)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		metadata.TokenEndpoint,
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send refresh token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, extractOAuthError(body, resp.StatusCode, "refresh token request failed")
	}

	var tokenResp Token
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	// Set expiration time
	if tokenResp.ExpiresIn > 0 {
		tokenResp.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	// If no new refresh token is provided, keep the old one
	oldToken, _ := h.config.TokenStore.GetToken()
	if tokenResp.RefreshToken == "" && oldToken != nil {
		tokenResp.RefreshToken = oldToken.RefreshToken
	}

	// Save the token
	if err := h.config.TokenStore.SaveToken(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to save token: %w", err)
	}

	return &tokenResp, nil
}

// RefreshToken is a public wrapper for refreshToken
func (h *OAuthHandler) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	return h.refreshToken(ctx, refreshToken)
}

// GetClientID returns the client ID
func (h *OAuthHandler) GetClientID() string {
	return h.config.ClientID
}

// extractOAuthError attempts to parse an OAuth error response from the response body
func extractOAuthError(body []byte, statusCode int, context string) error {
	// Try to parse the error as an OAuth error response
	var oauthErr OAuthError
	if err := json.Unmarshal(body, &oauthErr); err == nil && oauthErr.ErrorCode != "" {
		return fmt.Errorf("%s: %w", context, oauthErr)
	}

	// If not a valid OAuth error, return the raw response
	return fmt.Errorf("%s with status %d: %s", context, statusCode, body)
}

// GetClientSecret returns the client secret
func (h *OAuthHandler) GetClientSecret() string {
	return h.config.ClientSecret
}

// SetBaseURL sets the base URL for the API server
func (h *OAuthHandler) SetBaseURL(baseURL string) {
	h.baseURL = baseURL
}

// GetExpectedState returns the expected state value (for testing purposes)
func (h *OAuthHandler) GetExpectedState() string {
	return h.expectedState
}

func (h *OAuthHandler) SetExpectedState(expectedState string) {
	h.expectedState = expectedState
}

// OAuthError represents a standard OAuth 2.0 error response
type OAuthError struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// Error implements the error interface
func (e OAuthError) Error() string {
	if e.ErrorDescription != "" {
		return fmt.Sprintf("OAuth error: %s - %s", e.ErrorCode, e.ErrorDescription)
	}
	return fmt.Sprintf("OAuth error: %s", e.ErrorCode)
}

// OAuthProtectedResource represents the response from /.well-known/oauth-protected-resource
type OAuthProtectedResource struct {
	AuthorizationServers []string `json:"authorization_servers"`
	Resource             string   `json:"resource"`
	ResourceName         string   `json:"resource_name,omitempty"`
}

// getServerMetadata fetches the OAuth server metadata
func (h *OAuthHandler) getServerMetadata(ctx context.Context) (*AuthServerMetadata, error) {
	logrus.Info("=== MCP OAuth: Starting server metadata discovery ===")

	h.metadataOnce.Do(func() {
		// If AuthServerMetadataURL is explicitly provided, use it directly
		if h.config.AuthServerMetadataURL != "" {
			logrus.Infof("🔧 MCP OAuth: Using explicit AuthServerMetadataURL: %s", h.config.AuthServerMetadataURL)
			h.fetchMetadataFromURL(ctx, h.config.AuthServerMetadataURL)
			if h.serverMetadata != nil {
				logrus.Infof("✅ MCP OAuth: Successfully fetched metadata from explicit URL")
			} else {
				logrus.Errorf("❌ MCP OAuth: Failed to fetch metadata from explicit URL")
			}
			return
		}

		// Try to discover the authorization server via OAuth Protected Resource
		// as per RFC 9728 (https://datatracker.ietf.org/doc/html/rfc9728)
		baseURL, err := h.extractBaseURL()
		if err != nil {
			logrus.Errorf("❌ MCP OAuth: Failed to extract base URL: %v", err)
			h.metadataFetchErr = fmt.Errorf("failed to extract base URL: %w", err)
			return
		}
		logrus.Infof("🌐 MCP OAuth: Extracted base URL: %s", baseURL)

		// Try to fetch the OAuth Protected Resource metadata
		protectedResourceURL := baseURL + "/.well-known/oauth-protected-resource"
		logrus.Infof("🔍 MCP OAuth: Attempting to fetch protected resource metadata from: %s", protectedResourceURL)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, protectedResourceURL, nil)
		if err != nil {
			logrus.Errorf("❌ MCP OAuth: Failed to create protected resource request: %v", err)
			h.metadataFetchErr = fmt.Errorf("failed to create protected resource request: %w", err)
			return
		}

		req.Header.Set("Accept", "application/json")
		req.Header.Set("MCP-Protocol-Version", "2025-03-26")
		logrus.Infof("📝 MCP OAuth: Request headers: Accept=%s, MCP-Protocol-Version=%s",
			req.Header.Get("Accept"), req.Header.Get("MCP-Protocol-Version"))

		resp, err := h.httpClient.Do(req)
		if err != nil {
			logrus.Errorf("❌ MCP OAuth: Failed to send protected resource request: %v", err)
			h.metadataFetchErr = fmt.Errorf("failed to send protected resource request: %w", err)
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		logrus.Infof("📥 MCP OAuth: Protected resource response - Status: %d, Body: %s", resp.StatusCode, string(body))

		// If we can't get the protected resource metadata, fall back to default endpoints
		if resp.StatusCode != http.StatusOK {
			logrus.Warnf("⚠️ MCP OAuth: Protected resource request failed with status %d, falling back to default endpoints", resp.StatusCode)
			metadata, err := h.getDefaultEndpoints(baseURL)
			if err != nil {
				logrus.Errorf("❌ MCP OAuth: Failed to get default endpoints: %v", err)
				h.metadataFetchErr = fmt.Errorf("failed to get default endpoints: %w", err)
				return
			}
			h.serverMetadata = metadata
			logrus.Infof("✅ MCP OAuth: Using default endpoints for base URL: %s", baseURL)
			logrus.Infof("📋 MCP OAuth: Default metadata - Issuer: %s, AuthZ: %s, Token: %s",
				metadata.Issuer, metadata.AuthorizationEndpoint, metadata.TokenEndpoint)
			return
		}

		// Parse the protected resource metadata
		var protectedResource OAuthProtectedResource
		if err := json.NewDecoder(bytes.NewReader(body)).Decode(&protectedResource); err != nil {
			logrus.Errorf("❌ MCP OAuth: Failed to decode protected resource response: %v", err)
			h.metadataFetchErr = fmt.Errorf("failed to decode protected resource response: %w", err)
			return
		}

		logrus.Infof("📋 MCP OAuth: Parsed protected resource - Resource: %s, AuthServers: %v",
			protectedResource.Resource, protectedResource.AuthorizationServers)

		// If no authorization servers are specified, fall back to default endpoints
		if len(protectedResource.AuthorizationServers) == 0 {
			logrus.Warnf("⚠️ MCP OAuth: No authorization servers found in protected resource, falling back to default endpoints")
			metadata, err := h.getDefaultEndpoints(baseURL)
			if err != nil {
				logrus.Errorf("❌ MCP OAuth: Failed to get default endpoints: %v", err)
				h.metadataFetchErr = fmt.Errorf("failed to get default endpoints: %w", err)
				return
			}
			h.serverMetadata = metadata
			logrus.Infof("✅ MCP OAuth: Using default endpoints for base URL: %s", baseURL)
			return
		}

		// Use the first authorization server
		authServerURL := protectedResource.AuthorizationServers[0]
		logrus.Infof("🎯 MCP OAuth: Using authorization server: %s", authServerURL)
		// FIXME: @zsw
		authServerURL = strings.TrimSuffix(authServerURL, "/")
		// Try OpenID Connect discovery first
		oidcURL := authServerURL + "/.well-known/openid-configuration"
		logrus.Infof("🔍 MCP OAuth: Trying OpenID Connect discovery: %s", oidcURL)
		h.fetchMetadataFromURL(ctx, oidcURL)
		if h.serverMetadata != nil {
			logrus.Infof("✅ MCP OAuth: Successfully fetched metadata via OpenID Connect discovery")
			return
		}

		// If OpenID Connect discovery fails, try OAuth Authorization Server Metadata
		oauthURL := authServerURL + "/.well-known/oauth-authorization-server"
		logrus.Infof("🔍 MCP OAuth: Trying OAuth Authorization Server discovery: %s", oauthURL)
		h.fetchMetadataFromURL(ctx, oauthURL)
		if h.serverMetadata != nil {
			logrus.Infof("✅ MCP OAuth: Successfully fetched metadata via OAuth Authorization Server discovery")
			return
		}

		// If both discovery methods fail, use default endpoints based on the authorization server URL
		logrus.Warnf("⚠️ MCP OAuth: Both discovery methods failed, falling back to default endpoints for auth server")
		metadata, err := h.getDefaultEndpoints(authServerURL)
		if err != nil {
			logrus.Errorf("❌ MCP OAuth: Failed to get default endpoints for auth server: %v", err)
			h.metadataFetchErr = fmt.Errorf("failed to get default endpoints: %w", err)
			return
		}
		h.serverMetadata = metadata
		logrus.Infof("✅ MCP OAuth: Using default endpoints for auth server: %s", authServerURL)
	})

	if h.metadataFetchErr != nil {
		logrus.Errorf("❌ MCP OAuth: Server metadata discovery failed: %v", h.metadataFetchErr)
		return nil, h.metadataFetchErr
	}

	logrus.Infof("✅ MCP OAuth: Server metadata discovery completed successfully")
	if h.serverMetadata != nil {
		logrus.Infof("📋 MCP OAuth: Final metadata - Issuer: %s, AuthZ: %s, Token: %s",
			h.serverMetadata.Issuer, h.serverMetadata.AuthorizationEndpoint, h.serverMetadata.TokenEndpoint)
	}
	return h.serverMetadata, nil
}

// fetchMetadataFromURL fetches and parses OAuth server metadata from a URL
func (h *OAuthHandler) fetchMetadataFromURL(ctx context.Context, metadataURL string) {
	logrus.Infof("🔗 MCP OAuth: Fetching metadata from URL: %s", metadataURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		logrus.Errorf("❌ MCP OAuth: Failed to create metadata request for %s: %v", metadataURL, err)
		h.metadataFetchErr = fmt.Errorf("failed to create metadata request: %w", err)
		return
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2025-03-26")
	logrus.Infof("📝 MCP OAuth: Metadata request headers: Accept=%s, MCP-Protocol-Version=%s",
		req.Header.Get("Accept"), req.Header.Get("MCP-Protocol-Version"))

	resp, err := h.httpClient.Do(req)
	if err != nil {
		logrus.Errorf("❌ MCP OAuth: Failed to send metadata request to %s: %v", metadataURL, err)
		h.metadataFetchErr = fmt.Errorf("failed to send metadata request: %w", err)
		return
	}
	defer resp.Body.Close()

	// Read response body for logging
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		logrus.Errorf("❌ MCP OAuth: Failed to read metadata response body from %s: %v", metadataURL, readErr)
		h.metadataFetchErr = fmt.Errorf("failed to read response body: %w", readErr)
		return
	}

	logrus.Infof("📥 MCP OAuth: Metadata response from %s - Status: %d, Body: %s",
		metadataURL, resp.StatusCode, string(body))

	if resp.StatusCode != http.StatusOK {
		logrus.Warnf("⚠️ MCP OAuth: Metadata discovery failed for %s with status %d", metadataURL, resp.StatusCode)
		// If metadata discovery fails, don't set any metadata
		return
	}

	var metadata AuthServerMetadata
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&metadata); err != nil {
		logrus.Errorf("❌ MCP OAuth: Failed to decode metadata response from %s: %v", metadataURL, err)
		h.metadataFetchErr = fmt.Errorf("failed to decode metadata response: %w", err)
		return
	}

	h.serverMetadata = &metadata
	logrus.Infof("✅ MCP OAuth: Successfully parsed metadata from %s", metadataURL)
	logrus.Infof("📋 MCP OAuth: Metadata details - Issuer: %s, AuthZ: %s, Token: %s, JWKS: %s",
		metadata.Issuer, metadata.AuthorizationEndpoint, metadata.TokenEndpoint, metadata.JwksURI)
}

// extractBaseURL extracts the base URL from the first request
func (h *OAuthHandler) extractBaseURL() (string, error) {
	logrus.Info("🔍 MCP OAuth: Extracting base URL...")

	// If we have a base URL from a previous request, use it
	if h.baseURL != "" {
		logrus.Infof("✅ MCP OAuth: Using cached base URL: %s", h.baseURL)
		return h.baseURL, nil
	}

	// Otherwise, we need to infer it from the redirect URI
	if h.config.RedirectURI == "" {
		logrus.Error("❌ MCP OAuth: No base URL available and no redirect URI provided")
		return "", fmt.Errorf("no base URL available and no redirect URI provided")
	}

	logrus.Infof("🔗 MCP OAuth: Inferring base URL from redirect URI: %s", h.config.RedirectURI)

	// Parse the redirect URI to extract the authority
	parsedURL, err := url.Parse(h.config.RedirectURI)
	if err != nil {
		logrus.Errorf("❌ MCP OAuth: Failed to parse redirect URI %s: %v", h.config.RedirectURI, err)
		return "", fmt.Errorf("failed to parse redirect URI: %w", err)
	}

	// Use the scheme and host from the redirect URI
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	logrus.Infof("✅ MCP OAuth: Extracted base URL: %s (scheme=%s, host=%s)",
		baseURL, parsedURL.Scheme, parsedURL.Host)
	return baseURL, nil
}

// GetServerMetadata is a public wrapper for getServerMetadata
func (h *OAuthHandler) GetServerMetadata(ctx context.Context) (*AuthServerMetadata, error) {
	return h.getServerMetadata(ctx)
}

// getDefaultEndpoints returns default OAuth endpoints based on the base URL
func (h *OAuthHandler) getDefaultEndpoints(baseURL string) (*AuthServerMetadata, error) {
	logrus.Infof("🛠️ MCP OAuth: Creating default endpoints for base URL: %s", baseURL)

	// Parse the base URL to extract the authority
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		logrus.Errorf("❌ MCP OAuth: Failed to parse base URL %s: %v", baseURL, err)
		return nil, fmt.Errorf("failed to parse base URL: %w", err)
	}

	logrus.Infof("🔍 MCP OAuth: Parsed URL - Scheme: %s, Host: %s, Path: %s",
		parsedURL.Scheme, parsedURL.Host, parsedURL.Path)

	// Discard any path component to get the authorization base URL
	parsedURL.Path = ""
	authBaseURL := parsedURL.String()

	logrus.Infof("🌐 MCP OAuth: Auth base URL (without path): %s", authBaseURL)

	// Validate that the URL has a scheme and host
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		logrus.Errorf("❌ MCP OAuth: Invalid base URL - missing scheme or host in %q", baseURL)
		return nil, fmt.Errorf("invalid base URL: missing scheme or host in %q", baseURL)
	}

	metadata := &AuthServerMetadata{
		Issuer:                authBaseURL,
		AuthorizationEndpoint: authBaseURL + "/authorize",
		TokenEndpoint:         authBaseURL + "/token",
		RegistrationEndpoint:  authBaseURL + "/register",
	}

	logrus.Infof("✅ MCP OAuth: Created default endpoints:")
	logrus.Infof("  📍 Issuer: %s", metadata.Issuer)
	logrus.Infof("  🔐 Authorization: %s", metadata.AuthorizationEndpoint)
	logrus.Infof("  🎫 Token: %s", metadata.TokenEndpoint)
	logrus.Infof("  📝 Registration: %s", metadata.RegistrationEndpoint)

	return metadata, nil
}

// RegisterClient performs dynamic client registration
func (h *OAuthHandler) RegisterClient(ctx context.Context, clientName string) error {
	metadata, err := h.getServerMetadata(ctx)
	if err != nil {
		return fmt.Errorf("failed to get server metadata: %w", err)
	}

	if metadata.RegistrationEndpoint == "" {
		return errors.New("server does not support dynamic client registration")
	}

	// Prepare registration request
	regRequest := map[string]any{
		"client_name":                clientName,
		"redirect_uris":              []string{h.config.RedirectURI},
		"token_endpoint_auth_method": "none", // For public clients
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"scope":                      strings.Join(h.config.Scopes, " "),
	}

	// Add client_secret if this is a confidential client
	if h.config.ClientSecret != "" {
		regRequest["token_endpoint_auth_method"] = "client_secret_basic"
	}

	reqBody, err := json.Marshal(regRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal registration request: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		metadata.RegistrationEndpoint,
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return fmt.Errorf("failed to create registration request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send registration request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return extractOAuthError(body, resp.StatusCode, "registration request failed")
	}

	var regResponse struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&regResponse); err != nil {
		return fmt.Errorf("failed to decode registration response: %w", err)
	}

	// Update the client configuration
	h.config.ClientID = regResponse.ClientID
	if regResponse.ClientSecret != "" {
		h.config.ClientSecret = regResponse.ClientSecret
	}

	return nil
}

// ErrInvalidState is returned when the state parameter doesn't match the expected value
var ErrInvalidState = errors.New("invalid state parameter, possible CSRF attack")

// ProcessAuthorizationResponse processes the authorization response and exchanges the code for a token
func (h *OAuthHandler) ProcessAuthorizationResponse(ctx context.Context, code, state, codeVerifier string) error {
	// Validate the state parameter to prevent CSRF attacks
	if h.expectedState == "" {
		return errors.New("no expected state found, authorization flow may not have been initiated properly")
	}

	if state != h.expectedState {
		return ErrInvalidState
	}

	// Clear the expected state after validation
	defer func() {
		h.expectedState = ""
	}()

	metadata, err := h.getServerMetadata(ctx)
	if err != nil {
		return fmt.Errorf("failed to get server metadata: %w", err)
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", h.config.ClientID)
	data.Set("redirect_uri", h.config.RedirectURI)

	// 根据 ClientType 判断是否使用 base64 编码的 Authorization header
	var authHeader string
	if h.config.ClientType == "confidential" {
		// 使用 client_secret_basic 认证方法
		// 将 client_id:client_secret 进行 base64 编码
		credentials := h.config.ClientID + ":" + h.config.ClientSecret
		encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
		authHeader = "Basic " + encoded
	} else if h.config.ClientSecret != "" {
		// 对于 public 客户端或未指定 ClientType 的情况，继续使用表单参数
		data.Set("client_secret", h.config.ClientSecret)
	}

	if h.config.PKCEEnabled && codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		metadata.TokenEndpoint,
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// 如果需要使用 Authorization header，则设置它
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return extractOAuthError(body, resp.StatusCode, "token request failed")
	}

	var tokenResp Token
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	// Set expiration time
	if tokenResp.ExpiresIn > 0 {
		tokenResp.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	// Save the token
	if err := h.config.TokenStore.SaveToken(&tokenResp); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	return nil
}

// GetAuthorizationURL returns the URL for the authorization endpoint
func (h *OAuthHandler) GetAuthorizationURL(ctx context.Context, state, codeChallenge string) (string, error) {
	metadata, err := h.getServerMetadata(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get server metadata: %w", err)
	}

	logrus.Infof("GetAuthorizationURL: %s", metadata.AuthorizationEndpoint)

	// Store the state for later validation
	h.expectedState = state

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", h.config.ClientID)
	params.Set("redirect_uri", h.config.RedirectURI)
	params.Set("state", state)

	if len(h.config.Scopes) > 0 {
		params.Set("scope", strings.Join(h.config.Scopes, " "))
	}

	if h.config.PKCEEnabled && codeChallenge != "" {
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")
	}

	return metadata.AuthorizationEndpoint + "?" + params.Encode(), nil
}

