package oidc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// OIDCConfig represents the necessary fields from the OIDC discovery document
type OIDCConfig struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JwksUri               string `json:"jwks_uri"`
}

func RetrieveOIDCConfiguration(issuerURL string) (*OIDCConfig, error) {

	// Form the URL to the OpenID configuration
	configURL := issuerURL + "/.well-known/openid-configuration"

	// Make the HTTP GET request to the configuration URL
	resp, err := http.Get(configURL)
	if err != nil {
		return nil, fmt.Errorf("error making request to OIDC configuration: %v", err)
	}
	defer resp.Body.Close()

	// Read and decode the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading OIDC configuration response: %v", err)
	}

	var config OIDCConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, fmt.Errorf("error unmarshaling OIDC configuration: %v", err)
	}

	return &config, nil

}

// DiscoverTokenEndpoint discovers the token endpoint from the OIDC provider's configuration
func DiscoverTokenEndpoint(issuerURL string) (string, error) {
	fmt.Printf("oidclib - starting discovering OIDC token endpoint for %s\n", issuerURL)

	config, _ := RetrieveOIDCConfiguration(issuerURL)

	// Check if the token endpoint is available
	if config.TokenEndpoint == "" {
		return "", fmt.Errorf("token endpoint not found in OIDC configuration")
	}
	fmt.Printf("oidclib - OIDC token endpoint discovered: %s\n", config.TokenEndpoint)

	fmt.Printf("oidclib - finished discovering OIDC token endpoint for %s\n", issuerURL)
	return config.TokenEndpoint, nil
}

// DiscoverTokenEndpoint discovers the token endpoint from the OIDC provider's configuration
func DiscoverAuthenticationEndpoint(issuerURL string) (string, error) {
	fmt.Printf("oidclib - starting discovering OIDC authentication endpoint for %s\n", issuerURL)

	config, _ := RetrieveOIDCConfiguration(issuerURL)

	// Check if the token endpoint is available
	if config.AuthorizationEndpoint == "" {
		return "", fmt.Errorf("authentication endpoint not found in OIDC configuration")
	}
	fmt.Printf("oidclib - OIDC authentication endpoint discovered: %s\n", config.AuthorizationEndpoint)

	fmt.Printf("oidclib - finished discovering OIDC authentication endpoint for %s\n", issuerURL)
	return config.AuthorizationEndpoint, nil
}
