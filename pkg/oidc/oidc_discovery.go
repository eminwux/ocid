/*
The MIT License (MIT)

Copyright (c) 2024 Emiliano Spinella (eminwux)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package oidc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/eminwux/ocid/pkg/logger"
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
func DiscoverTokenEndpoint(issuerURL string, verbose bool) (string, error) {
	logger.Verbose(verbose, "starting discovering OIDC token endpoint for %s\n", issuerURL)

	config, _ := RetrieveOIDCConfiguration(issuerURL)

	// Check if the token endpoint is available
	if config.TokenEndpoint == "" {
		return "", fmt.Errorf("token endpoint not found in OIDC configuration")
	}
	logger.Verbose(verbose, "OIDC token endpoint discovered: %s\n", config.TokenEndpoint)

	logger.Verbose(verbose, "finished discovering OIDC token endpoint for %s\n", issuerURL)
	return config.TokenEndpoint, nil
}

// DiscoverTokenEndpoint discovers the token endpoint from the OIDC provider's configuration
func DiscoverAuthenticationEndpoint(issuerURL string, verbose bool) (string, error) {
	logger.Verbose(verbose, "starting discovering OIDC authentication endpoint for %s\n", issuerURL)

	config, _ := RetrieveOIDCConfiguration(issuerURL)

	// Check if the token endpoint is available
	if config.AuthorizationEndpoint == "" {
		return "", fmt.Errorf("authentication endpoint not found in OIDC configuration")
	}
	logger.Verbose(verbose, "OIDC authentication endpoint discovered: %s\n", config.AuthorizationEndpoint)

	logger.Verbose(verbose, "finished discovering OIDC authentication endpoint for %s\n", issuerURL)
	return config.AuthorizationEndpoint, nil
}
