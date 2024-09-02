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

package oauth2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/eminwux/ocid/pkg/logger"
)

const GRANT_TYPE = "client_credentials"
const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// GrantTypeClientAssertionJWTRequest represents the structure of the payload for the Client Assertion JWT grant
type GrantTypeClientAssertionJWTRequest struct {
	GrantType          string `json:"grant_type"`
	ClientID           string `json:"client_id"`
	ClientAssertionJWT string `json:"client_assertion"`
	Scope              string `json:"scope"`
}

type GrantTypeClientAssertionJWTResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    string `json:"expires_in"`
	ExpiresOn    string `json:"expires_on"`
	ExtExpiresIn string `json:"ext_expires_in"`
	NotBefore    string `json:"not_before"`
	Resource     string `json:"resource"`
	TokenType    string `json:"token_type"`
}

// GrantClientAssertionJWT handles the OAuth2 Client Assertion JWT grant flow
func GrantClientAssertionJWT(grant *GrantTypeClientAssertionJWTRequest, tokenEndpoint string, verbose bool) (*GrantTypeClientAssertionJWTResponse, error) {
	// logger.Verbose(verbose, "initiating "+GRANT_TYPE+" flow")
	// // Construct the form data payload
	// data := url.Values{}
	// data.Set("grant_type", GRANT_TYPE)
	// data.Set("client_assertion_type", CLIENT_ASSERTION_TYPE)

	// // Add optional parameters to the payload if they are provided
	// if grant.ClientID != "" {
	// 	data.Set("client_id", grant.ClientID)
	// }

	// if grant.ClientAssertionJWT != "" {
	// 	data.Set("client_assertion", grant.ClientAssertionJWT)
	// }

	// data.Set("scope", grant.Scope)

	logger.Verbose(verbose, "initiating '%s' flow", GRANT_TYPE_CLIENT_CREDENTIALS)

	// Convert the struct to a map
	grantMap := make(map[string]string)

	// Marshal the struct to JSON and then to a map
	jsonData, err := json.Marshal(grant)
	if err != nil {
		return nil, fmt.Errorf("error marshaling struct to JSON: %v", err)
	}
	if err := json.Unmarshal(jsonData, &grantMap); err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON to map: %v", err)
	}

	// Add the mandatory grant_type field
	grantMap["grant_type"] = GRANT_TYPE_CLIENT_CREDENTIALS
	grantMap["client_assertion_type"] = CLIENT_ASSERTION_TYPE

	// Convert the map to url.Values
	data := url.Values{}
	for key, value := range grantMap {
		data.Set(key, value)
	}
	logger.Verbose(verbose, "token endpoint set to %s\n", tokenEndpoint)
	logger.Verbose(verbose, "sending payload %s\n", data.Encode())

	// Create the HTTP client for making requests
	client := &http.Client{}

	// Create and set up the HTTP request
	req, err := http.NewRequest("POST", tokenEndpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("error creating HTTP request: %v", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Perform the HTTP request to the token endpoint
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing HTTP request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body from the server
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	// Check if the HTTP request was successful (HTTP 200 OK)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error from server: %s (HTTP %d)", string(body), resp.StatusCode)
	}

	logger.Verbose(verbose, "received HTTP %d\n", http.StatusOK)

	// Parse the JSON response
	var result GrantTypeClientAssertionJWTResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON response: %v", err)
	}

	// Format the JSON response for easier reading
	prettyJSON, err := json.MarshalIndent(result, "", "    ")
	if err != nil {
		return nil, fmt.Errorf("error formatting JSON response: %v", err)
	}

	// Display the formatted JSON response
	logger.Verbose(verbose, "received response: %s\n", string(prettyJSON))

	logger.Verbose(verbose, "finished 'client_credentials' flow successfully")
	return &result, nil
}
