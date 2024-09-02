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

const GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials"

type GrantTypeClientCredentialsRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Scope        string `json:"scope"`
}

type GrantTypeClientCredentialsResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	IdToken          string `json:"id_token"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	Scope            string `json:"scope"`
	TokenType        string `json:"token_type"`
}

func GrantClientCredentials(grant *GrantTypeClientCredentialsRequest, tokenEndpoint string, verbose bool) (*GrantTypeClientCredentialsResponse, error) {
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

	// Convert the map to url.Values
	data := url.Values{}
	for key, value := range grantMap {
		data.Set(key, value)
	}

	logger.Verbose(verbose, "token endpoint set to %s\n", tokenEndpoint)
	logger.Verbose(verbose, "sending payload %s\n", data.Encode())

	// Create the HTTP client
	client := &http.Client{}

	// Create and set up the HTTP request
	req, err := http.NewRequest("POST", tokenEndpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Perform the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Check if the HTTP request was successful
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error from server: %s", body)
	}

	logger.Verbose(verbose, "got HTTP %d\n", http.StatusOK)

	logger.Verbose(verbose, "finished 'password' flow\n")

	// Unmarshal the JSON response
	var result GrantTypeClientCredentialsResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil

}
