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
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/eminwux/ocid/pkg/logger"
)

const GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code"
const RESPONSE_TYPE = "code"
const REDIRECT_URI_SCHEMA = "http://"
const REDIRECT_URI_HOST = "localhost:8080"
const REDIRECT_URI_ENDPOINT = "callback"

type GrantTypeAuthorizationCodeRequest struct {
	GrantType           string `json:"grant_type"`
	ResponseType        string `json:"response_type"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

type GrantTypeAuthorizationCodeResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	IdToken          string `json:"id_token"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	Scope            string `json:"scope"`
	SessionState     string `json:"session_state"`
	TokenType        string `json:"token_type"`
}

// Shared structure to store token and control access
var tokenData struct {
	Response *GrantTypeAuthorizationCodeResponse
	Mutex    sync.Mutex
}
var tokenReady = make(chan bool, 1) // Channel to signal when the token is ready

func exchangeCodeForToken(grant *GrantTypeAuthorizationCodeRequest, tokenEndpoint string, code string, verbose bool) (*GrantTypeAuthorizationCodeResponse, error) {

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
	grantMap["grant_type"] = GRANT_TYPE_AUTHORIZATION_CODE
	grantMap["code"] = code
	grantMap["redirect_uri"] = buildRedirectURI()

	// Convert the map to url.Values
	data := url.Values{}
	for key, value := range grantMap {
		data.Set(key, value)
	}

	logger.Verbose(verbose, "authorization_code flow - token endpoint set to %s\n", tokenEndpoint)
	logger.Verbose(verbose, "authorization_code flow - sending payload %s\n", data.Encode())

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

	// Unmarshal the JSON response
	var result GrantTypeAuthorizationCodeResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func GrantAuthorizationCode(grant *GrantTypeAuthorizationCodeRequest, authorizationEndpoint string, tokenEndpoint string, verbose bool) (*GrantTypeAuthorizationCodeResponse, error) {
	logger.Verbose(verbose, "initiating '%s' flow\n", GRANT_TYPE_AUTHORIZATION_CODE)

	// Define a closure that captures the 'grant' variable
	handleCallback := func(w http.ResponseWriter, r *http.Request) {
		logger.Verbose(verbose, "authorization_code flow - callback has been hit\n")
		code := r.FormValue("code")
		logger.Verbose(verbose, "authorization_code flow - received code=%s\n", code)
		logger.Verbose(verbose, "authorization_code flow - retrieving access_token\n")

		response, err := exchangeCodeForToken(grant, tokenEndpoint, code, verbose)
		if err != nil {
			logger.Verbose(verbose, "Failed to exchange token:%s ", err.Error())
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			if flusher, ok := w.(http.Flusher); ok {
				// Flush the buffered data to the client
				flusher.Flush()
			} else {
				// Handle the case where flushing is not supported
				http.Error(w, "Flushing not supported", http.StatusInternalServerError)
			}
			tokenReady <- true
			return
		}

		logger.Verbose(verbose, "authorization_code flow - received access_token\n")

		// Lock the mutex to safely update the global tokenData
		tokenData.Mutex.Lock()
		// tokenData.Token = token.AccessToken
		tokenData.Response = response
		tokenData.Mutex.Unlock()

		// Signal that the token is ready
		tokenReady <- true

		// Message sent back to the final user
		fmt.Fprintf(w, "Authentication successful. You can close this window.")
	}

	// Set up HTTP server
	// http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	// 	http.Redirect(w, r, oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline), http.StatusTemporaryRedirect)
	// })

	http.HandleFunc("/callback", handleCallback)

	go func() {
		// fmt.Println("Started running on http://localhost:8080")
		log.Fatal(http.ListenAndServe(":8080", nil))
	}()

	data := url.Values{}
	data.Set("response_type", RESPONSE_TYPE)
	data.Set("scope", grant.Scope)
	data.Set("client_id", grant.ClientID)

	redirect_uri := buildRedirectURI()
	data.Set("redirect_uri", redirect_uri)

	// Print the URL for the user to visit
	fmt.Fprintf(os.Stderr, "Please visit the following URL to log in: ")
	fmt.Fprintf(os.Stderr, "%s?%s\n", authorizationEndpoint, data.Encode())

	// Wait for the token to be ready
	<-tokenReady

	logger.Verbose(verbose, "finished '%s' flow\n", GRANT_TYPE_AUTHORIZATION_CODE)

	return tokenData.Response, nil
}

func buildRedirectURI() string {
	return REDIRECT_URI_SCHEMA + REDIRECT_URI_HOST + "/" + REDIRECT_URI_ENDPOINT
}
