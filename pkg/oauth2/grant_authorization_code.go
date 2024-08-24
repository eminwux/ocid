package oauth2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
)

const GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code"
const RESPONSE_TYPE = "code"
const REDIRECT_URI_SCHEMA = "http://"
const REDIRECT_URI_HOST = "localhost:8080"
const REDIRECT_URI_ENDPOINT = "callback"

type GrantTypeAuthorizationCodeRequest struct {
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
	Token string
	Mutex sync.Mutex
}
var tokenReady = make(chan bool, 1) // Channel to signal when the token is ready

func exchangeCodeForToken(grant *GrantTypeAuthorizationCodeRequest, tokenEndpoint string, code string) (*GrantTypeAuthorizationCodeResponse, error) {

	// Create the HTTP client
	client := &http.Client{}

	data := url.Values{}
	data.Set("grant_type", GRANT_TYPE_AUTHORIZATION_CODE)
	data.Set("code", code)
	data.Set("redirect_uri", buildRedirectURI())
	data.Set("client_id", grant.ClientID)

	fmt.Printf("authorization_code flow - token endpoint set to %s\n", tokenEndpoint)
	fmt.Printf("authorization_code flow - sending payload %s\n", data.Encode())

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

	fmt.Printf("oidclib - got HTTP %d\n", http.StatusOK)

	// Unmarshal the JSON response
	// var result map[string]interface{}
	var result GrantTypeAuthorizationCodeResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	// Marshal the JSON data into a pretty-printed format
	prettyJSON, err := json.MarshalIndent(result, "", "    ")
	if err != nil {
		return nil, fmt.Errorf("error marshaling JSON for pretty print: %v", err)
	}

	// Print the pretty JSON
	fmt.Println(string(prettyJSON))

	return &result, nil
}

func GrantAuthorizationCode(grant *GrantTypeAuthorizationCodeRequest, authorizationEndpoint string, tokenEndpoint string) (string, error) {
	fmt.Printf("oidclib - initiating 'password' flow\n")

	// Define a closure that captures the 'grant' variable
	handleCallback := func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("authorization_code flow - callback has been hit\n")
		code := r.FormValue("code")
		fmt.Printf("authorization_code flow - received code=%s\n", code)
		fmt.Printf("authorization_code flow - retrieving access_token\n")

		token, err := exchangeCodeForToken(grant, tokenEndpoint, code)
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Printf("authorization_code flow - received access_token\n")

		// Lock the mutex to safely update the global tokenData
		tokenData.Mutex.Lock()
		// tokenData.Token = token.AccessToken
		tokenData.Token = token.AccessToken
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
	fmt.Println("Please visit the following URL to log in:")
	fmt.Printf("%s?%s\n", authorizationEndpoint, data.Encode())

	// Wait for the token to be ready
	<-tokenReady

	fmt.Printf("oidclib - go\n")

	fmt.Printf("oidclib - finished 'password' flow\n")

	accessToken := "asd"
	return accessToken, nil
}

func buildRedirectURI() string {
	return REDIRECT_URI_SCHEMA + REDIRECT_URI_HOST + "/" + REDIRECT_URI_ENDPOINT
}
