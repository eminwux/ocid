package oauth2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const GRANT_TYPE = "client_credentials"
const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// GrantTypeClientAssertionJWT represents the structure of the payload for the Client Assertion JWT grant
type GrantTypeClientAssertionJWT struct {
	ClientID           string `json:"client_id"`
	ClientAssertionJWT string `json:"client_assertion"`
	Scope              string `json:"scope"`
}

// GrantClientAssertionJWT handles the OAuth2 Client Assertion JWT grant flow
func GrantClientAssertionJWT(grant *GrantTypeClientAssertionJWT, tokenEndpoint string) (string, error) {
	fmt.Println("oidclib - initiating " + GRANT_TYPE + " flow")

	// Create the HTTP client for making requests
	client := &http.Client{}

	// Construct the form data payload
	data := url.Values{}
	data.Set("grant_type", GRANT_TYPE)
	data.Set("client_assertion_type", CLIENT_ASSERTION_TYPE)

	// Add optional parameters to the payload if they are provided
	if grant.ClientID != "" {
		data.Set("client_id", grant.ClientID)
	}

	if grant.ClientAssertionJWT != "" {
		data.Set("client_assertion", grant.ClientAssertionJWT)
	}

	data.Set("scope", grant.Scope)

	fmt.Printf("oidclib - token endpoint set to %s\n", tokenEndpoint)

	// Display the payload that will be sent to the server
	fmt.Printf("oidclib - sending payload:\n%s\n", data.Encode())

	// Create and set up the HTTP request
	req, err := http.NewRequest("POST", tokenEndpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("error creating HTTP request: %v", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Perform the HTTP request to the token endpoint
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error performing HTTP request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body from the server
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %v", err)
	}

	// Check if the HTTP request was successful (HTTP 200 OK)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error from server: %s (HTTP %d)", string(body), resp.StatusCode)
	}

	fmt.Printf("oidclib - received HTTP %d\n", http.StatusOK)

	// Parse the JSON response
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("error unmarshaling JSON response: %v", err)
	}

	// Format the JSON response for easier reading
	prettyJSON, err := json.MarshalIndent(result, "", "    ")
	if err != nil {
		return "", fmt.Errorf("error formatting JSON response: %v", err)
	}

	// Display the formatted JSON response
	fmt.Println("oidclib - received response:\n", string(prettyJSON))

	// Extract the access token from the response
	accessToken, ok := result["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("access token not found in the response")
	}

	fmt.Println("oidclib - finished 'client_credentials' flow successfully")
	return accessToken, nil
}
