package oauth2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const GRANT_TYPE_PASSWORD = "password"

type GrantTypePassword struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Scope        string `json:"scope"`
}

func GrantPassword(grant *GrantTypePassword, tokenEndpoint string) (string, error) {
	fmt.Printf("oidclib - initiating 'password' flow\n")

	// Create the HTTP client
	client := &http.Client{}

	data := url.Values{}
	data.Set("grant_type", GRANT_TYPE_PASSWORD)
	data.Set("client_id", grant.ClientID)

	if grant.ClientSecret != "" {
		data.Set("client_secret", grant.ClientSecret)
	}

	data.Set("username", grant.Username)
	data.Set("password", grant.Password)
	data.Set("scope", grant.Scope)

	fmt.Printf("oidclib - token endpoint set to %s\n", tokenEndpoint)
	fmt.Printf("oidclib - sending payload %s\n", data.Encode())

	// Create and set up the HTTP request
	req, err := http.NewRequest("POST", tokenEndpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Perform the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Check if the HTTP request was successful
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error from server: %s", body)
	}

	fmt.Printf("oidclib - got HTTP %d\n", http.StatusOK)

	// Unmarshal the JSON response
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	// Marshal the JSON data into a pretty-printed format
	prettyJSON, err := json.MarshalIndent(result, "", "    ")
	if err != nil {
		return "", fmt.Errorf("error marshaling JSON for pretty print: %v", err)
	}

	// Print the pretty JSON
	fmt.Println(string(prettyJSON))

	// Extract the access token from the response
	accessToken, ok := result["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("access token not found in the response")
	}

	fmt.Printf("oidclib - finished 'password' flow\n")
	return accessToken, nil

}
