package oauth2

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/eminwux/ocid/pkg/jwt"
)

type GrantTypeAuthorizationCodePKCERequest struct {
	ResponseType        string `json:"response_type"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	CodeVerifier        string `json:"code_verifier"` // this is never sent to the AS
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// Shared structure to store token and control access
var tokenDataPKCE struct {
	Token string
	Mutex sync.Mutex
}
var tokenReadyPKCE = make(chan bool, 1) // Channel to signal when the token is ready

func exchangeCodePKCEForToken(grant *GrantTypeAuthorizationCodePKCERequest, tokenEndpoint string, code string) (*GrantTypeAuthorizationCodeResponse, error) {

	// Create the HTTP client
	client := &http.Client{}

	data := url.Values{}
	data.Set("grant_type", GRANT_TYPE_AUTHORIZATION_CODE)
	data.Set("code", code)
	data.Set("redirect_uri", buildRedirectURI())
	data.Set("client_id", grant.ClientID)
	data.Set("code_verifier", grant.CodeVerifier)

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

	jwt.DecodeJWT(result.AccessToken)

	return &result, nil
}

func GrantAuthorizationCodePKCE(grant *GrantTypeAuthorizationCodePKCERequest, authorizationEndpoint string, tokenEndpoint string) (string, error) {
	fmt.Printf("oidclib - initiating 'password' flow\n")

	// Define a closure that captures the 'grant' variable
	handleCallback := func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("authorization_code flow - callback has been hit\n")
		code := r.FormValue("code")
		fmt.Printf("authorization_code flow - received code=%s\n", code)
		fmt.Printf("authorization_code flow - retrieving access_token\n")

		token, err := exchangeCodePKCEForToken(grant, tokenEndpoint, code)
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

	if grant.CodeChallengeMethod != "" {
		verifier, challenge, err := generateCodeChallenge(grant.CodeChallengeMethod)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
		fmt.Println("Code Verifier:", verifier)
		fmt.Println("Code Challenge:", challenge)

		grant.CodeVerifier = verifier
		grant.CodeChallenge = challenge

		data.Set("code_challenge", grant.CodeChallenge)
		data.Set("code_challenge_method", grant.CodeChallengeMethod)
	}

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

// generateRandomString generates a URL-safe random string of specified length.
func generateRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b), nil
}

// generateCodeChallenge generates PKCE code verifier and challenge.
func generateCodeChallenge(method string) (verifier string, challenge string, err error) {
	// Generate a code verifier of length 43 to 128 characters
	verifier, err = generateRandomString(43)
	if err != nil {
		return "", "", fmt.Errorf("error generating code verifier: %w", err)
	}

	switch method {
	case "plain":
		// For plain, the challenge is the same as the verifier
		challenge = verifier
	case "S256":
		// For S256, the challenge is the SHA256 hash of the verifier, then base64url-encoded
		s256 := sha256.Sum256([]byte(verifier))
		challenge = base64.RawURLEncoding.EncodeToString(s256[:])
	default:
		return "", "", fmt.Errorf("unsupported method: %s", method)
	}

	return verifier, challenge, nil
}
