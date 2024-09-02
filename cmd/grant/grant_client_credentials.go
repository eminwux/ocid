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

package grant

import (
	"encoding/json"
	"fmt"

	"github.com/eminwux/ocid/pkg/oauth2"
	"github.com/eminwux/ocid/pkg/oidc"

	"github.com/spf13/cobra"
)

// ClientCredentialsCmdInput holds the necessary parameters for client credentials grant.
type ClientCredentialsCmdInput struct {
	url          string
	clientId     string
	clientSecret string
	scope        string
	verbose      bool
}

// clientCredentialsCmdInput is an instance of ClientCredentialsCmdInput to store flag values.
var clientCredentialsCmdInput ClientCredentialsCmdInput

// clientCredentialsCmd represents the password command
var clientCredentialsCmd = &cobra.Command{
	Use:   "client_credentials",
	Short: "Authenticate using client credentials",
	Long: `Authenticate using the OAuth 2.0 Client Credentials Grant.
This command allows a confidential client to obtain an access token using its client credentials.

Example:
  ./ocid client_credentials --url http://example.com --client_id yourClientID --client_secret yourClientSecret --scope openid`,
	Run: func(cmd *cobra.Command, args []string) {
		clientCredentialsCmdInput.run()
	},
}

// init sets up the command and flags.
func init() {
	clientCredentialsCmd.Flags().StringVarP(&clientCredentialsCmdInput.url, "url", "", "", "OAuth server URL (required)")
	clientCredentialsCmd.Flags().StringVarP(&clientCredentialsCmdInput.clientId, "client_id", "c", "", "Client ID (required)")
	clientCredentialsCmd.Flags().StringVarP(&clientCredentialsCmdInput.clientSecret, "client_secret", "s", "", "Client Secret (required)")
	clientCredentialsCmd.Flags().StringVarP(&clientCredentialsCmdInput.scope, "scope", "o", "", "Scope for the access request (required)")
	clientCredentialsCmd.Flags().BoolVarP(&clientCredentialsCmdInput.verbose, "verbose", "v", false, "Enable verbose")

	// Marking flags as required.
	requiredFlags := []string{"url", "client_id", "client_secret", "scope"}
	for _, flag := range requiredFlags {
		clientCredentialsCmd.MarkFlagRequired(flag)
	}
}

// run performs the OAuth2 client credentials grant request.
func (i *ClientCredentialsCmdInput) run() {

	grantRequest := oauth2.GrantTypeClientCredentialsRequest{
		ClientID:     i.clientId,
		ClientSecret: i.clientSecret,
		Scope:        i.scope,
	}

	tokenEndpoint, err := oidc.DiscoverTokenEndpoint(i.url, i.verbose)
	if err != nil {
		fmt.Printf("Error discovering token endpoint: %v\n", err)
		return
	}
	response, err := oauth2.GrantClientCredentials(&grantRequest, tokenEndpoint, i.verbose)
	if err != nil {
		fmt.Printf("Error during client credentials grant: %v\n", err)
	}

	// Marshal the struct to JSON with indentation
	prettyJSON, err := json.MarshalIndent(response, "", "    ")
	if err != nil {
		fmt.Println("Failed to generate pretty JSON:", err)
		return
	}

	// Print the pretty JSON
	fmt.Println(string(prettyJSON))
}
