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
	"os"

	"github.com/eminwux/ocid/pkg/oauth2"
	"github.com/eminwux/ocid/pkg/oidc"

	"github.com/spf13/cobra"
)

// AuthorizationCodeCmdInput holds the necessary parameters for authorization code grant.
type AuthorizationCodeCmdInput struct {
	url          string
	clientId     string
	clientSecret string
	scope        string
	pkce         bool
	pkceMethod   string
	verbose      bool
}

var authorizationCodeCmdInput AuthorizationCodeCmdInput

// authorizationCodeCmd represents the password command
var authorizationCodeCmd = &cobra.Command{
	Use:   "authorization_code",
	Short: "Authenticate using the authorization code grant",
	Long: `Authenticate using the OAuth 2.0 Authorization Code Grant with optional PKCE.
This command initiates the flow where the client first redirects a user to an authorization server,
then the user logs in, and finally the client receives an authorization code that is used to get an access token.

Example:
  ./ocid authorization_code --url http://example.com --client_id yourClientID --client_secret yourClientSecret --scope openid --pkce --pkce-challenge-method S256`,
	Run: func(cmd *cobra.Command, args []string) {

		if authorizationCodeCmdInput.pkce {
			switch authorizationCodeCmdInput.pkceMethod {
			case "plain", "S256":
				break
			default:
				fmt.Printf("Invalid PKCE method: %s\n", authorizationCodeCmdInput.pkceMethod)
				cmd.Usage()
				os.Exit(1)
			}
		}

		authorizationCodeCmdInput.run()

	},
}

// init sets up the command and flags.
func init() {
	authorizationCodeCmd.Flags().StringVarP(&authorizationCodeCmdInput.url, "url", "", "", "Url (required)")
	authorizationCodeCmd.Flags().StringVarP(&authorizationCodeCmdInput.clientId, "client_id", "c", "", "Client ID (required)")
	authorizationCodeCmd.Flags().StringVarP(&authorizationCodeCmdInput.clientSecret, "client_secret", "s", "", "Client Secret (required)")
	authorizationCodeCmd.Flags().StringVarP(&authorizationCodeCmdInput.scope, "scope", "o", "", "Scope (required)")
	authorizationCodeCmd.Flags().BoolVarP(&authorizationCodeCmdInput.verbose, "verbose", "v", false, "Enable verbose")

	authorizationCodeCmd.Flags().BoolVarP(&authorizationCodeCmdInput.pkce, "pkce", "", false, "Enable PKCE")
	authorizationCodeCmd.Flags().StringVarP(&authorizationCodeCmdInput.pkceMethod, "pkce-challenge-method", "", "plain", "Used together with --pkce to define challenge method (plain [default], S256)")

	requiredFlags := []string{"url", "client_id", "scope"}
	for _, flag := range requiredFlags {
		authorizationCodeCmd.MarkFlagRequired(flag)
	}
}

func (i *AuthorizationCodeCmdInput) run() {

	// Discover endpoints from the authorization server
	authorizationEndpoint, err := oidc.DiscoverAuthenticationEndpoint(i.url, i.verbose)
	if err != nil {
		fmt.Println("failed to discover authentication endpoint: ", err)
		return

	}
	tokenEndpoint, err := oidc.DiscoverTokenEndpoint(i.url, i.verbose)
	if err != nil {
		fmt.Println("failed to discover token endpoint: %w", err)
		return
	}

	var response interface{}

	if i.pkce {

		grantRequest := oauth2.GrantTypeAuthorizationCodePKCERequest{
			ClientID:            i.clientId,
			Scope:               i.scope,
			CodeChallengeMethod: i.pkceMethod,
		}

		response, err = oauth2.GrantAuthorizationCodePKCE(&grantRequest, authorizationEndpoint, tokenEndpoint, i.verbose)
		if err != nil {
			fmt.Println(err)
		}

	} else {

		grantRequest := oauth2.GrantTypeAuthorizationCodeRequest{
			ClientID: i.clientId,
			Scope:    i.scope,
		}

		response, err = oauth2.GrantAuthorizationCode(&grantRequest, authorizationEndpoint, tokenEndpoint, i.verbose)
		if err != nil {
			fmt.Println(err)
		}

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
