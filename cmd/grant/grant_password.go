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

// PasswordCmdInput holds the necessary parameters for password grant.
type PasswordCmdInput struct {
	url          string
	username     string
	password     string
	clientId     string
	clientSecret string
	scope        string
	verbose      bool
}

// passwordCmdInput is an instance of PasswordCmdInput to store flag values.
var passwordCmdInput PasswordCmdInput

// passwordCmd represents the password command
var passwordCmd = &cobra.Command{
	Use:   "password",
	Short: "Authenticate using the password grant type",
	Long: `Authenticate using the OAuth 2.0 Password Grant Type.
This command allows direct input of the resource owner's credentials
(username and password) to obtain an access token directly.

Example:
  ./ocid password --url http://example.com --username user --password pass --client_id id --scope openid`,
	Run: func(cmd *cobra.Command, args []string) {

		passwordCmdInput.run()

	},
}

// init sets up the command and flags.
func init() {
	passwordCmd.Flags().StringVarP(&passwordCmdInput.url, "url", "", "", "OAuth server URL (required)")
	passwordCmd.Flags().StringVarP(&passwordCmdInput.username, "username", "u", "", "Username for authentication (required)")
	passwordCmd.Flags().StringVarP(&passwordCmdInput.password, "password", "p", "", "Password for authentication (required)")
	passwordCmd.Flags().StringVarP(&passwordCmdInput.clientId, "client_id", "c", "", "Client ID (required)")
	passwordCmd.Flags().StringVarP(&passwordCmdInput.clientSecret, "client_secret", "s", "", "Client Secret (optional)")
	passwordCmd.Flags().StringVarP(&passwordCmdInput.scope, "scope", "o", "", "Scope for the access request (required)")
	passwordCmd.Flags().BoolVarP(&passwordCmdInput.verbose, "verbose", "v", false, "Enable verbose")

	// Marking flags as required.
	requiredFlags := []string{"url", "username", "password", "client_id", "scope"}
	for _, flag := range requiredFlags {
		passwordCmd.MarkFlagRequired(flag)
	}
}

// run performs the OAuth2 password grant request.
func (i *PasswordCmdInput) run() {

	grantRequest := oauth2.GrantTypePasswordRequest{
		Username:     i.username,
		Password:     i.password,
		ClientID:     i.clientId,
		ClientSecret: i.clientSecret,
		Scope:        i.scope,
	}

	tokenEndpoint, err := oidc.DiscoverTokenEndpoint(i.url, i.verbose)
	if err != nil {
		fmt.Printf("Error discovering token endpoint: %v\n", err)
		return
	}
	response, err := oauth2.GrantPassword(&grantRequest, tokenEndpoint, i.verbose)
	if err != nil {
		fmt.Printf("Error during password grant: %v\n", err)
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
