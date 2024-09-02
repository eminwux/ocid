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

// ClientAssertionCmdInput holds the input parameters for the client assertion JWT command
type ClientAssertionCmdInput struct {
	url                string
	clientId           string
	clientAssertionJWT string
	scope              string
	verbose            bool
}

var clientAssertionCmdInput ClientAssertionCmdInput

// clientAssertionJWTCmd represents the client_assertion_jwt command
var clientAssertionJWTCmd = &cobra.Command{
	Use:   "client_assertion_jwt",
	Short: "Request an OAuth 2.0 token using Client Assertion JWT Grant",
	Long: `This command allows you to obtain an OAuth 2.0 access token using the Client Assertion JWT Grant type.
	
The Client Assertion JWT Grant is typically used in situations where a client needs to authenticate using a JWT
instead of a client secret. This method is often employed by confidential clients like microservices, where JWTs
are used for authentication.

Examples of usage:

1. To obtain a token:
   ./your-cli client_assertion_jwt --url https://example.com/ --client_id your-client-id --client_assertion_jwt your-jwt --scope your-scope

2. To use in scripts or automation:
   ./your-cli client_assertion_jwt -c your-client-id -j your-jwt -o your-scope --url https://example.com/`,
	Run: func(cmd *cobra.Command, args []string) {
		clientAssertionCmdInput.run()
	},
}

// init sets up the command and flags.
func init() {

	// Register the command and its flags
	clientAssertionJWTCmd.Flags().StringVarP(&clientAssertionCmdInput.url, "url", "", "", "The OIDC endpoint URL (required)")
	clientAssertionJWTCmd.Flags().StringVarP(&clientAssertionCmdInput.clientId, "client_id", "c", "", "Client ID for authentication (required)")
	clientAssertionJWTCmd.Flags().StringVarP(&clientAssertionCmdInput.clientAssertionJWT, "client_assertion_jwt", "j", "", "JWT used for client assertion (required)")
	clientAssertionJWTCmd.Flags().StringVarP(&clientAssertionCmdInput.scope, "scope", "o", "", "Scope of the access request (required)")
	clientAssertionJWTCmd.Flags().BoolVarP(&clientAssertionCmdInput.verbose, "verbose", "v", false, "Enable verbose")

	// Mark certain flags as required
	clientAssertionJWTCmd.MarkFlagRequired("url")
	clientAssertionJWTCmd.MarkFlagRequired("client_assertion_jwt")
	clientAssertionJWTCmd.MarkFlagRequired("scope")
}

// run executes the client assertion JWT grant process
func (i *ClientAssertionCmdInput) run() {

	// Construct the grant request
	grantRequest := oauth2.GrantTypeClientAssertionJWTRequest{
		ClientID:           i.clientId,
		ClientAssertionJWT: i.clientAssertionJWT,
		Scope:              i.scope,
	}

	// Discover the token endpoint from the provided URL
	tokenEndpoint, err := oidc.DiscoverTokenEndpoint(i.url, i.verbose)
	if err != nil {
		fmt.Println("Error discovering token endpoint:", err)
		return
	}

	// Attempt to obtain the access token using the client assertion JWT grant
	response, err := oauth2.GrantClientAssertionJWT(&grantRequest, tokenEndpoint, i.verbose)
	if err != nil {
		fmt.Println("Error obtaining access token:", err)
		return
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
