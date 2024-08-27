package grant

import (
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

		fmt.Printf("-- Starting OAuth Client Assertion JWT Grant\n")

		// Display input parameters for clarity
		fmt.Printf("\nParameters: \n")
		fmt.Printf("\turl: %s\n", clientAssertionCmdInput.url)
		fmt.Printf("\tclient_id: %s\n", clientAssertionCmdInput.clientId)
		fmt.Printf("\tclient_assertion: %s\n", clientAssertionCmdInput.clientAssertionJWT)
		fmt.Printf("\tscope: %s\n\n", clientAssertionCmdInput.scope)

		// Execute the grant request
		clientAssertionCmdInput.run()

		fmt.Printf("-- Finished OAuth Client Assertion JWT Grant\n")
	},
}

func init() {

	// Register the command and its flags
	clientAssertionJWTCmd.Flags().StringVarP(&clientAssertionCmdInput.url, "url", "", "", "The OIDC endpoint URL (required)")
	clientAssertionJWTCmd.Flags().StringVarP(&clientAssertionCmdInput.clientId, "client_id", "c", "", "Client ID for authentication (required)")
	clientAssertionJWTCmd.Flags().StringVarP(&clientAssertionCmdInput.clientAssertionJWT, "client_assertion_jwt", "j", "", "JWT used for client assertion (required)")
	clientAssertionJWTCmd.Flags().StringVarP(&clientAssertionCmdInput.scope, "scope", "o", "", "Scope of the access request (required)")

	// Mark certain flags as required
	clientAssertionJWTCmd.MarkFlagRequired("url")
	clientAssertionJWTCmd.MarkFlagRequired("client_assertion_jwt")
	clientAssertionJWTCmd.MarkFlagRequired("scope")
}

// run executes the client assertion JWT grant process
func (i *ClientAssertionCmdInput) run() {

	// Construct the grant request
	grantRequest := oauth2.GrantTypeClientAssertionJWT{
		ClientID:           i.clientId,
		ClientAssertionJWT: i.clientAssertionJWT,
		Scope:              i.scope,
	}

	// Discover the token endpoint from the provided URL
	tokenEndpoint, err := oidc.DiscoverTokenEndpoint(i.url)
	if err != nil {
		fmt.Println("Error discovering token endpoint:", err)
		return
	}

	// Attempt to obtain the access token using the client assertion JWT grant
	_, err = oauth2.GrantClientAssertionJWT(&grantRequest, tokenEndpoint)
	if err != nil {
		fmt.Println("Error obtaining access token:", err)
		return
	}

	fmt.Println("Access token obtained successfully.")
}
