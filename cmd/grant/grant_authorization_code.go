package grant

import (
	"fmt"
	"os"

	"github.com/eminwux/ocid/pkg/oauth2"
	"github.com/eminwux/ocid/pkg/oidc"

	"github.com/spf13/cobra"
)

type AuthorizationCodeCmdInput struct {
	url          string
	clientId     string
	clientSecret string
	scope        string
	pkce         bool
	pkceMethod   string
}

var authorizationCodeCmdInput AuthorizationCodeCmdInput

// authorizationCodeCmd represents the password command
var authorizationCodeCmd = &cobra.Command{
	Use:   "authorization_code",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {

		fmt.Printf("-- Starting OAuth Client Credentials Grant\n")

		fmt.Printf("\nParameters: \n")
		fmt.Printf("\turl: %s\n", authorizationCodeCmdInput.url)
		fmt.Printf("\tclient_id: %s\n", authorizationCodeCmdInput.clientId)
		fmt.Printf("\tclient_secret: %s\n", authorizationCodeCmdInput.clientSecret)
		fmt.Printf("\tscope: %s\n\n", authorizationCodeCmdInput.scope)

		if authorizationCodeCmdInput.pkce {
			switch authorizationCodeCmdInput.pkceMethod {
			case "plain", "S256":
				fmt.Printf("PKCE Method used: %s\n", authorizationCodeCmdInput.pkceMethod)
			default:
				fmt.Printf("Invalid PKCE method: %s\n", authorizationCodeCmdInput.pkceMethod)
				cmd.Usage()
				os.Exit(1)
			}
		}

		authorizationCodeCmdInput.run()

		fmt.Printf("-- Finished OAuth Client Credentials Grant\n")

	},
}

func init() {

	// cmd.RootCmd.AddCommand(authoricationCmd)

	authorizationCodeCmd.Flags().StringVarP(&authorizationCodeCmdInput.url, "url", "", "", "Url (required)")
	authorizationCodeCmd.Flags().StringVarP(&authorizationCodeCmdInput.clientId, "client_id", "c", "", "Client ID (required)")
	authorizationCodeCmd.Flags().StringVarP(&authorizationCodeCmdInput.clientSecret, "client_secret", "s", "", "Client Secret (required)")
	authorizationCodeCmd.Flags().StringVarP(&authorizationCodeCmdInput.scope, "scope", "o", "", "Scope (required)")

	authorizationCodeCmd.Flags().BoolVarP(&authorizationCodeCmdInput.pkce, "pkce", "", false, "Enable PKCE")
	authorizationCodeCmd.Flags().StringVarP(&authorizationCodeCmdInput.pkceMethod, "pkce-challenge-method", "", "plain", "Used together with --pkce to define challenge method (plain [default], S256)")

	// Mark flags as required
	authorizationCodeCmd.MarkFlagRequired("url")
	authorizationCodeCmd.MarkFlagRequired("client_id")
	authorizationCodeCmd.MarkFlagRequired("scope")
}

func (i *AuthorizationCodeCmdInput) run() {

	authorizationEndpoint, err := oidc.DiscoverAuthenticationEndpoint(i.url)
	if err != nil {
		fmt.Println(err)
	}
	tokenEndpoint, err := oidc.DiscoverTokenEndpoint(i.url)
	if err != nil {
		fmt.Println(err)
	}

	if i.pkce {

		grantRequest := oauth2.GrantTypeAuthorizationCodePKCERequest{
			ClientID:            i.clientId,
			Scope:               i.scope,
			CodeChallengeMethod: i.pkceMethod,
		}

		_, err = oauth2.GrantAuthorizationCodePKCE(&grantRequest, authorizationEndpoint, tokenEndpoint)
		if err != nil {
			fmt.Println(err)
		}

	} else {

		grantRequest := oauth2.GrantTypeAuthorizationCodeRequest{
			ClientID: i.clientId,
			Scope:    i.scope,
		}

		_, err = oauth2.GrantAuthorizationCode(&grantRequest, authorizationEndpoint, tokenEndpoint)
		if err != nil {
			fmt.Println(err)
		}

	}

}
