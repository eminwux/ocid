package grant

import (
	"fmt"

	"github.com/eminwux/ocid/pkg/oauth2"
	"github.com/eminwux/ocid/pkg/oidc"

	"github.com/spf13/cobra"
)

type ClientCredentialsCmdInput struct {
	url          string
	clientId     string
	clientSecret string
	scope        string
}

var clientCredentialsCmdInput ClientCredentialsCmdInput

// clientCredentialsCmd represents the password command
var clientCredentialsCmd = &cobra.Command{
	Use:   "client_credentials",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {

		fmt.Printf("-- Starting OAuth Client Credentials Grant\n")

		fmt.Printf("\nParameters: \n")
		fmt.Printf("\turl: %s\n", clientCredentialsCmdInput.url)
		fmt.Printf("\tclient_id: %s\n", clientCredentialsCmdInput.clientId)
		fmt.Printf("\tclient_secret: %s\n", clientCredentialsCmdInput.clientSecret)
		fmt.Printf("\tscope: %s\n\n", clientCredentialsCmdInput.scope)

		clientCredentialsCmdInput.run()

		fmt.Printf("-- Finished OAuth Client Credentials Grant\n")

	},
}

func init() {

	// cmd.RootCmd.AddCommand(authoricationCmd)

	clientCredentialsCmd.Flags().StringVarP(&clientCredentialsCmdInput.url, "url", "", "", "Url (required)")
	clientCredentialsCmd.Flags().StringVarP(&clientCredentialsCmdInput.clientId, "client_id", "c", "", "Client ID (required)")
	clientCredentialsCmd.Flags().StringVarP(&clientCredentialsCmdInput.clientSecret, "client_secret", "s", "", "Client Secret (required)")
	clientCredentialsCmd.Flags().StringVarP(&clientCredentialsCmdInput.scope, "scope", "o", "", "Scope (required)")

	// Mark flags as required
	clientCredentialsCmd.MarkFlagRequired("url")
	clientCredentialsCmd.MarkFlagRequired("client_id")
	clientCredentialsCmd.MarkFlagRequired("scope")
}

func (i *ClientCredentialsCmdInput) run() {

	grantRequest := oauth2.GrantTypeClientCredentials{
		ClientID:     i.clientId,
		ClientSecret: i.clientSecret,
		Scope:        i.scope,
	}

	tokenEndpoint, err := oidc.DiscoverTokenEndpoint(i.url)
	if err != nil {
		fmt.Println(err)
	}
	_, err = oauth2.GrantClientCredentials(&grantRequest, tokenEndpoint)
	if err != nil {
		fmt.Println(err)
	}
}
