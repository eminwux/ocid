/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package grant

import (
	"fmt"

	"github.com/eminwux/ocid/pkg/oauth2"
	"github.com/eminwux/ocid/pkg/oidc"

	"github.com/spf13/cobra"
)

type PasswordCmdInput struct {
	url          string
	username     string
	password     string
	clientId     string
	clientSecret string
	scope        string
}

var passwordCmdInput PasswordCmdInput

// passwordCmd represents the password command
var passwordCmd = &cobra.Command{
	Use:   "password",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {

		fmt.Printf("-- Starting OAuth Resource Owner Password Credentials (ROPC) Grant\n")
		fmt.Printf("\nParameters: \n")
		fmt.Printf("\turl: %s\n", passwordCmdInput.url)
		fmt.Printf("\tusername: %s\n", passwordCmdInput.username)
		fmt.Printf("\tpassword: %s\n", passwordCmdInput.password)
		fmt.Printf("\tclient_id: %s\n", passwordCmdInput.clientId)
		if passwordCmdInput.clientSecret != "" {
			fmt.Printf("\tclient_secret: %s\n", passwordCmdInput.clientSecret)
		}
		fmt.Printf("\tscope: %s\n\n", passwordCmdInput.scope)

		passwordCmdInput.run()

		fmt.Printf("-- Finished OAuth Resource Owner Password Credentials (ROPC) Grant\n")

	},
}

func init() {

	// cmd.RootCmd.AddCommand(PasswordCmd)

	passwordCmd.Flags().StringVarP(&passwordCmdInput.url, "url", "", "", "Url (required)")
	passwordCmd.Flags().StringVarP(&passwordCmdInput.username, "username", "u", "", "Username (required)")
	passwordCmd.Flags().StringVarP(&passwordCmdInput.password, "password", "p", "", "Password (required)")
	passwordCmd.Flags().StringVarP(&passwordCmdInput.clientId, "client_id", "c", "", "Client ID (required)")
	passwordCmd.Flags().StringVarP(&passwordCmdInput.clientSecret, "client_secret", "s", "", "Client Secret (required)")
	passwordCmd.Flags().StringVarP(&passwordCmdInput.scope, "scope", "o", "", "Scope (required)")

	// Mark flags as required
	passwordCmd.MarkFlagRequired("url")
	passwordCmd.MarkFlagRequired("username")
	passwordCmd.MarkFlagRequired("password")
	passwordCmd.MarkFlagRequired("client_id")
	passwordCmd.MarkFlagRequired("scope")
}

func (i *PasswordCmdInput) run() {

	grantRequest := oauth2.GrantTypePassword{
		Username:     i.username,
		Password:     i.password,
		ClientID:     i.clientId,
		ClientSecret: i.clientSecret,
		Scope:        i.scope,
	}

	tokenEndpoint, err := oidc.DiscoverTokenEndpoint(i.url)
	if err != nil {
		fmt.Println(err)
	}
	_, err = oauth2.GrantPassword(&grantRequest, tokenEndpoint)
	if err != nil {
		fmt.Println(err)
	}
}
