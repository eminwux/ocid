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
	"fmt"

	"github.com/spf13/cobra"
)

// GrantCmd represents the parent command for various OAuth grant commands.
var GrantCmd = &cobra.Command{
	Use:   "grant",
	Short: "Manage OAuth grant flows",
	Long: `The 'grant' command serves as a parent command for managing different OAuth 2.0 grant flows including 
password, client credentials, client assertion JWT, and authorization code grants.

Use this command to interact with various OAuth grant commands to authenticate and obtain tokens in different scenarios:

- password: Directly authenticate using a username and password to obtain an access token.
- client_credentials: Authenticate using client credentials to obtain an access token without a user.
- client_assertion_jwt: Authenticate using a JWT assertion to obtain an access token.
- authorization_code: Use an authorization code obtained via redirect after user authentication to request an access token.

Examples:
  ./ocid grant password --help
  ./ocid grant client_credentials --help
  ./ocid grant client_assertion_jwt --help
  ./ocid grant authorization_code --help

Run './ocid grant [command] --help' for more details on each specific grant type.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Use 'ocid grant [command] --help' to see more information about a specific command.")
	},
}

func init() {

	GrantCmd.AddCommand(passwordCmd)
	GrantCmd.AddCommand(clientCredentialsCmd)
	GrantCmd.AddCommand(clientAssertionJWTCmd)
	GrantCmd.AddCommand(authorizationCodeCmd)
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// grantCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// grantCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
