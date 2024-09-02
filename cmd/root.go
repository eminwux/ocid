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

package cmd

import (
	"fmt"
	"os"

	"github.com/eminwux/ocid/cmd/grant"
	"github.com/eminwux/ocid/cmd/jwt"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ocid",
	Short: "OCID is a command line interface for managing OAuth2 and JWT operations",
	Long: `OCID is a powerful command-line tool designed to facilitate the management of OAuth2 flows
and JSON Web Token (JWT) operations. It provides comprehensive support for various OAuth2 grant types
including password, client credentials, authorization code, and more, as well as utilities for handling JWTs.

Examples of usage:
  ./ocid grant --help       # Explore various OAuth2 grant commands
  ./ocid jwt --help         # Manage JWT operations like decoding

The tool is designed to be extensible and is suited for both development and production use,
helping developers and administrators manage authentication and authorization operations effectively.`,

	// Run is left commented out because rootCmd does not perform any action by itself.
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Use './ocid [command] --help' to see more information about a specific command.")
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.ocid.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	// rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	rootCmd.AddCommand(grant.GrantCmd)
	rootCmd.AddCommand(jwt.JWTCmd)
}
