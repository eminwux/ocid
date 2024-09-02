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

package jwt

import (
	"fmt"

	"github.com/spf13/cobra"
)

// JWTCmd represents the parent command for JWT-related operations.
var JWTCmd = &cobra.Command{
	Use:   "jwt",
	Short: "JWT management and utility commands",
	Long: `The 'jwt' command provides tools for managing and manipulating JSON Web Tokens (JWTs). It supports 
various operations such as decoding JWTs to inspect their headers and payloads.

Usage of this command includes operations like decoding JWTs to understand their structure and contents, which 
is useful for debugging and development purposes in security-sensitive environments.

Examples:
  ./ocid jwt decode --jwt your.jwt.token --header   # Decode and show the header of the JWT
  ./ocid jwt decode --jwt your.jwt.token --full     # Decode and show both header and payload of the JWT

Use './ocid jwt [subcommand] --help' for more details on each operation.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Use 'ocid jwt [subcommand] --help' to see more information about a specific operation.")
	},
}

func init() {

	JWTCmd.AddCommand(JWTDecodeCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// grantCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// grantCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
