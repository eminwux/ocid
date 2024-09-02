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
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/eminwux/ocid/pkg/jwt"
	"github.com/spf13/cobra"
)

type JWTDecodeCmdInput struct {
	jwt        string
	showHeader bool
	showFull   bool
}

var jwtCmdInput JWTDecodeCmdInput

// JWTDecodeCmd represents the jwt decode command
var JWTDecodeCmd = &cobra.Command{
	Use:   "decode",
	Short: "Decodes JWT tokens",
	Long: `Decodes and prints JSON Web Tokens (JWT). By default, it prints the payload in a pretty format.
You can also use flags to print the header or the full token.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Check if the JWT token is provided via the -j flag
		if jwtCmdInput.jwt == "" {
			// If not, try to read it from stdin
			info, err := os.Stdin.Stat()
			if err != nil {
				fmt.Printf("error accessing stdin: %v", err)
				return
			}

			// If there is piped input, read it
			if (info.Mode() & os.ModeCharDevice) == 0 {
				scanner := bufio.NewScanner(os.Stdin)
				for scanner.Scan() {
					jwtCmdInput.jwt = strings.TrimSpace(scanner.Text())
					break
				}

				if err := scanner.Err(); err != nil {
					fmt.Printf("error reading stdin: %v", err)
					return
				}
			}
		}

		// Ensure the JWT token is provided either via flag or stdin
		if jwtCmdInput.jwt == "" {
			fmt.Printf("JWT token must be provided via the -j flag or stdin")
			return
		}

		jwtCmdInput.run()
	},
}

func init() {
	JWTDecodeCmd.Flags().StringVarP(&jwtCmdInput.jwt, "jwt", "j", "", "JWT token (required)")
	JWTDecodeCmd.Flags().BoolVarP(&jwtCmdInput.showHeader, "header", "", false, "Print the header")
	JWTDecodeCmd.Flags().BoolVarP(&jwtCmdInput.showFull, "full", "", false, "Print both header and payload")

}

func (i *JWTDecodeCmdInput) run() {

	jwt, err := jwt.DecodeJWT(i.jwt)
	if err != nil {
		fmt.Printf("Error decoding token: %v\n", err)
		return
	}

	prettyHeaderJSON, err := json.MarshalIndent(&jwt.Header, "", "    ")
	if err != nil {
		fmt.Printf("failed to marshal header: %w", err)
	}

	prettyPayloadJSON, err := json.MarshalIndent(&jwt.Payload, "", "    ")
	if err != nil {
		fmt.Printf("failed to marshal header: %w", err)
	}

	if i.showHeader {
		fmt.Println(string(prettyHeaderJSON))
	}
	fmt.Println(string(prettyPayloadJSON))

}
