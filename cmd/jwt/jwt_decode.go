package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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
	RunE: func(cmd *cobra.Command, args []string) error {
		return decodeJWT(jwtCmdInput.jwt, jwtCmdInput.showHeader, jwtCmdInput.showFull)
	},
}

func init() {
	JWTDecodeCmd.Flags().StringVarP(&jwtCmdInput.jwt, "jwt", "j", "", "JWT token (required)")
	JWTDecodeCmd.Flags().BoolVarP(&jwtCmdInput.showHeader, "header", "", false, "Print the header")
	JWTDecodeCmd.Flags().BoolVarP(&jwtCmdInput.showFull, "full", "", false, "Print both header and payload")
	JWTDecodeCmd.MarkFlagRequired("jwt")
}

func decodeJWT(token string, showHeader, showFull bool) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid token format")
	}

	header, err := decodeBase64(parts[0])
	if err != nil {
		return err
	}

	payload, err := decodeBase64(parts[1])
	if err != nil {
		return err
	}

	if showHeader && showFull {
		fmt.Println("Header:")
		printJSON(header)
		fmt.Println("Payload:")
		printJSON(payload)
	} else if showHeader {
		fmt.Println("Header:")
		printJSON(header)
	} else {
		fmt.Println("Payload:")
		printJSON(payload)
	}

	return nil
}

func decodeBase64(b64 string) (string, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func printJSON(jsonStr string) {
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &obj); err != nil {
		fmt.Println("Error parsing JSON:", err)
		return
	}
	prettyJSON, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		fmt.Println("Error creating pretty JSON:", err)
		return
	}
	fmt.Println(string(prettyJSON))
}
