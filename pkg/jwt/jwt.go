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
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

type JWT struct {
	Header    map[string]interface{}
	Payload   map[string]interface{}
	Signature []byte
}

// decodeBase64 decodes a Base64 URL encoded string.
func decodeBase64(str string) ([]byte, error) {
	// Add padding as required
	if m := len(str) % 4; m != 0 {
		str += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(str)
}

// decodeJWT decodes the header and payload of a JWT without validating its signature.
func DecodeJWT(token string) (*JWT, error) {
	var jwt JWT

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token, expected 3 parts got %d", len(parts))
	}

	// Decode HEADER
	headerBytes, err := decodeBase64(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}
	// var headerMap map[string]interface{}

	if err = json.Unmarshal(headerBytes, &jwt.Header); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}

	// prettyHeaderJSON, err := json.MarshalIndent(&jwt.Header, "", "    ")
	// if err != nil {
	// 	return "", "", nil, fmt.Errorf("failed to marshal header: %w", err)

	// }
	// headerJSON = string(prettyHeaderJSON)
	// fmt.Println("JWT Header:")
	// fmt.Println(headerJSON)

	// Decode PAYLOAD
	payloadBytes, err := decodeBase64(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	// var payloadMap map[string]interface{}
	if err = json.Unmarshal(payloadBytes, &jwt.Payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}

	// prettyPayloadJSON, err := json.MarshalIndent(&jwt.Payload, "", "    ")
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to marshal payload: %w", err)

	// }
	// payloadJSON = string(prettyPayloadJSON)
	// fmt.Println("JWT Payload:")
	// fmt.Println(payloadJSON)

	// Extract signature
	jwt.Signature, err = decodeBase64(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}
	// fmt.Println("Signature Bytes:", signatureBytes)

	return &jwt, nil
}

// verifySignatureRS256 checks if the provided JWT signature is valid using RS256 and a given RSA public key
func verifySignatureRS256(token string, publicKey *rsa.PublicKey) (bool, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid token: expected 3 parts, got %d", len(parts))
	}

	// Base64 decode the signature
	signature, err := decodeBase64(parts[2])
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %v", err)
	}

	// Recreate the signed part
	signingInput := parts[0] + "." + parts[1]

	// Hash the signing input using SHA256
	hash := sha256.New()
	_, err = hash.Write([]byte(signingInput))
	if err != nil {
		return false, fmt.Errorf("failed to hash signing input: %v", err)
	}
	hashed := hash.Sum(nil)

	// Verify the signature with the public key
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, signature)
	if err != nil {
		return false, fmt.Errorf("signature verification failed: %v", err)
	}
	return true, nil
}

// parseRSAPublicKeyFromPEM parses RSA public key from PEM format
func parseRSAPublicKeyFromPEM(pubKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil {
		return nil, errors.New("public key error: no key found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %v", err)
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("key type is not RSA")
	}
}
