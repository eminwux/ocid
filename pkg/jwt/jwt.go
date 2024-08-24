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

// decodeBase64 decodes a Base64 URL encoded string.
func decodeBase64(str string) ([]byte, error) {
	// Add padding as required
	if m := len(str) % 4; m != 0 {
		str += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(str)
}

// decodeJWT decodes the header and payload of a JWT without validating its signature.
func DecodeJWT(token string) (headerJSON string, payloadJSON string, signature []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", nil, fmt.Errorf("invalid token, expected 3 parts got %d", len(parts))
	}

	// Decode HEADER
	headerBytes, err := decodeBase64(parts[0])
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to decode header: %w", err)
	}
	var headerMap map[string]interface{}
	if err = json.Unmarshal(headerBytes, &headerMap); err != nil {
		return "", "", nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}

	prettyHeaderJSON, err := json.MarshalIndent(headerMap, "", "    ")
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to marshal header: %w", err)

	}
	headerJSON = string(prettyHeaderJSON)
	fmt.Println("JWT Header:")
	fmt.Println(headerJSON)

	// Decode PAYLOAD
	payloadBytes, err := decodeBase64(parts[1])
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var payloadMap map[string]interface{}
	if err = json.Unmarshal(payloadBytes, &payloadMap); err != nil {
		return "", "", nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}

	prettyPayloadJSON, err := json.MarshalIndent(payloadMap, "", "    ")
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to marshal payload: %w", err)

	}
	payloadJSON = string(prettyPayloadJSON)
	fmt.Println("JWT Payload:")
	fmt.Println(payloadJSON)

	// Extract signature
	signatureBytes, err := decodeBase64(parts[2])
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to decode signature: %w", err)
	}
	fmt.Println("Signature Bytes:", signatureBytes)

	return string(headerBytes), string(payloadBytes), signatureBytes, nil
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
