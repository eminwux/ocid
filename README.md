# OCID CLI Tool

`ocid` is a command-line interface (CLI) tool designed to interact with OAuth Authorization Servers and OpenID Connect (OIDC) Identity Providers. With `ocid`, you can easily execute various authentication flows, obtain tokens, refresh tokens, exchange tokens, and more.

## Features

- **OAuth 2.0 and OIDC Support**: Interact with OAuth and OIDC providers for secure authentication and token management.
- **Multiple Grant Types**: Supports various OAuth grant types including:
  - Authorization Code Grant
  - Client Credentials Grant
  - Resource Owner Password Credentials (ROPC) Grant
  - Client Assertion JWT Grant
- **PKCE Support**: Built-in support for Proof Key for Code Exchange (PKCE) for enhanced security during authorization flows.

## Installation

To install `ocid`, you can build the binary from the source and copy it to your local bin directory:

```bash
go build
sudo cp ocid /usr/local/bin
```

This will make the ocid command available globally on your system.

## Usage
The ocid CLI is designed to be simple and intuitive. Below are some examples of how to use the tool.

### Authorization Code Grant
`ocid grant authorization_code`: Executes the Authorization Code Grant flow.

Without PKCE:

```bash
ocid grant authorization_code \
  --url https://your-oidc-issuer.com \
  --client_id your-client-id \
  --client_secret your-client-secret \
  --scope your-scope \
  --pkce \
  --pkce-challenge-method S256
```

With PKCE:
```bash
ocid grant authorization_code \
  --url https://your-oidc-issuer.com \
  --client_id your-client-id \
  --client_secret your-client-secret \
  --scope your-scope \
```

PKCE (for Authorization Code Grant)
`--pkce`: Enable PKCE.
`--pkce-challenge-method`: Specify the PKCE challenge method (plain or S256, default is plain).


### Client Credentials Grant
`ocid grant client_credentials`: Executes the Client Credentials Grant flow.

```bash
ocid grant client_credentials \
  --url https://your-oidc-issuer.com \
  --client_id your-client-id \
  --client_secret your-client-secret \
  --scope your-scope
```

### Resource Owner Password Credentials (ROPC) Grant
`ocid grant password`: Executes the Resource Owner Password Credentials (ROPC) Grant flow.

```bash
ocid grant password \
  --url https://your-oidc-issuer.com \
  --username your-username \
  --password your-password \
  --client_id your-client-id \
  --client_secret your-client-secret \
  --scope your-scope
```
### Client Assertion JWT Grant
`ocid grant client_assertion_jwt`: Executes the Client Assertion JWT Grant flow.

This flow is used in scenarios where a client authenticates using a JSON Web Token (JWT) instead of a client secret. This is typically used by confidential clients such as microservices.

```bash
ocid grant client_assertion_jwt \
  --url https://your-oidc-issuer.com \
  --client_id your-client-id \
  --client_assertion_jwt your-signed-jwt \
  --scope your-scope
```
## Command-Specific Flags
Each grant type command has specific flags that need to be provided:

`--url`: The OIDC issuer server URL (required).
`--client_id`: The client ID (required).
`--client_secret`: The client secret (required for some flows).
`--scope`: The scope of the access request (required).

## License

This project is licensed under the MIT License.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request or open an issue.

## Contact
For any questions or support, please contact [eminwux@gmail.com].