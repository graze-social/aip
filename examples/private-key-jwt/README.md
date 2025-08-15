# Private Key JWT OAuth Client Example

This example demonstrates how to use private_key_jwt client authentication with the AIP OAuth server, as defined in [RFC 7523](https://tools.ietf.org/html/rfc7523).

## Overview

Private Key JWT authentication allows OAuth clients to authenticate using a cryptographically signed JWT instead of a client secret. This provides enhanced security and is particularly useful for:

- Public clients that cannot securely store secrets
- Server-to-server applications requiring strong authentication
- Applications requiring non-repudiation

## Prerequisites

- OpenSSL (for key generation and JWT signing)
- jq (for JSON processing)
- AIP server running on `http://localhost:8081` (or set `AIP_BASE_URL`)

### Install Dependencies

```bash
# macOS
brew install openssl jq

# Ubuntu/Debian
sudo apt-get install openssl jq

# Alpine Linux
apk add openssl jq
```

## Quick Start

### 1. Start the AIP Server

First, start your AIP server:

```bash
# From the project root
cargo run --bin aip
```

### 2. Create and Register a Private Key JWT Client

```bash
cd examples/private-key-jwt

# Create a client with default name
./create_private_key_jwt_client.sh

# Or with a custom name
./create_private_key_jwt_client.sh "My Custom Client"
```

This script will:
- Generate an ES256 key pair (P-256 curve)
- Create a JWK Set with the public key
- Register the client with the AIP server
- Save all artifacts to `private_key_jwt_client/`

### 3. Test the OAuth Flow

```bash
./test_private_key_jwt.sh
```

This script demonstrates:
- JWT client assertion creation and signing
- Pushed Authorization Request (PAR) with private_key_jwt auth
- Authorization URL generation
- Client credentials grant token exchange
- API endpoint testing with the access token

## Files Created

After running the setup script, you'll have:

```
private_key_jwt_client/
├── private_key.pem          # Private key (keep secret!)
├── public_key.pem          # Public key
├── jwks.json               # JWK Set for client registration
└── client_registration.json # Client registration response
```

## How It Works

### 1. Client Registration

The client registers with `token_endpoint_auth_method: "private_key_jwt"` and provides a JWK Set containing its public key:

```json
{
  "client_name": "My Private Key JWT Client",
  "token_endpoint_auth_method": "private_key_jwt",
  "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
  "response_types": ["code"],
  "redirect_uris": ["http://localhost:8080/callback"],
  "scope": "atproto:atproto",
  "jwks": {
    "keys": [
      {
        "kty": "EC",
        "crv": "P-256",
        "x": "...",
        "y": "...",
        "use": "sig",
        "alg": "ES256",
        "kid": "key-1"
      }
    ]
  }
}
```

### 2. JWT Client Assertion

For each OAuth request (PAR, token exchange), the client creates a signed JWT with:

**Header:**
```json
{
  "typ": "JWT",
  "alg": "ES256",
  "kid": "key-1"
}
```

**Claims:**
```json
{
  "iss": "client_id",           // Client ID as issuer
  "sub": "client_id",           // Client ID as subject  
  "aud": "https://server/oauth/token", // Token endpoint as audience
  "iat": 1234567890,            // Issued at time
  "exp": 1234568190,            // Expiration (max 5 minutes)
  "jti": "unique-jwt-id"        // Unique JWT ID (prevents replay)
}
```

### 3. Client Authentication

Instead of using `client_secret`, requests include:

```
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtleS0xIn0...
```

## Example Requests

### PAR Request with Private Key JWT

```bash
curl -X POST "http://localhost:8081/oauth/par" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "response_type=code" \
  -d "client_id=your_client_id" \
  -d "redirect_uri=http://localhost:8080/callback" \
  -d "scope=atproto:atproto" \
  -d "state=test-state" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtleS0xIn0..."
```

### Token Exchange with Private Key JWT

```bash
curl -X POST "http://localhost:8081/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=authorization_code_here" \
  -d "redirect_uri=http://localhost:8080/callback" \
  -d "client_id=your_client_id" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtleS0xIn0..."
```

## Security Considerations

1. **Private Key Security**: Keep `private_key.pem` secure and never expose it
2. **JWT Expiration**: JWTs should have short expiration times (≤ 5 minutes)
3. **JTI Uniqueness**: Each JWT should have a unique `jti` to prevent replay attacks
4. **Key Rotation**: Regularly rotate your key pairs and update the JWK Set
5. **Audience Validation**: Always include the correct audience in your JWTs

## Troubleshooting

### Common Issues

1. **Invalid JWT Format**: Ensure proper base64url encoding without padding
2. **Signature Verification Failed**: Check that your JWK Set matches your private key
3. **Expired JWT**: JWTs are only valid for a short time (5 minutes max)
4. **Wrong Audience**: JWT audience must match the token endpoint URL

### Debug Mode

Set environment variable for verbose output:

```bash
export AIP_LOG=debug
./test_private_key_jwt.sh
```

## Integration with Other Examples

This example works with the other OAuth examples:

- Use the generated `client_id` with the `simple-website` example
- Configure the `dpop-website` example to use private_key_jwt
- Test with the `lifecycle-website` for complete OAuth lifecycle management

## RFC Compliance

This implementation follows:

- [RFC 7523](https://tools.ietf.org/html/rfc7523): JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants
- [RFC 7517](https://tools.ietf.html/rfc7517): JSON Web Key (JWK)
- [RFC 9126](https://tools.ietf.org/html/rfc9126): OAuth 2.0 Pushed Authorization Requests (PAR)
- [RFC 6749](https://tools.ietf.org/html/rfc6749): The OAuth 2.0 Authorization Framework

## Next Steps

1. Integrate private_key_jwt into your OAuth client application
2. Set up proper key management and rotation
3. Test with different grant types (authorization_code, client_credentials)
4. Monitor JWT authentication in production logs