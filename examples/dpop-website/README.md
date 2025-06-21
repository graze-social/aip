# DPoP Website Example

A demonstration website that showcases enterprise-grade OAuth 2.1 security with DPoP (Demonstration of Proof-of-Possession) and PAR (Pushed Authorization Request) against AIP (ATProtocol Identity Provider).

## Features

- **DPoP Token Binding** - Access tokens are cryptographically bound to client's key pair
- **Replay Protection** - Each request includes a unique proof token preventing replay attacks
- **PAR Security** - Uses Pushed Authorization Request for maximum authorization security
- **Dynamic Client Registration** - Automatically registers with DPoP support enabled
- **ES256 Cryptography** - Uses ECDSA P-256 keys for DPoP proof generation
- **ATProtocol Integration** - Full integration with ATProtocol OAuth and DPoP

## Security Benefits

DPoP provides several security advantages over traditional Bearer tokens:

1. **Token Binding** - Tokens are bound to specific cryptographic keys
2. **Theft Protection** - Stolen tokens cannot be used without the private key
3. **Replay Prevention** - Unique proof tokens (JTI) prevent request replay
4. **Enhanced Verification** - Server verifies both token and cryptographic proof

## Quick Start

1. **Start the AIP server** (in another terminal):
   ```bash
   cd ../../
   EXTERNAL_BASE=http://localhost:8080 cargo run --bin aip
   ```

2. **Start the DPoP demo client**:
   ```bash
   cargo run
   ```

3. **Open your browser** and navigate to http://localhost:3002

## Configuration

Configure the example using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `AIP_BASE_URL` | Base URL of the AIP server | `http://localhost:8080` |
| `DEMO_BASE_URL` | Base URL of this demo client | `http://localhost:3002` |
| `PORT` | Port for the demo client to listen on | `3002` |

## DPoP Flow

1. **Key Generation** - Client generates ES256 key pair on startup
2. **Client Registration** - Registers with `dpop_bound_access_tokens: true`
3. **PAR with DPoP** - Includes DPoP proof in Pushed Authorization Request
4. **Token Exchange** - Exchanges code for DPoP-bound access token with proof
5. **Protected Calls** - All API calls include DPoP proof headers

## DPoP Proof Structure

Each DPoP proof is a JWT containing:

```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": { /* embedded public key */ }
}
```

With claims:
- `jti` - Unique proof identifier
- `htm` - HTTP method
- `htu` - HTTP URI  
- `iat` - Issued at timestamp
- `ath` - Access token hash (when applicable)

## API Endpoints

- `GET /` - Home page showing DPoP status and configuration
- `GET /login` - Initiates DPoP OAuth flow
- `GET /callback` - Handles OAuth callback with DPoP token exchange
- `GET /protected` - Protected route using DPoP-bound tokens

## Dependencies

This example requires ATProtocol dependencies for DPoP implementation:

- **atproto-client** - DPoP-enabled HTTP client
- **atproto-identity** - Cryptographic key management
- **atproto-oauth** - OAuth and JWK utilities
- **axum** - Web framework
- **reqwest** - HTTP client
- **serde** - JSON serialization
- Standard crypto libraries (base64, sha2, uuid)

## Development Notes

Make sure to update the ATProtocol dependency paths in `Cargo.toml` to match your local setup:

```toml
atproto-client = { path = "/path/to/atproto-identity-rs/crates/atproto-client" }
atproto-identity = { path = "/path/to/atproto-identity-rs/crates/atproto-identity" }
atproto-oauth = { path = "/path/to/atproto-identity-rs/crates/atproto-oauth" }
```