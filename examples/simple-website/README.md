# Simple Website Example

A minimal functional website that demonstrates OAuth 2.1 + PAR authentication with dynamic client registration against AIP (ATProtocol Identity Provider).

## Features

- **Dynamic Client Registration** - Automatically registers OAuth client on startup using RFC 7591
- **OAuth 2.1 + PAR** - Implements Pushed Authorization Request (RFC 9126) for enhanced security
- **PKCE Protection** - Uses Proof Key for Code Exchange to prevent authorization code interception
- **ATProtocol Integration** - Demonstrates authentication with ATProtocol handles and DIDs
- **JWT Access Tokens** - Exchanges authorization codes for JWT tokens
- **Protected API Calls** - Uses Bearer tokens to access protected AIP endpoints

## Quick Start

1. **Start the AIP server** (in another terminal):
   ```bash
   cd ../../
   EXTERNAL_BASE=http://localhost:8080 cargo run --bin aip
   ```

2. **Start the demo client**:
   ```bash
   cargo run
   ```

3. **Open your browser** and navigate to http://localhost:3001

## Configuration

Configure the example using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `AIP_BASE_URL` | Base URL of the AIP server | `http://localhost:8080` |
| `DEMO_BASE_URL` | Base URL of this demo client | `http://localhost:3001` |
| `PORT` | Port for the demo client to listen on | `3001` |

## Authentication Flow

1. **Application Startup:**
   - Discovers AIP's OAuth server metadata from `/.well-known/oauth-authorization-server`
   - Registers itself dynamically with AIP using RFC 7591
   - Obtains client credentials (ID and optional secret)

2. **OAuth Authentication Flow:**
   - User visits home page and enters ATProtocol handle (optional)
   - Client discovers OAuth server metadata
   - Makes PAR request with PKCE parameters using registered client ID
   - User is redirected to AIP for authentication
   - After authentication, authorization code is returned via callback
   - Code is exchanged for JWT access token using client credentials
   - User is redirected to protected page displaying session information

## API Endpoints

The demo implements these endpoints:

- `GET /` - Home page with authentication form
- `GET /login` - Initiates OAuth flow with metadata discovery and PAR
- `GET /callback` - OAuth callback handler for authorization code exchange
- `GET /protected` - Protected route that displays ATProtocol session information

## Dependencies

This example uses standard web technologies:

- **axum** - Web framework
- **reqwest** - HTTP client for OAuth calls
- **serde** - JSON serialization
- **tokio** - Async runtime
- **uuid** - For generating state parameters
- **base64**, **sha2**, **rand** - For PKCE implementation

No ATProtocol-specific dependencies are required for basic OAuth flows.