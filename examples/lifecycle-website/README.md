# Lifecycle Website Example

A web application that demonstrates ATProtocol lifecycle management with DPoP authentication and service proxying through AIP (ATProtocol Identity Provider).

## Features

- **ATProtocol Lifecycle Management** - Full session lifecycle with refresh capabilities
- **DPoP Authentication** - Enterprise-grade token binding and proof-of-possession
- **Service Proxying** - Demonstrates proxied PDS calls via service DID
- **Real-time Testing** - Interactive interface for testing API calls
- **Session Monitoring** - Tracks session expiration and refresh status
- **HTMX Integration** - Dynamic updates without page reloads

## Use Cases

This example demonstrates:

1. **Session Management** - How to handle ATProtocol session lifecycle
2. **Token Refresh** - Automatic and forced token refresh scenarios  
3. **Service Integration** - Using service DIDs to proxy PDS requests
4. **Error Handling** - Robust error handling for various failure scenarios
5. **Real-time Monitoring** - Live monitoring of authentication status

## Quick Start

1. **Start the AIP server** (in another terminal):
   ```bash
   cd ../../
   EXTERNAL_BASE=http://localhost:8080 cargo run --bin aip
   ```

2. **Start the lifecycle website**:
   ```bash
   cargo run
   ```

3. **Open your browser** and navigate to http://localhost:3003

## Configuration

Configure the example using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `AIP_BASE_URL` | Base URL of the AIP server | `http://localhost:8080` |
| `DEMO_BASE_URL` | Base URL of this demo client | `http://localhost:3003` |
| `PORT` | Port for the demo client to listen on | `3003` |
| `SERVICE_DID` | Service DID for proxying requests | `did:plc:example` |
| `DPOP_KEY` | Pre-existing DPoP key (JSON format) | Generated on startup |

## Advanced Configuration

### Using a Pre-existing DPoP Key

You can configure the website to use a specific DPoP key by setting the `DPOP_KEY` environment variable:

```bash
export DPOP_KEY='{"key_type":"P256Private","key_data":"base64-encoded-key-data"}'
cargo run
```

### Service DID Configuration

Set a specific service DID for proxying ATProtocol requests:

```bash
export SERVICE_DID="did:plc:your-service-did"
cargo run
```

## API Flow

1. **Authentication** - Standard OAuth 2.1 + DPoP flow
2. **Session Retrieval** - Calls `/api/atprotocol/session` to get session details
3. **PDS Interaction** - Makes proxied calls to PDS via service DID
4. **Lifecycle Management** - Handles session refresh and expiration

## API Endpoints

- `GET /` - Home page with authentication form
- `GET /login` - Initiates OAuth flow
- `GET /callback` - OAuth callback handler
- `GET /test` - Interactive testing interface
- `GET /invoke` - Makes authenticated API calls (HTMX endpoint)

## Interactive Features

The test page provides:

- **Live API Testing** - Click to make authenticated calls
- **Force Refresh** - Option to force session refresh
- **Response History** - View past API call results
- **Real-time Updates** - HTMX-powered dynamic updates
- **Error Monitoring** - Detailed error reporting and status tracking

## Session Management

The example demonstrates:

- **Automatic Refresh** - Sessions are refreshed as needed
- **Force Refresh** - Manual session refresh capability
- **Expiration Monitoring** - Tracks and displays session expiration
- **Error Recovery** - Handles various authentication failure scenarios

## Dependencies

This example requires ATProtocol dependencies:

- **atproto-client** - DPoP-enabled HTTP client and session management
- **atproto-identity** - Key management and cryptographic operations
- **atproto-oauth** - OAuth utilities and JWK handling
- **chrono** - Date/time handling for session expiration
- **axum** - Web framework
- **reqwest** - HTTP client
- **serde** - JSON serialization

## Development Notes

1. **Update dependency paths** in `Cargo.toml` to match your local ATProtocol setup
2. **Configure service DID** appropriate for your testing environment
3. **Monitor session expiration** to understand lifecycle behavior
4. **Test force refresh** to see session renewal in action

This example is ideal for understanding how to build production ATProtocol applications with proper session management and service integration.