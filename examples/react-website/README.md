# AIP React Demo Client with DPoP Support

A React TypeScript example application that demonstrates OAuth authentication with AIP (ATProtocol Identity Provider) and ATProtocol XRPC calls with **proper DPoP signing** using the Backend for Frontend (BFF) pattern.

## Features

- **Dynamic OAuth Client Registration** using RFC 7591
- **OAuth 2.1 + PAR Flow** with PKCE for secure authentication
- **JWT Bearer Token** handling for API access
- **ATProtocol Session Management** via AIP API
- **DPoP-signed XRPC Calls** via BFF proxy with RFC 9449 compliant signing
- **Backend for Frontend (BFF)** pattern for secure DPoP key handling
- **Modern React** with TypeScript and hooks

## Architecture

### BFF (Backend for Frontend) Pattern

This demo implements the BFF pattern where:

1. **React App** calls the BFF server for XRPC operations
2. **BFF Server** handles DPoP proof generation and signing
3. **BFF Server** proxies XRPC requests to PDS with proper DPoP headers
4. **DPoP private keys** never leave the server side

```
React App → BFF Server → AIP Server (for session)
              ↓
         PDS (with DPoP proofs)
```

## Getting Started

### Prerequisites

- Node.js 18+ and npm
- Running AIP server (see main project README)

### Installation

```bash
cd examples/react-website
npm install
```

### Running the Demo

**Option 1: Production Mode (Recommended)**

```bash
# 1. Build the React app
npm run build

# 2. Start the BFF server (serves React app + handles DPoP)
npm run server:dev

# 3. Open your browser to http://localhost:3001
```

**Option 2: Development Mode with Hot Reload**

```bash
# Terminal 1: Start BFF server
npm run server:dev

# Terminal 2: Start Vite dev server (different port)
npm run dev

# Open http://localhost:3002 for React development
# Note: XRPC calls will proxy to BFF server on 3001
```

### Development Mode

For development with hot reload:

```bash
# Terminal 1: Start Vite dev server
npm run dev

# Terminal 2: Start BFF server
npm run server:dev
```

### Configuration

Environment variables:

- **AIP_BASE_URL**: Base URL of the AIP server (default: "http://localhost:8080")
- **PORT**: Port for BFF server (default: 3002)

## OAuth Flow

1. **Application Startup**: Dynamic client registration with AIP server
2. **User Input**: Enter ATProtocol handle or DID (optional)
3. **OAuth Initiation**: Discover OAuth metadata and create PAR request
4. **User Authorization**: Redirect to AIP for authentication
5. **Token Exchange**: Exchange authorization code for JWT access token
6. **Session Access**: Use JWT to retrieve ATProtocol session information
7. **XRPC Calls**: React app calls BFF, which handles DPoP signing and PDS communication

## DPoP Flow

1. **React App** makes XRPC request to `/api/xrpc-proxy` with JWT token
2. **BFF Server** extracts JWT and calls AIP `/api/atprotocol/session`
3. **BFF Server** receives ATProtocol session with DPoP private key
4. **BFF Server** generates RFC 9449 compliant DPoP proof JWT
5. **BFF Server** makes XRPC call to PDS with `Authorization: DPoP <token>` and `DPoP: <proof>`
6. **BFF Server** returns response to React app

## Architecture Components

### Frontend (React)
- **React Hooks**: For state management and side effects
- **TypeScript**: Full type safety for OAuth flows and API responses
- **Vite**: Fast development server and build tool

### Backend (BFF Server)
- **Express.js**: Web server for API and static file serving
- **jose**: RFC 7515/7517/9449 compliant JWT and DPoP handling
- **node-fetch**: HTTP client for AIP and PDS communication

## API Integration

### React App → BFF Server

- `POST /api/xrpc-proxy` - Proxies XRPC calls with DPoP signing

### BFF Server → AIP Server

- `GET /.well-known/oauth-authorization-server` - OAuth server metadata
- `POST /oauth/clients/register` - Dynamic client registration
- `POST /oauth/par` - Pushed Authorization Requests
- `GET /oauth/authorize` - User authorization
- `POST /oauth/token` - Token exchange
- `GET /api/atprotocol/session` - ATProtocol session info with DPoP key

### BFF Server → PDS

- `GET /xrpc/garden.lexicon.ngerakines.helloworld.Hello` with:
  - `Authorization: DPoP <access_token>`
  - `DPoP: <proof_jwt>`
  - `atproto-proxy: did:web:ngerakines.tunn.dev#helloworld`

## Development

```bash
# Install dependencies
npm install

# Start Vite dev server (frontend only)
npm run dev

# Start BFF server in development mode
npm run server:dev

# Type check
npm run type-check

# Build React app for production
npm run build

# Build BFF server
npm run build:server

# Run production BFF server
npm run server
```

## Security Benefits

- **DPoP private keys** never exposed to browser/client
- **Server-side proof generation** ensures proper RFC 9449 compliance
- **JWT tokens** remain in browser but cannot be used for direct PDS access
- **BFF pattern** provides additional security layer and token validation