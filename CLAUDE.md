# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AIP (ATProtocol Identity Provider) is a web application that manages ATProtocol access tokens using OAuth and app-passwords. The project is built with Rust using the Axum web framework and integrates with the ATProtocol ecosystem.

## OAuth and OAuth Integrations

AIP provides OAuth login features that are backed by integrations, including ATProtocol OAuth. The following naming convention is used:

* "Base OAuth" refers to OAuth authentication process directly against AIP itself.
* "ATProtocol OAuth" (aka "atpoauth") refers to using ATProtocol OAuth authentication as a part of "Base OAuth" to create an active ATProtocol OAuth session that can be accessed with "Base OAuth" credentials.

Code pertaining to base OAuth features and functionality is organized in the `src/oauth/` package. This includes OAuth helpers and tooling that is not specific to ATProtocol OAuth.

Code pertaining to ATProtocol OAuth features and functionality is organized in the `src/oauth/atprotocol/` package.

### Client Management API

AIP includes optional client management API endpoints for dynamic client registration and management. These endpoints can be enabled or disabled using the `ENABLE_CLIENT_API` environment variable:

* When `ENABLE_CLIENT_API=true`, the following endpoints are available:
  - `POST /oauth/clients/register` - Dynamic Client Registration (RFC 7591)
  - `GET /oauth/clients/{client_id}` - Retrieve client information
  - `PUT /oauth/clients/{client_id}` - Update client configuration
  - `DELETE /oauth/clients/{client_id}` - Delete client registration

* When `ENABLE_CLIENT_API` is not set or set to any value other than "true", these client management endpoints are disabled and will return 404 responses.

The core OAuth endpoints (authorize, token, PAR) remain available regardless of this setting.

### XRPC Client Management

AIP includes an XRPC endpoint for administrative client management:

- `POST /xrpc/tools.graze.aip.clients.Update` - Update client configuration via XRPC

This endpoint requires authorization with a DID that is included in the `ADMIN_DIDS` configuration.

### Client Token Expiration

Client token expiration durations can be configured globally using environment variables:

- `CLIENT_DEFAULT_ACCESS_TOKEN_EXPIRATION` - Default access token lifetime (default: "1d")
- `CLIENT_DEFAULT_REFRESH_TOKEN_EXPIRATION` - Default refresh token lifetime (default: "14d")

These values use the `duration_str` format (e.g., "1d", "12h", "3600s").

## Common Development Commands

### Build Commands
```bash
# Build the project in debug mode
cargo build

# Build the project in release mode
cargo build --release

# Run the project (default: PostgreSQL + Redis)
cargo run

# Run in release mode
cargo run --release

# Run with development features (SQLite + Redis, no PostgreSQL)
cargo run --bin aip --no-default-features --features dev

# Run with SQLite only (useful when DATABASE_URL points to SQLite)
cargo run --bin aip --no-default-features --features sqlite,reload
```

### Testing and Quality Assurance
```bash
# Run tests
cargo test

# Run tests with output displayed
cargo test -- --nocapture

# Run a specific test
cargo test test_name

# Check code without building
cargo check

# Format code
cargo fmt

# Check formatting without modifying files
cargo fmt -- --check

# Run clippy linter
cargo clippy

# Run clippy with all targets
cargo clippy --all-targets --all-features
```

### Documentation
```bash
# Generate and open documentation
cargo doc --open

# Generate documentation without dependencies
cargo doc --no-deps
```

## Architecture Notes

The project structure:
- Binary crate at `src/bin/aip.rs` - The main application entry point
- Library modules:
  - `src/config.rs` - Configuration types and environment variable handling
  - `src/http.rs` - HTTP server configuration and request handlers
  - `src/templates.rs` - Template engine configuration (embed/reload modes)
  - `src/errors.rs` - Error types using standardized error codes
  - `src/storage/` - Storage trait definitions and implementations
- Static files in `static/` directory
- Templates in `templates/` directory
- Database migrations in `migrations/` directory (organized by database type)
- Using Rust edition 2021 with async/await patterns
- Example applications in `examples/` directory:
  - `simple-website` - Minimal OAuth 2.1 + PAR demo with dynamic client registration
  - `dpop-website` - Example demonstrating DPoP (Demonstrating Proof of Possession)
  - `lifecycle-website` - Example showing OAuth lifecycle management
  - `react-website` - React-based frontend example

Key dependencies:
- Axum for the web framework
- ATProtocol crates for identity and OAuth support
- Minijinja for templating
- Tower for middleware
- Tokio for async runtime
- SQLx for database access (with optional SQLite and PostgreSQL support)

## Storage Implementations

AIP supports multiple storage backends through a trait-based architecture. Storage traits are defined in `src/storage/traits.rs` and can be implemented for different backends.

### Storage Traits

The following storage traits are defined:
- `OAuthClientStore` - Stores OAuth client registrations
- `AuthorizationCodeStore` - Stores OAuth authorization codes
- `AccessTokenStore` - Stores OAuth access tokens
- `RefreshTokenStore` - Stores OAuth refresh tokens
- `KeyStore` - Stores cryptographic keys for JWT signing
- `PARStorage` - Stores Pushed Authorization Requests
- `AtpOAuthSessionStorage` - Stores ATProtocol OAuth sessions
- `AuthorizationRequestStorage` - Stores authorization requests
- `NonceStorage` - Stores and checks nonces to prevent replay attacks
- `OAuthStorage` - Combined trait that includes all of the above

### Storage Backends

AIP provides three storage backend implementations:

1. **In-Memory Storage** (Default)
   - Module: `src/storage/inmemory/`
   - Always available, no feature flag required
   - Suitable for development and testing
   - Data is lost when the server restarts

2. **SQLite Storage**
   - Module: `src/storage/sqlite/`
   - Feature flag: `sqlite`
   - Suitable for single-instance deployments
   - Persistent storage in a local file
   - Migrations: `migrations/sqlite/`

3. **PostgreSQL Storage**
   - Module: `src/storage/postgres/`
   - Feature flag: `postgres`
   - Suitable for production deployments
   - Supports high availability and scaling
   - Migrations: `migrations/postgres/`

### Building with Storage Features

```bash
# Build with development features (SQLite + Redis, recommended for local development)
cargo build --no-default-features --features dev

# Build with SQLite support only
cargo build --no-default-features --features sqlite

# Build with PostgreSQL support (default)
cargo build

# Build with both SQLite and PostgreSQL support
cargo build --features sqlite,postgres
```

### Development Workflow

When developing locally with SQLite:

1. **Set up your `.env` file** with SQLite configuration:
   ```bash
   STORAGE_BACKEND=sqlite
   DATABASE_URL=sqlite://aip.db
   ```

2. **Run migrations** for SQLite:
   ```bash
   sqlx migrate run --source migrations/sqlite
   ```

3. **Use the dev features** to avoid PostgreSQL compilation issues:
   ```bash
   # Recommended for SQLite development
   cargo run --bin aip --no-default-features --features dev
   
   # Alternative for SQLite-only development
   cargo run --bin aip --no-default-features --features sqlite,reload
   ```

4. **For production builds** use the default features (PostgreSQL):
   ```bash
   cargo build --release
   ```

### SQLx Query Validation

If you encounter SQLx compilation errors when using `--features sqlite` with default features:

- This happens because PostgreSQL modules are compiled but SQLx validates against the SQLite database in `DATABASE_URL`
- Solution: Use `--no-default-features --features dev` for SQLite development
- Alternative: Use `SQLX_OFFLINE=true` with prepared query cache

### Running Migrations

For SQLite:
```bash
sqlx migrate run --database-url sqlite://path/to/database.db --source migrations/sqlite
```

For PostgreSQL:
```bash
sqlx migrate run --database-url postgresql://aip:aip_dev_password@localhost:5434/aip_test --source migrations/postgres
```

### PostgreSQL Development Environment

A Docker setup is provided for running PostgreSQL during development:

```bash
# Start PostgreSQL using Docker Compose
docker-compose up -d postgres

# Stop PostgreSQL
docker-compose down

# View PostgreSQL logs
docker-compose logs postgres

# Connect to PostgreSQL
psql postgres://aip:aip_dev_password@localhost:5434/aip_dev
```

The default PostgreSQL development credentials are:
- User: `aip`
- Password: `aip_dev_password`
- Database: `aip_dev`
- Port: `5434`

## Error Handling

All error strings must use this format:

    error-aip-<domain>-<number> <message>: <details>

Example errors:

* error-aip-resolve-1 Multiple DIDs resolved for method
* error-aip-plc-1 HTTP request failed: https://google.com/ Not Found
* error-aip-key-1 Error decoding key: invalid

Errors should be represented as enums using the `thiserror` library when possible using `src/errors.rs` as a reference and example.

Avoid creating new errors with the `anyhow!(...)` macro.

## Visibility

Types and methods should have the lowest visibility necessary, defaulting to `private`. If `public` visibility is necessary, attempt to make it public to the crate only. Using completely public visibility should be a last resort.

## Time, Date, and Duration

Use the `chrono` crate for time, date, and duration logic.

Use the `duration_str` crate for parsing string duration values.

All stored dates and times must be in UTC. UTC should be used whenever determining the current time and computing values like expiration.

## HTTP Handler Organization

HTTP handlers should be organized as Rust source files in the `src/http` directory and should have the `handler_` prefix. Each handler should have it's own request and response types and helper functionality.

Example handler: `handler_index.rs`

### OAuth 2.0 Endpoints

The AIP server implements the following OAuth 2.0 endpoints:

- `GET /oauth/authorize` - Authorization endpoint for OAuth flows
- `POST /oauth/token` - Token endpoint for exchanging authorization codes for access tokens
- `POST /oauth/par` - Pushed Authorization Request endpoint (RFC 9126)
- `POST /oauth/clients/register` - Dynamic Client Registration endpoint (RFC 7591)
- `GET /oauth/atp/callback` - ATProtocol OAuth callback handler
- `GET /.well-known/oauth-authorization-server` - OAuth server metadata discovery (RFC 8414)
- `GET /.well-known/oauth-protected-resource` - Protected resource metadata
- `GET /.well-known/jwks.json` - JSON Web Key Set for token verification

If functionality can be shared across more than one handler, put it in a source file that has the format `utils_[domain].rs`. 

Example helper: `utils_oauth.rs` and `utils_atprotocol_oauth.rs`

HTTP middleware should be organized as Rust source files in the `src/http` directory and should have the prefix `middleware_`.

Example middleware: `middleware_i18n.rs`

## Example Applications

The project includes several example applications in the `examples/` directory:

### Simple Website Example

The `simple-website` example (located in `examples/simple-website/`) provides a minimal functional website that demonstrates OAuth 2.1 + PAR authentication with dynamic client registration. It includes:

- **Dynamic client registration** on startup using RFC 7591
- **Home page** (`GET /`) displaying client registration status and OAuth login link
- **Login handler** (`GET /login`) that discovers OAuth metadata, performs PAR request, and redirects to AIP
- **OAuth callback handler** (`GET /callback`) that exchanges authorization code for JWT access token with client authentication
- **Protected route** (`GET /protected`) that uses JWT bearer token to call AIP `GET /api/atprotocol/session` endpoint

### Running the Simple Website Example

```bash
# Start the AIP server (in one terminal)
EXTERNAL_BASE=http://localhost:8080 cargo run --bin aip

# Start the simple website example (in another terminal)
cd examples/simple-website
cargo run
```

### Configuration

The demo client uses these environment variables:

- `AIP_BASE_URL`: Base URL of the AIP server (default: "http://localhost:8080")
- `DEMO_BASE_URL`: Base URL of the demo client (default: "http://localhost:3001")
- `PORT`: Port for the demo client to listen on (default: 3001)

**Note:** OAuth client credentials are now obtained dynamically through client registration, eliminating the need for hardcoded client IDs.

### Usage Flow

**Application Startup:**
1. The demo client starts and discovers AIP's OAuth server metadata from `/.well-known/oauth-authorization-server`
2. The client registers itself dynamically with AIP using RFC 7591 (or tries a fallback registration endpoint)
3. Client credentials (ID and optional secret) are obtained and stored for the session

**OAuth Authentication Flow:**
1. Visit http://localhost:3001 in your browser
2. The home page displays the client registration status and OAuth configuration
3. Click "Start OAuth Login" to initiate the OAuth 2.1 + PAR flow
4. The demo client discovers AIP's OAuth server metadata (if not cached)
5. The demo client optionally fetches protected resource metadata from `/.well-known/oauth-protected-resource`
6. A PAR (Pushed Authorization Request) is made to AIP with PKCE parameters using the registered client ID
7. You're redirected to AIP to complete authentication
8. After authentication, you're redirected back with an authorization code
9. The authorization code is exchanged for a JWT access token using the registered client credentials
10. You're redirected to `/protected` with the JWT token as a query parameter
11. The protected route uses the JWT as a Bearer token to call AIP's session endpoint and displays your ATProtocol session information