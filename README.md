# AIP - ATProtocol Identity Provider

![Image from 391 Vol 1– 19 by Francis Picabia, https://archive.org/details/391-vol-1-19/page/n98/mode/1up](./aip.png)

AIP (ATProtocol Identity Provider) is a high-performance OAuth 2.1 authorization server with native ATProtocol integration. It provides secure authentication and token management for decentralized identity applications, enabling OAuth flows backed by ATProtocol identities.

## Features

- **OAuth 2.1 Authorization Server** - Complete implementation with PKCE, PAR, and client registration
- **ATProtocol Integration** - Native support for ATProtocol OAuth flows and identity resolution
- **DPoP Support** - RFC 9449 Demonstration of Proof of Possession for enhanced security
- **Multiple Storage Backends** - In-memory, SQLite, and PostgreSQL options
- **Dynamic Client Registration** - RFC 7591 compliant client registration
- **Template Engine** - Embedded templates for production or filesystem reloading for development
- **Production Ready** - Docker support, graceful shutdown, and comprehensive logging

## Quick Start

### Prerequisites

- Rust 1.87+
- Optional: PostgreSQL or SQLite for persistent storage

### Installation

```bash
# Clone the repository
git clone https://github.com/graze-social/aip.git
cd aip

# Build and run (development mode with auto-reloading templates)
cargo run --bin aip

# Or build for production with embedded templates
cargo build --release --no-default-features --features embed,postgres
```

### Configuration

Configure via environment variables:

```bash
# Required
export EXTERNAL_BASE=http://localhost:8080
export DPOP_NONCE_SEED=$(openssl rand -hex 32)

# Optional
export PORT=8080
export STORAGE_BACKEND=postgres  # postgres, sqlite, or inmemory
export DATABASE_URL=postgresql://user:pass@localhost/aip
export LOG_LEVEL=info

# Token Configuration
export CLIENT_DEFAULT_ACCESS_TOKEN_EXPIRATION=1d   # Default access token lifetime
export CLIENT_DEFAULT_REFRESH_TOKEN_EXPIRATION=14d # Default refresh token lifetime

# Admin Configuration
export ADMIN_DIDS=did:plc:admin1,did:plc:admin2    # Comma-separated list of admin DIDs
```

see [CONFIGURATION.md](./CONFIGURATION.md) for more.

## Architecture

### OAuth 2.1 Endpoints

- `GET /oauth/authorize` - Authorization endpoint
- `POST /oauth/token` - Token endpoint
- `POST /oauth/par` - Pushed Authorization Request (RFC 9126)
- `POST /oauth/clients/register` - Dynamic client registration (RFC 7591)
- `GET /.well-known/oauth-authorization-server` - Server metadata discovery

### ATProtocol Integration

- `GET /oauth/atp/callback` - ATProtocol OAuth callback handler
- `GET /api/atprotocol/session` - Session information endpoint
- Native ATProtocol identity resolution and DID document handling

### Storage Layer

The application uses a trait-based storage system supporting multiple backends:

- **In-Memory** - Default, suitable for development and testing
- **SQLite** - Single-instance deployments (`--features sqlite`)
- **PostgreSQL** - Production deployments with high availability (`--features postgres`)

## Development

### Running Tests

```bash
# Run all tests
cargo test

# Run with specific features
cargo test --features postgres,sqlite

# Run library tests
cargo test --lib
```

### Code Quality

```bash
# Format code
cargo fmt

# Run linter
cargo clippy

# Check without building
cargo check
```

### Database Setup

#### PostgreSQL

```bash
# Start PostgreSQL with Docker Compose
docker-compose up -d postgres

# Run migrations
sqlx migrate run --database-url postgresql://aip:aip_dev_password@localhost:5434/aip_dev --source migrations/postgres
```

#### SQLite

```bash
# Run migrations
sqlx migrate run --database-url sqlite://aip.db --source migrations/sqlite
```

## Examples

The repository includes several example applications demonstrating different OAuth flows:

- **simple-website** - Basic OAuth 2.1 + PAR with dynamic client registration
- **dpop-website** - DPoP (Demonstration of Proof of Possession) example
- **lifecycle-website** - OAuth lifecycle management
- **react-website** - React frontend with TypeScript

See the `examples/` directory for detailed documentation and setup instructions.

## Docker Deployment

```bash
# Build image
docker build -t aip .

# Run with environment variables
docker run -p 8080:8080 \
  -e EXTERNAL_BASE=https://your-domain.com \
  -e DATABASE_URL=postgresql://user:pass@db/aip \
  aip
```

## API Documentation

### OAuth 2.1 Flow

1. **Client Registration** (optional)
   ```bash
   curl -X POST http://localhost:8080/oauth/clients/register \
     -H "Content-Type: application/json" \
     -d '{"redirect_uris": ["https://app.example.com/callback"]}'
   ```

2. **Authorization Request**
   ```
   GET /oauth/authorize?client_id=xxx&redirect_uri=xxx&state=xxx&code_challenge=xxx&code_challenge_method=S256
   ```

3. **Token Exchange**
   ```bash
   curl -X POST http://localhost:8080/oauth/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=authorization_code&code=xxx&client_id=xxx&code_verifier=xxx"
   ```

### Protected Resource Access

```bash
curl -H "Authorization: Bearer <jwt_token>" \
  http://localhost:8080/api/atprotocol/session
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Standards

- Follow Rust conventions and run `cargo fmt`
- Add tests for new functionality
- Update documentation for API changes
- All error messages must follow the format: `error-aip-<domain>-<number> <message>: <details>`

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

For security issues, please create a private security advisory instead of opening a public issue.

## Related Projects

- [ATProtocol](https://github.com/bluesky-social/atproto) - Authenticated Transfer Protocol
- [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) - OAuth 2.1 Security Best Current Practice

---

## Binaries

This crate produces two binaries:

### aip
The main OAuth 2.1 authorization server with ATProtocol integration. This server provides:
- **OAuth 2.1 Authorization Server** - Complete implementation with authorization, token, and PAR endpoints
- **ATProtocol OAuth Integration** - Native support for ATProtocol identity resolution and OAuth flows
- **Dynamic Client Registration** - RFC 7591 compliant client registration and management
- **Token Management** - JWT-based access tokens with DPoP support (RFC 9449)
- **Multiple Storage Backends** - In-memory, SQLite, and PostgreSQL support
- **Production Ready** - Docker support, graceful shutdown, comprehensive logging, and template management

### aip-client-management
A comprehensive CLI tool for managing OAuth 2.1 clients programmatically. Features include:
- **Dynamic Client Registration** - Register new OAuth 2.1 clients with full metadata support
- **Client Information Retrieval** - Get detailed client configuration and status
- **Client Configuration Updates** - Modify client settings including redirect URIs and scopes
- **Client Lifecycle Management** - Delete and manage client registrations
- **OAuth 2.1 Compliance** - Support for all standard OAuth 2.1 client parameters and metadata
- **Flexible Output** - JSON and human-readable output formats

For detailed usage of the client management tool, run:
```bash
aip-client-management --help
```

---

Built with ❤️ using Rust and the ATProtocol ecosystem.
