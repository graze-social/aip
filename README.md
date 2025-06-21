# AIP - ATProtocol Identity Provider

![Image from 391 Vol 1– 19 by Francis Picabia, https://archive.org/details/391-vol-1-19/page/n98/mode/1up](./aip.png)

A high-performance OAuth 2.1 authorization server with native ATProtocol integration, enabling secure authentication and token management for decentralized identity applications.

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

- Rust 1.70+
- Optional: PostgreSQL or SQLite for persistent storage

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/aip-rs.git
cd aip-rs

# Build and run (development mode with auto-reloading templates)
cargo run

# Or build for production with embedded templates
cargo build --release --no-default-features --features embed,postgres
```

### Configuration

Configure via environment variables:

```bash
# Required
export EXTERNAL_BASE=http://localhost:8080

# Optional
export PORT=8080
export STORAGE_BACKEND=postgres  # postgres, sqlite, or inmemory
export DATABASE_URL=postgresql://user:pass@localhost/aip
export LOG_LEVEL=info
```

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

# Run integration tests
cargo test --test oauth_integration
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

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `EXTERNAL_BASE` | Required | Public base URL of the server |
| `PORT` | `8080` | HTTP server port |
| `STORAGE_BACKEND` | `inmemory` | Storage backend: `inmemory`, `sqlite`, `postgres` |
| `DATABASE_URL` | - | Database connection string (for SQLite/PostgreSQL) |
| `LOG_LEVEL` | `info` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `TEMPLATE_PATH` | `templates/` | Template directory (development mode) |
| `STATIC_PATH` | `static/` | Static files directory |

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

For security issues, please email security@your-domain.com instead of opening a public issue.

## Related Projects

- [ATProtocol](https://github.com/bluesky-social/atproto) - Authenticated Transfer Protocol
- [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) - OAuth 2.1 Security Best Current Practice

---

Built with ❤️ using Rust and the ATProtocol ecosystem.
