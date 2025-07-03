# AIP Configuration Guide

This document provides comprehensive guidance for configuring the ATProtocol Identity Provider (AIP). All configuration is managed through environment variables, making it suitable for containerized deployments.

## Table of Contents

- [Quick Start](#quick-start)
- [Configuration Reference](#configuration-reference)
- [Security Configuration](#security-configuration)
- [Storage Backends](#storage-backends)
- [Key Generation](#key-generation)
- [Network Configuration](#network-configuration)
- [Template Configuration](#template-configuration)
- [Container Deployment](#container-deployment)
- [Production Configuration](#production-configuration)
- [Troubleshooting](#troubleshooting)

## Quick Start

### Minimal Development Configuration

For local development, you only need:

```bash
export EXTERNAL_BASE=http://localhost:8080
export DPOP_NONCE_SEED=$(openssl rand -hex 32)
```

### Container Deployment Template

Copy this `.env` file for container deployments:

```bash
# ============================================================================
# AIP (ATProtocol Identity Provider) Configuration
# ============================================================================
# 
# This file contains all configuration options for AIP.
# Copy this file to .env and customize the values for your deployment.
# 
# Security Note: Keep this file secure and never commit secrets to version control.
# ============================================================================

# ----------------------------------------------------------------------------
# REQUIRED CONFIGURATION
# ----------------------------------------------------------------------------

# External base URL - This MUST match your public domain/IP
# Examples:
#   Development: http://localhost:8080
#   Production:  https://auth.example.com
EXTERNAL_BASE=https://auth.example.com

# DPoP nonce seed - MUST be a 64-character hex string
# Generate with: openssl rand -hex 32
# This is used for replay attack prevention in OAuth flows
DPOP_NONCE_SEED=109d5799f295bd9ff88544cd50e981e37be30ec1b36b3c885ccae7e3b329a65f

# ----------------------------------------------------------------------------
# HTTP SERVER CONFIGURATION
# ----------------------------------------------------------------------------

# HTTP server port (default: 8080)
HTTP_PORT=8080

# Static files directory (development only)
# Default: {CARGO_MANIFEST_DIR}/static
# HTTP_STATIC_PATH=/app/static

# Templates directory (development only)
# Default: {CARGO_MANIFEST_DIR}/templates  
# HTTP_TEMPLATES_PATH=/app/templates

# HTTP client timeout for external requests
# Supports: "30s", "5m", or plain numbers (seconds)
# Default: 10s
HTTP_CLIENT_TIMEOUT=30s

# User agent for outbound HTTP requests
# Default: aip/{version} (+https://tangled.sh/@smokesignal.events/aip-rs)
# USER_AGENT=MyAIP/1.0 (+https://example.com/aip)

# ----------------------------------------------------------------------------
# STORAGE BACKEND CONFIGURATION
# ----------------------------------------------------------------------------

# Storage backend selection
# Options: "memory", "sqlite", "postgres"
# - memory: In-memory storage (development only, data lost on restart)
# - sqlite: File-based SQLite database (single instance deployments)
# - postgres: PostgreSQL database (production deployments)
STORAGE_BACKEND=postgres

# Database connection string (required for sqlite/postgres)
# PostgreSQL: postgresql://user:password@host:port/database
# SQLite: sqlite:///path/to/database.db
DATABASE_URL=postgresql://aip:secure_password_here@postgres:5432/aip_production

# Redis URL for caching and session storage (optional)
# redis://[username:password@]host:port[/database]
# REDIS_URL=redis://redis:6379/0

# ----------------------------------------------------------------------------
# ATPROTOCOL INTEGRATION
# ----------------------------------------------------------------------------

# PLC Directory hostname for DID resolution
# Default: plc.directory (official ATProtocol PLC server)
# PLC_HOSTNAME=plc.directory

# DNS nameservers for ATProtocol handle resolution
# Comma-separated list of IP addresses
# Leave empty to use system default DNS
# DNS_NAMESERVERS=8.8.8.8,1.1.1.1

# ATProtocol OAuth signing keys
# Semicolon-separated list of KeyData DID strings
# If not provided, a new P-256 key will be generated automatically
# 
# To generate keys manually:
# 1. Generate P-256 private key: goat key generate -t p256
# 
# Example (DO NOT USE IN PRODUCTION):
ATPROTO_OAUTH_SIGNING_KEYS=did:key:z42tqXsadF3WKAPX1QRWtztWFyybuNLJ6g7PzqsszsxacTbW

# ----------------------------------------------------------------------------
# OAUTH 2.1 CONFIGURATION
# ----------------------------------------------------------------------------

# OAuth signing keys for JWT token signing
# Same format as ATProtocol signing keys
# If not provided, a new P-256 key will be generated automatically
# 
# For production, generate dedicated keys:
# OAUTH_SIGNING_KEYS=did:key:z42tyEDc1V1gZxMu9vyXYkqBjRSQDtbHQdSGM67fQPnDdMo6

# OAuth supported scopes (space-separated)
# Default scopes provide ATProtocol access with transition support
# Default: "atproto:atproto atproto:transition:generic atproto:transition:email"
OAUTH_SUPPORTED_SCOPES=atproto:atproto atproto:transition:generic atproto:transition:email

# Enable client management API endpoints
# Set to "true" to enable dynamic client registration and management endpoints
# Default: false (disabled)
ENABLE_CLIENT_API=false

# Client token expiration configuration
# Default access token lifetime (supports duration format: 1d, 12h, 3600s)
# Default: 1d
CLIENT_DEFAULT_ACCESS_TOKEN_EXPIRATION=1d

# Default refresh token lifetime (supports duration format: 14d, 336h, 1209600s)
# Default: 14d
CLIENT_DEFAULT_REFRESH_TOKEN_EXPIRATION=14d

# Admin DIDs for XRPC management endpoints
# Comma-separated list of DIDs authorized to manage clients via XRPC
# Default: (empty - no admin access)
ADMIN_DIDS=did:plc:admin1,did:plc:admin2

# ----------------------------------------------------------------------------
# TLS/SSL CONFIGURATION
# ----------------------------------------------------------------------------

# Certificate bundles for HTTPS client connections
# Semicolon-separated paths to PEM certificate files
# Used when connecting to external services with custom CAs
# CERTIFICATE_BUNDLES=/etc/ssl/certs/ca-bundle.pem;/etc/ssl/custom-ca.pem

# ----------------------------------------------------------------------------
# LOGGING CONFIGURATION
# ----------------------------------------------------------------------------

# Rust log level configuration
# Levels: trace, debug, info, warn, error
# Format: target=level,global_level
# Examples:
#   RUST_LOG=info                    # Global info level
#   RUST_LOG=aip=debug,info         # Debug for aip crate, info for others
#   RUST_LOG=aip=trace,sqlx=debug   # Trace for aip, debug for sqlx
RUST_LOG=aip=info,warn

# ----------------------------------------------------------------------------
# PRODUCTION SECURITY SETTINGS
# ----------------------------------------------------------------------------

# For production deployments, ensure:
# 1. EXTERNAL_BASE uses HTTPS
# 2. Database credentials are secure and rotated regularly
# 3. DPOP_NONCE_SEED is unique per deployment
# 4. OAuth signing keys are backed up securely
# 5. TLS certificates are properly configured
# 6. Environment variables are not logged or exposed

# ----------------------------------------------------------------------------
# FEATURE FLAGS (Compile-time)
# ----------------------------------------------------------------------------

# These are set during compilation, not runtime:
# 
# Default features: ["reload", "redis", "postgres"]
# 
# Available features:
# - embed: Embedded templates for production (smaller binary)
# - reload: Template auto-reloading for development
# - sqlite: SQLite storage backend support
# - postgres: PostgreSQL storage backend support  
# - redis: Redis caching support
#
# Build examples:
# cargo build --release --no-default-features --features embed,postgres
# cargo build --features sqlite,redis
```

## Configuration Reference

### Required Variables

| Variable | Description | Example | Notes |
|----------|-------------|---------|-------|
| `EXTERNAL_BASE` | Public base URL of your AIP server | `https://auth.example.com` | Must be accessible to OAuth clients |
| `DPOP_NONCE_SEED` | 64-character hex string for DPoP nonces | `924f8a4c...569181e` | Generate with `openssl rand -hex 32` |

### HTTP Server Configuration

| Variable | Default | Description | Examples |
|----------|---------|-------------|----------|
| `HTTP_PORT` | `8080` | HTTP server port | `8080`, `3000` |
| `HTTP_STATIC_PATH` | `{project}/static` | Static files directory | `/app/static` |
| `HTTP_TEMPLATES_PATH` | `{project}/templates` | Templates directory | `/app/templates` |
| `HTTP_CLIENT_TIMEOUT` | `10s` | Timeout for external HTTP requests | `30s`, `5m`, `120` |
| `USER_AGENT` | `aip/{version} (+...)` | User agent for outbound requests | `MyAIP/1.0` |

### Storage Configuration

| Variable | Default | Description | Examples |
|----------|---------|-------------|----------|
| `STORAGE_BACKEND` | `memory` | Storage backend type | `memory`, `sqlite`, `postgres` |
| `DATABASE_URL` | - | Database connection string | See [Storage Backends](#storage-backends) |
| `REDIS_URL` | - | Redis connection string | `redis://localhost:6379/0` |

### ATProtocol Configuration

| Variable | Default | Description | Examples |
|----------|---------|-------------|----------|
| `PLC_HOSTNAME` | `plc.directory` | PLC server for DID resolution | `plc.directory` |
| `DNS_NAMESERVERS` | system default | Custom DNS servers (comma-separated) | `8.8.8.8,1.1.1.1` |
| `ATPROTO_OAUTH_SIGNING_KEYS` | auto-generated | ATProtocol signing keys | See [Key Generation](#key-generation) |

### OAuth Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `OAUTH_SIGNING_KEYS` | auto-generated | OAuth JWT signing keys |
| `OAUTH_SUPPORTED_SCOPES` | `atproto:atproto atproto:transition:generic atproto:transition:email` | Supported OAuth scopes (space-separated) |
| `ENABLE_CLIENT_API` | `false` | Enable client management API endpoints (`true`/`false`) |

### Client Management API Configuration

The client management API provides endpoints for dynamic client registration and management. These endpoints are disabled by default for security reasons.

| Variable | Default | Description | Security Notes |
|----------|---------|-------------|----------------|
| `ENABLE_CLIENT_API` | `false` | Enable client management endpoints | Only enable when client management is required |

#### Client Management Endpoints

When `ENABLE_CLIENT_API=true`, the following endpoints become available:

- `POST /oauth/clients/register` - Dynamic Client Registration (RFC 7591)
- `GET /oauth/clients/{client_id}` - Retrieve client information  
- `PUT /oauth/clients/{client_id}` - Update client configuration
- `DELETE /oauth/clients/{client_id}` - Delete client registration

#### Security Considerations

- **Disable by default**: Only enable when dynamic client registration is required
- **Access control**: Implement appropriate access controls and authentication
- **Monitoring**: Monitor client registration activities for suspicious behavior
- **Rate limiting**: Consider implementing rate limiting on registration endpoints

```bash
# Enable client management API (use with caution)
ENABLE_CLIENT_API=true

# Disable client management API (default, recommended for most deployments)
ENABLE_CLIENT_API=false
```

### TLS Configuration

| Variable | Default | Description | Examples |
|----------|---------|-------------|----------|
| `CERTIFICATE_BUNDLES` | - | Custom CA certificates (semicolon-separated) | `/etc/ssl/ca.pem;/etc/ssl/custom.pem` |

## Security Configuration

### DPoP Nonce Seed

The `DPOP_NONCE_SEED` is critical for preventing replay attacks in OAuth flows:

```bash
# Generate a secure random seed
DPOP_NONCE_SEED=$(openssl rand -hex 32)
```

**Security Requirements:**
- Must be exactly 64 hexadecimal characters
- Should be unique per deployment
- Must be kept secret and secure
- Should be rotated periodically in production

### Signing Keys

AIP uses cryptographic keys for signing JWTs and ATProtocol tokens:

#### Automatic Key Generation
If not specified, AIP will automatically generate P-256 ECDSA keys on startup:

```bash
# Keys will be auto-generated and logged
# WARNING: Keys are lost on restart with in-memory storage
```

#### Manual Key Generation

1. **Generate P-256 private key:**
   ```bash
   goat key generate -t p256
   ```

2. **Convert to KeyData format** (requires ATProtocol tools):
   ```bash
   # Use ATProtocol SDK to convert PEM to KeyData DID string
   # Result: did:key:z42tyo6ayNA7X8QUiyEchsrhRxRqjrJ5WZpgJhLtA5FdCKxp
   ```

3. **Configure environment:**
   ```bash
   OAUTH_SIGNING_KEYS=did:key:z42tvNarooqbGeRjuSGMP8GHSMcHDKGf4piREtFjTwZor4w8
   ATPROTO_OAUTH_SIGNING_KEYS=did:key:z42tk67cUGyzb2dipDwukPsfJAqXuoYzSrhQyWm5o42T4szi
   ```

#### Key Rotation

For production deployments:
1. Generate new keys before rotating
2. Update environment variables
3. Restart the service
4. Securely delete old keys

## Storage Backends

### In-Memory Storage (Development)

Suitable for development and testing only:

```bash
STORAGE_BACKEND=memory
# No DATABASE_URL required
```

**Characteristics:**
- Fast performance
- Data lost on restart
- Not suitable for production
- No persistence across deployments

### SQLite Storage (Single Instance)

Best for single-instance deployments:

```bash
STORAGE_BACKEND=sqlite
DATABASE_URL=sqlite:///var/lib/aip/aip.db
```

**Setup:**
1. Create database directory:
   ```bash
   mkdir -p /var/lib/aip
   ```

2. Run migrations:
   ```bash
   sqlx migrate run --database-url sqlite:///var/lib/aip/aip.db --source migrations/sqlite
   ```

**Characteristics:**
- File-based persistence
- No separate database server required
- Limited concurrent access
- Good for small to medium deployments

### PostgreSQL Storage (Production)

Recommended for production deployments:

```bash
STORAGE_BACKEND=postgres
DATABASE_URL=postgresql://aip_user:secure_password@postgres:5432/aip_production
```

**Setup:**
1. Create database and user:
   ```sql
   CREATE DATABASE aip_production;
   CREATE USER aip_user WITH ENCRYPTED PASSWORD 'secure_password';
   GRANT ALL PRIVILEGES ON DATABASE aip_production TO aip_user;
   ```

2. Run migrations:
   ```bash
   sqlx migrate run --database-url postgresql://aip_user:secure_password@postgres:5432/aip_production --source migrations/postgres
   ```

**Characteristics:**
- High performance and scalability
- Full ACID compliance
- Supports high availability
- Excellent for production workloads

### Redis Configuration (Optional)

Redis can be used for caching and session storage:

```bash
REDIS_URL=redis://username:password@redis:6379/0
```

**Connection String Format:**
- Basic: `redis://host:port/database`
- With auth: `redis://username:password@host:port/database`
- With TLS: `rediss://host:port/database`

## Key Generation

### Cryptographic Requirements

AIP requires ECDSA P-256 keys for:
- OAuth JWT token signing
- ATProtocol OAuth integration
- DPoP proof validation

### Key Generation Methods

#### Method 1: Goat
```bash
# Generate P-256 private key
goat key generate -t p256

```

#### Method 2: Automatic Generation
Let AIP generate keys automatically on first startup:

```bash
# AIP will log the generated key
# 2024-01-01T12:00:00Z INFO Generated new P-256 OAuth signing key: did:key:...
```

### Key Backup and Recovery

For production deployments:

1. **Backup generated keys:**
   ```bash
   # Extract key from logs or environment
   echo "did:key:zDnae..." > oauth-signing-key.txt
   ```

2. **Secure storage:**
   - Store keys in a secure key management system
   - Use environment variable injection in containers
   - Rotate keys periodically

3. **Recovery process:**
   - Restore keys from backup
   - Update environment variables
   - Restart services

## Network Configuration

### External Base URL

The `EXTERNAL_BASE` must be accessible to OAuth clients:

```bash
# Development
EXTERNAL_BASE=http://localhost:8080

# Production with custom port
EXTERNAL_BASE=https://auth.example.com:8443

# Production with load balancer
EXTERNAL_BASE=https://auth.example.com
```

### DNS Configuration

For ATProtocol handle resolution:

```bash
# Use custom DNS servers
DNS_NAMESERVERS=8.8.8.8,1.1.1.1,208.67.222.222

# Use system default (leave empty)
# DNS_NAMESERVERS=
```

### TLS Configuration

For external HTTPS connections:

```bash
# Custom CA certificates
CERTIFICATE_BUNDLES=/etc/ssl/certs/ca-bundle.pem;/etc/ssl/custom-ca.pem
```

## Template Configuration

### Embedded Templates (Production)

Build with embedded templates for smaller containers:

```bash
# Compile with embedded templates
cargo build --release --no-default-features --features embed,postgres

# No template path configuration needed
```

### Auto-Reloading Templates (Development)

For development with template hot-reloading:

```bash
# Use default features including "reload"
cargo build

# Configure template paths
HTTP_TEMPLATES_PATH=/path/to/templates
HTTP_STATIC_PATH=/path/to/static
```

## Container Deployment

### Docker Compose Example

```yaml
version: '3.8'

services:
  aip:
    image: aip:latest
    ports:
      - "8080:8080"
    environment:
      - EXTERNAL_BASE=https://auth.example.com
      - DPOP_NONCE_SEED=47dfd40e83cb7e3e6e161fa3d7b24a79b4acca80745db0dc00895459854a7884
      - STORAGE_BACKEND=postgres
      - DATABASE_URL=postgresql://aip:${DB_PASSWORD}@postgres:5432/aip
      - RUST_LOG=aip=info,warn
    depends_on:
      - postgres
    restart: unless-stopped

  postgres:
    image: postgres:17-alpine
    environment:
      - POSTGRES_DB=aip
      - POSTGRES_USER=aip
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

volumes:
  postgres_data:
```

### Kubernetes Example

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aip
spec:
  replicas: 2
  selector:
    matchLabels:
      app: aip
  template:
    metadata:
      labels:
        app: aip
    spec:
      containers:
      - name: aip
        image: aip:latest
        ports:
        - containerPort: 8080
        env:
        - name: EXTERNAL_BASE
          value: "https://auth.example.com"
        - name: DPOP_NONCE_SEED
          valueFrom:
            secretKeyRef:
              name: aip-secrets
              key: dpop-nonce-seed
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: aip-secrets
              key: database-url
        - name: STORAGE_BACKEND
          value: "postgres"
        livenessProbe:
          httpGet:
            path: /
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
```

## Production Configuration

### Security Checklist

- [ ] `EXTERNAL_BASE` uses HTTPS
- [ ] `DPOP_NONCE_SEED` is unique and secure
- [ ] Database credentials are rotated regularly  
- [ ] OAuth signing keys are backed up
- [ ] TLS certificates are valid and monitored
- [ ] Environment variables are not logged
- [ ] Network access is restricted appropriately
- [ ] `ENABLE_CLIENT_API` is only enabled when client management is required

### Performance Tuning

```bash
# Increase HTTP client timeout for slow networks
HTTP_CLIENT_TIMEOUT=60s

# Configure custom DNS for faster resolution
DNS_NAMESERVERS=8.8.8.8,1.1.1.1

# Use connection pooling with PostgreSQL
DATABASE_URL=postgresql://user:pass@host/db?max_connections=20

# Enable Redis for caching
REDIS_URL=redis://redis:6379/0
```

### Monitoring Configuration

```bash
# Detailed logging for troubleshooting
RUST_LOG=aip=debug,sqlx=info,tower_http=debug

# Production logging
RUST_LOG=aip=info,warn

# Minimal logging for high-traffic deployments
RUST_LOG=warn
```

### High Availability Setup

For HA deployments:

1. **Load balancer configuration:**
   - Use sticky sessions for OAuth flows
   - Health check endpoint: `GET /`
   - Configure SSL termination

2. **Database setup:**
   - Use PostgreSQL with replication
   - Configure connection pooling
   - Monitor database performance

3. **Storage considerations:**
   - Shared storage for SQLite (not recommended)
   - PostgreSQL primary/replica setup
   - Redis cluster for caching

## Troubleshooting

### Common Configuration Issues

#### Invalid EXTERNAL_BASE
```
Error: OAuth callback mismatch
Solution: Ensure EXTERNAL_BASE matches the URL clients can reach
```

#### Missing DPOP_NONCE_SEED
```
Error: error-aip-config-1 DPOP_NONCE_SEED must be set
Solution: Generate with: openssl rand -hex 32
```

#### Database Connection Failed
```
Error: error-aip-storage-1 Database connection failed
Solutions:
1. Verify DATABASE_URL format
2. Check database server is running
3. Verify credentials and permissions
4. Run database migrations
```

#### Key Generation Issues
```
Error: Failed to generate OAuth signing key
Solutions:
1. Check available entropy on system
2. Verify OpenSSL installation
3. Generate keys manually and set environment variables
```

### Debugging Configuration

#### Enable Debug Logging
```bash
RUST_LOG=aip=debug,config=debug
```

#### Validate Configuration
```bash
# Test configuration without starting server
cargo run --bin aip --help

# Check environment variables
env | grep -E "(EXTERNAL_BASE|DPOP_NONCE_SEED|DATABASE_URL)"
```

#### Test Database Connection
```bash
# PostgreSQL
psql $DATABASE_URL -c "SELECT version();"

# SQLite
sqlite3 /path/to/database.db ".schema"
```

### Performance Issues

#### Slow External Requests
```bash
# Increase timeout
HTTP_CLIENT_TIMEOUT=60s

# Use faster DNS
DNS_NAMESERVERS=8.8.8.8,1.1.1.1
```

#### Database Performance
```bash
# Connection pooling
DATABASE_URL=postgresql://user:pass@host/db?max_connections=20&pool_timeout=30

# Enable Redis caching
REDIS_URL=redis://localhost:6379/0
```

For additional support, check the project documentation and issue tracker.