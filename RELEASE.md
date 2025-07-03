# RELEASE.md

AIP is developed with the intention of being deployed as a container that is backed by a database. While the project includes in-memory implementations of internal storage interfaces for development and testing purposes, these are not meant to be used in non-development environments and will result in data loss.

## Storage Methods

### SQLite Storage
SQLite storage solutions are available for low-resource deployments. However, caution is advised as there is no formal migration process for data from SQLite storage to PostgreSQL storage.

### PostgreSQL Storage (Preferred)
The PostgreSQL storage method is the preferred solution for production deployments. AIP uses PostgreSQL 17 features and capabilities.

## Template Embedding

For release builds, templates are "embedded" into the application for performance and security when the container is built. While this can be tuned with the "reload" feature, using the "embed" feature is strongly recommended for production deployments.

## Building with Custom Templates

Custom templates can be included in the build process by adding the directory containing your custom templates to the build context and using the `templates` build argument.

### Process

1. Clone the AIP project:
   ```bash
   git clone [repository-url] && cd aip
   ```

2. Copy your templates into the build context:
   ```bash
   cp -r path/to/your/template-dir ./custom-templates
   ```

3. Build AIP with your custom templates:
   ```bash
   docker build --platform=linux/amd64 --pull --build-arg TEMPLATES=./custom-templates -t aip:version_custom .
   ```

## Static Assets

AIP can also serve the static assets it uses. See the `Dockerfile` for all of the supported build arguments.

## Runtime Configuration

### Client Management API

AIP includes optional client management API endpoints that can be enabled or disabled at runtime:

```bash
# Enable client management API (provides dynamic client registration)
ENABLE_CLIENT_API=true

# Disable client management API (default, more secure)
ENABLE_CLIENT_API=false
```

**Security Note**: The client management API is disabled by default. Only enable it when dynamic client registration and management capabilities are required for your deployment.

### Token Configuration

AIP supports configurable token expiration times for OAuth clients:

```bash
# Default access token lifetime (supports duration format: 1d, 12h, 3600s)
# Default: 1d
CLIENT_DEFAULT_ACCESS_TOKEN_EXPIRATION=1d

# Default refresh token lifetime (supports duration format: 14d, 336h, 1209600s)
# Default: 14d
CLIENT_DEFAULT_REFRESH_TOKEN_EXPIRATION=14d
```

### Admin Configuration

AIP supports administrative access for client management via XRPC endpoints:

```bash
# Admin DIDs for XRPC management endpoints
# Comma-separated list of DIDs authorized to manage clients via XRPC
# Default: (empty - no admin access)
ADMIN_DIDS=did:plc:admin1,did:plc:admin2
```

**Security Note**: Admin DIDs provide privileged access to client management operations. Only configure trusted DIDs with administrative privileges.

## Additional Build Arguments

Refer to the project's `Dockerfile` for a comprehensive list of all supported build arguments and configuration options available during the container build process.