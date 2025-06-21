-- Migration: Create OAuth clients table
-- This table stores OAuth 2.1 client registrations for dynamic client registration

CREATE TABLE oauth_clients (
    -- Primary identifier for the OAuth client
    client_id TEXT PRIMARY KEY,
    
    -- Client secret (nullable for public clients)
    client_secret TEXT,
    
    -- Human-readable client name
    client_name TEXT,
    
    -- JSON array of allowed redirect URIs
    redirect_uris TEXT NOT NULL,
    
    -- JSON array of grant types (authorization_code, client_credentials, refresh_token)
    grant_types TEXT NOT NULL,
    
    -- JSON array of response types (code)
    response_types TEXT NOT NULL,
    
    -- Space-separated scope values that can be requested by this client
    scope TEXT,
    
    -- Token endpoint authentication method
    -- Values: client_secret_basic, client_secret_post, none, private_key_jwt
    token_endpoint_auth_method TEXT NOT NULL,
    
    -- Client type (public or confidential)
    client_type TEXT NOT NULL,
    
    -- Timestamp when the client was registered (ISO 8601 format)
    created_at TEXT NOT NULL,
    
    -- Timestamp when the client was last updated (ISO 8601 format)
    updated_at TEXT NOT NULL,
    
    -- Additional client metadata as JSON
    metadata TEXT NOT NULL
);

-- Index for efficient client lookups
CREATE INDEX idx_oauth_clients_created_at ON oauth_clients(created_at);
CREATE INDEX idx_oauth_clients_client_type ON oauth_clients(client_type);