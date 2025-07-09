-- Migration: Create oauth_requests table
-- This table stores ATProtocol OAuth authorization requests for tracking OAuth flows

CREATE TABLE oauth_requests (
    -- OAuth state parameter as primary key
    oauth_state TEXT PRIMARY KEY,
    
    -- Issuer URL
    issuer TEXT NOT NULL,
    
    -- DID being authenticated (nullable)
    did TEXT,
    
    -- Authorization server endpoint
    authorization_server TEXT NOT NULL,
    
    -- Nonce for security
    nonce TEXT NOT NULL,
    
    -- PKCE verifier
    pkce_verifier TEXT NOT NULL,
    
    -- Signing public key
    signing_public_key TEXT NOT NULL,
    
    -- DPoP private key
    dpop_private_key TEXT NOT NULL,
    
    -- Creation timestamp (ISO 8601 format)
    created_at TEXT NOT NULL,
    
    -- Expiration timestamp (ISO 8601 format)
    expires_at TEXT NOT NULL
);

-- Indexes for efficient lookups
CREATE INDEX idx_oauth_requests_expires_at ON oauth_requests(expires_at);
CREATE INDEX idx_oauth_requests_did ON oauth_requests(did);
CREATE INDEX idx_oauth_requests_created_at ON oauth_requests(created_at);
CREATE INDEX idx_oauth_requests_authorization_server ON oauth_requests(authorization_server);