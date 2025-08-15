-- Migration: Remove did column from oauth_requests table
-- This removes the did column which was previously made nullable but is no longer needed

-- SQLite doesn't support ALTER TABLE DROP COLUMN directly, so we need to recreate the table

-- Step 1: Create new table without did column
CREATE TABLE oauth_requests_new (
    -- OAuth state parameter as primary key
    oauth_state TEXT PRIMARY KEY,
    
    -- Issuer URL
    issuer TEXT NOT NULL,
    
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

-- Step 2: Copy data from old table to new table, excluding the did column
INSERT INTO oauth_requests_new (
    oauth_state,
    issuer,
    authorization_server,
    nonce,
    pkce_verifier,
    signing_public_key,
    dpop_private_key,
    created_at,
    expires_at
)
SELECT 
    oauth_state,
    issuer,
    authorization_server,
    nonce,
    pkce_verifier,
    signing_public_key,
    dpop_private_key,
    created_at,
    expires_at
FROM oauth_requests;

-- Step 3: Drop old table
DROP TABLE oauth_requests;

-- Step 4: Rename new table to original name
ALTER TABLE oauth_requests_new RENAME TO oauth_requests;

-- Step 5: Recreate indexes (excluding did-related ones)
CREATE INDEX idx_oauth_requests_expires_at ON oauth_requests(expires_at);
CREATE INDEX idx_oauth_requests_created_at ON oauth_requests(created_at);
CREATE INDEX idx_oauth_requests_authorization_server ON oauth_requests(authorization_server);