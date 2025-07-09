-- Migration: Allow null DID in atp_oauth_sessions table
-- This allows sessions to be created before DID resolution is complete,
-- which is needed for URL-based authorization server flows

-- SQLite doesn't support ALTER COLUMN to change NOT NULL constraint,
-- so we need to recreate the table

-- Step 1: Create new table with nullable did column
CREATE TABLE atp_oauth_sessions_new (
    -- session_id is the primary key
    session_id TEXT PRIMARY KEY,
    
    -- DID being authenticated (can be null during initial session creation)
    did TEXT,
    
    -- Session iteration (for refresh flows)
    iteration INTEGER NOT NULL,
    
    -- Session creation time (ISO 8601 format)
    session_created_at TEXT NOT NULL,
    
    -- ATProtocol OAuth state for tracking
    atp_oauth_state TEXT NOT NULL,
    
    -- JWK thumbprint of the signing key used to create the session
    signing_key_jkt TEXT NOT NULL,
    
    -- String serialized KeyData p256 private key provided to oauth_init
    dpop_key TEXT NOT NULL,
    
    -- Access token from token exchange process
    access_token TEXT,
    
    -- Refresh token from token exchange process
    refresh_token TEXT,
    
    -- Timestamp when the access token was created (ISO 8601 format)
    access_token_created_at TEXT,
    
    -- Timestamp when the access token expires (ISO 8601 format)
    access_token_expires_at TEXT,
    
    -- Scopes associated with the access token (JSON array)
    access_token_scopes TEXT,
    
    -- Additional session metadata (JSON)
    metadata TEXT
);

-- Step 2: Copy data from old table to new table
INSERT INTO atp_oauth_sessions_new (
    session_id, did, iteration, session_created_at, atp_oauth_state, 
    signing_key_jkt, dpop_key, access_token, refresh_token, 
    access_token_created_at, access_token_expires_at, access_token_scopes, metadata
)
SELECT 
    session_id, did, iteration, session_created_at, atp_oauth_state,
    signing_key_jkt, dpop_key, access_token, refresh_token,
    access_token_created_at, access_token_expires_at, access_token_scopes, metadata
FROM atp_oauth_sessions;

-- Step 3: Drop old table
DROP TABLE atp_oauth_sessions;

-- Step 4: Rename new table to original name
ALTER TABLE atp_oauth_sessions_new RENAME TO atp_oauth_sessions;

-- Step 5: Recreate indexes
-- Unique index on session_id and iteration
CREATE UNIQUE INDEX idx_atp_oauth_sessions_session_iteration ON atp_oauth_sessions(session_id, iteration);

-- Other indexes for efficient lookups
CREATE INDEX idx_atp_oauth_sessions_did ON atp_oauth_sessions(did);
CREATE INDEX idx_atp_oauth_sessions_did_session ON atp_oauth_sessions(did, session_id);
CREATE INDEX idx_atp_oauth_sessions_iteration ON atp_oauth_sessions(iteration);
CREATE INDEX idx_atp_oauth_sessions_created_at ON atp_oauth_sessions(session_created_at);
CREATE INDEX idx_atp_oauth_sessions_access_token_expires ON atp_oauth_sessions(access_token_expires_at);