-- Migration: Create atp_oauth_sessions table
-- This table stores ATProtocol OAuth sessions for bridging OAuth flows

CREATE TABLE atp_oauth_sessions (
    -- Composite primary key: did + session_id + iteration
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    -- Unique session ID
    session_id TEXT NOT NULL,
    
    -- DID being authenticated
    did TEXT NOT NULL,
    
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
    
    -- Unique constraint on did + session_id + iteration
    UNIQUE(did, session_id, iteration)
);

-- Indexes for efficient lookups
CREATE INDEX idx_atp_oauth_sessions_did_session ON atp_oauth_sessions(did, session_id);
CREATE INDEX idx_atp_oauth_sessions_iteration ON atp_oauth_sessions(iteration);
CREATE INDEX idx_atp_oauth_sessions_created_at ON atp_oauth_sessions(session_created_at);
CREATE INDEX idx_atp_oauth_sessions_access_token_expires ON atp_oauth_sessions(access_token_expires_at);