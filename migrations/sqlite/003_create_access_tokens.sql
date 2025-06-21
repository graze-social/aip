-- Migration: Create access_tokens table
-- This table stores OAuth access tokens

CREATE TABLE access_tokens (
    -- The access token value
    token TEXT PRIMARY KEY,
    
    -- Token type (bearer, dpop)
    token_type TEXT NOT NULL,
    
    -- Client ID that owns this token
    client_id TEXT NOT NULL,
    
    -- User ID (optional for client credentials flow)
    user_id TEXT,
    
    -- Optional session ID for tracking
    session_id TEXT,
    
    -- Session iteration for ATProtocol OAuth sessions
    session_iteration INTEGER,
    
    -- Granted scope (space-separated values)
    scope TEXT,
    
    -- Timestamp when the token was created (ISO 8601 format)
    created_at TEXT NOT NULL,
    
    -- Timestamp when the token expires (ISO 8601 format)
    expires_at TEXT NOT NULL,
    
    -- DPoP key thumbprint for DPoP tokens
    dpop_jkt TEXT,
    
    -- Foreign key reference to oauth_clients
    FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE
);

-- Indexes for efficient lookups
CREATE INDEX idx_access_tokens_client_id ON access_tokens(client_id);
CREATE INDEX idx_access_tokens_user_id ON access_tokens(user_id);
CREATE INDEX idx_access_tokens_expires_at ON access_tokens(expires_at);
CREATE INDEX idx_access_tokens_session_id ON access_tokens(session_id);
CREATE INDEX idx_access_tokens_dpop_jkt ON access_tokens(dpop_jkt);