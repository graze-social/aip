-- Migration: Create refresh_tokens table
-- This table stores OAuth refresh tokens

CREATE TABLE refresh_tokens (
    -- The refresh token value
    token TEXT PRIMARY KEY,
    
    -- Associated access token
    access_token TEXT NOT NULL,
    
    -- Client ID that owns this token
    client_id TEXT NOT NULL,
    
    -- User ID that owns this token
    user_id TEXT NOT NULL,
    
    -- Optional session ID for tracking
    session_id TEXT,
    
    -- Granted scope (space-separated values)
    scope TEXT,
    
    -- Timestamp when the token was created (ISO 8601 format)
    created_at TEXT NOT NULL,
    
    -- Timestamp when the token expires (ISO 8601 format, optional for long-lived tokens)
    expires_at TEXT,
    
    -- Foreign key reference to oauth_clients
    FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    
    -- Foreign key reference to access_tokens
    FOREIGN KEY (access_token) REFERENCES access_tokens(token) ON DELETE CASCADE
);

-- Indexes for efficient lookups
CREATE INDEX idx_refresh_tokens_client_id ON refresh_tokens(client_id);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_access_token ON refresh_tokens(access_token);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_session_id ON refresh_tokens(session_id);