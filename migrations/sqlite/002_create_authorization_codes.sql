-- Migration: Create authorization_codes table
-- This table stores OAuth authorization codes for the authorization code flow

CREATE TABLE authorization_codes (
    -- The authorization code value
    code TEXT PRIMARY KEY,
    
    -- Client ID that requested this code
    client_id TEXT NOT NULL,
    
    -- User ID that authorized this code
    user_id TEXT NOT NULL,
    
    -- Optional session ID for tracking
    session_id TEXT,
    
    -- Redirect URI used in the authorization request
    redirect_uri TEXT NOT NULL,
    
    -- Granted scope (space-separated values)
    scope TEXT,
    
    -- PKCE code challenge
    code_challenge TEXT,
    
    -- PKCE code challenge method (S256, plain)
    code_challenge_method TEXT,
    
    -- Timestamp when the code was created (ISO 8601 format)
    created_at TEXT NOT NULL,
    
    -- Timestamp when the code expires (ISO 8601 format)
    expires_at TEXT NOT NULL,
    
    -- Whether this code has been used (0 = false, 1 = true)
    used INTEGER NOT NULL DEFAULT 0,
    
    -- Foreign key reference to oauth_clients
    FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE
);

-- Indexes for efficient lookups
CREATE INDEX idx_authorization_codes_client_id ON authorization_codes(client_id);
CREATE INDEX idx_authorization_codes_user_id ON authorization_codes(user_id);
CREATE INDEX idx_authorization_codes_expires_at ON authorization_codes(expires_at);
CREATE INDEX idx_authorization_codes_used ON authorization_codes(used);