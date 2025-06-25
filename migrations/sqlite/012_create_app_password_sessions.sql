-- Migration: Create app_password_sessions table
-- This table stores sessions associated with app passwords

CREATE TABLE app_password_sessions (
    -- Composite primary key: client_id + did
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    -- OAuth client ID
    client_id TEXT NOT NULL,
    
    -- ATProtocol DID
    did TEXT NOT NULL,
    
    -- Access token from the session
    access_token TEXT NOT NULL,
    
    -- Refresh token from the session
    refresh_token TEXT,
    
    -- When the access token was created (ISO 8601 format)
    access_token_created_at TEXT NOT NULL,
    
    -- When the access token expires (ISO 8601 format)
    access_token_expires_at TEXT NOT NULL,
    
    -- Session iteration
    iteration INTEGER NOT NULL,
    
    -- When the session was exchanged/authenticated (ISO 8601 format)
    session_exchanged_at TEXT,
    
    -- Any exchange error
    exchange_error TEXT,
    
    -- Unique constraint on client_id + did (composite primary key)
    UNIQUE(client_id, did),
    
    -- Foreign key to app_passwords table
    FOREIGN KEY (client_id, did) REFERENCES app_passwords(client_id, did) ON DELETE CASCADE
);

-- Indexes for efficient lookups
CREATE INDEX idx_app_password_sessions_client_id ON app_password_sessions(client_id);
CREATE INDEX idx_app_password_sessions_did ON app_password_sessions(did);
CREATE INDEX idx_app_password_sessions_expires_at ON app_password_sessions(access_token_expires_at);