-- Migration: Create app password tables for ATProtocol authentication
-- This migration creates the app_passwords and app_password_sessions tables

-- App Passwords table for storing hashed app passwords
CREATE TABLE app_passwords (
    -- OAuth client ID
    client_id VARCHAR(255) NOT NULL,
    
    -- ATProtocol DID (must be unique)
    did VARCHAR(255) NOT NULL UNIQUE,
    
    -- The app password (stored as clear text)
    app_password TEXT NOT NULL,
    
    -- When this password was created
    created_at TIMESTAMPTZ NOT NULL,
    
    -- When this password was last updated
    updated_at TIMESTAMPTZ NOT NULL,
    
    -- Composite primary key on client_id + did
    PRIMARY KEY (client_id, did),
    
    -- Foreign key to oauth_clients
    CONSTRAINT fk_app_passwords_client_id FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE
);

-- Indexes for efficient lookups
CREATE INDEX idx_app_passwords_client_id ON app_passwords(client_id);
CREATE INDEX idx_app_passwords_did ON app_passwords(did);
CREATE INDEX idx_app_passwords_updated_at ON app_passwords(updated_at);

-- App Password Sessions table for storing sessions associated with app passwords
CREATE TABLE app_password_sessions (
    -- OAuth client ID
    client_id VARCHAR(255) NOT NULL,
    
    -- ATProtocol DID
    did VARCHAR(255) NOT NULL,
    
    -- Access token from the session
    access_token TEXT NOT NULL,
    
    -- Refresh token from the session
    refresh_token TEXT,
    
    -- When the access token was created
    access_token_created_at TIMESTAMPTZ NOT NULL,
    
    -- When the access token expires
    access_token_expires_at TIMESTAMPTZ NOT NULL,
    
    -- Session iteration
    iteration INTEGER NOT NULL,
    
    -- When the session was exchanged/authenticated
    session_exchanged_at TIMESTAMPTZ,
    
    -- Any exchange error
    exchange_error TEXT,
    
    -- Composite primary key on client_id + did
    PRIMARY KEY (client_id, did),
    
    -- Foreign key to app_passwords table with CASCADE DELETE
    CONSTRAINT fk_app_password_sessions FOREIGN KEY (client_id, did) REFERENCES app_passwords(client_id, did) ON DELETE CASCADE
);

-- Indexes for efficient lookups
CREATE INDEX idx_app_password_sessions_client_id ON app_password_sessions(client_id);
CREATE INDEX idx_app_password_sessions_did ON app_password_sessions(did);
CREATE INDEX idx_app_password_sessions_expires_at ON app_password_sessions(access_token_expires_at);