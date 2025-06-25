-- Migration: Create app_passwords table
-- This table stores hashed app passwords for ATProtocol authentication

CREATE TABLE app_passwords (
    -- Composite primary key: client_id + did
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    -- OAuth client ID
    client_id TEXT NOT NULL,
    
    -- ATProtocol DID (must be unique)
    did TEXT NOT NULL UNIQUE,
    
    -- The app password (stored as clear text)
    app_password TEXT NOT NULL,
    
    -- When this password was created (ISO 8601 format)
    created_at TEXT NOT NULL,
    
    -- When this password was last updated (ISO 8601 format)
    updated_at TEXT NOT NULL,
    
    -- Unique constraint on client_id + did (composite primary key)
    UNIQUE(client_id, did)
);

-- Indexes for efficient lookups
CREATE INDEX idx_app_passwords_client_id ON app_passwords(client_id);
CREATE INDEX idx_app_passwords_did ON app_passwords(did);
CREATE INDEX idx_app_passwords_updated_at ON app_passwords(updated_at);