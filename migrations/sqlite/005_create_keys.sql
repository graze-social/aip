-- Migration: Create keys table
-- This table stores cryptographic keys for JWT signing and other purposes

CREATE TABLE keys (
    -- Key identifier
    key_id TEXT PRIMARY KEY,
    
    -- The key data as a string (KeyData serialized format)
    key_data TEXT NOT NULL,
    
    -- Key type for categorization (signing, encryption, etc.)
    key_type TEXT NOT NULL DEFAULT 'signing',
    
    -- Timestamp when the key was created (ISO 8601 format)
    created_at TEXT NOT NULL,
    
    -- Whether this is the default signing key (0 = false, 1 = true)
    is_default_signing INTEGER NOT NULL DEFAULT 0
);

-- Indexes for efficient lookups
CREATE INDEX idx_keys_key_type ON keys(key_type);
CREATE INDEX idx_keys_is_default_signing ON keys(is_default_signing);
CREATE INDEX idx_keys_created_at ON keys(created_at);

-- Ensure only one default signing key
CREATE UNIQUE INDEX idx_keys_unique_default_signing ON keys(is_default_signing) WHERE is_default_signing = 1;