-- Add JWKS column to oauth_clients for private_key_jwt authentication
-- This stores the client's public key set in JWK Set format

ALTER TABLE oauth_clients 
ADD COLUMN jwks TEXT;

-- SQLite doesn't support JSONB, but we can store JSON as TEXT
-- The application layer will handle JSON serialization/deserialization