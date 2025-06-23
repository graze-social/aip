-- Migration: Add nonce support to access_tokens and refresh_tokens tables
-- This migration adds the nonce column for OpenID Connect support to token tables

-- Add nonce column to access_tokens table
ALTER TABLE access_tokens 
ADD COLUMN nonce TEXT;

-- Add nonce column to refresh_tokens table  
ALTER TABLE refresh_tokens
ADD COLUMN nonce TEXT;

-- Add comments for documentation
COMMENT ON COLUMN access_tokens.nonce IS 'OpenID Connect nonce parameter for preventing replay attacks';
COMMENT ON COLUMN refresh_tokens.nonce IS 'OpenID Connect nonce parameter for preventing replay attacks';

-- Update covering indexes to include the new nonce column for better query performance
DROP INDEX IF EXISTS idx_access_tokens_lookup;
CREATE INDEX idx_access_tokens_lookup ON access_tokens(token)
    INCLUDE (client_id, user_id, session_id, scope, nonce, dpop_jkt)
    WHERE revoked = FALSE;