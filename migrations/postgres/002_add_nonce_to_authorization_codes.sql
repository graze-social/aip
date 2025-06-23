-- Migration: Add nonce support to authorization_codes table
-- This migration adds the nonce column for OpenID Connect support

-- Add nonce column to authorization_codes table
ALTER TABLE authorization_codes 
ADD COLUMN nonce TEXT;

-- Add comment for documentation
COMMENT ON COLUMN authorization_codes.nonce IS 'OpenID Connect nonce parameter for preventing replay attacks';

-- Update the covering index to include the new nonce column for better query performance
DROP INDEX IF EXISTS idx_authorization_codes_lookup;
CREATE INDEX idx_authorization_codes_lookup ON authorization_codes(code) 
    INCLUDE (client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce)
    WHERE used = FALSE;