-- Add JWKS column to oauth_clients for private_key_jwt authentication
-- This stores the client's public key set in JWK Set format

ALTER TABLE oauth_clients 
ADD COLUMN jwks JSONB;

-- Add index for JWKS queries (optional, for performance)
CREATE INDEX idx_oauth_clients_jwks ON oauth_clients USING GIN (jwks);

-- Add comment explaining the column
COMMENT ON COLUMN oauth_clients.jwks IS 'JSON Web Key Set for private_key_jwt client authentication (RFC 7517)';