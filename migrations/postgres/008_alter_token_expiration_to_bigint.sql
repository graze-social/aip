-- Fix token expiration column types to match Rust i64 type
-- Changes INTEGER (32-bit) columns to BIGINT (64-bit) to fix type mismatch error

-- Alter access_token_expiration column from INTEGER to BIGINT
ALTER TABLE oauth_clients 
ALTER COLUMN access_token_expiration TYPE BIGINT;

-- Alter refresh_token_expiration column from INTEGER to BIGINT
ALTER TABLE oauth_clients 
ALTER COLUMN refresh_token_expiration TYPE BIGINT;

-- Update comments to reflect the type change
COMMENT ON COLUMN oauth_clients.access_token_expiration IS 'Access token lifetime in seconds as BIGINT (default: 86400 = 1 day)';
COMMENT ON COLUMN oauth_clients.refresh_token_expiration IS 'Refresh token lifetime in seconds as BIGINT (default: 1209600 = 14 days)';