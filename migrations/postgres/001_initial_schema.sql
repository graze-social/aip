-- AIP Complete Schema Migration for PostgreSQL 17
-- This migration creates all tables needed for the AIP OAuth 2.1 server
-- Consolidated from multiple migration files with PostgreSQL 17 optimizations

-- OAuth Clients table for dynamic client registration (RFC 7591)
CREATE TABLE oauth_clients (
    client_id VARCHAR(255) PRIMARY KEY,
    client_secret TEXT,
    client_name TEXT NOT NULL,
    redirect_uris JSONB NOT NULL,
    grant_types JSONB NOT NULL,
    response_types JSONB NOT NULL,
    scope TEXT,
    token_endpoint_auth_method VARCHAR(50) NOT NULL,
    client_type VARCHAR(20) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT chk_client_type CHECK (client_type IN ('public', 'confidential')),
    CONSTRAINT chk_auth_method CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'client_secret_post', 'none', 'private_key_jwt'))
);

CREATE INDEX idx_oauth_clients_created_at ON oauth_clients(created_at);
CREATE INDEX idx_oauth_clients_client_type ON oauth_clients(client_type);

-- Keys table for JWT signing and verification
CREATE TABLE keys (
    key_id VARCHAR(255) PRIMARY KEY,
    key_data TEXT NOT NULL,
    key_type VARCHAR(50) NOT NULL DEFAULT 'signing',
    created_at TIMESTAMPTZ NOT NULL,
    is_default_signing BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_keys_key_type ON keys(key_type);
CREATE INDEX idx_keys_is_default_signing ON keys(is_default_signing);
CREATE INDEX idx_keys_created_at ON keys(created_at);
CREATE UNIQUE INDEX idx_keys_default_signing_unique ON keys(is_default_signing) WHERE is_default_signing = TRUE;

-- Authorization Codes table for OAuth 2.1 authorization code flow
CREATE TABLE authorization_codes (
    code VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    session_id VARCHAR(255),
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    code_challenge TEXT,
    code_challenge_method VARCHAR(10),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT chk_code_challenge_method CHECK (code_challenge_method IS NULL OR code_challenge_method IN ('S256', 'plain')),
    CONSTRAINT fk_authorization_codes_client_id FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE
);

CREATE INDEX idx_authorization_codes_client_id ON authorization_codes(client_id);
CREATE INDEX idx_authorization_codes_expires_at ON authorization_codes(expires_at);
CREATE INDEX idx_authorization_codes_user_id ON authorization_codes(user_id);

-- Access Tokens table with DPoP support
CREATE TABLE access_tokens (
    token VARCHAR(255) PRIMARY KEY,
    token_type VARCHAR(20) NOT NULL DEFAULT 'Bearer',
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255),
    session_id VARCHAR(255),
    session_iteration INTEGER,
    scope TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    dpop_jkt VARCHAR(255),
    CONSTRAINT chk_token_type CHECK (token_type IN ('Bearer', 'DPoP')),
    CONSTRAINT fk_access_tokens_client_id FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE
);

CREATE INDEX idx_access_tokens_client_id ON access_tokens(client_id);
CREATE INDEX idx_access_tokens_user_id ON access_tokens(user_id);
CREATE INDEX idx_access_tokens_expires_at ON access_tokens(expires_at);
CREATE INDEX idx_access_tokens_revoked ON access_tokens(revoked);
CREATE INDEX idx_access_tokens_dpop_jkt ON access_tokens(dpop_jkt);

-- Refresh Tokens table for token refresh flow
CREATE TABLE refresh_tokens (
    token VARCHAR(255) PRIMARY KEY,
    access_token VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    session_id VARCHAR(255),
    scope TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT fk_refresh_tokens_client_id FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE
);

CREATE INDEX idx_refresh_tokens_client_id ON refresh_tokens(client_id);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_revoked ON refresh_tokens(revoked);

-- PAR (Pushed Authorization Request) table for RFC 9126
CREATE TABLE par_requests (
    request_uri VARCHAR(255) PRIMARY KEY,
    authorization_request JSONB NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    subject VARCHAR(255),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT fk_par_requests_client_id FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE
);

CREATE INDEX idx_par_requests_client_id ON par_requests(client_id);
CREATE INDEX idx_par_requests_expires_at ON par_requests(expires_at);
CREATE INDEX idx_par_requests_subject ON par_requests(subject);
CREATE INDEX idx_par_requests_created_at ON par_requests(created_at);

-- ATProtocol OAuth Sessions table with iteration support
CREATE TABLE atp_oauth_sessions (
    session_id VARCHAR(255) NOT NULL,
    did VARCHAR(255) NOT NULL,
    iteration INTEGER NOT NULL,
    session_created_at TIMESTAMPTZ NOT NULL,
    atp_oauth_state TEXT NOT NULL,
    signing_key_jkt VARCHAR(255) NOT NULL,
    dpop_key TEXT NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    access_token_created_at TIMESTAMPTZ,
    access_token_expires_at TIMESTAMPTZ,
    access_token_scopes JSONB,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (session_id, did, iteration)
);

CREATE INDEX idx_atp_oauth_sessions_session_id ON atp_oauth_sessions(session_id);
CREATE INDEX idx_atp_oauth_sessions_did ON atp_oauth_sessions(did);
CREATE INDEX idx_atp_oauth_sessions_iteration ON atp_oauth_sessions(iteration);
CREATE INDEX idx_atp_oauth_sessions_created_at ON atp_oauth_sessions(session_created_at);
CREATE INDEX idx_atp_oauth_sessions_access_token ON atp_oauth_sessions(access_token);
CREATE INDEX idx_atp_oauth_sessions_latest ON atp_oauth_sessions(did, session_id, iteration DESC);

-- Authorization Requests table for temporary request storage
CREATE TABLE authorization_requests (
    session_id VARCHAR(255) PRIMARY KEY,
    request_data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_authorization_requests_created_at ON authorization_requests(created_at);

-- OAuth Requests table for ATProtocol OAuth flow tracking
CREATE TABLE oauth_requests (
    oauth_state VARCHAR(255) PRIMARY KEY,
    issuer VARCHAR(500) NOT NULL,
    did VARCHAR(255) NOT NULL,
    nonce VARCHAR(255) NOT NULL,
    pkce_verifier TEXT NOT NULL,
    signing_public_key TEXT NOT NULL,
    dpop_private_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_oauth_requests_expires_at ON oauth_requests(expires_at);
CREATE INDEX idx_oauth_requests_did ON oauth_requests(did);
CREATE INDEX idx_oauth_requests_created_at ON oauth_requests(created_at);

-- DID Documents table for ATProtocol identity resolution
CREATE TABLE did_documents (
    did VARCHAR(255) PRIMARY KEY,
    document JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT chk_did_format CHECK (did ~ '^did:[a-z0-9]+:[a-zA-Z0-9._-]+$')
);

CREATE INDEX idx_did_documents_updated_at ON did_documents(updated_at);
CREATE INDEX idx_did_documents_created_at ON did_documents(created_at);

-- PostgreSQL 17 specific optimizations

-- Create indexes for efficient expiry checks
-- Since CURRENT_TIMESTAMP is not immutable, we cannot use it in partial indexes
-- These indexes will still be used efficiently for queries comparing with CURRENT_TIMESTAMP

-- Create partial indexes for active tokens (not revoked)
CREATE INDEX idx_access_tokens_active ON access_tokens(client_id, user_id) 
    WHERE revoked = FALSE;

CREATE INDEX idx_refresh_tokens_active ON refresh_tokens(client_id, user_id) 
    WHERE revoked = FALSE;

-- Create covering indexes for common queries (PostgreSQL 11+ INCLUDE clause)
CREATE INDEX idx_oauth_clients_lookup ON oauth_clients(client_id) 
    INCLUDE (client_secret, client_type, token_endpoint_auth_method, redirect_uris);

CREATE INDEX idx_authorization_codes_lookup ON authorization_codes(code) 
    INCLUDE (client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method)
    WHERE used = FALSE;

-- Add comments for documentation
COMMENT ON TABLE oauth_clients IS 'OAuth 2.1 client registrations supporting dynamic client registration (RFC 7591)';
COMMENT ON TABLE keys IS 'Cryptographic keys for JWT signing and verification';
COMMENT ON TABLE authorization_codes IS 'OAuth 2.1 authorization codes for the authorization code flow';
COMMENT ON TABLE access_tokens IS 'OAuth 2.1 access tokens with DPoP support';
COMMENT ON TABLE refresh_tokens IS 'OAuth 2.1 refresh tokens for token refresh flow';
COMMENT ON TABLE par_requests IS 'Pushed Authorization Requests (RFC 9126)';
COMMENT ON TABLE atp_oauth_sessions IS 'ATProtocol OAuth session data with iteration support';
COMMENT ON TABLE authorization_requests IS 'Temporary authorization request data during OAuth flows';
COMMENT ON TABLE oauth_requests IS 'ATProtocol OAuth authorization requests for tracking OAuth flows';
COMMENT ON TABLE did_documents IS 'ATProtocol DID document storage for identity resolution caching';

COMMENT ON COLUMN access_tokens.dpop_jkt IS 'DPoP key thumbprint for DPoP-bound access tokens';
COMMENT ON COLUMN atp_oauth_sessions.iteration IS 'Session iteration number for supporting session updates';
COMMENT ON COLUMN oauth_clients.metadata IS 'Additional client metadata as JSON for extensibility';

-- PostgreSQL 17 additional features

-- Enable row-level security for sensitive tables (optional, requires setup)
-- ALTER TABLE access_tokens ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE authorization_codes ENABLE ROW LEVEL SECURITY;

-- Create a function to clean up expired tokens (can be called by pg_cron or similar)
CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS TABLE(
    deleted_access_tokens BIGINT,
    deleted_refresh_tokens BIGINT,
    deleted_authorization_codes BIGINT,
    deleted_par_requests BIGINT,
    deleted_oauth_requests BIGINT
) AS $$
DECLARE
    access_count BIGINT;
    refresh_count BIGINT;
    auth_code_count BIGINT;
    par_count BIGINT;
    oauth_count BIGINT;
BEGIN
    -- Delete expired access tokens
    DELETE FROM access_tokens WHERE expires_at < CURRENT_TIMESTAMP;
    GET DIAGNOSTICS access_count = ROW_COUNT;
    
    -- Delete expired refresh tokens
    DELETE FROM refresh_tokens WHERE expires_at < CURRENT_TIMESTAMP;
    GET DIAGNOSTICS refresh_count = ROW_COUNT;
    
    -- Delete expired or used authorization codes
    DELETE FROM authorization_codes WHERE expires_at < CURRENT_TIMESTAMP OR used = TRUE;
    GET DIAGNOSTICS auth_code_count = ROW_COUNT;
    
    -- Delete expired PAR requests
    DELETE FROM par_requests WHERE expires_at < CURRENT_TIMESTAMP;
    GET DIAGNOSTICS par_count = ROW_COUNT;
    
    -- Delete expired OAuth requests
    DELETE FROM oauth_requests WHERE expires_at < CURRENT_TIMESTAMP;
    GET DIAGNOSTICS oauth_count = ROW_COUNT;
    
    RETURN QUERY SELECT access_count, refresh_count, auth_code_count, par_count, oauth_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_expired_tokens() IS 'Removes expired tokens and authorization codes from all tables';

-- Create statistics for query optimization (PostgreSQL 14+)
CREATE STATISTICS oauth_clients_stats (dependencies) ON client_type, token_endpoint_auth_method FROM oauth_clients;
CREATE STATISTICS access_tokens_stats (dependencies) ON client_id, user_id, revoked FROM access_tokens;
CREATE STATISTICS atp_oauth_sessions_stats (dependencies) ON session_id, did, iteration FROM atp_oauth_sessions;

-- Additional performance indexes for common query patterns
CREATE INDEX idx_atp_oauth_sessions_active ON atp_oauth_sessions(did, session_id)
    WHERE access_token IS NOT NULL;

CREATE INDEX idx_oauth_clients_redirect_uris ON oauth_clients 
    USING GIN (redirect_uris);

CREATE INDEX idx_oauth_clients_grant_types ON oauth_clients 
    USING GIN (grant_types);

-- Create a view for the latest ATP OAuth sessions
CREATE OR REPLACE VIEW v_latest_atp_oauth_sessions AS
SELECT DISTINCT ON (session_id, did) 
    session_id,
    did,
    iteration,
    session_created_at,
    atp_oauth_state,
    signing_key_jkt,
    dpop_key,
    access_token,
    refresh_token,
    access_token_created_at,
    access_token_expires_at,
    access_token_scopes,
    metadata
FROM atp_oauth_sessions
ORDER BY session_id, did, iteration DESC;

COMMENT ON VIEW v_latest_atp_oauth_sessions IS 'View showing only the latest iteration of each ATP OAuth session';