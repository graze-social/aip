-- Migration: Create par_requests table
-- This table stores Pushed Authorization Requests (PAR) as per RFC 9126

CREATE TABLE par_requests (
    -- Unique request URI identifier
    request_uri TEXT PRIMARY KEY,
    
    -- The authorization request data as JSON
    authorization_request TEXT NOT NULL,
    
    -- Client ID that made the request
    client_id TEXT NOT NULL,
    
    -- Timestamp when the request was created (ISO 8601 format)
    created_at TEXT NOT NULL,
    
    -- Timestamp when the request expires (ISO 8601 format)
    expires_at TEXT NOT NULL,
    
    -- Optional ATProtocol subject (legacy support)
    subject TEXT,
    
    -- Foreign key reference to oauth_clients
    FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE
);

-- Indexes for efficient lookups
CREATE INDEX idx_par_requests_client_id ON par_requests(client_id);
CREATE INDEX idx_par_requests_expires_at ON par_requests(expires_at);
CREATE INDEX idx_par_requests_created_at ON par_requests(created_at);