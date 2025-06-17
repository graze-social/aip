-- Migration: Create authorization_requests table
-- This table stores authorization requests by session ID

CREATE TABLE authorization_requests (
    -- Session ID as primary key
    session_id TEXT PRIMARY KEY,
    
    -- The authorization request data as JSON
    request_data TEXT NOT NULL,
    
    -- Timestamp when the request was stored (ISO 8601 format)
    created_at TEXT NOT NULL
);

-- Index for efficient cleanup
CREATE INDEX idx_authorization_requests_created_at ON authorization_requests(created_at);