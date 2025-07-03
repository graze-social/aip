-- Migration: Add token expiration fields to OAuth clients table
-- This migration adds access_token_expiration and refresh_token_expiration columns
-- to the oauth_clients table to support configurable token lifetimes

-- Add access_token_expiration column (stored as seconds, default 1 day = 86400 seconds)
ALTER TABLE oauth_clients 
ADD COLUMN access_token_expiration INTEGER NOT NULL DEFAULT 86400;

-- Add refresh_token_expiration column (stored as seconds, default 14 days = 1209600 seconds)
ALTER TABLE oauth_clients 
ADD COLUMN refresh_token_expiration INTEGER NOT NULL DEFAULT 1209600;

-- Create indexes for performance if needed for queries filtering by expiration
CREATE INDEX idx_oauth_clients_access_token_expiration ON oauth_clients(access_token_expiration);
CREATE INDEX idx_oauth_clients_refresh_token_expiration ON oauth_clients(refresh_token_expiration);