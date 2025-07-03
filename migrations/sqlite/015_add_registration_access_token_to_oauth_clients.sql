-- Migration: Add registration_access_token field to OAuth clients table
-- This migration adds the registration_access_token column to the oauth_clients table
-- to support OAuth Dynamic Client Registration (RFC 7591) token-based client management

-- Add registration_access_token column (stored as TEXT, nullable for existing clients)
ALTER TABLE oauth_clients 
ADD COLUMN registration_access_token TEXT;

-- Create index for potential queries filtering by this field
CREATE INDEX idx_oauth_clients_registration_access_token ON oauth_clients(registration_access_token);