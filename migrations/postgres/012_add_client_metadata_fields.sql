-- Migration: Add OAuth client metadata fields
-- Adds application_type, software_id, and software_version fields to oauth_clients table
-- These fields support RFC 7591 Dynamic Client Registration metadata

ALTER TABLE oauth_clients ADD COLUMN application_type VARCHAR(20);
ALTER TABLE oauth_clients ADD COLUMN software_id TEXT;
ALTER TABLE oauth_clients ADD COLUMN software_version TEXT;

-- Add check constraint for application_type
ALTER TABLE oauth_clients ADD CONSTRAINT chk_application_type 
    CHECK (application_type IS NULL OR application_type IN ('web', 'native'));

-- Add comments for documentation
COMMENT ON COLUMN oauth_clients.application_type IS 'OAuth client application type (web or native) from RFC 7591';
COMMENT ON COLUMN oauth_clients.software_id IS 'Unique identifier for the client software from RFC 7591';
COMMENT ON COLUMN oauth_clients.software_version IS 'Version of the client software from RFC 7591';