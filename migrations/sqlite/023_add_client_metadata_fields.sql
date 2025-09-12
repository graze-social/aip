-- Migration: Add OAuth client metadata fields
-- Adds application_type, software_id, and software_version fields to oauth_clients table
-- These fields support RFC 7591 Dynamic Client Registration metadata

ALTER TABLE oauth_clients ADD COLUMN application_type TEXT;
ALTER TABLE oauth_clients ADD COLUMN software_id TEXT;
ALTER TABLE oauth_clients ADD COLUMN software_version TEXT;