-- Migration: Add require_redirect_exact field to OAuth clients table
-- This migration adds the require_redirect_exact column to the oauth_clients table
-- to support configurable redirect URI matching (exact vs prefix matching)

-- Add require_redirect_exact column (stored as INTEGER representing boolean, default 1 = true)
ALTER TABLE oauth_clients 
ADD COLUMN require_redirect_exact INTEGER NOT NULL DEFAULT 1;

-- Create index for potential queries filtering by this field
CREATE INDEX idx_oauth_clients_require_redirect_exact ON oauth_clients(require_redirect_exact);