-- Migration: Refactor atp_oauth_sessions primary key and oauth_requests table
-- This migration combines three separate migrations:
-- 1. Refactor atp_oauth_sessions primary key (remove did from PK)
-- 2. Add authorization_server column to oauth_requests
-- 3. Remove did column from oauth_requests
--
-- Changes to atp_oauth_sessions:
-- - Remove 'did' from primary key, making (session_id, iteration) the primary key
-- - Update indexes and view
--
-- Changes to oauth_requests:
-- - Add 'authorization_server' column
-- - Remove 'did' column (including its index)

-- ==========================================
-- Part 1: Refactor atp_oauth_sessions table
-- ==========================================

-- Step 1: Drop the existing primary key constraint
ALTER TABLE atp_oauth_sessions DROP CONSTRAINT atp_oauth_sessions_pkey;

-- Step 2: Add new primary key constraint on session_id and iteration
ALTER TABLE atp_oauth_sessions ADD PRIMARY KEY (session_id, iteration);

-- Step 4: Drop old indexes that may no longer be optimal
DROP INDEX IF EXISTS idx_atp_oauth_sessions_session_id;

-- Step 5: Create indexes for performance
-- Index on access token expiration for cleanup queries
CREATE INDEX IF NOT EXISTS idx_atp_oauth_sessions_access_token_expires ON atp_oauth_sessions(access_token_expires_at);

-- Index on access_token for token lookups
CREATE INDEX IF NOT EXISTS idx_atp_oauth_sessions_access_token ON atp_oauth_sessions(access_token);

-- Step 6: Update the view to reflect the new primary key structure
CREATE OR REPLACE VIEW v_latest_atp_oauth_sessions AS
SELECT DISTINCT ON (session_id) 
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
ORDER BY session_id, iteration DESC;

-- ==========================================
-- Part 2: Refactor oauth_requests table
-- ==========================================

-- Step 1: Add 'authorization_server' column
ALTER TABLE oauth_requests ADD COLUMN authorization_server VARCHAR(500) NOT NULL DEFAULT '';

-- Step 2: Remove the default constraint after adding the column
-- This ensures existing rows get a default value but new rows must provide a value
ALTER TABLE oauth_requests ALTER COLUMN authorization_server DROP DEFAULT;

-- Step 3: Drop index on did column (if it exists)
DROP INDEX IF EXISTS idx_oauth_requests_did;

-- Step 4: Drop the did column (no longer needed)
ALTER TABLE oauth_requests DROP COLUMN did;