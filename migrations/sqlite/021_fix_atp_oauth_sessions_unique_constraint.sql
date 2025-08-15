-- Migration: Fix ATP OAuth sessions unique constraint issue
-- 
-- Problem: The table has both:
-- 1. session_id TEXT PRIMARY KEY (allows only 1 record per session_id)  
-- 2. UNIQUE INDEX on (session_id, iteration) (redundant and causing constraint violations)
--
-- Since session_id values are unique ULIDs, the unique index on (session_id, iteration) 
-- is redundant and prevents legitimate session updates during OAuth callback processing.
--
-- Solution: Drop the redundant unique index, keeping only the PRIMARY KEY constraint

-- Drop the redundant unique index that was causing constraint violations
DROP INDEX IF EXISTS idx_atp_oauth_sessions_session_iteration;