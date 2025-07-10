-- Migration: Add metadata column to atp_oauth_sessions table
-- This column stores additional session metadata as JSON

ALTER TABLE atp_oauth_sessions ADD COLUMN metadata TEXT;