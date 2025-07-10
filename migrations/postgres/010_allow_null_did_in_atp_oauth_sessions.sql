-- Migration: Allow null DID in atp_oauth_sessions table
-- This allows sessions to be created before DID resolution is complete,
-- which is needed for URL-based authorization server flows

-- PostgreSQL supports ALTER COLUMN to change NOT NULL constraint
ALTER TABLE atp_oauth_sessions ALTER COLUMN did DROP NOT NULL;