-- Migration: Add nonce support to access_tokens and refresh_tokens tables
-- This migration adds the nonce column for OpenID Connect support to token tables

-- Add nonce column to access_tokens table
ALTER TABLE access_tokens 
ADD COLUMN nonce TEXT;

-- Add nonce column to refresh_tokens table
ALTER TABLE refresh_tokens
ADD COLUMN nonce TEXT;

-- SQLite doesn't support adding comments to columns after table creation,
-- so the column purpose is documented here:
-- nonce: OpenID Connect nonce parameter for preventing replay attacks