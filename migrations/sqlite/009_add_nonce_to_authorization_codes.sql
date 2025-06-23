-- Migration: Add nonce support to authorization_codes table
-- This migration adds the nonce column for OpenID Connect support

-- Add nonce column to authorization_codes table
ALTER TABLE authorization_codes 
ADD COLUMN nonce TEXT;

-- SQLite doesn't support adding comments to columns after table creation,
-- so the column purpose is documented here:
-- nonce: OpenID Connect nonce parameter for preventing replay attacks