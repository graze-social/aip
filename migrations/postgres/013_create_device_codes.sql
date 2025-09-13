-- Create device_codes table for RFC 8628 Device Authorization Grant
CREATE TABLE device_codes (
    device_code TEXT PRIMARY KEY,
    user_code TEXT UNIQUE NOT NULL,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
    scope TEXT,
    authorized_user TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes for efficient lookups
CREATE INDEX idx_device_codes_user_code ON device_codes(user_code);
CREATE INDEX idx_device_codes_expires_at ON device_codes(expires_at);
CREATE INDEX idx_device_codes_client_id ON device_codes(client_id);