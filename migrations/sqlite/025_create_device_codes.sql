-- Create device_codes table for RFC 8628 Device Authorization Grant
CREATE TABLE device_codes (
    device_code TEXT PRIMARY KEY,
    user_code TEXT UNIQUE NOT NULL,
    client_id TEXT NOT NULL,
    scope TEXT,
    authorized_user TEXT,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (client_id) REFERENCES oauth_clients (client_id)
);

-- Create indexes for efficient lookups
CREATE INDEX idx_device_codes_user_code ON device_codes(user_code);
CREATE INDEX idx_device_codes_expires_at ON device_codes(expires_at);
CREATE INDEX idx_device_codes_client_id ON device_codes(client_id);