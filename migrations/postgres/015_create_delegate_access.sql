-- Delegate access table: allows one DID to act on behalf of another
CREATE TABLE IF NOT EXISTS delegate_access (
    owner_did TEXT NOT NULL,
    delegate_did TEXT NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (owner_did, delegate_did)
);

CREATE INDEX IF NOT EXISTS idx_delegate_access_owner ON delegate_access (owner_did);
CREATE INDEX IF NOT EXISTS idx_delegate_access_delegate ON delegate_access (delegate_did);
