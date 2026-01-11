-- OIDC signing keys for ID Token generation
CREATE TABLE IF NOT EXISTS oidc_keys (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	kid TEXT NOT NULL UNIQUE,
	private_key TEXT NOT NULL,
	public_key TEXT NOT NULL,
	is_active INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

-- Add nonce and auth_time to authcodes for OIDC
ALTER TABLE authcodes ADD COLUMN nonce TEXT;
ALTER TABLE authcodes ADD COLUMN auth_time INTEGER;

CREATE INDEX IF NOT EXISTS idx_oidc_keys_kid ON oidc_keys(kid);
CREATE INDEX IF NOT EXISTS idx_oidc_keys_active ON oidc_keys(is_active);
