-- Add tables for IndieAuth/OAuth 2.0 support
-- Apps (auto-registered on first authorization request)
CREATE TABLE IF NOT EXISTS apps (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	client_id TEXT NOT NULL UNIQUE,
	redirect_uris TEXT NOT NULL, -- JSON array
	name TEXT,
	first_seen INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	last_used INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
-- User permissions per app
CREATE TABLE IF NOT EXISTS permissions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
	client_id TEXT NOT NULL,
	scopes TEXT NOT NULL, -- JSON array
	granted_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	last_used INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
	FOREIGN KEY (client_id) REFERENCES apps(client_id) ON DELETE CASCADE,
	UNIQUE(user_id, client_id)
);
-- Authorization codes (short-lived, single-use)
CREATE TABLE IF NOT EXISTS authcodes (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	code TEXT NOT NULL UNIQUE,
	user_id INTEGER NOT NULL,
	client_id TEXT NOT NULL,
	redirect_uri TEXT NOT NULL,
	scopes TEXT NOT NULL, -- JSON array
	code_challenge TEXT NOT NULL,
	code_challenge_method TEXT NOT NULL DEFAULT 'S256',
	expires_at INTEGER NOT NULL,
	used INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
-- Indexes
CREATE INDEX IF NOT EXISTS idx_apps_client_id ON apps(client_id);
CREATE INDEX IF NOT EXISTS idx_permissions_user_id ON permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_permissions_client_id ON permissions(client_id);
CREATE INDEX IF NOT EXISTS idx_authcodes_code ON authcodes(code);
CREATE INDEX IF NOT EXISTS idx_authcodes_expires_at ON authcodes(expires_at);
