-- Full schema for indiko
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT NOT NULL UNIQUE,
	name TEXT NOT NULL,
	email TEXT,
	photo TEXT,
	url TEXT,
	status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'inactive')),
	role TEXT NOT NULL DEFAULT 'user',
	is_admin INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS credentials (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
	credential_id BLOB NOT NULL UNIQUE,
	public_key BLOB NOT NULL,
	counter INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	token TEXT NOT NULL UNIQUE,
	user_id INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS challenges (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	challenge TEXT NOT NULL UNIQUE,
	username TEXT NOT NULL,
	type TEXT NOT NULL CHECK(type IN ('registration', 'authentication')),
	expires_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS invites (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	code TEXT NOT NULL UNIQUE,
	created_by INTEGER NOT NULL,
	used INTEGER NOT NULL DEFAULT 0,
	used_by INTEGER,
	used_at INTEGER,
	max_uses INTEGER DEFAULT 1,
	current_uses INTEGER NOT NULL DEFAULT 0,
	expires_at INTEGER,
	note TEXT,
	message TEXT,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
	FOREIGN KEY (used_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS apps (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	client_id TEXT NOT NULL UNIQUE,
	redirect_uris TEXT NOT NULL,
	name TEXT,
	logo_url TEXT,
	description TEXT,
	is_preregistered INTEGER NOT NULL DEFAULT 0,
	client_secret_hash TEXT,
	available_roles TEXT,
	default_role TEXT,
	first_seen INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	last_used INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS permissions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
	client_id TEXT NOT NULL,
	scopes TEXT NOT NULL,
	role TEXT,
	granted_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	last_used INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
	FOREIGN KEY (client_id) REFERENCES apps(client_id) ON DELETE CASCADE,
	UNIQUE(user_id, client_id)
);

CREATE TABLE IF NOT EXISTS authcodes (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	code TEXT NOT NULL UNIQUE,
	user_id INTEGER NOT NULL,
	client_id TEXT NOT NULL,
	redirect_uri TEXT NOT NULL,
	scopes TEXT NOT NULL,
	code_challenge TEXT NOT NULL,
	code_challenge_method TEXT NOT NULL DEFAULT 'S256',
	expires_at INTEGER NOT NULL,
	used INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS invite_roles (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	invite_id INTEGER NOT NULL,
	app_id INTEGER NOT NULL,
	role TEXT NOT NULL,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	FOREIGN KEY (invite_id) REFERENCES invites(id) ON DELETE CASCADE,
	FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE,
	UNIQUE(invite_id, app_id)
);

CREATE TABLE IF NOT EXISTS invite_uses (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	invite_id INTEGER NOT NULL,
	user_id INTEGER NOT NULL,
	used_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	FOREIGN KEY (invite_id) REFERENCES invites(id) ON DELETE CASCADE,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_challenges_challenge ON challenges(challenge);
CREATE INDEX IF NOT EXISTS idx_challenges_expires_at ON challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_invites_code ON invites(code);
CREATE INDEX IF NOT EXISTS idx_apps_client_id ON apps(client_id);
CREATE INDEX IF NOT EXISTS idx_permissions_user_id ON permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_permissions_client_id ON permissions(client_id);
CREATE INDEX IF NOT EXISTS idx_authcodes_code ON authcodes(code);
CREATE INDEX IF NOT EXISTS idx_authcodes_expires_at ON authcodes(expires_at);
CREATE INDEX IF NOT EXISTS idx_invite_roles_invite_id ON invite_roles(invite_id);
CREATE INDEX IF NOT EXISTS idx_invite_roles_app_id ON invite_roles(app_id);
CREATE INDEX IF NOT EXISTS idx_invite_uses_invite_id ON invite_uses(invite_id);
CREATE INDEX IF NOT EXISTS idx_invite_uses_user_id ON invite_uses(user_id);
