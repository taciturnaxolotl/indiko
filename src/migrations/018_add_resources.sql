-- Registered resource servers: a client allowlist and per-user roles for an audience.
-- Audiences with no row keep plain RFC 8707 behaviour (consent is the only gate).
CREATE TABLE IF NOT EXISTS resources (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	identifier TEXT NOT NULL UNIQUE, -- normalized like validateResources(); the token's aud
	name TEXT NOT NULL,
	description TEXT,
	logo_url TEXT,
	available_roles TEXT, -- JSON array, NULL = free-form
	default_role TEXT,
	restrict_clients INTEGER NOT NULL DEFAULT 1,
	assignment_required INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- No FK on client_id: URL clients may be allowed before indiko has seen them.
CREATE TABLE IF NOT EXISTS resource_clients (
	resource_id INTEGER NOT NULL,
	client_id TEXT NOT NULL,
	allowed_roles TEXT, -- JSON array ceiling, NULL = any role
	PRIMARY KEY (resource_id, client_id),
	FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS resource_roles (
	resource_id INTEGER NOT NULL,
	user_id INTEGER NOT NULL,
	role TEXT NOT NULL,
	PRIMARY KEY (resource_id, user_id),
	FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_resource_roles_user ON resource_roles(user_id);
