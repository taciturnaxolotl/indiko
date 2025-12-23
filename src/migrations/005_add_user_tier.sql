PRAGMA foreign_keys = OFF;

CREATE TABLE users_new (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT NOT NULL UNIQUE,
	name TEXT NOT NULL,
	email TEXT,
	photo TEXT,
	url TEXT,
	status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'inactive')),
	role TEXT NOT NULL DEFAULT 'user',
	tier TEXT NOT NULL DEFAULT 'developer' CHECK(tier IN ('admin', 'developer', 'user')),
	is_admin INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

INSERT INTO users_new (id, username, name, email, photo, url, status, role, tier, is_admin, created_at)
SELECT 
	id, 
	username, 
	name, 
	email, 
	photo, 
	url, 
	status, 
	role, 
	CASE WHEN is_admin = 1 THEN 'admin' ELSE 'developer' END,
	is_admin, 
	created_at
FROM users;

DROP TABLE users;

ALTER TABLE users_new RENAME TO users;

PRAGMA foreign_keys = ON;
