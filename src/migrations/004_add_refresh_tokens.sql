CREATE TABLE tokens_new (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	token TEXT NOT NULL UNIQUE,
	user_id INTEGER NOT NULL,
	client_id TEXT NOT NULL,
	scope TEXT NOT NULL,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
	expires_at INTEGER NOT NULL,
	revoked INTEGER NOT NULL DEFAULT 0,
	refresh_token TEXT UNIQUE,
	refresh_expires_at INTEGER,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

INSERT INTO tokens_new (id, token, user_id, client_id, scope, created_at, expires_at, revoked)
SELECT id, token, user_id, client_id, scope, created_at, expires_at, revoked
FROM tokens;

DROP TABLE tokens;

ALTER TABLE tokens_new RENAME TO tokens;

CREATE INDEX idx_tokens_token ON tokens(token);
CREATE INDEX idx_tokens_user_id ON tokens(user_id);
CREATE INDEX idx_tokens_expires_at ON tokens(expires_at);
CREATE INDEX idx_tokens_refresh_token ON tokens(refresh_token);
