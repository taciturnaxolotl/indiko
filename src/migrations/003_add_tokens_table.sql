-- Add tokens table for IndieAuth access tokens
CREATE TABLE tokens (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	token TEXT NOT NULL UNIQUE,
	user_id INTEGER NOT NULL,
	client_id TEXT NOT NULL,
	scope TEXT NOT NULL,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
	expires_at INTEGER NOT NULL,
	revoked INTEGER NOT NULL DEFAULT 0,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_tokens_token ON tokens(token);
CREATE INDEX idx_tokens_user_id ON tokens(user_id);
CREATE INDEX idx_tokens_expires_at ON tokens(expires_at);
