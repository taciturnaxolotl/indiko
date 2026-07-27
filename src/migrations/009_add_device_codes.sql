-- RFC 8628: Device Authorization Grant
CREATE TABLE device_codes (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	device_code TEXT NOT NULL UNIQUE,
	user_code TEXT NOT NULL UNIQUE,
	client_id TEXT NOT NULL,
	scope TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	interval INTEGER NOT NULL DEFAULT 5,
	last_polled_at INTEGER,
	status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'denied')),
	user_id INTEGER,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_device_codes_device_code ON device_codes(device_code);
CREATE INDEX idx_device_codes_user_code ON device_codes(user_code);
CREATE INDEX idx_device_codes_expires_at ON device_codes(expires_at);
