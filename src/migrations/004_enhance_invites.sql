-- Enhance invites table with usage limits, expiry, and app role assignments
-- Note: SQLite doesn't support DROP COLUMN, so we keep old columns for backward compatibility
-- But we'll use the new columns going forward

-- Add new columns to invites table
ALTER TABLE invites ADD COLUMN max_uses INTEGER DEFAULT 1;
ALTER TABLE invites ADD COLUMN current_uses INTEGER NOT NULL DEFAULT 0;
ALTER TABLE invites ADD COLUMN expires_at INTEGER;
ALTER TABLE invites ADD COLUMN note TEXT;

-- Create invite_roles table for app-specific role assignments
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

CREATE INDEX IF NOT EXISTS idx_invite_roles_invite_id ON invite_roles(invite_id);
CREATE INDEX IF NOT EXISTS idx_invite_roles_app_id ON invite_roles(app_id);

-- Create invite_uses table to track each use (supports multi-use invites)
CREATE TABLE IF NOT EXISTS invite_uses (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	invite_id INTEGER NOT NULL,
	user_id INTEGER NOT NULL,
	used_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	FOREIGN KEY (invite_id) REFERENCES invites(id) ON DELETE CASCADE,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_invite_uses_invite_id ON invite_uses(invite_id);
CREATE INDEX IF NOT EXISTS idx_invite_uses_user_id ON invite_uses(user_id);

-- Migrate existing single-use invites to new structure
-- For invites that have been used, set current_uses = 1 and max_uses = 1
UPDATE invites SET current_uses = 1, max_uses = 1 WHERE used = 1;

-- For unused invites, set max_uses = 1 and current_uses = 0
UPDATE invites SET max_uses = 1, current_uses = 0 WHERE used = 0;

-- Migrate old invite uses to new invite_uses table
INSERT INTO invite_uses (invite_id, user_id, used_at)
SELECT id, used_by, used_at FROM invites WHERE used = 1 AND used_by IS NOT NULL AND used_at IS NOT NULL;
