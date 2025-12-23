-- Add refresh token support
ALTER TABLE tokens ADD COLUMN refresh_token TEXT UNIQUE;
ALTER TABLE tokens ADD COLUMN refresh_expires_at INTEGER;

CREATE INDEX idx_tokens_refresh_token ON tokens(refresh_token);
