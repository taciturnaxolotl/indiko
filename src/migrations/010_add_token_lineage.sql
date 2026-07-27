-- Refresh token rotation lineage (RFC 9700 §4.14.2 reuse detection).
-- family: shared id tying every rotation of one grant together.
-- rotated: token superseded by a newer rotation (kept, not deleted, so reuse is detectable).
ALTER TABLE tokens ADD COLUMN family TEXT;
ALTER TABLE tokens ADD COLUMN rotated INTEGER NOT NULL DEFAULT 0;

-- Existing rows each become their own single-member family.
UPDATE tokens SET family = lower(hex(randomblob(16))) WHERE family IS NULL;

CREATE INDEX idx_tokens_family ON tokens(family);
