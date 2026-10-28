-- Tie an authorization code to the token family it minted (RFC 6749 §4.1.2,
-- RFC 9700 §4.5). Replaying a used code means it leaked, so every token that
-- descends from it is revoked, the same way refresh-token reuse is handled.
ALTER TABLE authcodes ADD COLUMN family TEXT;
