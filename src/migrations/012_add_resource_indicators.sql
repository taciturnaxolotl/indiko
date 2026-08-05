-- RFC 8707 Resource Indicators: bind an access token to a specific resource
-- server (its `aud`). The requested `resource` rides from the authorization
-- request → the auth code / device code → the issued token, and is echoed as
-- `aud` from token introspection so a resource server can verify the token was
-- minted for IT and reject one intended for a different service.
-- NULL means the token is unscoped (no resource requested) — today's behaviour.
ALTER TABLE authcodes ADD COLUMN resource TEXT DEFAULT NULL;
ALTER TABLE device_codes ADD COLUMN resource TEXT DEFAULT NULL;
ALTER TABLE tokens ADD COLUMN resource TEXT DEFAULT NULL;
