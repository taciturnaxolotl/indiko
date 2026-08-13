-- Record which RFC 8707 resources a user actually consented to for an app.
-- Auto-approval previously checked scopes alone, so a client already approved
-- for `profile` could add `&resource=https://anything` and get a token for that
-- audience without the consent screen ever appearing. Storing the granted
-- audiences lets the auto-approve path require coverage of both.
-- NULL means the grant covers no resources — any `resource` re-prompts.
ALTER TABLE permissions ADD COLUMN resources TEXT DEFAULT NULL;
