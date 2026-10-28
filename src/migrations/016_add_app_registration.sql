-- Record HOW each OAuth client came to exist, so the admin UI (and later the
-- consent page) can tell a client an admin created apart from one anybody
-- registered through the unauthenticated /oauth/register endpoint. Both were
-- previously stored as is_preregistered = 1 and were indistinguishable, which
-- let a self-registered client borrow the trust of an admin-created one.
--
-- Values:
--   'admin' - created by an admin in the clients UI (default for existing rows)
--   'dcr'   - RFC 7591 dynamic client registration (anyone, unauthenticated)
--   'url'   - IndieAuth URL client auto-registered on first authorization
ALTER TABLE apps ADD COLUMN registration TEXT NOT NULL DEFAULT 'admin';

-- Existing auto-registered URL clients are the is_preregistered = 0 rows.
UPDATE apps SET registration = 'url' WHERE is_preregistered = 0;
