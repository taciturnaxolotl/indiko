-- Grant types a client registered for (RFC 7591 §2), as a JSON array.
-- Only clients registered through /oauth/register declare one. NULL means
-- unrestricted: every auto-registered URL client, and every app that predates
-- this column, keeps working exactly as before.
-- Storing it is what lets registration require redirect_uris only for clients
-- that actually redirect, and lets the token endpoint refuse a grant the client
-- never registered for.
ALTER TABLE apps ADD COLUMN grant_types TEXT DEFAULT NULL;
