-- Add username column to authcodes table for direct access without user_id lookup
ALTER TABLE authcodes ADD COLUMN username TEXT NOT NULL DEFAULT '';
-- Add ldap_username column to invites table
-- When set, the invite can only be used by a user with that exact username
-- Used for LDAP-verified user provisioning flow
ALTER TABLE invites ADD COLUMN ldap_username TEXT DEFAULT NULL;
-- Add provisioned_via_ldap flag for audit purposes
-- Allows admins to identify LDAP-provisioned accounts
-- Important: If a user is deleted from LDAP, their account remains active but this flag tracks its origin
ALTER TABLE users ADD COLUMN provisioned_via_ldap INTEGER NOT NULL DEFAULT 0;
-- Add last_ldap_verified_at timestamp for LDAP account sync with grace period
-- Tracks when we last verified the user exists in LDAP
-- Used to implement caching and grace periods for orphaned account detection
ALTER TABLE users ADD COLUMN last_ldap_verified_at INTEGER DEFAULT NULL;
