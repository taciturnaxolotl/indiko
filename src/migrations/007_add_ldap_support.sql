-- LDAP Integration Support
-- This migration adds columns needed for LDAP authentication and account provisioning

-- Add username column to authcodes table for direct access without user_id lookup
ALTER TABLE authcodes ADD COLUMN username TEXT NOT NULL DEFAULT '';

-- Add ldap_username column to invites table
-- When set, the invite can only be used by a user with that exact username
-- Used for LDAP-verified user provisioning flow
ALTER TABLE invites ADD COLUMN ldap_username TEXT DEFAULT NULL;

-- Add provisioned_via_ldap flag for audit purposes
-- Allows admins to identify LDAP-provisioned accounts
-- Important: If user is deleted from LDAP, the account remains active but this flag tracks its origin
ALTER TABLE users ADD COLUMN provisioned_via_ldap INTEGER NOT NULL DEFAULT 0;
