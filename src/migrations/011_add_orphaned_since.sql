-- Track when a user was first detected as orphaned (missing from LDAP).
-- NULL means the user is not currently considered orphaned.
-- Used by the hourly cleanup job to implement a real grace period:
-- action is only taken after orphaned_since + grace_period has elapsed.
ALTER TABLE users ADD COLUMN orphaned_since INTEGER DEFAULT NULL;
