-- Add status and role columns to users table
ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'inactive'));
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user';
-- Update existing admin users to have 'admin' role
UPDATE users SET role = 'admin' WHERE is_admin = 1;
