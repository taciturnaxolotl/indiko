-- Add columns to apps table for pre-registration metadata
ALTER TABLE apps ADD COLUMN logo_url TEXT;
ALTER TABLE apps ADD COLUMN description TEXT;
ALTER TABLE apps ADD COLUMN is_preregistered INTEGER NOT NULL DEFAULT 0;
ALTER TABLE apps ADD COLUMN client_secret_hash TEXT;
-- Add role column to permissions table for per-user, per-app roles
ALTER TABLE permissions ADD COLUMN role TEXT;
