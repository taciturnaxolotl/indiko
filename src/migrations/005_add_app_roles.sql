-- Add available_roles column to apps table (JSON array of role names)
ALTER TABLE apps ADD COLUMN available_roles TEXT;

-- Add default_role column to apps table
ALTER TABLE apps ADD COLUMN default_role TEXT;
