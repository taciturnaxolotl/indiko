-- Add name column to credentials table for multiple passkey support
ALTER TABLE credentials ADD COLUMN name TEXT;

-- Update existing credentials with a default name
UPDATE credentials SET name = 'Passkey ' || id WHERE name IS NULL;
