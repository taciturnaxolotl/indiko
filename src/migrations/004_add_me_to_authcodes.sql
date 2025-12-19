-- Add me parameter to authcodes for IndieAuth client delegation
ALTER TABLE authcodes ADD COLUMN me TEXT;
