-- Whether the user chose to stay signed in to an IndieAuth client that has no
-- way to ask for offline_access itself. Carried on the code so the token
-- endpoint knows to mint a refresh token without widening the granted scope.
ALTER TABLE authcodes ADD COLUMN issue_refresh INTEGER NOT NULL DEFAULT 0;
