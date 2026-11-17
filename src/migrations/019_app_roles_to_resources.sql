-- Per-app roles become resource roles: an app points at the resource whose roles it carries.
ALTER TABLE apps ADD COLUMN resource_id INTEGER REFERENCES resources(id) ON DELETE SET NULL;

-- Every app that used roles gets a resource of its own; ikc_ ids are not URIs, hence urn:.
CREATE TEMP TABLE app_home AS
SELECT
	a.id AS app_id,
	a.client_id,
	CASE WHEN a.client_id LIKE 'http%' THEN rtrim(a.client_id, '/')
		ELSE 'urn:indiko:app:' || a.client_id END AS identifier,
	COALESCE(a.name, a.client_id) AS name,
	a.available_roles,
	a.default_role
FROM apps a
WHERE a.available_roles IS NOT NULL
	OR a.default_role IS NOT NULL
	OR EXISTS (SELECT 1 FROM permissions p WHERE p.client_id = a.client_id AND COALESCE(p.role, '') != '')
	OR EXISTS (SELECT 1 FROM invite_roles i WHERE i.app_id = a.id);

INSERT OR IGNORE INTO resources (identifier, name, available_roles, default_role)
SELECT identifier, name, available_roles, default_role FROM app_home;

UPDATE apps SET resource_id = (
	SELECT r.id FROM resources r JOIN app_home h ON h.identifier = r.identifier
	WHERE h.app_id = apps.id
) WHERE id IN (SELECT app_id FROM app_home);

INSERT OR IGNORE INTO resource_clients (resource_id, client_id)
SELECT resource_id, client_id FROM apps WHERE resource_id IS NOT NULL;

-- A role equal to the default was only ever a snapshot of it; the resource default covers it.
INSERT OR IGNORE INTO resource_roles (resource_id, user_id, role)
SELECT a.resource_id, p.user_id, p.role
FROM permissions p JOIN apps a ON a.client_id = p.client_id
WHERE a.resource_id IS NOT NULL
	AND COALESCE(p.role, '') != ''
	AND p.role IS NOT COALESCE(a.default_role, '');

CREATE TABLE invite_resource_roles (
	invite_id INTEGER NOT NULL,
	resource_id INTEGER NOT NULL,
	role TEXT NOT NULL,
	PRIMARY KEY (invite_id, resource_id),
	FOREIGN KEY (invite_id) REFERENCES invites(id) ON DELETE CASCADE,
	FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE
);

INSERT OR IGNORE INTO invite_resource_roles (invite_id, resource_id, role)
SELECT i.invite_id, a.resource_id, i.role
FROM invite_roles i JOIN apps a ON a.id = i.app_id
WHERE a.resource_id IS NOT NULL;

DROP TABLE invite_roles;
DROP TABLE app_home;
ALTER TABLE apps DROP COLUMN available_roles;
ALTER TABLE apps DROP COLUMN default_role;
ALTER TABLE permissions DROP COLUMN role;
