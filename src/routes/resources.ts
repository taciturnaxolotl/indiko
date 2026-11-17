import { db } from "../db";
import { storedToResources, validateResources } from "../lib/oauth/resource";
import {
	parseRoleList,
	type RegisteredResource,
	type ResourceRow,
	rowToResource,
} from "../lib/oauth/resource-registry";
import { canonicalizeURL } from "../lib/oauth/urls";
import { requireAdmin } from "../lib/session";
import {
	type Checked,
	MAX_URL_LENGTH,
	optionalHttpUrl,
	optionalText,
} from "../lib/validate";

// Admin CRUD for registered resource servers; the policy lives in resource-registry.ts.

const MAX_NAME_LENGTH = 256;
const MAX_DESCRIPTION_LENGTH = 2048;
const MAX_ROLE_LENGTH = 64;
const MAX_ROLES = 32;

type Settings = Omit<RegisteredResource, "id" | "identifier">;

const NEW_RESOURCE: Settings = {
	name: "",
	description: null,
	logoUrl: null,
	availableRoles: null,
	defaultRole: null,
	restrictClients: true,
	assignmentRequired: false,
};

const badRequest = (error: string) => Response.json({ error }, { status: 400 });
const notFound = (what: string) =>
	Response.json({ error: `${what} not found` }, { status: 404 });

async function readJson(req: Request): Promise<Record<string, unknown> | null> {
	const body = await req.json().catch(() => null);
	return body && typeof body === "object" && !Array.isArray(body)
		? (body as Record<string, unknown>)
		: null;
}

function roleList(
	value: unknown,
	label: string,
): Checked<string[] | null | undefined> {
	if (value === undefined || value === null) return { ok: true, value };
	if (!Array.isArray(value) || value.length > MAX_ROLES) {
		return {
			ok: false,
			error: `${label} must be a list of at most ${MAX_ROLES} roles`,
		};
	}
	const roles = new Set<string>();
	for (const role of value) {
		if (
			typeof role !== "string" ||
			!role.trim() ||
			role.length > MAX_ROLE_LENGTH
		) {
			return { ok: false, error: `${label} contains an invalid role` };
		}
		roles.add(role.trim());
	}
	return { ok: true, value: roles.size > 0 ? [...roles] : null };
}

function flag(value: unknown, label: string): Checked<boolean | undefined> {
	return value === undefined || typeof value === "boolean"
		? { ok: true, value }
		: { ok: false, error: `${label} must be true or false` };
}

const roleAllowed = (role: string, roles: string[] | null) =>
	roles === null || roles.includes(role);

/** Apply a request body over `base`; omitted fields keep their current value. */
function mergeSettings(
	base: Settings,
	body: Record<string, unknown>,
): Checked<Settings> {
	const fields = {
		name: optionalText(body.name, "name", MAX_NAME_LENGTH),
		description: optionalText(
			body.description,
			"description",
			MAX_DESCRIPTION_LENGTH,
		),
		logoUrl: optionalHttpUrl(body.logoUrl, "logoUrl"),
		availableRoles: roleList(body.availableRoles, "availableRoles"),
		defaultRole: optionalText(body.defaultRole, "defaultRole", MAX_ROLE_LENGTH),
		restrictClients: flag(body.restrictClients, "restrictClients"),
		assignmentRequired: flag(body.assignmentRequired, "assignmentRequired"),
	};
	const merged: Record<string, unknown> = { ...base };
	for (const [key, result] of Object.entries(fields)) {
		if (!result.ok) return result;
		if (result.value !== undefined) merged[key] = result.value;
	}
	const settings = merged as Settings;
	if (!settings.name) return { ok: false, error: "name is required" };
	if (
		settings.defaultRole &&
		!roleAllowed(settings.defaultRole, settings.availableRoles)
	) {
		return { ok: false, error: "defaultRole must be one of availableRoles" };
	}
	return { ok: true, value: settings };
}

function settingsParams(s: Settings) {
	return [
		s.name,
		s.description,
		s.logoUrl,
		s.availableRoles ? JSON.stringify(s.availableRoles) : null,
		s.defaultRole,
		s.restrictClients ? 1 : 0,
		s.assignmentRequired ? 1 : 0,
	];
}

/** URL clients compare canonicalized; admin-created ikc_ ids are taken as is. */
function normalizeClientId(value: unknown): Checked<string> {
	if (typeof value !== "string" || !value || value.length > MAX_URL_LENGTH) {
		return { ok: false, error: "clientId is required" };
	}
	if (value.startsWith("http://") || value.startsWith("https://")) {
		try {
			return { ok: true, value: canonicalizeURL(value) };
		} catch {
			return { ok: false, error: "clientId is not a valid URL" };
		}
	}
	if (/^ikc_[A-Za-z0-9_-]+$/.test(value)) return { ok: true, value };
	return {
		ok: false,
		error: "clientId must be a client URL or an ikc_ client id",
	};
}

function loadResource(id: string): RegisteredResource | null {
	if (!/^\d+$/.test(id)) return null;
	const row = db.query("SELECT * FROM resources WHERE id = ?").get(Number(id));
	return row ? rowToResource(row as ResourceRow) : null;
}

function revokeTokensFor(identifier: string): void {
	const bound = db
		.query(
			"SELECT id, resource FROM tokens WHERE revoked = 0 AND resource IS NOT NULL",
		)
		.all() as { id: number; resource: string }[];
	const revoke = db.query("UPDATE tokens SET revoked = 1 WHERE id = ?");
	db.transaction(() => {
		for (const token of bound) {
			if (storedToResources(token.resource).includes(identifier)) {
				revoke.run(token.id);
			}
		}
	})();
}

// GET /api/admin/resources
export function listResources(req: Request): Response {
	const user = requireAdmin(req);
	if (user instanceof Response) return user;

	const rows = db
		.query(
			`SELECT r.*,
				(SELECT COUNT(*) FROM resource_clients c WHERE c.resource_id = r.id) AS client_count,
				(SELECT COUNT(*) FROM resource_roles u WHERE u.resource_id = r.id) AS user_count
			 FROM resources r ORDER BY r.name COLLATE NOCASE`,
		)
		.all() as Array<ResourceRow & { client_count: number; user_count: number }>;

	return Response.json({
		resources: rows.map((row) => ({
			...rowToResource(row),
			clientCount: row.client_count,
			userCount: row.user_count,
		})),
	});
}

// POST /api/admin/resources
export async function createResource(req: Request): Promise<Response> {
	const user = requireAdmin(req);
	if (user instanceof Response) return user;

	const body = await readJson(req);
	if (!body) return badRequest("Body must be a JSON object");

	const [identifier] =
		typeof body.identifier === "string"
			? (validateResources([body.identifier]) ?? [])
			: [];
	if (!identifier) {
		return badRequest(
			"identifier must be an absolute http(s) URI with no fragment",
		);
	}
	const settings = mergeSettings(NEW_RESOURCE, body);
	if (!settings.ok) return badRequest(settings.error);

	if (
		db.query("SELECT 1 FROM resources WHERE identifier = ?").get(identifier)
	) {
		return Response.json(
			{ error: "A resource with that identifier already exists" },
			{ status: 409 },
		);
	}

	const result = db
		.query(
			`INSERT INTO resources (name, description, logo_url, available_roles, default_role, restrict_clients, assignment_required, identifier)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		)
		.run(...settingsParams(settings.value), identifier);

	return Response.json(
		{ resource: loadResource(String(result.lastInsertRowid)) },
		{ status: 201 },
	);
}

// GET /api/admin/resources/:id
export function getResource(req: Request, id: string): Response {
	const user = requireAdmin(req);
	if (user instanceof Response) return user;

	const resource = loadResource(id);
	if (!resource) return notFound("Resource");

	const clients = db
		.query(
			`SELECT c.client_id, c.allowed_roles, a.name
			 FROM resource_clients c LEFT JOIN apps a ON a.client_id = c.client_id
			 WHERE c.resource_id = ? ORDER BY c.client_id`,
		)
		.all(resource.id) as Array<{
		client_id: string;
		allowed_roles: string | null;
		name: string | null;
	}>;

	const users = db
		.query(
			`SELECT u.username, u.name, r.role
			 FROM resource_roles r JOIN users u ON u.id = r.user_id
			 WHERE r.resource_id = ? ORDER BY u.username`,
		)
		.all(resource.id);

	return Response.json({
		resource,
		clients: clients.map((c) => ({
			clientId: c.client_id,
			name: c.name,
			allowedRoles: parseRoleList(c.allowed_roles),
		})),
		users,
	});
}

// PUT /api/admin/resources/:id  (the identifier is the `aud` on live tokens, so it never changes)
export async function updateResource(
	req: Request,
	id: string,
): Promise<Response> {
	const user = requireAdmin(req);
	if (user instanceof Response) return user;

	const resource = loadResource(id);
	if (!resource) return notFound("Resource");

	const body = await readJson(req);
	if (!body) return badRequest("Body must be a JSON object");
	if (
		body.identifier !== undefined &&
		body.identifier !== resource.identifier
	) {
		return badRequest(
			"identifier cannot change; create a new resource instead",
		);
	}
	const settings = mergeSettings(resource, body);
	if (!settings.ok) return badRequest(settings.error);

	const roles = settings.value.availableRoles;
	if (roles) {
		const stranded = (
			db
				.query("SELECT DISTINCT role FROM resource_roles WHERE resource_id = ?")
				.all(resource.id) as { role: string }[]
		)
			.map((r) => r.role)
			.filter((role) => !roles.includes(role));
		if (stranded.length > 0) {
			return badRequest(
				`Users still hold roles missing from availableRoles: ${stranded.join(", ")}`,
			);
		}
	}

	db.query(
		`UPDATE resources SET name = ?, description = ?, logo_url = ?, available_roles = ?,
			default_role = ?, restrict_clients = ?, assignment_required = ? WHERE id = ?`,
	).run(...settingsParams(settings.value), resource.id);

	return Response.json({ resource: loadResource(id) });
}

// DELETE /api/admin/resources/:id
export function deleteResource(req: Request, id: string): Response {
	const user = requireAdmin(req);
	if (user instanceof Response) return user;

	const resource = loadResource(id);
	if (!resource) return notFound("Resource");

	// Unregistered means unrestricted, so outstanding tokens must not survive the row.
	revokeTokensFor(resource.identifier);
	db.query("DELETE FROM resources WHERE id = ?").run(resource.id);
	return Response.json({ success: true });
}

// PUT /api/admin/resources/:id/clients  { clientId, allowedRoles? }
export async function setResourceClient(
	req: Request,
	id: string,
): Promise<Response> {
	const user = requireAdmin(req);
	if (user instanceof Response) return user;

	const resource = loadResource(id);
	if (!resource) return notFound("Resource");

	const body = await readJson(req);
	if (!body) return badRequest("Body must be a JSON object");
	const clientId = normalizeClientId(body.clientId);
	if (!clientId.ok) return badRequest(clientId.error);
	const allowed = roleList(body.allowedRoles, "allowedRoles");
	if (!allowed.ok) return badRequest(allowed.error);
	const invalid = (allowed.value ?? []).filter(
		(role) => !roleAllowed(role, resource.availableRoles),
	);
	if (invalid.length > 0) {
		return badRequest(`Unknown roles for this resource: ${invalid.join(", ")}`);
	}

	db.query(
		`INSERT INTO resource_clients (resource_id, client_id, allowed_roles) VALUES (?, ?, ?)
		 ON CONFLICT (resource_id, client_id) DO UPDATE SET allowed_roles = excluded.allowed_roles`,
	).run(
		resource.id,
		clientId.value,
		allowed.value ? JSON.stringify(allowed.value) : null,
	);
	return Response.json({ success: true, clientId: clientId.value });
}

// DELETE /api/admin/resources/:id/clients?client_id=...
export function removeResourceClient(req: Request, id: string): Response {
	const user = requireAdmin(req);
	if (user instanceof Response) return user;

	const resource = loadResource(id);
	if (!resource) return notFound("Resource");

	const clientId = normalizeClientId(
		new URL(req.url).searchParams.get("client_id"),
	);
	if (!clientId.ok) return badRequest(clientId.error);

	const result = db
		.query(
			"DELETE FROM resource_clients WHERE resource_id = ? AND client_id = ?",
		)
		.run(resource.id, clientId.value);
	if (result.changes === 0) return notFound("Client entry");
	return Response.json({ success: true });
}

// PUT /api/admin/resources/:id/users/:username  { role }
export async function setResourceUserRole(
	req: Request,
	id: string,
	username: string,
): Promise<Response> {
	const user = requireAdmin(req);
	if (user instanceof Response) return user;

	const resource = loadResource(id);
	if (!resource) return notFound("Resource");

	const target = db
		.query("SELECT id FROM users WHERE username = ?")
		.get(username) as { id: number } | undefined;
	if (!target) return notFound("User");

	const body = await readJson(req);
	if (!body) return badRequest("Body must be a JSON object");
	const role = optionalText(body.role, "role", MAX_ROLE_LENGTH);
	if (!role.ok) return badRequest(role.error);
	const trimmed = role.value?.trim();
	if (!trimmed) return badRequest("role is required");
	if (!roleAllowed(trimmed, resource.availableRoles)) {
		return badRequest(
			`role must be one of: ${(resource.availableRoles ?? []).join(", ")}`,
		);
	}

	db.query(
		`INSERT INTO resource_roles (resource_id, user_id, role) VALUES (?, ?, ?)
		 ON CONFLICT (resource_id, user_id) DO UPDATE SET role = excluded.role`,
	).run(resource.id, target.id, trimmed);
	return Response.json({ success: true });
}

// DELETE /api/admin/resources/:id/users/:username
export function removeResourceUserRole(
	req: Request,
	id: string,
	username: string,
): Response {
	const user = requireAdmin(req);
	if (user instanceof Response) return user;

	const resource = loadResource(id);
	if (!resource) return notFound("Resource");

	const result = db
		.query(
			`DELETE FROM resource_roles WHERE resource_id = ?
			 AND user_id = (SELECT id FROM users WHERE username = ?)`,
		)
		.run(resource.id, username);
	if (result.changes === 0) return notFound("Role assignment");
	return Response.json({ success: true });
}
