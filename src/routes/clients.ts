import { nanoid } from "nanoid";
import { db } from "../db";
import {
	clientDisplayName,
	clientRegistration,
} from "../lib/oauth/client-display";
import { hashSecret } from "../lib/secrets";
import { getSessionUserFlexible, validateCsrf } from "../lib/session";

function generateClientSecret(): string {
	return `iks_${nanoid(43)}`; // indiko secret
}

function generateClientId(): string {
	return `ikc_${nanoid(21)}`; // indiko client
}

// Input caps for admin-supplied client metadata.
const MAX_NAME_LENGTH = 256;
const MAX_DESCRIPTION_LENGTH = 2048;
const MAX_URL_LENGTH = 2048;

function isHttpUrl(value: string): boolean {
	try {
		const u = new URL(value);
		return u.protocol === "http:" || u.protocol === "https:";
	} catch {
		return false;
	}
}

/**
 * Validate an optional free-text field: must be a string within `max` when
 * present. Returns the normalized value (null for empty/absent) or an error
 * message. `undefined` is passed through so callers can tell "omitted" from
 * "cleared".
 */
function optionalText(
	value: unknown,
	label: string,
	max: number,
):
	| { ok: true; value: string | null | undefined }
	| { ok: false; error: string } {
	if (value === undefined) return { ok: true, value: undefined };
	if (value === null || value === "") return { ok: true, value: null };
	if (typeof value !== "string") {
		return { ok: false, error: `${label} must be a string` };
	}
	if (value.length > max) {
		return { ok: false, error: `${label} must be at most ${max} characters` };
	}
	return { ok: true, value };
}

function optionalHttpUrl(
	value: unknown,
	label: string,
):
	| { ok: true; value: string | null | undefined }
	| { ok: false; error: string } {
	const text = optionalText(value, label, MAX_URL_LENGTH);
	if (!text.ok) return text;
	if (typeof text.value === "string" && !isHttpUrl(text.value)) {
		return { ok: false, error: `${label} must be an http(s) URL` };
	}
	return text;
}

/** redirect_uris must be a non-empty array of http(s) URL strings. */
function validateRedirectUris(
	value: unknown,
): { ok: true; value: string[] } | { ok: false; error: string } {
	if (!Array.isArray(value) || value.length === 0) {
		return { ok: false, error: "At least one redirect URI is required" };
	}
	for (const uri of value) {
		if (
			typeof uri !== "string" ||
			uri.length > MAX_URL_LENGTH ||
			!isHttpUrl(uri)
		) {
			return {
				ok: false,
				error: `Invalid redirect URI: ${typeof uri === "string" ? uri.slice(0, 200) : String(uri)}`,
			};
		}
	}
	return { ok: true, value: value as string[] };
}

export function listClients(req: Request): Response {
	const user = getSessionUserFlexible(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.isAdmin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	const clients = db
		.query(
			`SELECT 
				id,
				client_id,
				name,
				logo_url,
				description,
				redirect_uris,
				is_preregistered,
				registration,
				first_seen,
				last_used
			FROM apps
			ORDER BY is_preregistered DESC, last_used DESC`,
		)
		.all() as Array<{
		id: number;
		client_id: string;
		name: string | null;
		logo_url: string | null;
		description: string | null;
		redirect_uris: string;
		is_preregistered: number;
		registration: string | null;
		first_seen: number;
		last_used: number;
	}>;

	// Get distinct roles for each app
	const appRoles = db
		.query(
			`SELECT a.id as app_id, p.role 
			FROM permissions p
			JOIN apps a ON p.client_id = a.client_id
			WHERE p.role IS NOT NULL AND p.role != '' 
			GROUP BY a.id, p.role 
			ORDER BY a.id, p.role`,
		)
		.all() as Array<{ app_id: number; role: string }>;

	// Group roles by app_id
	const rolesByApp = new Map<number, string[]>();
	for (const { app_id, role } of appRoles) {
		if (!rolesByApp.has(app_id)) {
			rolesByApp.set(app_id, []);
		}
		rolesByApp.get(app_id)?.push(role);
	}

	return Response.json({
		clients: clients.map((c) => ({
			id: c.id,
			clientId: c.client_id,
			name: clientDisplayName(c.client_id, c.name),
			logoUrl: c.logo_url,
			description: c.description,
			redirectUris: JSON.parse(c.redirect_uris) as string[],
			isPreregistered: c.is_preregistered === 1,
			registration: clientRegistration(c),
			firstSeen: c.first_seen,
			lastUsed: c.last_used,
			roles: rolesByApp.get(c.id) || [],
		})),
	});
}

export async function createClient(req: Request): Promise<Response> {
	const user = getSessionUserFlexible(req);
	if (user instanceof Response) {
		return user;
	}

	const csrfError = validateCsrf(req);
	if (csrfError) return csrfError;

	if (!user.isAdmin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	// Only admin and developer tiers can create apps
	if (user.tier !== "admin" && user.tier !== "developer") {
		return Response.json(
			{ error: "Developer or admin tier required to create apps" },
			{ status: 403 },
		);
	}

	try {
		const body = await req.json();
		const {
			name: rawName,
			logoUrl: rawLogoUrl,
			description: rawDescription,
			redirectUris: rawRedirectUris,
			availableRoles,
			defaultRole,
		} = body;

		const redirects = validateRedirectUris(rawRedirectUris);
		if (!redirects.ok) {
			return Response.json({ error: redirects.error }, { status: 400 });
		}
		const redirectUris = redirects.value;

		const nameCheck = optionalText(rawName, "Name", MAX_NAME_LENGTH);
		if (!nameCheck.ok) {
			return Response.json({ error: nameCheck.error }, { status: 400 });
		}
		const descriptionCheck = optionalText(
			rawDescription,
			"Description",
			MAX_DESCRIPTION_LENGTH,
		);
		if (!descriptionCheck.ok) {
			return Response.json({ error: descriptionCheck.error }, { status: 400 });
		}
		const logoCheck = optionalHttpUrl(rawLogoUrl, "Logo URL");
		if (!logoCheck.ok) {
			return Response.json({ error: logoCheck.error }, { status: 400 });
		}
		const name = nameCheck.value ?? null;
		const description = descriptionCheck.value ?? null;
		const logoUrl = logoCheck.value ?? null;

		// Generate client ID and secret for pre-registered clients
		const clientId = generateClientId();
		const clientSecret = generateClientSecret();
		const clientSecretHash = hashSecret(clientSecret);

		// Validate roles if provided
		let rolesArray: string[] = [];
		if (availableRoles) {
			if (!Array.isArray(availableRoles)) {
				return Response.json(
					{ error: "Available roles must be an array" },
					{ status: 400 },
				);
			}
			rolesArray = availableRoles.filter(
				(r: unknown) => typeof r === "string" && r.trim(),
			);
		}

		// Validate default role is in available roles
		if (
			defaultRole &&
			rolesArray.length > 0 &&
			!rolesArray.includes(defaultRole)
		) {
			return Response.json(
				{ error: "Default role must be one of the available roles" },
				{ status: 400 },
			);
		}

		const result = db
			.query(
				`INSERT INTO apps (client_id, name, logo_url, description, redirect_uris, is_preregistered, registration, client_secret_hash, available_roles, default_role, first_seen, last_used) 
				VALUES (?, ?, ?, ?, ?, 1, 'admin', ?, ?, ?, ?, ?)`,
			)
			.run(
				clientId,
				name,
				logoUrl,
				description,
				JSON.stringify(redirectUris),
				clientSecretHash,
				rolesArray.length > 0 ? JSON.stringify(rolesArray) : null,
				defaultRole || null,
				Math.floor(Date.now() / 1000),
				Math.floor(Date.now() / 1000),
			);

		return Response.json({
			success: true,
			client: {
				id: result.lastInsertRowid,
				clientId,
				clientSecret, // Return the plain secret only once on creation
				name: name || clientId,
				logoUrl,
				description,
				redirectUris,
				isPreregistered: true,
				registration: "admin",
			},
		});
	} catch (error) {
		console.error("Create client error:", error);
		return Response.json({ error: "Failed to create client" }, { status: 500 });
	}
}

export function getClient(req: Request, clientId: string): Response {
	const user = getSessionUserFlexible(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.isAdmin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	const client = db
		.query(
			`SELECT 
				id,
				client_id,
				name,
				logo_url,
				description,
				redirect_uris,
				is_preregistered,
				registration,
				available_roles,
				default_role,
				first_seen,
				last_used
			FROM apps
			WHERE client_id = ?`,
		)
		.get(clientId) as
		| {
				id: number;
				client_id: string;
				name: string | null;
				logo_url: string | null;
				description: string | null;
				redirect_uris: string;
				is_preregistered: number;
				registration: string | null;
				available_roles: string | null;
				default_role: string | null;
				first_seen: number;
				last_used: number;
		  }
		| undefined;

	if (!client) {
		return Response.json({ error: "Client not found" }, { status: 404 });
	}

	const users = db
		.query(
			`SELECT 
				u.username,
				u.name,
				p.scopes,
				p.role,
				p.granted_at,
				p.last_used
			FROM permissions p
			JOIN users u ON p.user_id = u.id
			WHERE p.client_id = ?
			ORDER BY p.last_used DESC`,
		)
		.all(clientId) as Array<{
		username: string;
		name: string;
		scopes: string;
		role: string | null;
		granted_at: number;
		last_used: number;
	}>;

	return Response.json({
		client: {
			id: client.id,
			clientId: client.client_id,
			name: clientDisplayName(client.client_id, client.name),
			logoUrl: client.logo_url,
			description: client.description,
			redirectUris: JSON.parse(client.redirect_uris) as string[],
			isPreregistered: client.is_preregistered === 1,
			registration: clientRegistration(client),
			availableRoles: client.available_roles
				? (JSON.parse(client.available_roles) as string[])
				: null,
			defaultRole: client.default_role,
			firstSeen: client.first_seen,
			lastUsed: client.last_used,
		},
		users: users.map((u) => ({
			username: u.username,
			name: u.name,
			scopes: JSON.parse(u.scopes) as string[],
			role: u.role,
			grantedAt: u.granted_at,
			lastUsed: u.last_used,
		})),
	});
}

export async function updateClient(
	req: Request,
	clientId: string,
): Promise<Response> {
	const user = getSessionUserFlexible(req);
	if (user instanceof Response) {
		return user;
	}

	const csrfError = validateCsrf(req);
	if (csrfError) return csrfError;

	if (!user.isAdmin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	try {
		const body = await req.json();
		if (!body || typeof body !== "object" || Array.isArray(body)) {
			return Response.json(
				{ error: "Body must be a JSON object" },
				{ status: 400 },
			);
		}
		const {
			name,
			logoUrl,
			description,
			redirectUris,
			availableRoles,
			defaultRole,
		} = body as Record<string, unknown>;

		const existing = db
			.query(
				"SELECT id, is_preregistered, available_roles, default_role FROM apps WHERE client_id = ?",
			)
			.get(clientId) as
			| {
					id: number;
					is_preregistered: number;
					available_roles: string | null;
					default_role: string | null;
			  }
			| undefined;

		if (!existing) {
			return Response.json({ error: "Client not found" }, { status: 404 });
		}

		// Partial update: a field that is absent from the body is left as-is.
		// Only fields that are present are validated and written. `null` (or
		// "") clears an optional field.
		const updates: string[] = [];
		const values: (string | null)[] = [];

		const nameCheck = optionalText(name, "Name", MAX_NAME_LENGTH);
		if (!nameCheck.ok) {
			return Response.json({ error: nameCheck.error }, { status: 400 });
		}
		if (nameCheck.value !== undefined) {
			updates.push("name = ?");
			values.push(nameCheck.value);
		}

		const logoCheck = optionalHttpUrl(logoUrl, "Logo URL");
		if (!logoCheck.ok) {
			return Response.json({ error: logoCheck.error }, { status: 400 });
		}
		if (logoCheck.value !== undefined) {
			updates.push("logo_url = ?");
			values.push(logoCheck.value);
		}

		const descriptionCheck = optionalText(
			description,
			"Description",
			MAX_DESCRIPTION_LENGTH,
		);
		if (!descriptionCheck.ok) {
			return Response.json({ error: descriptionCheck.error }, { status: 400 });
		}
		if (descriptionCheck.value !== undefined) {
			updates.push("description = ?");
			values.push(descriptionCheck.value);
		}

		// redirect_uris is NOT NULL: when provided it must be a valid list;
		// when omitted it is untouched.
		if (redirectUris !== undefined) {
			const redirects = validateRedirectUris(redirectUris);
			if (!redirects.ok) {
				return Response.json({ error: redirects.error }, { status: 400 });
			}
			updates.push("redirect_uris = ?");
			values.push(JSON.stringify(redirects.value));
		}

		// Roles: start from what is stored, overlay whatever the body provides.
		let rolesArray: string[] = existing.available_roles
			? (JSON.parse(existing.available_roles) as string[])
			: [];
		if (availableRoles !== undefined) {
			if (availableRoles === null) {
				// Explicitly disable roles
				rolesArray = [];
			} else if (Array.isArray(availableRoles)) {
				rolesArray = availableRoles.filter(
					(r: unknown): r is string => typeof r === "string" && !!r.trim(),
				);
			} else {
				return Response.json(
					{ error: "Available roles must be an array or null" },
					{ status: 400 },
				);
			}
			updates.push("available_roles = ?");
			values.push(rolesArray.length > 0 ? JSON.stringify(rolesArray) : null);
		}

		let effectiveDefault: string | null = existing.default_role;
		if (defaultRole !== undefined) {
			if (defaultRole === null || defaultRole === "") {
				effectiveDefault = null;
			} else if (typeof defaultRole === "string") {
				if (defaultRole.length > MAX_NAME_LENGTH) {
					return Response.json(
						{
							error: `Default role must be at most ${MAX_NAME_LENGTH} characters`,
						},
						{ status: 400 },
					);
				}
				effectiveDefault = defaultRole;
			} else {
				return Response.json(
					{ error: "Default role must be a string or null" },
					{ status: 400 },
				);
			}
			updates.push("default_role = ?");
			values.push(effectiveDefault);
		} else if (
			availableRoles !== undefined &&
			effectiveDefault &&
			rolesArray.length > 0 &&
			!rolesArray.includes(effectiveDefault)
		) {
			// The role list changed underneath an unchanged default that is no
			// longer in it: clear the default rather than leave a dangling one.
			effectiveDefault = null;
			updates.push("default_role = ?");
			values.push(null);
		}

		// Validate default role is in available roles
		if (
			defaultRole !== undefined &&
			effectiveDefault &&
			rolesArray.length > 0 &&
			!rolesArray.includes(effectiveDefault)
		) {
			return Response.json(
				{ error: "Default role must be one of the available roles" },
				{ status: 400 },
			);
		}

		if (updates.length === 0) {
			return Response.json({ error: "No fields to update" }, { status: 400 });
		}

		db.query(`UPDATE apps SET ${updates.join(", ")} WHERE client_id = ?`).run(
			...values,
			clientId,
		);

		return Response.json({ success: true });
	} catch (error) {
		console.error("Update client error:", error);
		return Response.json({ error: "Failed to update client" }, { status: 500 });
	}
}

export function deleteClient(req: Request, clientId: string): Response {
	const user = getSessionUserFlexible(req);
	if (user instanceof Response) {
		return user;
	}

	const csrfError = validateCsrf(req);
	if (csrfError) return csrfError;

	if (!user.isAdmin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	const existing = db
		.query("SELECT id FROM apps WHERE client_id = ?")
		.get(clientId);

	if (!existing) {
		return Response.json({ error: "Client not found" }, { status: 404 });
	}

	// tokens.client_id and device_codes.client_id have no FK to apps, so they
	// would outlive the client. Kill everything it was ever issued first;
	// permissions cascade via FK but are deleted explicitly to be unambiguous.
	db.query("UPDATE tokens SET revoked = 1 WHERE client_id = ?").run(clientId);
	db.query("DELETE FROM device_codes WHERE client_id = ?").run(clientId);
	db.query("DELETE FROM authcodes WHERE client_id = ? AND used = 0").run(
		clientId,
	);
	db.query("DELETE FROM permissions WHERE client_id = ?").run(clientId);
	db.query("DELETE FROM apps WHERE client_id = ?").run(clientId);

	return Response.json({ success: true });
}

export async function setUserRole(
	req: Request,
	clientId: string,
	username: string,
): Promise<Response> {
	const user = getSessionUserFlexible(req);
	if (user instanceof Response) {
		return user;
	}

	const csrfError = validateCsrf(req);
	if (csrfError) return csrfError;

	if (!user.isAdmin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	try {
		const body = await req.json();
		const { role } = body;

		const targetUser = db
			.query("SELECT id FROM users WHERE username = ?")
			.get(username) as { id: number } | undefined;

		if (!targetUser) {
			return Response.json({ error: "User not found" }, { status: 404 });
		}

		const client = db
			.query("SELECT id, available_roles FROM apps WHERE client_id = ?")
			.get(clientId) as
			| { id: number; available_roles: string | null }
			| undefined;

		if (!client) {
			return Response.json({ error: "Client not found" }, { status: 404 });
		}

		// Validate role against available roles if defined
		if (role && client.available_roles) {
			const availableRoles = JSON.parse(client.available_roles) as string[];
			if (!availableRoles.includes(role)) {
				return Response.json(
					{
						error: `Role must be one of: ${availableRoles.join(", ")}`,
					},
					{ status: 400 },
				);
			}
		}

		const permission = db
			.query("SELECT id FROM permissions WHERE user_id = ? AND client_id = ?")
			.get(targetUser.id, clientId) as { id: number } | undefined;

		if (!permission) {
			return Response.json(
				{ error: "User has not authorized this client" },
				{ status: 404 },
			);
		}

		db.query(
			"UPDATE permissions SET role = ? WHERE user_id = ? AND client_id = ?",
		).run(role || null, targetUser.id, clientId);

		return Response.json({ success: true });
	} catch (error) {
		console.error("Set user role error:", error);
		return Response.json({ error: "Failed to set user role" }, { status: 500 });
	}
}

export function regenerateClientSecret(
	req: Request,
	clientId: string,
): Response {
	const user = getSessionUserFlexible(req);
	if (user instanceof Response) {
		return user;
	}

	const csrfError = validateCsrf(req);
	if (csrfError) return csrfError;

	if (!user.isAdmin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	const client = db
		.query("SELECT id, is_preregistered FROM apps WHERE client_id = ?")
		.get(clientId) as { id: number; is_preregistered: number } | undefined;

	if (!client) {
		return Response.json({ error: "Client not found" }, { status: 404 });
	}

	if (client.is_preregistered !== 1) {
		return Response.json(
			{ error: "Cannot regenerate secret for auto-registered clients" },
			{ status: 400 },
		);
	}

	// Generate new client secret
	const clientSecret = generateClientSecret();
	const clientSecretHash = hashSecret(clientSecret);

	db.query("UPDATE apps SET client_secret_hash = ? WHERE client_id = ?").run(
		clientSecretHash,
		clientId,
	);

	return Response.json({
		success: true,
		clientSecret, // Return the new plain secret
	});
}
