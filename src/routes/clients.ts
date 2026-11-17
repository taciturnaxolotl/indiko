import { nanoid } from "nanoid";
import { db } from "../db";
import {
	clientDisplayName,
	clientRegistration,
} from "../lib/oauth/client-display";
import { appRole, homeResource } from "../lib/oauth/resource-registry";
import { hashSecret } from "../lib/secrets";
import { requireAdmin } from "../lib/session";
import {
	type Checked,
	isHttpUrl,
	MAX_URL_LENGTH,
	optionalHttpUrl,
	optionalText,
} from "../lib/validate";

function generateClientSecret(): string {
	return `iks_${nanoid(43)}`; // indiko secret
}

function generateClientId(): string {
	return `ikc_${nanoid(21)}`; // indiko client
}

// Input caps for admin-supplied client metadata.
const MAX_NAME_LENGTH = 256;
const MAX_DESCRIPTION_LENGTH = 2048;

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

/** `undefined` leaves the link alone, `null` clears it, a number must name a resource. */
function checkResourceId(value: unknown): Checked<number | null | undefined> {
	if (value === undefined || value === null) return { ok: true, value };
	if (
		!Number.isInteger(value) ||
		!db.query("SELECT 1 FROM resources WHERE id = ?").get(value as number)
	) {
		return { ok: false, error: "resourceId must name an existing resource" };
	}
	return { ok: true, value: value as number };
}

/** An app is always allowed on the resource it takes its roles from. */
function allowOnHomeResource(clientId: string, resourceId: number | null) {
	if (resourceId === null) return;
	db.query(
		"INSERT OR IGNORE INTO resource_clients (resource_id, client_id) VALUES (?, ?)",
	).run(resourceId, clientId);
}

export function listClients(req: Request): Response {
	const user = requireAdmin(req);
	if (user instanceof Response) return user;

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
		})),
	});
}

export async function createClient(req: Request): Promise<Response> {
	const user = requireAdmin(req);
	if (user instanceof Response) return user;

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
			resourceId: rawResourceId,
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
		const resourceCheck = checkResourceId(rawResourceId);
		if (!resourceCheck.ok) {
			return Response.json({ error: resourceCheck.error }, { status: 400 });
		}
		const name = nameCheck.value ?? null;
		const description = descriptionCheck.value ?? null;
		const logoUrl = logoCheck.value ?? null;

		// Generate client ID and secret for pre-registered clients
		const clientId = generateClientId();
		const clientSecret = generateClientSecret();
		const clientSecretHash = hashSecret(clientSecret);

		const result = db
			.query(
				`INSERT INTO apps (client_id, name, logo_url, description, redirect_uris, is_preregistered, registration, client_secret_hash, resource_id, first_seen, last_used)
				VALUES (?, ?, ?, ?, ?, 1, 'admin', ?, ?, ?, ?)`,
			)
			.run(
				clientId,
				name,
				logoUrl,
				description,
				JSON.stringify(redirectUris),
				clientSecretHash,
				resourceCheck.value ?? null,
				Math.floor(Date.now() / 1000),
				Math.floor(Date.now() / 1000),
			);
		allowOnHomeResource(clientId, resourceCheck.value ?? null);

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
	const user = requireAdmin(req);
	if (user instanceof Response) return user;

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
				p.user_id,
				p.scopes,
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
		user_id: number;
		scopes: string;
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
			resource: homeResource(client.client_id),
			firstSeen: client.first_seen,
			lastUsed: client.last_used,
		},
		users: users.map((u) => ({
			username: u.username,
			name: u.name,
			scopes: JSON.parse(u.scopes) as string[],
			role: appRole(client.client_id, u.user_id),
			grantedAt: u.granted_at,
			lastUsed: u.last_used,
		})),
	});
}

export async function updateClient(
	req: Request,
	clientId: string,
): Promise<Response> {
	const user = requireAdmin(req);
	if (user instanceof Response) return user;

	try {
		const body = await req.json();
		if (!body || typeof body !== "object" || Array.isArray(body)) {
			return Response.json(
				{ error: "Body must be a JSON object" },
				{ status: 400 },
			);
		}
		const { name, logoUrl, description, redirectUris, resourceId } =
			body as Record<string, unknown>;

		const existing = db
			.query("SELECT id FROM apps WHERE client_id = ?")
			.get(clientId) as { id: number } | undefined;

		if (!existing) {
			return Response.json({ error: "Client not found" }, { status: 404 });
		}

		// Partial update: a field that is absent from the body is left as-is.
		// Only fields that are present are validated and written. `null` (or
		// "") clears an optional field.
		const updates: string[] = [];
		const values: (string | number | null)[] = [];

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

		const resourceCheck = checkResourceId(resourceId);
		if (!resourceCheck.ok) {
			return Response.json({ error: resourceCheck.error }, { status: 400 });
		}
		if (resourceCheck.value !== undefined) {
			updates.push("resource_id = ?");
			values.push(resourceCheck.value);
		}

		if (updates.length === 0) {
			return Response.json({ error: "No fields to update" }, { status: 400 });
		}

		db.query(`UPDATE apps SET ${updates.join(", ")} WHERE client_id = ?`).run(
			...values,
			clientId,
		);
		allowOnHomeResource(clientId, resourceCheck.value ?? null);

		return Response.json({ success: true });
	} catch (error) {
		console.error("Update client error:", error);
		return Response.json({ error: "Failed to update client" }, { status: 500 });
	}
}

export function deleteClient(req: Request, clientId: string): Response {
	const user = requireAdmin(req);
	if (user instanceof Response) return user;

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

export function regenerateClientSecret(
	req: Request,
	clientId: string,
): Response {
	const user = requireAdmin(req);
	if (user instanceof Response) return user;

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
