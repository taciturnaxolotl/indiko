import { db } from "../db";
import crypto from "crypto";

function hashSecret(secret: string): string {
	return crypto.createHash("sha256").update(secret).digest("hex");
}

function generateClientSecret(): string {
	return crypto.randomBytes(32).toString("base64url");
}

function getSessionUser(req: Request): { username: string; userId: number; is_admin: boolean } | Response {
	const authHeader = req.headers.get("Authorization");

	if (!authHeader || !authHeader.startsWith("Bearer ")) {
		return Response.json({ error: "Unauthorized" }, { status: 401 });
	}

	const token = authHeader.substring(7);

	const session = db
		.query(
			`SELECT s.expires_at, s.user_id, u.username, u.is_admin 
			FROM sessions s 
			JOIN users u ON s.user_id = u.id 
			WHERE s.token = ?`,
		)
		.get(token) as
		| { expires_at: number; user_id: number; username: string; is_admin: number }
		| undefined;

	if (!session) {
		return Response.json({ error: "Invalid session" }, { status: 401 });
	}

	const now = Math.floor(Date.now() / 1000);
	if (session.expires_at < now) {
		return Response.json({ error: "Session expired" }, { status: 401 });
	}

	return {
		username: session.username,
		userId: session.user_id,
		is_admin: session.is_admin === 1,
	};
}

export function listClients(req: Request): Response {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.is_admin) {
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
		first_seen: number;
		last_used: number;
	}>;

	return Response.json({
		clients: clients.map((c) => ({
			id: c.id,
			clientId: c.client_id,
			name: c.name || new URL(c.client_id).hostname,
			logoUrl: c.logo_url,
			description: c.description,
			redirectUris: JSON.parse(c.redirect_uris) as string[],
			isPreregistered: c.is_preregistered === 1,
			firstSeen: c.first_seen,
			lastUsed: c.last_used,
		})),
	});
}

export async function createClient(req: Request): Promise<Response> {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.is_admin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	try {
		const body = await req.json();
		const { clientId, name, logoUrl, description, redirectUris } = body;

		if (!clientId || typeof clientId !== "string") {
			return Response.json({ error: "Client ID is required" }, { status: 400 });
		}

		try {
			new URL(clientId);
		} catch {
			return Response.json({ error: "Client ID must be a valid URL" }, { status: 400 });
		}

		if (!redirectUris || !Array.isArray(redirectUris) || redirectUris.length === 0) {
			return Response.json({ error: "At least one redirect URI is required" }, { status: 400 });
		}

		for (const uri of redirectUris) {
			try {
				new URL(uri);
			} catch {
				return Response.json({ error: `Invalid redirect URI: ${uri}` }, { status: 400 });
			}
		}

		const existing = db
			.query("SELECT id FROM apps WHERE client_id = ?")
			.get(clientId);

		if (existing) {
			return Response.json({ error: "Client ID already exists" }, { status: 409 });
		}

		// Generate client secret for pre-registered clients
		const clientSecret = generateClientSecret();
		const clientSecretHash = hashSecret(clientSecret);

		const result = db
			.query(
				`INSERT INTO apps (client_id, name, logo_url, description, redirect_uris, is_preregistered, client_secret_hash, first_seen, last_used) 
				VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)`,
			)
			.run(
				clientId,
				name || null,
				logoUrl || null,
				description || null,
				JSON.stringify(redirectUris),
				clientSecretHash,
				Math.floor(Date.now() / 1000),
				Math.floor(Date.now() / 1000),
			);

		return Response.json({
			success: true,
			client: {
				id: result.lastInsertRowid,
				clientId,
				clientSecret, // Return the plain secret only once on creation
				name: name || new URL(clientId).hostname,
				logoUrl: logoUrl || null,
				description: description || null,
				redirectUris,
				isPreregistered: true,
			},
		});
	} catch (error) {
		console.error("Create client error:", error);
		return Response.json({ error: "Failed to create client" }, { status: 500 });
	}
}

export function getClient(req: Request, clientId: string): Response {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.is_admin) {
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
			name: client.name || new URL(client.client_id).hostname,
			logoUrl: client.logo_url,
			description: client.description,
			redirectUris: JSON.parse(client.redirect_uris) as string[],
			isPreregistered: client.is_preregistered === 1,
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

export async function updateClient(req: Request, clientId: string): Promise<Response> {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.is_admin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	try {
		const body = await req.json();
		const { name, logoUrl, description, redirectUris } = body;

		const existing = db
			.query("SELECT id, is_preregistered FROM apps WHERE client_id = ?")
			.get(clientId) as { id: number; is_preregistered: number } | undefined;

		if (!existing) {
			return Response.json({ error: "Client not found" }, { status: 404 });
		}

		if (redirectUris) {
			if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
				return Response.json({ error: "At least one redirect URI is required" }, { status: 400 });
			}

			for (const uri of redirectUris) {
				try {
					new URL(uri);
				} catch {
					return Response.json({ error: `Invalid redirect URI: ${uri}` }, { status: 400 });
				}
			}
		}

		db.query(
			`UPDATE apps 
			SET name = ?, logo_url = ?, description = ?, redirect_uris = ?
			WHERE client_id = ?`,
		).run(
			name || null,
			logoUrl || null,
			description || null,
			redirectUris ? JSON.stringify(redirectUris) : null,
			clientId,
		);

		return Response.json({ success: true });
	} catch (error) {
		console.error("Update client error:", error);
		return Response.json({ error: "Failed to update client" }, { status: 500 });
	}
}

export function deleteClient(req: Request, clientId: string): Response {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.is_admin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	const existing = db
		.query("SELECT id FROM apps WHERE client_id = ?")
		.get(clientId);

	if (!existing) {
		return Response.json({ error: "Client not found" }, { status: 404 });
	}

	db.query("DELETE FROM apps WHERE client_id = ?").run(clientId);

	return Response.json({ success: true });
}

export async function setUserRole(
	req: Request,
	clientId: string,
	username: string,
): Promise<Response> {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.is_admin) {
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
			.query("SELECT id FROM apps WHERE client_id = ?")
			.get(clientId);

		if (!client) {
			return Response.json({ error: "Client not found" }, { status: 404 });
		}

		const permission = db
			.query("SELECT id FROM permissions WHERE user_id = ? AND client_id = ?")
			.get(targetUser.id, clientId) as { id: number } | undefined;

		if (!permission) {
			return Response.json({ error: "User has not authorized this client" }, { status: 404 });
		}

		db.query("UPDATE permissions SET role = ? WHERE user_id = ? AND client_id = ?").run(
			role || null,
			targetUser.id,
			clientId,
		);

		return Response.json({ success: true });
	} catch (error) {
		console.error("Set user role error:", error);
		return Response.json({ error: "Failed to set user role" }, { status: 500 });
	}
}

export function regenerateClientSecret(req: Request, clientId: string): Response {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.is_admin) {
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
