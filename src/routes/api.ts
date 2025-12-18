import { db } from "../db";

function getSessionUser(req: Request): { username: string; userId: number; is_admin: boolean } | Response {
	const authHeader = req.headers.get("Authorization");

	if (!authHeader || !authHeader.startsWith("Bearer ")) {
		return Response.json({ error: "Unauthorized" }, { status: 401 });
	}

	const token = authHeader.substring(7);

	// Look up session
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

export function hello(req: Request): Response {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	return Response.json({
		message: `Hello ${user.username}! You're authenticated with passkeys.`,
		id: user.userId,
		username: user.username,
		isAdmin: user.is_admin,
	});
}

export function listUsers(req: Request): Response {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.is_admin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	const users = db
		.query(
			`SELECT u.id, u.username, u.name, u.email, u.photo, u.status, u.role, u.is_admin, u.created_at, 
			COUNT(c.id) as credential_count
			FROM users u
			LEFT JOIN credentials c ON u.id = c.user_id
			GROUP BY u.id
			ORDER BY u.created_at DESC`,
		)
		.all() as Array<{
		id: number;
		username: string;
		name: string;
		email: string | null;
		photo: string | null;
		status: string;
		role: string;
		is_admin: number;
		created_at: number;
		credential_count: number;
	}>;

	return Response.json({
		users: users.map((u) => ({
			id: u.id,
			username: u.username,
			name: u.name,
			email: u.email,
			photo: u.photo,
			status: u.status,
			role: u.role,
			isAdmin: u.is_admin === 1,
			createdAt: u.created_at,
			credentialCount: u.credential_count,
		})),
	});
}

export async function getProfile(req: Request): Promise<Response> {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	const profile = db
		.query(
			`SELECT id, username, name, email, photo, url, status, role, is_admin, created_at
			FROM users
			WHERE username = ?`,
		)
		.get(user.username) as
		| {
				id: number;
				username: string;
				name: string;
				email: string | null;
				photo: string | null;
				url: string | null;
				status: string;
				role: string;
				is_admin: number;
				created_at: number;
		  }
		| undefined;

	if (!profile) {
		return Response.json({ error: "Profile not found" }, { status: 404 });
	}

	return Response.json({
		id: profile.id,
		username: profile.username,
		name: profile.name,
		email: profile.email,
		photo: profile.photo,
		url: profile.url,
		status: profile.status,
		role: profile.role,
		isAdmin: profile.is_admin === 1,
		createdAt: profile.created_at,
	});
}

export async function updateProfile(req: Request): Promise<Response> {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	try {
		const body = await req.json();
		const { name, email, photo, url } = body;

		if (!name || typeof name !== "string") {
			return Response.json({ error: "Name is required" }, { status: 400 });
		}

		// Update profile
		db.query(
			"UPDATE users SET name = ?, email = ?, photo = ?, url = ? WHERE username = ?",
		).run(name, email || null, photo || null, url || null, user.username);

		return Response.json({ success: true });
	} catch (error) {
		console.error("Update profile error:", error);
		return Response.json({ error: "Failed to update profile" }, { status: 500 });
	}
}

export function getAuthorizedApps(req: Request): Response {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	const apps = db
		.query(
			`SELECT 
				a.client_id,
				a.name,
				a.first_seen,
				a.last_used as app_last_used,
				p.scopes,
				p.granted_at,
				p.last_used
			FROM permissions p
			JOIN apps a ON p.client_id = a.client_id
			WHERE p.user_id = ?
			ORDER BY p.last_used DESC`,
		)
		.all(user.userId) as Array<{
		client_id: string;
		name: string | null;
		first_seen: number;
		app_last_used: number;
		scopes: string;
		granted_at: number;
		last_used: number;
	}>;

	return Response.json({
		apps: apps.map((app) => ({
			clientId: app.client_id,
			name: app.name || new URL(app.client_id).hostname,
			scopes: JSON.parse(app.scopes) as string[],
			grantedAt: app.granted_at,
			lastUsed: app.last_used,
		})),
	});
}

export function revokeApp(req: Request, clientId: string): Response {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	// Delete permission
	const result = db
		.query("DELETE FROM permissions WHERE user_id = ? AND client_id = ?")
		.run(user.userId, clientId);

	if (result.changes === 0) {
		return Response.json({ error: "App not found" }, { status: 404 });
	}

	// Also delete any unused auth codes for this app
	db.query(
		"DELETE FROM authcodes WHERE user_id = ? AND client_id = ? AND used = 0",
	).run(user.userId, clientId);

	return Response.json({ success: true });
}

export function listAllApps(req: Request): Response {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.is_admin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	const apps = db
		.query(
			`SELECT 
				a.client_id,
				a.name,
				a.first_seen,
				a.last_used,
				COUNT(DISTINCT p.user_id) as user_count
			FROM apps a
			LEFT JOIN permissions p ON a.client_id = p.client_id
			GROUP BY a.client_id
			ORDER BY a.last_used DESC`,
		)
		.all() as Array<{
		client_id: string;
		name: string | null;
		first_seen: number;
		last_used: number;
		user_count: number;
	}>;

	return Response.json({
		apps: apps.map((app) => ({
			clientId: app.client_id,
			name: app.name || new URL(app.client_id).hostname,
			firstSeen: app.first_seen,
			lastUsed: app.last_used,
			userCount: app.user_count,
		})),
	});
}

export function getAppDetails(req: Request, clientId: string): Response {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.is_admin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	const app = db
		.query(
			`SELECT client_id, name, first_seen, last_used
			FROM apps
			WHERE client_id = ?`,
		)
		.get(clientId) as
		| {
				client_id: string;
				name: string | null;
				first_seen: number;
				last_used: number;
		  }
		| undefined;

	if (!app) {
		return Response.json({ error: "App not found" }, { status: 404 });
	}

	const permissions = db
		.query(
			`SELECT 
				u.username,
				u.name,
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
		scopes: string;
		granted_at: number;
		last_used: number;
	}>;

	return Response.json({
		app: {
			clientId: app.client_id,
			name: app.name || new URL(app.client_id).hostname,
			firstSeen: app.first_seen,
			lastUsed: app.last_used,
		},
		permissions: permissions.map((p) => ({
			username: p.username,
			name: p.name,
			scopes: JSON.parse(p.scopes) as string[],
			grantedAt: p.granted_at,
			lastUsed: p.last_used,
		})),
	});
}

export function revokeAppForUser(
	req: Request,
	clientId: string,
	username: string,
): Response {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.is_admin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	const targetUser = db
		.query("SELECT id FROM users WHERE username = ?")
		.get(username) as { id: number } | undefined;

	if (!targetUser) {
		return Response.json({ error: "User not found" }, { status: 404 });
	}

	const result = db
		.query("DELETE FROM permissions WHERE user_id = ? AND client_id = ?")
		.run(targetUser.id, clientId);

	if (result.changes === 0) {
		return Response.json({ error: "Permission not found" }, { status: 404 });
	}

	db.query(
		"DELETE FROM authcodes WHERE user_id = ? AND client_id = ? AND used = 0",
	).run(targetUser.id, clientId);

	return Response.json({ success: true });
}

export function disableUser(req: Request, userId: string): Response {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.is_admin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	const targetUserId = Number.parseInt(userId, 10);
	if (Number.isNaN(targetUserId)) {
		return Response.json({ error: "Invalid user ID" }, { status: 400 });
	}

	// Prevent disabling self
	if (targetUserId === user.id) {
		return Response.json({ error: "Cannot disable your own account" }, { status: 400 });
	}

	const targetUser = db
		.query("SELECT id, username FROM users WHERE id = ?")
		.get(targetUserId) as { id: number; username: string } | undefined;

	if (!targetUser) {
		return Response.json({ error: "User not found" }, { status: 404 });
	}

	db.query("UPDATE users SET status = 'suspended' WHERE id = ?").run(targetUserId);

	db.query("DELETE FROM sessions WHERE user_id = ?").run(targetUserId);

	return Response.json({ success: true });
}

export function enableUser(req: Request, userId: string): Response {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.is_admin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	const targetUserId = Number.parseInt(userId, 10);
	if (Number.isNaN(targetUserId)) {
		return Response.json({ error: "Invalid user ID" }, { status: 400 });
	}

	const targetUser = db
		.query("SELECT id, username FROM users WHERE id = ?")
		.get(targetUserId) as { id: number; username: string } | undefined;

	if (!targetUser) {
		return Response.json({ error: "User not found" }, { status: 404 });
	}

	db.query("UPDATE users SET status = 'active' WHERE id = ?").run(targetUserId);

	return Response.json({ success: true });
}

export function deleteUser(req: Request, userId: string): Response {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.is_admin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	const targetUserId = Number.parseInt(userId, 10);
	if (Number.isNaN(targetUserId)) {
		return Response.json({ error: "Invalid user ID" }, { status: 400 });
	}

	if (targetUserId === user.userId) {
		return Response.json({ error: "Cannot delete your own account" }, { status: 400 });
	}

	const targetUser = db
		.query("SELECT id FROM users WHERE id = ?")
		.get(targetUserId) as { id: number } | undefined;

	if (!targetUser) {
		return Response.json({ error: "User not found" }, { status: 404 });
	}

	db.query("DELETE FROM sessions WHERE user_id = ?").run(targetUserId);
	db.query("DELETE FROM credentials WHERE user_id = ?").run(targetUserId);
	db.query("DELETE FROM permissions WHERE user_id = ?").run(targetUserId);
	db.query("DELETE FROM authcodes WHERE user_id = ?").run(targetUserId);
	db.query("DELETE FROM users WHERE id = ?").run(targetUserId);

	return Response.json({ success: true });
}
