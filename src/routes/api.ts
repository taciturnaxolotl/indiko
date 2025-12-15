import { db } from "../db";

function getSessionUser(req: Request): { username: string; is_admin: boolean } | Response {
	const authHeader = req.headers.get("Authorization");

	if (!authHeader || !authHeader.startsWith("Bearer ")) {
		return Response.json({ error: "Unauthorized" }, { status: 401 });
	}

	const token = authHeader.substring(7);

	// Look up session
	const session = db
		.query(
			`SELECT s.expires_at, u.username, u.is_admin 
			FROM sessions s 
			JOIN users u ON s.user_id = u.id 
			WHERE s.token = ?`,
		)
		.get(token) as
		| { expires_at: number; username: string; is_admin: number }
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
