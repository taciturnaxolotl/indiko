import { db } from "../db";

export function hello(req: Request): Response {
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

	return Response.json({
		message: `Hello ${session.username}! You're authenticated with passkeys.`,
		username: session.username,
		isAdmin: session.is_admin === 1,
	});
}
