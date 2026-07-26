import { db } from "../../db";
import { unauthorizedResponse } from "../../lib/oauth/errors";
import { getSessionUser } from "../../lib/session";

// GET /userinfo - Get user profile from access token
export function userinfo(req: Request): Response {
	try {
		const authHeader = req.headers.get("Authorization");

		if (!authHeader?.startsWith("Bearer ")) {
			return unauthorizedResponse(
				"invalid_request",
				"Missing or invalid Authorization header",
			);
		}

		const tokenValue = authHeader.substring(7);

		const tokenData = db
			.query(
				"SELECT t.user_id, t.scope, t.expires_at, t.revoked, u.name, u.email, u.photo, u.url, u.username FROM tokens t JOIN users u ON t.user_id = u.id WHERE t.token = ?",
			)
			.get(tokenValue) as
			| {
					user_id: number;
					scope: string;
					expires_at: number;
					revoked: number;
					name: string;
					email: string | null;
					photo: string | null;
					url: string | null;
					username: string;
			  }
			| undefined;

		if (!tokenData || tokenData.revoked === 1) {
			return unauthorizedResponse(
				"invalid_token",
				"Invalid or revoked access token",
			);
		}

		const now = Math.floor(Date.now() / 1000);
		if (tokenData.expires_at < now) {
			return unauthorizedResponse("invalid_token", "Access token expired");
		}

		const scopes = tokenData.scope.split(" ");

		const origin = process.env.ORIGIN || "http://localhost:3000";
		const response: Record<string, string> = {};

		// sub claim - use stable canonical profile URL (OIDC Core §2)
		response.sub = `${origin}/u/${tokenData.username}`;

		if (scopes.includes("profile")) {
			response.name = tokenData.name;
			if (tokenData.photo) response.picture = tokenData.photo; // OIDC uses 'picture'
			if (tokenData.url) {
				response.website = tokenData.url; // OIDC uses 'website'
			}
		}

		if (scopes.includes("email") && tokenData.email) {
			response.email = tokenData.email;
		}

		// Pure IndieAuth request without claims and without openid scope
		if (Object.keys(response).length === 1 && !scopes.includes("openid")) {
			return Response.json(
				{
					error: "insufficient_scope",
					error_description: "Token does not have profile or email scope",
				},
				{ status: 403 },
			);
		}

		return Response.json(response, {
			headers: {
				"Content-Type": "application/json",
				"Cache-Control": "no-store",
			},
		});
	} catch (error) {
		console.error("Userinfo error:", error);
		return Response.json(
			{
				error: "server_error",
				error_description: "Internal server error",
			},
			{ status: 500 },
		);
	}
}

// POST /auth/logout - Clear session
export function logout(req: Request): Response {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	const authHeader = req.headers.get("Authorization");
	const tokenValue = authHeader?.substring(7);

	if (tokenValue) {
		db.query("DELETE FROM sessions WHERE token = ?").run(tokenValue);
	}

	return Response.json({ success: true });
}
