import crypto from "node:crypto";
import { db } from "../db";

export interface SessionUser {
	username: string;
	userId: number;
	isAdmin: boolean;
	tier: string;
}

const SESSION_QUERY = `
	SELECT s.expires_at, s.user_id, u.username, u.is_admin, u.tier, u.status
	FROM sessions s
	JOIN users u ON s.user_id = u.id
	WHERE s.token = ?`;

interface SessionRow {
	expires_at: number;
	user_id: number;
	username: string;
	is_admin: number;
	tier: string;
	status: string;
}

function lookupSession(token: string): SessionRow | undefined {
	return db.query(SESSION_QUERY).get(token) as SessionRow | undefined;
}

function validateSession(session: SessionRow | undefined): SessionUser | null {
	if (!session) return null;

	const now = Math.floor(Date.now() / 1000);
	if (session.expires_at < now) return null;
	if (session.status !== "active") return null;

	return {
		username: session.username,
		userId: session.user_id,
		isAdmin: session.is_admin === 1,
		tier: session.tier,
	};
}

/**
 * Authenticate via Bearer token (API requests).
 * Returns a SessionUser, or a 401/403 Response to send back.
 */
export function getSessionUser(req: Request): SessionUser | Response {
	const authHeader = req.headers.get("Authorization");

	if (!authHeader?.startsWith("Bearer ")) {
		return Response.json({ error: "Unauthorized" }, { status: 401 });
	}

	const token = authHeader.substring(7);
	const session = lookupSession(token);

	if (!session) {
		return Response.json({ error: "Invalid session" }, { status: 401 });
	}

	const now = Math.floor(Date.now() / 1000);
	if (session.expires_at < now) {
		return Response.json({ error: "Session expired" }, { status: 401 });
	}

	if (session.status !== "active") {
		return Response.json({ error: "Account is suspended" }, { status: 403 });
	}

	return {
		username: session.username,
		userId: session.user_id,
		isAdmin: session.is_admin === 1,
		tier: session.tier,
	};
}

/**
 * Authenticate via the indiko_session cookie (browser pages).
 * Returns null when unauthenticated so callers can redirect.
 */
export function getUserFromCookie(req: Request): SessionUser | null {
	const cookieHeader = req.headers.get("Cookie");
	if (!cookieHeader) return null;

	const cookies = Object.fromEntries(
		cookieHeader.split("; ").map((c) => {
			const [key, ...v] = c.split("=");
			return [key, v.join("=")];
		}),
	);

	const sessionToken = cookies.indiko_session;
	if (!sessionToken) return null;

	return validateSession(lookupSession(sessionToken));
}

/**
 * Authenticate via Bearer token or indiko_session cookie, whichever is
 * present. Returns a SessionUser or a 401/403 Response. Use this for
 * endpoints that serve both API clients and browser pages.
 */
export function getSessionUserFlexible(req: Request): SessionUser | Response {
	const bearerResult = getSessionUser(req);
	if (!(bearerResult instanceof Response)) return bearerResult;

	// Bearer auth failed — try cookie auth
	const cookieUser = getUserFromCookie(req);
	if (cookieUser) return cookieUser;

	return bearerResult; // return the original 401
}

// --- CSRF protection ---
//
// The CSRF token is a random value stored alongside the session. It's set as
// a non-HttpOnly cookie (indiko_csrf) so client-side JS can read it and send
// it back as the X-CSRF-Token header on mutating requests. Cross-origin
// attackers can't read the cookie (same-origin policy) and can't set custom
// headers cross-origin without a CORS preflight, so this blocks CSRF even
// though the session cookie is SameSite=Lax.

const CSRF_COOKIE = "indiko_csrf";
const CSRF_HEADER = "x-csrf-token";

export function generateCsrfToken(): string {
	return crypto.randomBytes(32).toString("base64url");
}

export function csrfCookieHeader(token: string): string {
	const isProduction = process.env.NODE_ENV === "production";
	const secure = isProduction ? "; Secure" : "";
	return `${CSRF_COOKIE}=${token}; Path=/; SameSite=Lax${secure}`;
}

function readCsrfCookie(req: Request): string | null {
	const cookieHeader = req.headers.get("Cookie");
	if (!cookieHeader) return null;
	const match = cookieHeader.match(new RegExp(`${CSRF_COOKIE}=([^;]+)`));
	return match?.[1] ?? null;
}

/**
 * Validate the CSRF token on a mutating request. The token from the
 * X-CSRF-Token header must match the indiko_csrf cookie.
 * Returns null if valid, or a 403 Response to send back.
 */
export function validateCsrf(req: Request): Response | null {
	const cookieToken = readCsrfCookie(req);
	const headerToken = req.headers.get(CSRF_HEADER);

	if (!cookieToken || !headerToken) {
		return Response.json({ error: "CSRF token missing" }, { status: 403 });
	}

	if (cookieToken !== headerToken) {
		return Response.json({ error: "CSRF token mismatch" }, { status: 403 });
	}

	return null;
}
