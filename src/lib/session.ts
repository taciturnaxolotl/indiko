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
	const sessionToken = readSessionCookie(req);
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

// --- Cookie helpers ---

const SESSION_COOKIE = "indiko_session";
const SESSION_MAX_AGE = 86400; // 24 hours

/**
 * Cookies get the Secure flag whenever the configured ORIGIN is https.
 * This is derived from ORIGIN (validated at startup) rather than NODE_ENV so
 * an HTTPS deployment that forgets to set NODE_ENV still gets Secure cookies.
 */
export function cookieSecureFlag(): string {
	return (process.env.ORIGIN || "").startsWith("https://") ? "; Secure" : "";
}

/** Set-Cookie value for a fresh session cookie. */
export function sessionCookieHeader(token: string): string {
	return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_MAX_AGE}${cookieSecureFlag()}`;
}

/** Set-Cookie value that clears the session cookie. */
export function clearSessionCookieHeader(): string {
	return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${cookieSecureFlag()}`;
}

/** Read the raw session token from the Cookie header, if present. */
export function readSessionCookie(req: Request): string | null {
	const cookieHeader = req.headers.get("Cookie");
	if (!cookieHeader) return null;
	const match = cookieHeader.match(
		new RegExp(`(?:^|;\\s*)${SESSION_COOKIE}=([^;]+)`),
	);
	return match?.[1] ?? null;
}

// --- CSRF protection ---
//
// The CSRF token is derived from the session token (sha256 of a domain
// prefix + the session token), so it is bound to exactly one session and
// cannot be swapped in by an attacker who manages to plant a cookie. It is
// set as a non-HttpOnly cookie (indiko_csrf) so client-side JS can read it
// and send it back as the X-CSRF-Token header (or a hidden form field) on
// mutating requests. Cross-origin attackers can't read the cookie
// (same-origin policy) and can't set custom headers cross-origin without a
// CORS preflight, so this blocks CSRF even though the session cookie is
// SameSite=Lax. The server never trusts the indiko_csrf cookie itself — it
// recomputes the expected value from the session cookie on every check.

const CSRF_COOKIE = "indiko_csrf";
const CSRF_HEADER = "x-csrf-token";
const CSRF_DOMAIN = "indiko-csrf:";

/** Derive the CSRF token bound to a given session token. */
export function csrfTokenFor(sessionToken: string): string {
	return crypto
		.createHash("sha256")
		.update(CSRF_DOMAIN + sessionToken)
		.digest("base64url");
}

export function csrfCookieHeader(token: string): string {
	return `${CSRF_COOKIE}=${token}; Path=/; SameSite=Lax; Max-Age=${SESSION_MAX_AGE}${cookieSecureFlag()}`;
}

/** Set-Cookie value that clears the CSRF cookie. */
export function clearCsrfCookieHeader(): string {
	return `${CSRF_COOKIE}=; Path=/; SameSite=Lax; Max-Age=0${cookieSecureFlag()}`;
}

/**
 * The CSRF token this request's session is entitled to (for embedding in
 * forms). Derived from the session cookie, never read from the CSRF cookie.
 * Returns null when there is no session cookie.
 */
export function getCsrfToken(req: Request): string | null {
	const sessionToken = readSessionCookie(req);
	if (!sessionToken) return null;
	return csrfTokenFor(sessionToken);
}

/** Constant-time comparison of a presented CSRF token against the expected one. */
export function csrfTokenMatches(
	presented: string | null | undefined,
	expected: string | null | undefined,
): boolean {
	if (!presented || !expected) return false;
	const a = Buffer.from(presented);
	const b = Buffer.from(expected);
	if (a.length !== b.length) return false;
	return crypto.timingSafeEqual(a, b);
}

function readCsrfCookie(req: Request): string | null {
	const cookieHeader = req.headers.get("Cookie");
	if (!cookieHeader) return null;
	const match = cookieHeader.match(
		new RegExp(`(?:^|;\\s*)${CSRF_COOKIE}=([^;]+)`),
	);
	return match?.[1] ?? null;
}

/**
 * Headers that bring a browser's indiko_csrf cookie back in line with the
 * value derived from its session. The cookie is only a convenience copy for
 * page scripts, so when it is missing or stale (a session issued before the
 * derivation changed, say) it is simply reissued; nothing is trusted from it.
 * Returns an empty list when the cookie is already correct or there is no
 * session to derive from.
 */
export function csrfCookieRefreshHeaders(
	req: Request,
): Array<[string, string]> {
	const expected = getCsrfToken(req);
	if (!expected) return [];
	const present = readCsrfCookie(req);
	if (present && csrfTokenMatches(present, expected)) return [];
	return [["Set-Cookie", csrfCookieHeader(expected)]];
}

/**
 * Validate the CSRF token on a mutating request. The token from the
 * X-CSRF-Token header must equal the token derived from the session cookie.
 * Returns null if valid, or a 403 Response to send back. The 403 carries a
 * corrected indiko_csrf cookie so a page that was holding a stale copy can
 * retry without a fresh sign-in.
 */
export function validateCsrf(req: Request): Response | null {
	const expected = getCsrfToken(req);
	const headerToken = req.headers.get(CSRF_HEADER);
	const refresh = csrfCookieRefreshHeaders(req);

	if (!expected || !headerToken) {
		return Response.json(
			{ error: "CSRF token missing", code: "csrf" },
			{ status: 403, headers: refresh },
		);
	}

	if (!csrfTokenMatches(headerToken, expected)) {
		return Response.json(
			{ error: "CSRF token mismatch", code: "csrf" },
			{ status: 403, headers: refresh },
		);
	}

	return null;
}
