import { beforeEach, describe, expect, test } from "bun:test";
import {
	clearCsrfCookieHeader,
	clearSessionCookieHeader,
	cookieSecureFlag,
	csrfCookieHeader,
	csrfTokenFor,
	csrfTokenMatches,
	getCsrfToken,
	getSessionUser,
	getUserFromCookie,
	sessionCookieHeader,
	validateCsrf,
} from "../src/lib/session";
import {
	bearerReq,
	cookieReq,
	createSession,
	createUser,
	db,
} from "./helpers/db";

beforeEach(() => {
	db.query("DELETE FROM sessions").run();
	db.query("DELETE FROM users").run();
});

describe("getSessionUser", () => {
	test("returns 401 without Authorization header", () => {
		const result = getSessionUser(bearerReq(null));
		expect(result).toBeInstanceOf(Response);
		expect((result as Response).status).toBe(401);
	});

	test("returns 401 for unknown token", () => {
		const result = getSessionUser(bearerReq("nope"));
		expect((result as Response).status).toBe(401);
	});

	test("returns 401 for expired session", () => {
		const userId = createUser({});
		const token = createSession(userId, {
			expiresAt: Math.floor(Date.now() / 1000) - 10,
		});
		const result = getSessionUser(bearerReq(token));
		expect((result as Response).status).toBe(401);
	});

	test("returns 403 for suspended user", () => {
		const userId = createUser({ status: "suspended" });
		const token = createSession(userId);
		const result = getSessionUser(bearerReq(token));
		expect((result as Response).status).toBe(403);
	});

	test("returns user with tier and isAdmin for valid session", async () => {
		const userId = createUser({ username: "kieran", tier: "admin" });
		const token = createSession(userId);
		const result = getSessionUser(bearerReq(token));

		expect(result).not.toBeInstanceOf(Response);
		if (result instanceof Response) return;

		expect(result.username).toBe("kieran");
		expect(result.userId).toBe(userId);
		expect(result.isAdmin).toBe(true);
		expect(result.tier).toBe("admin");
	});
});

describe("getUserFromCookie", () => {
	test("returns null without cookie", () => {
		expect(getUserFromCookie(cookieReq(null))).toBeNull();
	});

	test("returns null for unknown token", () => {
		expect(getUserFromCookie(cookieReq("nope"))).toBeNull();
	});

	test("returns user for valid session cookie", () => {
		const userId = createUser({ username: "kieran" });
		const token = createSession(userId);
		const user = getUserFromCookie(cookieReq(token));

		expect(user).not.toBeNull();
		expect(user?.username).toBe("kieran");
		expect(user?.tier).toBe("user");
	});

	test("does not match a cookie whose name merely ends in indiko_session", () => {
		const userId = createUser({ username: "kieran" });
		const token = createSession(userId);
		const req = new Request("http://localhost/", {
			headers: { Cookie: `xindiko_session=${token}` },
		});
		expect(getUserFromCookie(req)).toBeNull();
	});
});

function csrfReq(opts: {
	session?: string;
	csrfCookie?: string;
	header?: string;
}): Request {
	const headers = new Headers();
	const cookies: string[] = [];
	if (opts.session) cookies.push(`indiko_session=${opts.session}`);
	if (opts.csrfCookie) cookies.push(`indiko_csrf=${opts.csrfCookie}`);
	if (cookies.length) headers.set("Cookie", cookies.join("; "));
	if (opts.header) headers.set("X-CSRF-Token", opts.header);
	return new Request("http://localhost/api/test", { method: "POST", headers });
}

describe("CSRF token binding", () => {
	test("csrfTokenFor is deterministic and session-specific", () => {
		const a = csrfTokenFor("session-a");
		expect(a).toBe(csrfTokenFor("session-a"));
		expect(a).not.toBe(csrfTokenFor("session-b"));
		// base64url sha256: 43 chars, no padding, URL-safe alphabet
		expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
	});

	test("getCsrfToken derives from the session cookie, not the csrf cookie", () => {
		const req = csrfReq({ session: "sess-1", csrfCookie: "attacker-value" });
		expect(getCsrfToken(req)).toBe(csrfTokenFor("sess-1"));
		expect(getCsrfToken(csrfReq({ csrfCookie: "attacker-value" }))).toBeNull();
	});

	test("validateCsrf accepts the token derived from the session", () => {
		const session = "sess-ok";
		const derived = csrfTokenFor(session);
		expect(
			validateCsrf(csrfReq({ session, csrfCookie: derived, header: derived })),
		).toBeNull();
		// The csrf cookie is informational; only the header matters
		expect(validateCsrf(csrfReq({ session, header: derived }))).toBeNull();
	});

	test("validateCsrf rejects a matching-but-unbound cookie/header pair", () => {
		// Classic double-submit bypass: attacker plants indiko_csrf=X and
		// sends X-CSRF-Token: X. Must fail because X != csrfTokenFor(session).
		const res = validateCsrf(
			csrfReq({ session: "sess-1", csrfCookie: "X", header: "X" }),
		);
		expect(res).toBeInstanceOf(Response);
		expect(res?.status).toBe(403);
	});

	test("validateCsrf rejects a token derived from a different session", () => {
		const other = csrfTokenFor("sess-2");
		const res = validateCsrf(csrfReq({ session: "sess-1", header: other }));
		expect(res?.status).toBe(403);
	});

	test("validateCsrf rejects missing header or missing session", () => {
		expect(validateCsrf(csrfReq({ session: "sess-1" }))?.status).toBe(403);
		expect(
			validateCsrf(csrfReq({ header: csrfTokenFor("sess-1") }))?.status,
		).toBe(403);
	});

	test("csrfTokenMatches is strict about length and content", () => {
		const t = csrfTokenFor("s");
		expect(csrfTokenMatches(t, t)).toBe(true);
		expect(csrfTokenMatches(t.slice(0, -1), t)).toBe(false);
		expect(csrfTokenMatches(`${t}x`, t)).toBe(false);
		expect(csrfTokenMatches(null, t)).toBe(false);
		expect(csrfTokenMatches(t, null)).toBe(false);
	});
});

describe("cookie Secure flag follows ORIGIN scheme", () => {
	function withOrigin<T>(origin: string, fn: () => T): T {
		const prev = process.env.ORIGIN;
		process.env.ORIGIN = origin;
		try {
			return fn();
		} finally {
			process.env.ORIGIN = prev ?? "";
		}
	}

	test("https origin sets Secure regardless of NODE_ENV", () => {
		withOrigin("https://id.example", () => {
			expect(cookieSecureFlag()).toBe("; Secure");
			expect(sessionCookieHeader("t")).toContain("; Secure");
			expect(sessionCookieHeader("t")).toContain("HttpOnly");
			expect(csrfCookieHeader("c")).toContain("; Secure");
			expect(csrfCookieHeader("c")).not.toContain("HttpOnly");
			expect(clearSessionCookieHeader()).toContain("Max-Age=0; Secure");
			expect(clearCsrfCookieHeader()).toContain("Max-Age=0; Secure");
		});
	});

	test("http origin omits Secure", () => {
		withOrigin("http://localhost:3000", () => {
			expect(cookieSecureFlag()).toBe("");
			expect(sessionCookieHeader("t")).not.toContain("Secure");
			expect(csrfCookieHeader("c")).not.toContain("Secure");
		});
	});
});
