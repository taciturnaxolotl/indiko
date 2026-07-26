import { beforeEach, describe, expect, test } from "bun:test";
import { getSessionUser, getUserFromCookie } from "../src/lib/session";
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
});
