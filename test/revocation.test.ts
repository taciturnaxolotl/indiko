// Revocation must actually cut off access: revoking an app (self-service or
// admin) and deleting a client must kill issued tokens and pending device
// codes, and approving a device must leave a grant the user can later revoke.

import { beforeEach, describe, expect, test } from "bun:test";
import { getCsrfToken } from "../src/lib/session";
import {
	getAuthorizedApps,
	revokeApp,
	revokeAppForUser,
} from "../src/routes/api";
import { deleteClient } from "../src/routes/clients";
import { devicePost } from "../src/routes/oauth/device-verify";
import { createSession, createUser, db } from "./helpers/db";

const CLIENT_ID = "https://client.example/";
const OTHER_CLIENT_ID = "https://other.example/";

/**
 * Whatever CSRF scheme session.ts implements (cookie double-submit or
 * session-derived), `getCsrfToken` yields the value the server expects for
 * this session. Probe with a placeholder cookie so both designs work.
 */
function csrfFor(sessionToken: string): string {
	const probe = new Request("http://localhost/", {
		headers: {
			Cookie: `indiko_session=${sessionToken}; indiko_csrf=probe-csrf`,
		},
	});
	return getCsrfToken(probe) ?? "probe-csrf";
}

function mutatingReq(
	sessionToken: string,
	url: string,
	method: string,
	body?: unknown,
): Request {
	const csrf = csrfFor(sessionToken);
	return new Request(url, {
		method,
		headers: {
			Authorization: `Bearer ${sessionToken}`,
			Cookie: `indiko_session=${sessionToken}; indiko_csrf=${csrf}`,
			"x-csrf-token": csrf,
			...(body !== undefined ? { "Content-Type": "application/json" } : {}),
		},
		body: body !== undefined ? JSON.stringify(body) : undefined,
	});
}

function seedApp(clientId = CLIENT_ID, defaultRole: string | null = null) {
	db.query(
		"INSERT INTO apps (client_id, redirect_uris, name, is_preregistered, default_role) VALUES (?, ?, ?, 0, ?)",
	).run(
		clientId,
		JSON.stringify([`${clientId}callback`]),
		"Test Client",
		defaultRole,
	);
}

function seedPermission(userId: number, clientId = CLIENT_ID) {
	db.query(
		"INSERT INTO permissions (user_id, client_id, scopes) VALUES (?, ?, ?)",
	).run(userId, clientId, JSON.stringify(["profile"]));
}

let tokenSeq = 0;
function seedToken(userId: number, clientId = CLIENT_ID): string {
	tokenSeq += 1;
	const token = `access-${tokenSeq}-${crypto.randomUUID()}`;
	db.query(
		"INSERT INTO tokens (token, user_id, client_id, scope, expires_at, refresh_token, refresh_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
	).run(
		token,
		userId,
		clientId,
		"profile",
		Math.floor(Date.now() / 1000) + 3600,
		`refresh-${tokenSeq}-${crypto.randomUUID()}`,
		Math.floor(Date.now() / 1000) + 86400,
	);
	return token;
}

function seedDeviceCode(
	clientId = CLIENT_ID,
	overrides: {
		userId?: number | null;
		status?: string;
		scope?: string;
		resource?: string | null;
	} = {},
): { deviceCode: string; userCode: string } {
	tokenSeq += 1;
	const deviceCode = `device-${tokenSeq}-${crypto.randomUUID()}`;
	const letters = "BCDFGHJKLMNPQRSTVWXZ";
	let userCode = "";
	for (let i = 0; i < 8; i++) {
		if (i === 4) userCode += "-";
		userCode += letters[Math.floor(Math.random() * letters.length)];
	}
	db.query(
		"INSERT INTO device_codes (device_code, user_code, client_id, scope, expires_at, interval, status, user_id, resource) VALUES (?, ?, ?, ?, ?, 5, ?, ?, ?)",
	).run(
		deviceCode,
		userCode,
		clientId,
		overrides.scope ?? "profile offline_access",
		Math.floor(Date.now() / 1000) + 600,
		overrides.status ?? "pending",
		overrides.userId ?? null,
		overrides.resource ?? null,
	);
	return { deviceCode, userCode };
}

function tokenRevoked(token: string): number {
	return (
		db.query("SELECT revoked FROM tokens WHERE token = ?").get(token) as {
			revoked: number;
		}
	).revoked;
}

function deviceCodeCount(clientId: string, userId?: number): number {
	if (userId === undefined) {
		return (
			db
				.query("SELECT COUNT(*) as n FROM device_codes WHERE client_id = ?")
				.get(clientId) as { n: number }
		).n;
	}
	return (
		db
			.query(
				"SELECT COUNT(*) as n FROM device_codes WHERE client_id = ? AND user_id = ?",
			)
			.get(clientId, userId) as { n: number }
	).n;
}

beforeEach(() => {
	db.query("DELETE FROM device_codes").run();
	db.query("DELETE FROM tokens").run();
	db.query("DELETE FROM authcodes").run();
	db.query("DELETE FROM permissions").run();
	db.query("DELETE FROM apps").run();
	db.query("DELETE FROM sessions").run();
	db.query("DELETE FROM users").run();
});

describe("revokeApp (self-service)", () => {
	test("revokes the user's tokens and device codes for that client only", async () => {
		const userId = createUser({});
		const otherUserId = createUser({});
		const session = createSession(userId);
		seedApp(CLIENT_ID);
		seedApp(OTHER_CLIENT_ID);
		seedPermission(userId, CLIENT_ID);
		seedPermission(userId, OTHER_CLIENT_ID);
		seedPermission(otherUserId, CLIENT_ID);

		const mine = seedToken(userId, CLIENT_ID);
		const mineOtherApp = seedToken(userId, OTHER_CLIENT_ID);
		const theirs = seedToken(otherUserId, CLIENT_ID);
		seedDeviceCode(CLIENT_ID, { userId, status: "approved" });
		seedDeviceCode(CLIENT_ID, { userId: otherUserId, status: "approved" });

		const res = revokeApp(
			mutatingReq(session, "http://localhost/api/apps/x", "DELETE"),
			CLIENT_ID,
		);
		expect(res.status).toBe(200);

		expect(tokenRevoked(mine)).toBe(1);
		expect(tokenRevoked(mineOtherApp)).toBe(0);
		expect(tokenRevoked(theirs)).toBe(0);
		expect(deviceCodeCount(CLIENT_ID, userId)).toBe(0);
		expect(deviceCodeCount(CLIENT_ID, otherUserId)).toBe(1);

		const perm = db
			.query("SELECT id FROM permissions WHERE user_id = ? AND client_id = ?")
			.get(userId, CLIENT_ID);
		expect(perm).toBeNull();
	});

	test("404s and touches nothing when there is no grant", async () => {
		const userId = createUser({});
		const session = createSession(userId);
		seedApp(CLIENT_ID);
		const token = seedToken(userId, CLIENT_ID);

		const res = revokeApp(
			mutatingReq(session, "http://localhost/api/apps/x", "DELETE"),
			CLIENT_ID,
		);
		expect(res.status).toBe(404);
		expect(tokenRevoked(token)).toBe(0);
	});

	test("rejects a request without a CSRF token", async () => {
		const userId = createUser({});
		const session = createSession(userId);
		seedApp(CLIENT_ID);
		seedPermission(userId, CLIENT_ID);
		const token = seedToken(userId, CLIENT_ID);

		const res = revokeApp(
			new Request("http://localhost/api/apps/x", {
				method: "DELETE",
				headers: { Authorization: `Bearer ${session}` },
			}),
			CLIENT_ID,
		);
		expect(res.status).toBe(403);
		expect(tokenRevoked(token)).toBe(0);
	});
});

describe("revokeAppForUser (admin)", () => {
	test("revokes the target user's tokens and device codes", async () => {
		const adminId = createUser({ tier: "admin" });
		const targetId = createUser({ username: "target" });
		const session = createSession(adminId);
		seedApp(CLIENT_ID);
		seedPermission(targetId, CLIENT_ID);
		const token = seedToken(targetId, CLIENT_ID);
		seedDeviceCode(CLIENT_ID, { userId: targetId, status: "approved" });

		const res = revokeAppForUser(
			mutatingReq(session, "http://localhost/api/admin/apps/x", "DELETE"),
			CLIENT_ID,
			"target",
		);
		expect(res.status).toBe(200);
		expect(tokenRevoked(token)).toBe(1);
		expect(deviceCodeCount(CLIENT_ID, targetId)).toBe(0);
	});

	test("non-admins are refused", async () => {
		const userId = createUser({});
		const targetId = createUser({ username: "target2" });
		const session = createSession(userId);
		seedApp(CLIENT_ID);
		seedPermission(targetId, CLIENT_ID);
		const token = seedToken(targetId, CLIENT_ID);

		const res = revokeAppForUser(
			mutatingReq(session, "http://localhost/api/admin/apps/x", "DELETE"),
			CLIENT_ID,
			"target2",
		);
		expect(res.status).toBe(403);
		expect(tokenRevoked(token)).toBe(0);
	});
});

describe("deleteClient (admin)", () => {
	test("revokes every token for the client and drops its device codes and grants", async () => {
		const adminId = createUser({ tier: "admin" });
		const u1 = createUser({});
		const u2 = createUser({});
		const session = createSession(adminId);
		seedApp(CLIENT_ID);
		seedApp(OTHER_CLIENT_ID);
		seedPermission(u1, CLIENT_ID);
		seedPermission(u2, CLIENT_ID);
		seedPermission(u1, OTHER_CLIENT_ID);
		const t1 = seedToken(u1, CLIENT_ID);
		const t2 = seedToken(u2, CLIENT_ID);
		const tOther = seedToken(u1, OTHER_CLIENT_ID);
		seedDeviceCode(CLIENT_ID);
		seedDeviceCode(CLIENT_ID, { userId: u2, status: "approved" });
		seedDeviceCode(OTHER_CLIENT_ID);

		const res = deleteClient(
			mutatingReq(session, "http://localhost/api/admin/clients/x", "DELETE"),
			CLIENT_ID,
		);
		expect(res.status).toBe(200);

		expect(tokenRevoked(t1)).toBe(1);
		expect(tokenRevoked(t2)).toBe(1);
		expect(tokenRevoked(tOther)).toBe(0);
		expect(deviceCodeCount(CLIENT_ID)).toBe(0);
		expect(deviceCodeCount(OTHER_CLIENT_ID)).toBe(1);

		const perms = db
			.query("SELECT COUNT(*) as n FROM permissions WHERE client_id = ?")
			.get(CLIENT_ID) as { n: number };
		expect(perms.n).toBe(0);
		const app = db
			.query("SELECT id FROM apps WHERE client_id = ?")
			.get(CLIENT_ID);
		expect(app).toBeNull();
	});
});

describe("device approval records a revocable grant", () => {
	function approvalReq(
		sessionToken: string,
		userCode: string,
		action = "allow",
	): Request {
		const csrf = csrfFor(sessionToken);
		return new Request("http://localhost/device", {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Cookie: `indiko_session=${sessionToken}; indiko_csrf=${csrf}`,
			},
			body: new URLSearchParams({
				code: userCode,
				action,
				csrf_token: csrf,
			}).toString(),
		});
	}

	test("inserts a permissions row with scopes, resources and the app default role", async () => {
		const userId = createUser({});
		const session = createSession(userId);
		seedApp(CLIENT_ID, "viewer");
		const { userCode } = seedDeviceCode(CLIENT_ID, {
			scope: "profile email offline_access",
			resource: "https://api.example/v1",
		});

		const res = await devicePost(approvalReq(session, userCode));
		expect(res.status).toBe(200);
		expect(await res.text()).toContain("Device authorized");

		const perm = db
			.query(
				"SELECT scopes, resources, role FROM permissions WHERE user_id = ? AND client_id = ?",
			)
			.get(userId, CLIENT_ID) as {
			scopes: string;
			resources: string | null;
			role: string | null;
		};
		expect(perm).not.toBeNull();
		expect(JSON.parse(perm.scopes)).toEqual([
			"profile",
			"email",
			"offline_access",
		]);
		expect(perm.resources).toBe("https://api.example/v1");
		expect(perm.role).toBe("viewer");

		// It now shows on the user's /apps list …
		const listRes = getAuthorizedApps(
			new Request("http://localhost/api/apps", {
				headers: { Authorization: `Bearer ${session}` },
			}),
		);
		const list = (await listRes.json()) as {
			apps: Array<{ clientId: string }>;
		};
		expect(list.apps.map((a) => a.clientId)).toContain(CLIENT_ID);

		// … and can be revoked from there, which also kills the device code.
		const revokeRes = revokeApp(
			mutatingReq(session, "http://localhost/api/apps/x", "DELETE"),
			CLIENT_ID,
		);
		expect(revokeRes.status).toBe(200);
		expect(deviceCodeCount(CLIENT_ID, userId)).toBe(0);
	});

	test("merges with an existing grant instead of narrowing it", async () => {
		const userId = createUser({});
		const session = createSession(userId);
		seedApp(CLIENT_ID);
		db.query(
			"INSERT INTO permissions (user_id, client_id, scopes, resources, role) VALUES (?, ?, ?, ?, ?)",
		).run(
			userId,
			CLIENT_ID,
			JSON.stringify(["profile", "email"]),
			"https://a.example",
			"editor",
		);
		const { userCode } = seedDeviceCode(CLIENT_ID, {
			scope: "profile offline_access",
			resource: "https://b.example",
		});

		const res = await devicePost(approvalReq(session, userCode));
		expect(res.status).toBe(200);

		const perm = db
			.query(
				"SELECT scopes, resources, role FROM permissions WHERE user_id = ? AND client_id = ?",
			)
			.get(userId, CLIENT_ID) as {
			scopes: string;
			resources: string | null;
			role: string | null;
		};
		expect((JSON.parse(perm.scopes) as string[]).sort()).toEqual([
			"email",
			"offline_access",
			"profile",
		]);
		expect(perm.resources?.split(" ").sort()).toEqual([
			"https://a.example",
			"https://b.example",
		]);
		expect(perm.role).toBe("editor");
		const count = db
			.query("SELECT COUNT(*) as n FROM permissions WHERE user_id = ?")
			.get(userId) as { n: number };
		expect(count.n).toBe(1);
	});

	test("denying records no grant", async () => {
		const userId = createUser({});
		const session = createSession(userId);
		seedApp(CLIENT_ID);
		const { userCode } = seedDeviceCode(CLIENT_ID);

		const res = await devicePost(approvalReq(session, userCode, "deny"));
		expect(res.status).toBe(200);

		const perm = db
			.query("SELECT id FROM permissions WHERE user_id = ? AND client_id = ?")
			.get(userId, CLIENT_ID);
		expect(perm).toBeNull();
	});
});
