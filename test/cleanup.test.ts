import { beforeEach, describe, expect, test } from "bun:test";
import { sweepExpiredRecords } from "../src/lib/cleanup";
import { createUser, db } from "./helpers/db";

const CLIENT_ID = "https://client.example/";
const now = Math.floor(Date.now() / 1000);

function insertToken(
	userId: number,
	overrides: {
		expiresAt?: number;
		refreshToken?: string | null;
		refreshExpiresAt?: number | null;
		revoked?: number;
	} = {},
): string {
	const token = `at-${crypto.randomUUID()}`;
	db.query(
		`INSERT INTO tokens (token, user_id, client_id, scope, expires_at, refresh_token, refresh_expires_at, revoked)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
	).run(
		token,
		userId,
		CLIENT_ID,
		"profile offline_access",
		overrides.expiresAt ?? now + 3600,
		overrides.refreshToken ?? null,
		overrides.refreshExpiresAt ?? null,
		overrides.revoked ?? 0,
	);
	return token;
}

function tokenExists(token: string): boolean {
	return (
		(db.query("SELECT id FROM tokens WHERE token = ?").get(token) ?? null) !==
		null
	);
}

describe("sweepExpiredRecords", () => {
	let userId: number;

	beforeEach(() => {
		db.query("DELETE FROM tokens").run();
		db.query("DELETE FROM sessions").run();
		db.query("DELETE FROM authcodes").run();
		db.query("DELETE FROM device_codes").run();
		userId = createUser({});
	});

	test("keeps a token whose access token lapsed but refresh is still valid", () => {
		// The regression case: the hourly sweep used to key off expires_at,
		// deleting the live family head an hour after issuance.
		const token = insertToken(userId, {
			expiresAt: now - 1800,
			refreshToken: `rt-${crypto.randomUUID()}`,
			refreshExpiresAt: now + 29 * 86400,
		});

		const removed = sweepExpiredRecords(now);

		expect(removed.tokens).toBe(0);
		expect(tokenExists(token)).toBe(true);
	});

	test("removes an access-only token past its expiry", () => {
		const token = insertToken(userId, { expiresAt: now - 10 });

		const removed = sweepExpiredRecords(now);

		expect(removed.tokens).toBe(1);
		expect(tokenExists(token)).toBe(false);
	});

	test("keeps an access-only token that is still valid", () => {
		const token = insertToken(userId, { expiresAt: now + 3600 });

		const removed = sweepExpiredRecords(now);

		expect(removed.tokens).toBe(0);
		expect(tokenExists(token)).toBe(true);
	});

	test("removes a token whose refresh token has expired", () => {
		const token = insertToken(userId, {
			expiresAt: now - 1800,
			refreshToken: `rt-${crypto.randomUUID()}`,
			refreshExpiresAt: now - 10,
		});

		const removed = sweepExpiredRecords(now);

		expect(removed.tokens).toBe(1);
		expect(tokenExists(token)).toBe(false);
	});

	test("removes revoked tokens even if they have not expired", () => {
		const token = insertToken(userId, {
			refreshToken: `rt-${crypto.randomUUID()}`,
			refreshExpiresAt: now + 86400,
			revoked: 1,
		});

		const removed = sweepExpiredRecords(now);

		expect(removed.tokens).toBe(1);
		expect(tokenExists(token)).toBe(false);
	});

	test("keeps rotated-but-unexpired rows so reuse detection works", () => {
		const token = insertToken(userId, {
			refreshToken: `rt-${crypto.randomUUID()}`,
			refreshExpiresAt: now + 86400,
		});
		db.query("UPDATE tokens SET rotated = 1 WHERE token = ?").run(token);

		const removed = sweepExpiredRecords(now);

		expect(removed.tokens).toBe(0);
		expect(tokenExists(token)).toBe(true);
	});

	test("still sweeps expired sessions, authcodes, and device codes", () => {
		db.query(
			"INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
		).run("sess-dead", userId, now - 10);
		db.query(
			"INSERT INTO authcodes (code, user_id, client_id, redirect_uri, scopes, code_challenge, expires_at, used) VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
		).run("code-dead", userId, CLIENT_ID, `${CLIENT_ID}callback`, "[]", "c", now - 10);
		db.query(
			"INSERT INTO device_codes (device_code, user_code, client_id, scope, expires_at) VALUES (?, ?, ?, ?, ?)",
		).run("dc-dead", "UC-DEAD", CLIENT_ID, "profile", now - 10);

		const removed = sweepExpiredRecords(now);

		expect(removed.sessions).toBe(1);
		expect(removed.authcodes).toBe(1);
		expect(removed.deviceCodes).toBe(1);
	});
});
