// loginVerify must enforce the LDAP existence check for every flow —
// including conditional UI, which never passes through loginOptions'
// username branch — and a not-found result must stamp orphaned_since so the
// hourly job can restore the account later.
import { afterAll, beforeEach, describe, expect, mock, test } from "bun:test";

const actualLdap = await import("../src/ldap-cleanup");

let ldapResult: "exists" | "not_found" | "error" = "exists";
const checked: string[] = [];

mock.module("../src/ldap-cleanup", () => ({
	...actualLdap,
	checkLdapUser: async (username: string) => {
		checked.push(username);
		return ldapResult;
	},
}));

const { loginOptions, loginVerify } = await import("../src/routes/auth");
const { createSession, createUser, db } = await import("./helpers/db");

afterAll(() => {
	mock.module("../src/ldap-cleanup", () => actualLdap);
});

process.env.RP_ID ||= "localhost";
process.env.ORIGIN ||= "http://localhost:3000";

function json(path: string, body: unknown): Request {
	return new Request(`http://localhost${path}`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
}

function ldapUser(username: string, lastVerified: number | null = null) {
	const id = createUser({ username });
	db.query(
		"UPDATE users SET provisioned_via_ldap = 1, last_ldap_verified_at = ? WHERE id = ?",
	).run(lastVerified, id);
	db.query(
		"INSERT INTO credentials (user_id, credential_id, public_key, counter, name) VALUES (?, ?, ?, 0, 'pk')",
	).run(id, Buffer.from(`cred-${username}`), Buffer.from("pk"));
	return id;
}

function userRow(id: number) {
	return db
		.query("SELECT status, orphaned_since FROM users WHERE id = ?")
		.get(id) as { status: string; orphaned_since: number | null };
}

beforeEach(() => {
	ldapResult = "exists";
	checked.length = 0;
	db.query("DELETE FROM challenges").run();
	db.query("DELETE FROM credentials").run();
	db.query("DELETE FROM sessions").run();
	db.query("DELETE FROM users").run();
});

describe("loginVerify LDAP enforcement", () => {
	test("conditional flow suspends a user missing from LDAP and sets orphaned_since", async () => {
		const id = ldapUser("gone");
		createSession(id);
		ldapResult = "not_found";

		const res = await loginVerify(
			json("/auth/login/verify", {
				conditional: true,
				challenge: "irrelevant",
				response: { id: "cred-gone" },
			}),
		);

		expect(res.status).toBe(401);
		expect(checked).toEqual(["gone"]);
		const row = userRow(id);
		expect(row.status).toBe("suspended");
		expect(row.orphaned_since).not.toBeNull();
		// Existing sessions are revoked too
		expect(
			(
				db
					.query("SELECT COUNT(*) as c FROM sessions WHERE user_id = ?")
					.get(id) as { c: number }
			).c,
		).toBe(0);
	});

	test("an LDAP infrastructure error is fail-open and leaves the account alone", async () => {
		const id = ldapUser("flaky");
		ldapResult = "error";

		const res = await loginVerify(
			json("/auth/login/verify", {
				conditional: true,
				challenge: "nope",
				response: { id: "cred-flaky" },
			}),
		);

		// Falls through to the challenge lookup, which fails (we gave none)
		expect(res.status).toBe(400);
		const row = userRow(id);
		expect(row.status).toBe("active");
		expect(row.orphaned_since).toBeNull();
	});

	test("recent verification is cached and skips the directory", async () => {
		const nowSec = Math.floor(Date.now() / 1000);
		ldapUser("cached", nowSec - 60);
		ldapResult = "not_found"; // would suspend if consulted

		const res = await loginVerify(
			json("/auth/login/verify", {
				conditional: true,
				challenge: "nope",
				response: { id: "cred-cached" },
			}),
		);
		expect(res.status).toBe(400); // got past the LDAP gate to the challenge check
		expect(checked).toEqual([]);
	});

	test("stale verification is re-checked and refreshed", async () => {
		const nowSec = Math.floor(Date.now() / 1000);
		const id = ldapUser("stale", nowSec - 100 * 86400);

		await loginVerify(
			json("/auth/login/verify", {
				conditional: true,
				challenge: "nope",
				response: { id: "cred-stale" },
			}),
		);
		expect(checked).toEqual(["stale"]);
		const row = db
			.query("SELECT last_ldap_verified_at FROM users WHERE id = ?")
			.get(id) as { last_ldap_verified_at: number };
		expect(row.last_ldap_verified_at).toBeGreaterThanOrEqual(nowSec);
	});

	test("non-LDAP users never hit the directory", async () => {
		const id = createUser({ username: "local" });
		db.query(
			"INSERT INTO credentials (user_id, credential_id, public_key, counter, name) VALUES (?, ?, ?, 0, 'pk')",
		).run(id, Buffer.from("cred-local"), Buffer.from("pk"));
		ldapResult = "not_found";

		await loginVerify(
			json("/auth/login/verify", {
				conditional: true,
				challenge: "nope",
				response: { id: "cred-local" },
			}),
		);
		expect(checked).toEqual([]);
		expect(userRow(id).status).toBe("active");
	});
});

describe("loginOptions LDAP enforcement", () => {
	test("username flow suspends and stamps orphaned_since on not_found", async () => {
		const id = ldapUser("gone2");
		ldapResult = "not_found";

		const res = await loginOptions(
			json("/auth/login/options", { username: "gone2" }),
		);
		expect(res.status).toBe(401);
		const row = userRow(id);
		expect(row.status).toBe("suspended");
		expect(row.orphaned_since).not.toBeNull();
	});
});
