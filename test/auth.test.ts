import { beforeEach, describe, expect, test } from "bun:test";
import { groupEntryMatches, userIsInGroup } from "../src/ldap-cleanup";
import {
	ldapVerify,
	registerOptions,
	registerVerify,
} from "../src/routes/auth";
import { createUser, db } from "./helpers/db";

// WebAuthn option generation needs an RP ID; collision checks run before
// it, but the success-path tests below reach it.
process.env.RP_ID ||= "localhost";
process.env.ORIGIN ||= "http://localhost:3000";

function json(path: string, body: unknown): Request {
	return new Request(`http://localhost${path}`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
}

function addCredential(userId: number, id = `cred-${userId}`) {
	db.query(
		"INSERT INTO credentials (user_id, credential_id, public_key, counter, name) VALUES (?, ?, ?, 0, 'pk')",
	).run(userId, Buffer.from(id), Buffer.from("pk"));
}

function createInvite(
	createdBy: number,
	opts: { code?: string; ldapUsername?: string | null } = {},
): string {
	const code = opts.code ?? `inv-${crypto.randomUUID()}`;
	db.query(
		"INSERT INTO invites (code, created_by, max_uses, current_uses, expires_at, ldap_username) VALUES (?, ?, 1, 0, NULL, ?)",
	).run(code, createdBy, opts.ldapUsername ?? null);
	return code;
}

function addChallenge(username: string, challenge = crypto.randomUUID()) {
	db.query(
		"INSERT INTO challenges (challenge, username, type, expires_at) VALUES (?, ?, 'registration', ?)",
	).run(challenge, username, Math.floor(Date.now() / 1000) + 300);
	return challenge;
}

beforeEach(() => {
	db.query("DELETE FROM challenges").run();
	db.query("DELETE FROM invites").run();
	db.query("DELETE FROM credentials").run();
	db.query("DELETE FROM sessions").run();
	db.query("DELETE FROM users").run();
});

describe("case-insensitive username collisions", () => {
	test("registerOptions rejects a different-cased existing username", async () => {
		const admin = createUser({ username: "admin", tier: "admin" });
		addCredential(admin);
		const alice = createUser({ username: "alice" });
		addCredential(alice);
		const invite = createInvite(admin);

		const res = await registerOptions(
			json("/auth/register/options", { username: "Alice", inviteCode: invite }),
		);
		expect(res.status).toBe(400);
		expect(((await res.json()) as { error: string }).error).toBe(
			"Username already taken",
		);
	});

	test("registerVerify rejects a different-cased existing username", async () => {
		const admin = createUser({ username: "admin", tier: "admin" });
		addCredential(admin);
		const alice = createUser({ username: "alice" });
		addCredential(alice);

		const res = await registerVerify(
			json("/auth/register/verify", {
				username: "ALICE",
				response: { id: "x" },
				challenge: "c",
				inviteCode: "whatever",
			}),
		);
		expect(res.status).toBe(400);
		expect(((await res.json()) as { error: string }).error).toBe(
			"Username already taken",
		);
	});

	test("ldapVerify rejects a different-cased existing local account", async () => {
		const prevDn = process.env.LDAP_ADMIN_DN;
		const prevPw = process.env.LDAP_ADMIN_PASSWORD;
		process.env.LDAP_ADMIN_DN = "cn=admin,dc=example,dc=com";
		process.env.LDAP_ADMIN_PASSWORD = "secret";
		try {
			const alice = createUser({ username: "alice" });
			addCredential(alice);
			const res = await ldapVerify(
				json("/api/ldap-verify", { username: "Alice", password: "pw" }),
			);
			expect(res.status).toBe(400);
			expect(((await res.json()) as { error: string }).error).toContain(
				"Account already exists",
			);
		} finally {
			process.env.LDAP_ADMIN_DN = prevDn ?? "";
			process.env.LDAP_ADMIN_PASSWORD = prevPw ?? "";
			if (!prevDn) delete process.env.LDAP_ADMIN_DN;
			if (!prevPw) delete process.env.LDAP_ADMIN_PASSWORD;
		}
	});

	test("ldapVerify requires a string password", async () => {
		process.env.LDAP_ADMIN_DN = "cn=admin,dc=example,dc=com";
		process.env.LDAP_ADMIN_PASSWORD = "secret";
		try {
			const res = await ldapVerify(
				json("/api/ldap-verify", { username: "bob", password: { $ne: 1 } }),
			);
			expect(res.status).toBe(400);
		} finally {
			delete process.env.LDAP_ADMIN_DN;
			delete process.env.LDAP_ADMIN_PASSWORD;
		}
	});

	test("username-bound invites match case-insensitively", async () => {
		const admin = createUser({ username: "admin", tier: "admin" });
		addCredential(admin);
		const invite = createInvite(admin, { ldapUsername: "Carol" });

		const ok = await registerOptions(
			json("/auth/register/options", { username: "carol", inviteCode: invite }),
		);
		expect(ok.status).toBe(200);

		const bad = await registerOptions(
			json("/auth/register/options", { username: "dave", inviteCode: invite }),
		);
		expect(bad.status).toBe(400);
		expect(((await bad.json()) as { error: string }).error).toBe(
			"Username must match LDAP account",
		);
	});
});

describe("passkey reset requires a username-bound invite", () => {
	test("registerOptions refuses a reset with a general invite", async () => {
		const admin = createUser({ username: "admin", tier: "admin" });
		addCredential(admin);
		// Credential-less account (e.g. after reset-passkey.ts ran)
		createUser({ username: "locked", isAdmin: 1 });
		const invite = createInvite(admin); // not bound to anyone

		const res = await registerOptions(
			json("/auth/register/options", {
				username: "locked",
				inviteCode: invite,
			}),
		);
		expect(res.status).toBe(403);
		expect(((await res.json()) as { error: string }).error).toContain(
			"reset link issued for this username",
		);
	});

	test("registerOptions allows a reset with an invite bound to that user", async () => {
		const admin = createUser({ username: "admin", tier: "admin" });
		addCredential(admin);
		createUser({ username: "locked" });
		const invite = createInvite(admin, { ldapUsername: "Locked" });

		const res = await registerOptions(
			json("/auth/register/options", {
				username: "locked",
				inviteCode: invite,
			}),
		);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { challenge: string };
		expect(typeof body.challenge).toBe("string");
	});

	test("registerVerify refuses a reset with a general invite", async () => {
		const admin = createUser({ username: "admin", tier: "admin" });
		addCredential(admin);
		createUser({ username: "locked", isAdmin: 1 });
		const invite = createInvite(admin);
		const challenge = addChallenge("locked");

		const res = await registerVerify(
			json("/auth/register/verify", {
				username: "locked",
				response: { id: "x" },
				challenge,
				inviteCode: invite,
			}),
		);
		expect(res.status).toBe(403);
		expect(((await res.json()) as { error: string }).error).toContain(
			"reset link issued for this username",
		);
		// No credential was attached and the invite was not consumed
		expect(
			(
				db
					.query("SELECT COUNT(*) as c FROM credentials WHERE user_id != ?")
					.get(admin) as { c: number }
			).c,
		).toBe(0);
		expect(
			(
				db
					.query("SELECT current_uses FROM invites WHERE code = ?")
					.get(invite) as { current_uses: number }
			).current_uses,
		).toBe(0);
	});
});

describe("LDAP group membership evaluation", () => {
	const GROUP = "cn=indiko-users,ou=groups,dc=example,dc=com";

	test("matches on dn or objectName, case-insensitively", () => {
		expect(groupEntryMatches({ dn: GROUP }, GROUP)).toBe(true);
		expect(groupEntryMatches({ dn: GROUP.toUpperCase() }, GROUP)).toBe(true);
		expect(groupEntryMatches({ objectName: GROUP }, GROUP)).toBe(true);
		expect(
			groupEntryMatches(
				{ dn: "cn=indiko-users, ou=groups, dc=example, dc=com" },
				GROUP,
			),
		).toBe(true);
		expect(
			groupEntryMatches({ dn: "cn=other,ou=groups,dc=example,dc=com" }, GROUP),
		).toBe(false);
		expect(groupEntryMatches(null, GROUP)).toBe(false);
		expect(groupEntryMatches("string", GROUP)).toBe(false);
	});

	test("a user with no matching group is NOT a member", () => {
		expect(userIsInGroup({ dn: "uid=x", groups: [] }, GROUP)).toBe(false);
		expect(userIsInGroup({ dn: "uid=x" }, GROUP)).toBe(false);
		expect(
			userIsInGroup(
				{ dn: "uid=x", groups: [{ dn: "cn=other,dc=example,dc=com" }] },
				GROUP,
			),
		).toBe(false);
		expect(userIsInGroup(null, GROUP)).toBe(false);
		expect(userIsInGroup({ dn: "uid=x", groups: "not-an-array" }, GROUP)).toBe(
			false,
		);
	});

	test("a user whose groups include the configured DN is a member", () => {
		expect(
			userIsInGroup(
				{
					dn: "uid=x",
					groups: [{ dn: "cn=other,dc=example,dc=com" }, { dn: GROUP }],
				},
				GROUP,
			),
		).toBe(true);
	});
});
