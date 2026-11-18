import { beforeEach, describe, expect, test } from "bun:test";
import { csrfTokenFor } from "../src/lib/session";
import { resetUserPasskeys } from "../src/routes/api";
import { createSession, createUser, db } from "./helpers/db";

process.env.ORIGIN = "https://indiko.example";

function adminReq(cookie: string, userId: number): Request {
	return new Request(
		`http://localhost/api/admin/users/${userId}/passkeys/reset`,
		{
			method: "POST",
			headers: {
				Cookie: `indiko_session=${cookie}`,
				"X-CSRF-Token": csrfTokenFor(cookie),
			},
		},
	);
}

function addPasskey(userId: number) {
	db.query(
		"INSERT INTO credentials (user_id, credential_id, public_key) VALUES (?, ?, ?)",
	).run(userId, crypto.randomUUID(), "key");
}

const count = (sql: string, ...args: (string | number)[]) =>
	(db.query(sql).get(...args) as { n: number }).n;

let adminId: number;
let adminCookie: string;

beforeEach(() => {
	db.query("DELETE FROM invites").run();
	db.query("DELETE FROM credentials").run();
	db.query("DELETE FROM sessions").run();
	db.query("DELETE FROM users").run();
	adminId = createUser({ tier: "admin" });
	adminCookie = createSession(adminId);
});

describe("admin passkey reset", () => {
	test("wipes passkeys and sessions and returns a link bound to the account", async () => {
		const target = createUser({ username: "Creed" });
		addPasskey(target);
		addPasskey(target);
		createSession(target);

		const response = resetUserPasskeys(
			adminReq(adminCookie, target),
			String(target),
		);
		expect(response.status).toBe(200);
		const body = await response.json();

		expect(body.passkeys).toBe(2);
		expect(body.sessions).toBe(1);
		const url = new URL(body.url);
		expect(url.origin).toBe("https://indiko.example");
		expect(url.searchParams.get("username")).toBe("Creed");

		const invite = db
			.query("SELECT ldap_username, max_uses FROM invites WHERE code = ?")
			.get(url.searchParams.get("invite") ?? "") as {
			ldap_username: string;
			max_uses: number;
		};
		expect(invite).toEqual({ ldap_username: "Creed", max_uses: 1 });
		expect(
			count("SELECT COUNT(*) AS n FROM credentials WHERE user_id = ?", target),
		).toBe(0);
		expect(count("SELECT COUNT(*) AS n FROM users WHERE id = ?", target)).toBe(
			1,
		);
	});

	test("a second reset retires the first link", async () => {
		const target = createUser({});
		const first = await resetUserPasskeys(
			adminReq(adminCookie, target),
			String(target),
		).json();
		await resetUserPasskeys(
			adminReq(adminCookie, target),
			String(target),
		).json();

		const code = new URL(first.url).searchParams.get("invite") ?? "";
		expect(
			count("SELECT COUNT(*) AS n FROM invites WHERE code = ?", code),
		).toBe(0);
		expect(count("SELECT COUNT(*) AS n FROM invites")).toBe(1);
	});

	test("refuses to reset yourself", () => {
		addPasskey(adminId);
		const response = resetUserPasskeys(
			adminReq(adminCookie, adminId),
			String(adminId),
		);
		expect(response.status).toBe(400);
		expect(
			count("SELECT COUNT(*) AS n FROM credentials WHERE user_id = ?", adminId),
		).toBe(1);
	});

	test("refuses non-admins", () => {
		const user = createUser({});
		const target = createUser({});
		addPasskey(target);
		const response = resetUserPasskeys(
			adminReq(createSession(user), target),
			String(target),
		);
		expect(response.status).toBe(403);
		expect(
			count("SELECT COUNT(*) AS n FROM credentials WHERE user_id = ?", target),
		).toBe(1);
	});
});
