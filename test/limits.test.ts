// Input limits and crash-proofing: oversized or mistyped input is rejected
// with a 400 rather than stored, and a nameless opaque client can no longer
// take down the admin lists.

import { beforeEach, describe, expect, test } from "bun:test";
import {
	clientDisplayName,
	clientRegistration,
} from "../src/lib/oauth/client-display";
import { MAX_RESOURCES, validateResources } from "../src/lib/oauth/resource";
import { getCsrfToken } from "../src/lib/session";
import { getAppDetails, listAllApps, updateProfile } from "../src/routes/api";
import {
	createClient,
	getClient,
	listClients,
	updateClient,
} from "../src/routes/clients";
import { deviceAuthorization } from "../src/routes/oauth/device";
import { createInvite, updateInvite } from "../src/routes/oauth/invites";
import { registerClient } from "../src/routes/oauth/register";
import { createSession, createUser, db } from "./helpers/db";

function csrfFor(sessionToken: string): string {
	const probe = new Request("http://localhost/", {
		headers: {
			Cookie: `indiko_session=${sessionToken}; indiko_csrf=probe-csrf`,
		},
	});
	return getCsrfToken(probe) ?? "probe-csrf";
}

function authedReq(
	sessionToken: string,
	url: string,
	method: string,
	body?: unknown,
	rawBody?: string,
): Request {
	const csrf = csrfFor(sessionToken);
	return new Request(url, {
		method,
		headers: {
			Authorization: `Bearer ${sessionToken}`,
			Cookie: `indiko_session=${sessionToken}; indiko_csrf=${csrf}`,
			"x-csrf-token": csrf,
			"Content-Type": "application/json",
		},
		body: rawBody ?? (body !== undefined ? JSON.stringify(body) : undefined),
	});
}

function getReq(sessionToken: string, url: string): Request {
	return new Request(url, {
		headers: { Authorization: `Bearer ${sessionToken}` },
	});
}

beforeEach(() => {
	db.query("DELETE FROM invite_roles").run();
	db.query("DELETE FROM invites").run();
	db.query("DELETE FROM device_codes").run();
	db.query("DELETE FROM tokens").run();
	db.query("DELETE FROM permissions").run();
	db.query("DELETE FROM apps").run();
	db.query("DELETE FROM sessions").run();
	db.query("DELETE FROM users").run();
});

describe("validateResources", () => {
	test("accepts up to MAX_RESOURCES distinct values", () => {
		const values = Array.from(
			{ length: MAX_RESOURCES },
			(_, i) => `https://r${i}.example/api`,
		);
		expect(validateResources(values)).toHaveLength(MAX_RESOURCES);
	});

	test("rejects more than MAX_RESOURCES values", () => {
		const values = Array.from(
			{ length: MAX_RESOURCES + 1 },
			(_, i) => `https://r${i}.example/api`,
		);
		expect(validateResources(values)).toBeNull();
	});

	test("the cap counts raw values, so duplicates cannot smuggle past it", () => {
		const values = Array.from(
			{ length: MAX_RESOURCES + 5 },
			() => "https://same.example/api",
		);
		expect(validateResources(values)).toBeNull();
	});

	test("still rejects a fragment and non-http schemes", () => {
		expect(validateResources(["https://a.example/#frag"])).toBeNull();
		expect(validateResources(["ftp://a.example/"])).toBeNull();
	});
});

describe("clientDisplayName", () => {
	test("prefers the registered name", () => {
		expect(clientDisplayName("https://app.example/", "My App")).toBe("My App");
		expect(clientDisplayName("ikc_abc123", "Named")).toBe("Named");
	});

	test("falls back to the hostname for URL clients", () => {
		expect(clientDisplayName("https://app.example/path", null)).toBe(
			"app.example",
		);
	});

	test("never throws on opaque or garbage ids", () => {
		expect(clientDisplayName("ikc_abc123", null)).toBe("ikc_abc123");
		expect(clientDisplayName("ikc_abc123", "")).toBe("ikc_abc123");
		expect(clientDisplayName("ikc_abc123", "   ")).toBe("ikc_abc123");
		expect(clientDisplayName("", null)).toBe("");
		expect(clientDisplayName("not a url at all", undefined)).toBe(
			"not a url at all",
		);
	});

	test("clientRegistration derives 'url' for auto-registered rows", () => {
		expect(
			clientRegistration({ is_preregistered: 0, registration: "admin" }),
		).toBe("url");
		expect(
			clientRegistration({ is_preregistered: 1, registration: "dcr" }),
		).toBe("dcr");
		expect(
			clientRegistration({ is_preregistered: 1, registration: "admin" }),
		).toBe("admin");
		expect(
			clientRegistration({ is_preregistered: 1, registration: null }),
		).toBe("admin");
	});
});

describe("admin client/app lists survive a nameless opaque client", () => {
	test("listClients / getClient / listAllApps / getAppDetails all return 200", async () => {
		const adminId = createUser({ tier: "admin" });
		const session = createSession(adminId);
		db.query(
			"INSERT INTO apps (client_id, redirect_uris, name, is_preregistered, registration) VALUES (?, ?, NULL, 1, 'dcr')",
		).run("ikc_nameless", JSON.stringify(["https://x.example/cb"]));
		db.query(
			"INSERT INTO apps (client_id, redirect_uris, name, is_preregistered) VALUES (?, ?, NULL, 0)",
		).run("https://url.example/", JSON.stringify(["https://url.example/cb"]));

		const list = listClients(
			getReq(session, "http://localhost/api/admin/clients"),
		);
		expect(list.status).toBe(200);
		const clients = (await list.json()) as {
			clients: Array<{ clientId: string; name: string; registration: string }>;
		};
		const opaque = clients.clients.find((c) => c.clientId === "ikc_nameless");
		expect(opaque?.name).toBe("ikc_nameless");
		expect(opaque?.registration).toBe("dcr");
		const urlClient = clients.clients.find(
			(c) => c.clientId === "https://url.example/",
		);
		expect(urlClient?.name).toBe("url.example");
		expect(urlClient?.registration).toBe("url");

		const one = getClient(
			getReq(session, "http://localhost/api/admin/clients/x"),
			"ikc_nameless",
		);
		expect(one.status).toBe(200);
		expect(
			((await one.json()) as { client: { registration: string } }).client
				.registration,
		).toBe("dcr");

		const apps = listAllApps(
			getReq(session, "http://localhost/api/admin/apps"),
		);
		expect(apps.status).toBe(200);
		const appsBody = (await apps.json()) as {
			apps: Array<{ clientId: string; name: string; registration: string }>;
		};
		expect(appsBody.apps.find((a) => a.clientId === "ikc_nameless")?.name).toBe(
			"ikc_nameless",
		);

		const details = getAppDetails(
			getReq(session, "http://localhost/api/admin/apps/x"),
			"ikc_nameless",
		);
		expect(details.status).toBe(200);
		expect(((await details.json()) as { app: { name: string } }).app.name).toBe(
			"ikc_nameless",
		);
	});
});

describe("updateProfile input limits", () => {
	function profileReq(session: string, body: unknown) {
		return authedReq(session, "http://localhost/api/profile", "PUT", body);
	}

	test("accepts a normal profile", async () => {
		const userId = createUser({ username: "normal" });
		const session = createSession(userId);
		const res = await updateProfile(
			profileReq(session, {
				name: "Normal Person",
				email: "n@example.com",
				photo: "https://cdn.example/me.png",
			}),
		);
		expect(res.status).toBe(200);
		const row = db
			.query("SELECT name, email, photo FROM users WHERE id = ?")
			.get(userId) as { name: string; email: string; photo: string };
		expect(row).toEqual({
			name: "Normal Person",
			email: "n@example.com",
			photo: "https://cdn.example/me.png",
		});
	});

	const cases: Array<[string, Record<string, unknown>]> = [
		["oversized name", { name: "a".repeat(257) }],
		["whitespace-only name", { name: "   " }],
		["non-string name", { name: 42 }],
		["oversized email", { name: "ok", email: `${"e".repeat(250)}@x.example` }],
		["non-string email", { name: "ok", email: ["a@b"] }],
		["non-string photo", { name: "ok", photo: { url: "https://x" } }],
		[
			"oversized photo",
			{ name: "ok", photo: `https://x.example/${"p".repeat(2048)}` },
		],
		["javascript: photo", { name: "ok", photo: "javascript:alert(1)" }],
		["data: photo", { name: "ok", photo: "data:image/png;base64,AAAA" }],
		["relative photo", { name: "ok", photo: "/me.png" }],
		["non-string url", { name: "ok", url: 123 }],
		[
			"oversized url",
			{ name: "ok", url: `https://x.example/${"u".repeat(2048)}` },
		],
	];
	for (const [label, body] of cases) {
		test(`rejects ${label} with 400 and stores nothing`, async () => {
			const userId = createUser({});
			const session = createSession(userId);
			const before = db
				.query("SELECT name, email, photo, url FROM users WHERE id = ?")
				.get(userId);
			const res = await updateProfile(profileReq(session, body));
			expect(res.status).toBe(400);
			const after = db
				.query("SELECT name, email, photo, url FROM users WHERE id = ?")
				.get(userId);
			expect(after).toEqual(before);
		});
	}

	test("a name at exactly 256 characters is fine", async () => {
		const userId = createUser({});
		const session = createSession(userId);
		const res = await updateProfile(
			profileReq(session, { name: "n".repeat(256) }),
		);
		expect(res.status).toBe(200);
	});
});

describe("POST /oauth/register metadata limits", () => {
	function registerReq(body: unknown): Request {
		return new Request("http://localhost/oauth/register", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(body),
		});
	}
	const redirect_uris = ["https://app.example/cb"];

	test("stores registration = 'dcr'", async () => {
		const res = await registerClient(
			registerReq({ redirect_uris, client_name: "DCR App" }),
		);
		expect(res.status).toBe(201);
		const { client_id } = (await res.json()) as { client_id: string };
		const row = db
			.query(
				"SELECT registration, is_preregistered FROM apps WHERE client_id = ?",
			)
			.get(client_id) as { registration: string; is_preregistered: number };
		expect(row.registration).toBe("dcr");
		expect(row.is_preregistered).toBe(1);
	});

	test("rejects a client_name over 256 characters", async () => {
		const res = await registerClient(
			registerReq({ redirect_uris, client_name: "n".repeat(257) }),
		);
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_client_metadata");
	});

	test("rejects an empty or non-string client_name", async () => {
		for (const client_name of ["", "   ", 42, ["x"], {}]) {
			const res = await registerClient(
				registerReq({ redirect_uris, client_name }),
			);
			expect(res.status).toBe(400);
			expect((await res.json()).error).toBe("invalid_client_metadata");
		}
	});

	test("rejects a logo_uri over 2048 characters", async () => {
		const res = await registerClient(
			registerReq({
				redirect_uris,
				client_name: "x",
				logo_uri: `https://cdn.example/${"l".repeat(2048)}`,
			}),
		);
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_client_metadata");
	});

	test("rejects a logo_uri pointing at an internal address or non-http scheme", async () => {
		for (const logo_uri of [
			"http://127.0.0.1/logo.png",
			"http://100.100.100.200/logo.png",
			"http://localhost/logo.png",
			"javascript:alert(1)",
			"data:image/png;base64,AAAA",
			"not a url",
		]) {
			const res = await registerClient(
				registerReq({ redirect_uris, client_name: "x", logo_uri }),
			);
			expect(res.status).toBe(400);
			expect((await res.json()).error).toBe("invalid_client_metadata");
		}
		expect(
			(db.query("SELECT COUNT(*) as n FROM apps").get() as { n: number }).n,
		).toBe(0);
	});

	test("accepts a public https logo_uri", async () => {
		const res = await registerClient(
			registerReq({
				redirect_uris,
				client_name: "x",
				logo_uri: "https://cdn.example.com/logo.png",
			}),
		);
		expect(res.status).toBe(201);
		expect((await res.json()).logo_uri).toBe(
			"https://cdn.example.com/logo.png",
		);
	});

	test("a logo_uri on a reserved .example TLD is refused like any local host", async () => {
		const res = await registerClient(
			registerReq({
				redirect_uris,
				client_name: "x",
				logo_uri: "https://cdn.example/logo.png",
			}),
		);
		expect(res.status).toBe(400);
	});
});

describe("admin client create/update limits", () => {
	function seedAdmin() {
		const adminId = createUser({ tier: "admin" });
		return createSession(adminId);
	}
	const redirectUris = ["https://app.example/cb"];

	test("createClient caps name, description and logo and requires http(s) logo", async () => {
		const session = seedAdmin();
		const url = "http://localhost/api/admin/clients";
		const bad = [
			{ redirectUris, name: "n".repeat(257) },
			{ redirectUris, description: "d".repeat(2049) },
			{ redirectUris, logoUrl: `https://x.example/${"l".repeat(2048)}` },
			{ redirectUris, logoUrl: "javascript:alert(1)" },
			{ redirectUris, logoUrl: "ftp://x.example/logo.png" },
			{ redirectUris, name: ["array"] },
			{ redirectUris: ["myapp://callback"] },
			{ redirectUris: [42] },
			{ redirectUris: "https://app.example/cb" },
			{ redirectUris: [] },
		];
		for (const body of bad) {
			const res = await createClient(authedReq(session, url, "POST", body));
			expect(res.status).toBe(400);
		}
		expect(
			(db.query("SELECT COUNT(*) as n FROM apps").get() as { n: number }).n,
		).toBe(0);

		const ok = await createClient(
			authedReq(session, url, "POST", {
				redirectUris,
				name: "Fine",
				description: "d".repeat(2048),
				logoUrl: "https://cdn.example/logo.png",
			}),
		);
		expect(ok.status).toBe(200);
		const created = (await ok.json()) as {
			client: { clientId: string; registration: string };
		};
		expect(created.client.registration).toBe("admin");
		const row = db
			.query("SELECT registration FROM apps WHERE client_id = ?")
			.get(created.client.clientId) as { registration: string };
		expect(row.registration).toBe("admin");
	});

	test("updateClient leaves omitted fields unchanged", async () => {
		const session = seedAdmin();
		db.query(
			"INSERT INTO apps (client_id, redirect_uris, name, logo_url, description, is_preregistered, available_roles, default_role) VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
		).run(
			"ikc_upd",
			JSON.stringify(redirectUris),
			"Original",
			"https://cdn.example/o.png",
			"Original description",
			JSON.stringify(["admin", "viewer"]),
			"viewer",
		);

		const res = await updateClient(
			authedReq(session, "http://localhost/api/admin/clients/ikc_upd", "PUT", {
				description: "New description",
			}),
			"ikc_upd",
		);
		expect(res.status).toBe(200);

		const row = db
			.query(
				"SELECT name, logo_url, description, redirect_uris, available_roles, default_role FROM apps WHERE client_id = ?",
			)
			.get("ikc_upd") as Record<string, string | null>;
		expect(row.name).toBe("Original");
		expect(row.logo_url).toBe("https://cdn.example/o.png");
		expect(row.description).toBe("New description");
		expect(row.redirect_uris).toBe(JSON.stringify(redirectUris));
		expect(row.available_roles).toBe(JSON.stringify(["admin", "viewer"]));
		expect(row.default_role).toBe("viewer");
	});

	test("updateClient: null clears, redirectUris must be a non-empty http(s) list", async () => {
		const session = seedAdmin();
		db.query(
			"INSERT INTO apps (client_id, redirect_uris, name, description, is_preregistered) VALUES (?, ?, ?, ?, 1)",
		).run("ikc_upd2", JSON.stringify(redirectUris), "Original", "desc");
		const url = "http://localhost/api/admin/clients/ikc_upd2";

		for (const redirectUris of [
			[],
			["nope"],
			["custom://cb"],
			"https://x/cb",
			[1],
			null,
		]) {
			const res = await updateClient(
				authedReq(session, url, "PUT", { redirectUris }),
				"ikc_upd2",
			);
			expect(res.status).toBe(400);
		}
		const unchanged = db
			.query("SELECT redirect_uris FROM apps WHERE client_id = ?")
			.get("ikc_upd2") as { redirect_uris: string };
		expect(unchanged.redirect_uris).toBe(JSON.stringify(redirectUris));

		const clear = await updateClient(
			authedReq(session, url, "PUT", {
				description: null,
				redirectUris: ["https://new.example/cb"],
			}),
			"ikc_upd2",
		);
		expect(clear.status).toBe(200);
		const row = db
			.query(
				"SELECT name, description, redirect_uris FROM apps WHERE client_id = ?",
			)
			.get("ikc_upd2") as Record<string, string | null>;
		expect(row.name).toBe("Original");
		expect(row.description).toBeNull();
		expect(row.redirect_uris).toBe(JSON.stringify(["https://new.example/cb"]));

		const tooLong = await updateClient(
			authedReq(session, url, "PUT", { name: "n".repeat(257) }),
			"ikc_upd2",
		);
		expect(tooLong.status).toBe(400);

		const empty = await updateClient(
			authedReq(session, url, "PUT", {}),
			"ikc_upd2",
		);
		expect(empty.status).toBe(400);
	});
});

describe("invite input validation", () => {
	function seedAdmin() {
		const adminId = createUser({ tier: "admin" });
		return createSession(adminId);
	}
	const CREATE = "http://localhost/api/invites/create";

	test("createInvite rejects malformed JSON with 400", async () => {
		const session = seedAdmin();
		const res = await createInvite(
			authedReq(session, CREATE, "POST", undefined, "{not json"),
		);
		expect(res.status).toBe(400);
	});

	test("createInvite type-checks maxUses and expiresAt", async () => {
		const session = seedAdmin();
		const bad = [
			{ maxUses: "5" },
			{ maxUses: 0 },
			{ maxUses: -1 },
			{ maxUses: 1.5 },
			{ expiresAt: "tomorrow" },
			{ expiresAt: 1.5 },
			{ expiresAt: -1 },
			{ expiresAt: Date.now() }, // milliseconds, not seconds
			{ note: 42 },
			{ note: "n".repeat(1025) },
			{ message: ["x"] },
			{ appRoles: "admin" },
			{ appRoles: [{ appId: "1", role: "admin" }] },
			{ appRoles: [{ appId: 99999, role: "admin" }] }, // unknown app
		];
		for (const body of bad) {
			const res = await createInvite(authedReq(session, CREATE, "POST", body));
			expect(res.status).toBe(400);
		}
		expect(
			(db.query("SELECT COUNT(*) as n FROM invites").get() as { n: number }).n,
		).toBe(0);

		const future = Math.floor(Date.now() / 1000) + 86400;
		const ok = await createInvite(
			authedReq(session, CREATE, "POST", {
				maxUses: 3,
				expiresAt: future,
				note: "team",
			}),
		);
		expect(ok.status).toBe(200);
		const row = db
			.query("SELECT max_uses, expires_at, note FROM invites")
			.get() as { max_uses: number; expires_at: number; note: string };
		expect(row).toEqual({ max_uses: 3, expires_at: future, note: "team" });

		const defaults = await createInvite(authedReq(session, CREATE, "POST", {}));
		expect(defaults.status).toBe(200);
	});

	test("an invalid appRoles entry does not leave an orphan invite behind", async () => {
		const session = seedAdmin();
		const app = db
			.query(
				"INSERT INTO apps (client_id, redirect_uris, name, is_preregistered) VALUES (?, ?, ?, 1)",
			)
			.run("ikc_inv", "[]", "Inv App");
		const res = await createInvite(
			authedReq(session, CREATE, "POST", {
				appRoles: [
					{ appId: Number(app.lastInsertRowid), role: "admin" },
					{ appId: 424242, role: "admin" },
				],
			}),
		);
		expect(res.status).toBe(400);
		expect(
			(db.query("SELECT COUNT(*) as n FROM invites").get() as { n: number }).n,
		).toBe(0);
	});

	test("updateInvite type-checks and rejects malformed JSON", async () => {
		const session = seedAdmin();
		const created = db
			.query(
				"INSERT INTO invites (code, created_by, max_uses) VALUES (?, ?, 1)",
			)
			.run("code-1", createUser({ tier: "admin" }));
		const url = `http://localhost/api/invites/${created.lastInsertRowid}`;

		for (const body of [
			{ maxUses: "lots" },
			{ maxUses: 0 },
			{ expiresAt: "never" },
			{ note: 1 },
		]) {
			const res = await updateInvite(authedReq(session, url, "PATCH", body));
			expect(res.status).toBe(400);
		}
		const raw = await updateInvite(
			authedReq(session, url, "PATCH", undefined, "nope"),
		);
		expect(raw.status).toBe(400);

		const ok = await updateInvite(
			authedReq(session, url, "PATCH", { maxUses: 7, expiresAt: null }),
		);
		expect(ok.status).toBe(200);
		const row = db
			.query("SELECT max_uses, expires_at FROM invites WHERE id = ?")
			.get(created.lastInsertRowid) as { max_uses: number; expires_at: null };
		expect(row).toEqual({ max_uses: 7, expires_at: null });
	});
});

describe("device authorization scope cap", () => {
	function deviceReq(body: Record<string, string>): Request {
		return new Request("http://localhost/auth/device", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams(body).toString(),
		});
	}

	test("rejects a scope over 512 characters", async () => {
		db.query(
			"INSERT INTO apps (client_id, redirect_uris, name, is_preregistered) VALUES (?, ?, ?, 0)",
		).run("https://dev.example/", "[]", "Dev");
		const res = await deviceAuthorization(
			deviceReq({ client_id: "https://dev.example/", scope: "s".repeat(513) }),
		);
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_scope");
		expect(
			(
				db.query("SELECT COUNT(*) as n FROM device_codes").get() as {
					n: number;
				}
			).n,
		).toBe(0);
	});

	test("accepts a scope at exactly 512 characters", async () => {
		db.query(
			"INSERT INTO apps (client_id, redirect_uris, name, is_preregistered) VALUES (?, ?, ?, 0)",
		).run("https://dev.example/", "[]", "Dev");
		const res = await deviceAuthorization(
			deviceReq({ client_id: "https://dev.example/", scope: "s".repeat(512) }),
		);
		expect(res.status).toBe(200);
	});
});
