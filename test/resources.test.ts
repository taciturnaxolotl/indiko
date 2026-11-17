import { beforeEach, describe, expect, test } from "bun:test";
import {
	checkClientAccess,
	evaluateAccess,
} from "../src/lib/oauth/resource-registry";
import { hashSecret } from "../src/lib/secrets";
import { csrfTokenFor } from "../src/lib/session";
import { authorizeGet, authorizePost } from "../src/routes/oauth/authorize";
import { deviceAuthorization } from "../src/routes/oauth/device";
import { token, tokenIntrospect } from "../src/routes/oauth/token";
import {
	createResource,
	deleteResource,
	removeResourceClient,
	setResourceClient,
	setResourceUserRole,
} from "../src/routes/resources";
import { createSession, createUser, db } from "./helpers/db";

const API = "https://api.example.com";
const OTHER_API = "https://other.example.com";
const CLIENT_ID = "https://client.example/";
const OTHER_CLIENT = "https://stranger.example/";
const REDIRECT_URI = "https://client.example/callback";

function seedApp(clientId = CLIENT_ID) {
	db.query(
		"INSERT INTO apps (client_id, redirect_uris, name, is_preregistered) VALUES (?, ?, ?, 0)",
	).run(clientId, JSON.stringify([`${clientId}callback`]), "App");
}

function seedResource(
	opts: {
		identifier?: string;
		roles?: string[];
		defaultRole?: string;
		restrict?: boolean;
		assignment?: boolean;
	} = {},
): number {
	const result = db
		.query(
			"INSERT INTO resources (identifier, name, available_roles, default_role, restrict_clients, assignment_required) VALUES (?, ?, ?, ?, ?, ?)",
		)
		.run(
			opts.identifier ?? API,
			"Example API",
			opts.roles ? JSON.stringify(opts.roles) : null,
			opts.defaultRole ?? null,
			opts.restrict === false ? 0 : 1,
			opts.assignment ? 1 : 0,
		);
	return Number(result.lastInsertRowid);
}

function allowClient(
	resourceId: number,
	clientId = CLIENT_ID,
	allowedRoles: string[] | null = null,
) {
	db.query(
		"INSERT INTO resource_clients (resource_id, client_id, allowed_roles) VALUES (?, ?, ?)",
	).run(
		resourceId,
		clientId,
		allowedRoles ? JSON.stringify(allowedRoles) : null,
	);
}

function assign(resourceId: number, userId: number, role: string) {
	db.query(
		"INSERT INTO resource_roles (resource_id, user_id, role) VALUES (?, ?, ?)",
	).run(resourceId, userId, role);
}

function seedToken(
	userId: number,
	resource: string | null,
	clientId = CLIENT_ID,
): { access: string; refresh: string } {
	const access = `at-${crypto.randomUUID()}`;
	const refresh = `rt-${crypto.randomUUID()}`;
	const now = Math.floor(Date.now() / 1000);
	db.query(
		"INSERT INTO tokens (token, user_id, client_id, scope, expires_at, refresh_token, refresh_expires_at, family, resource) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
	).run(
		hashSecret(access),
		userId,
		clientId,
		"profile",
		now + 3600,
		hashSecret(refresh),
		now + 86400,
		crypto.randomUUID(),
		resource,
	);
	return { access, refresh };
}

function introspect(accessToken: string) {
	return tokenIntrospect(
		new Request("http://localhost/auth/token/introspect", {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Authorization: `Bearer ${accessToken}`,
			},
			body: new URLSearchParams({ token: accessToken }).toString(),
		}),
	);
}

function authorizeUrl(resource: string, clientId = CLIENT_ID): Request {
	const url = new URL("http://localhost/auth/authorize");
	for (const [key, value] of Object.entries({
		response_type: "code",
		client_id: clientId,
		redirect_uri: `${clientId}callback`,
		state: "s",
		code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		code_challenge_method: "S256",
		scope: "profile",
		resource,
	})) {
		url.searchParams.set(key, value);
	}
	return new Request(url);
}

function adminReq(
	cookie: string,
	method: string,
	body?: unknown,
	path = "http://localhost/api/admin/resources",
): Request {
	return new Request(path, {
		method,
		headers: {
			"Content-Type": "application/json",
			Cookie: `indiko_session=${cookie}`,
			"X-CSRF-Token": csrfTokenFor(cookie),
		},
		body: body === undefined ? undefined : JSON.stringify(body),
	});
}

beforeEach(() => {
	db.query("DELETE FROM resources").run();
	db.query("DELETE FROM tokens").run();
	db.query("DELETE FROM device_codes").run();
	db.query("DELETE FROM authcodes").run();
	db.query("DELETE FROM permissions").run();
	db.query("DELETE FROM apps").run();
	db.query("DELETE FROM sessions").run();
	db.query("DELETE FROM users").run();
});

/** The roles granted, or the denial error code. */
function access(clientId: string, userId: number, resources: string[]) {
	const result = evaluateAccess(clientId, userId, resources);
	return result.ok ? result.roles : result.denial.error;
}

describe("registry policy", () => {
	test("an unregistered audience passes every check", () => {
		expect(access(CLIENT_ID, createUser({}), [API])).toEqual({});
	});

	test("a restricted resource refuses clients it does not list", () => {
		const id = seedResource();
		expect(checkClientAccess(CLIENT_ID, [API])?.error).toBe("invalid_target");
		allowClient(id);
		expect(checkClientAccess(CLIENT_ID, [API])).toBeNull();
		expect(access(OTHER_CLIENT, createUser({}), [API])).toBe("invalid_target");
	});

	test("an open resource takes any client", () => {
		seedResource({ restrict: false });
		expect(checkClientAccess(OTHER_CLIENT, [API])).toBeNull();
	});

	test("assignment_required needs an assigned or default role", () => {
		const userId = createUser({});
		const id = seedResource({ assignment: true });
		allowClient(id);
		expect(access(CLIENT_ID, userId, [API])).toBe("access_denied");
		assign(id, userId, "reader");
		expect(access(CLIENT_ID, userId, [API])).toEqual({ [API]: "reader" });

		db.query("UPDATE resources SET default_role = 'guest' WHERE id = ?").run(
			id,
		);
		expect(access(CLIENT_ID, createUser({}), [API])).toEqual({
			[API]: "guest",
		});
	});

	test("a client ceiling withholds roles outside it", () => {
		const userId = createUser({});
		const id = seedResource();
		allowClient(id, CLIENT_ID, ["writer"]);
		assign(id, userId, "admin");
		expect(access(CLIENT_ID, userId, [API])).toEqual({});

		db.query("UPDATE resources SET assignment_required = 1").run();
		expect(access(CLIENT_ID, userId, [API])).toBe("access_denied");

		db.query("UPDATE resource_roles SET role = 'writer'").run();
		expect(access(CLIENT_ID, userId, [API])).toEqual({ [API]: "writer" });
	});
});

describe("authorize", () => {
	test("an unlisted client is refused before sign-in", async () => {
		seedApp();
		seedResource();
		const res = await authorizeGet(authorizeUrl(API));
		expect(res.status).toBe(302);
		const location = new URL(res.headers.get("Location") ?? "");
		expect(location.origin + location.pathname).toBe(REDIRECT_URI);
		expect(location.searchParams.get("error")).toBe("invalid_target");
	});

	test("a listed client proceeds to sign-in", async () => {
		seedApp();
		allowClient(seedResource());
		const res = await authorizeGet(authorizeUrl(API));
		expect(res.headers.get("Location")).toStartWith("/login");
	});

	test("a signed-in user without a required role is denied", async () => {
		seedApp();
		const id = seedResource({ assignment: true });
		allowClient(id);
		const userId = createUser({ username: "kieran" });
		const cookie = createSession(userId);
		const req = authorizeUrl(API);
		const res = await authorizeGet(
			new Request(req.url, {
				headers: { Cookie: `indiko_session=${cookie}` },
			}),
		);
		const location = new URL(res.headers.get("Location") ?? "");
		expect(location.searchParams.get("error")).toBe("access_denied");
	});

	test("consent POST re-checks a tampered resource field", async () => {
		seedApp();
		seedResource();
		const userId = createUser({ username: "kieran" });
		const cookie = createSession(userId);
		const csrf = csrfTokenFor(cookie);
		const res = await authorizePost(
			new Request("http://localhost/auth/authorize", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Cookie: `indiko_session=${cookie}; indiko_csrf=${csrf}`,
				},
				body: new URLSearchParams({
					action: "approve",
					client_id: CLIENT_ID,
					redirect_uri: REDIRECT_URI,
					state: "s",
					code_challenge: "c",
					scope: "profile",
					resource: API,
					csrf_token: csrf,
				}).toString(),
			}),
		);
		const location = new URL(res.headers.get("Location") ?? "");
		expect(location.searchParams.get("error")).toBe("invalid_target");
		const codes = db.query("SELECT COUNT(*) AS n FROM authcodes").get() as {
			n: number;
		};
		expect(codes.n).toBe(0);
	});
});

describe("device authorization", () => {
	test("an unlisted client gets invalid_target", async () => {
		seedApp();
		seedResource();
		const res = await deviceAuthorization(
			new Request("http://localhost/auth/device", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					client_id: CLIENT_ID,
					scope: "profile",
					resource: API,
				}).toString(),
			}),
		);
		expect(res.status).toBe(400);
		expect(((await res.json()) as { error: string }).error).toBe(
			"invalid_target",
		);
	});
});

describe("introspection", () => {
	test("reports the live role for a single registered audience", async () => {
		const userId = createUser({});
		const id = seedResource();
		allowClient(id);
		assign(id, userId, "reader");
		const { access } = seedToken(userId, API);

		const body = (await (await introspect(access)).json()) as Record<
			string,
			unknown
		>;
		expect(body.active).toBe(true);
		expect(body.aud).toBe(API);
		expect(body.role).toBe("reader");

		db.query("UPDATE resource_roles SET role = 'admin'").run();
		const after = (await (await introspect(access)).json()) as Record<
			string,
			unknown
		>;
		expect(after.role).toBe("admin");
	});

	test("reports roles by audience when a token has several", async () => {
		const userId = createUser({});
		const first = seedResource();
		const second = seedResource({ identifier: OTHER_API });
		allowClient(first);
		allowClient(second);
		assign(first, userId, "reader");
		assign(second, userId, "writer");
		const { access } = seedToken(userId, `${API} ${OTHER_API}`);

		const body = (await (await introspect(access)).json()) as Record<
			string,
			unknown
		>;
		expect(body.role).toBeUndefined();
		expect(body.roles).toEqual({ [API]: "reader", [OTHER_API]: "writer" });
	});

	test("a client dropped from the allowlist makes its tokens inactive", async () => {
		const userId = createUser({});
		const id = seedResource();
		allowClient(id);
		const { access } = seedToken(userId, API);
		const caller = seedToken(userId, null).access;

		db.query("DELETE FROM resource_clients").run();
		const res = await tokenIntrospect(
			new Request("http://localhost/auth/token/introspect", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: `Bearer ${caller}`,
				},
				body: new URLSearchParams({ token: access }).toString(),
			}),
		);
		expect(await res.json()).toEqual({ active: false });
	});

	test("an unregistered audience introspects as before, with no role", async () => {
		const userId = createUser({});
		const { access } = seedToken(userId, API);
		const body = (await (await introspect(access)).json()) as Record<
			string,
			unknown
		>;
		expect(body.active).toBe(true);
		expect(body.aud).toBe(API);
		expect(body.role).toBeUndefined();
	});
});

describe("refresh", () => {
	test("a grant the registry no longer allows cannot be renewed", async () => {
		seedApp();
		const userId = createUser({});
		const id = seedResource();
		allowClient(id);
		const { refresh } = seedToken(userId, API);
		db.query("DELETE FROM resource_clients").run();

		const res = await token(
			new Request("http://localhost/auth/token", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					grant_type: "refresh_token",
					refresh_token: refresh,
					client_id: CLIENT_ID,
				}).toString(),
			}),
		);
		expect(res.status).toBe(400);
		expect(((await res.json()) as { error: string }).error).toBe(
			"invalid_grant",
		);
	});
});

describe("admin API", () => {
	function admin(): string {
		return createSession(createUser({ username: "root", tier: "admin" }));
	}

	test("non-admins are refused", async () => {
		const cookie = createSession(createUser({}));
		const res = await createResource(
			adminReq(cookie, "POST", { identifier: API, name: "API" }),
		);
		expect(res.status).toBe(403);
	});

	test("create normalizes the identifier and rejects duplicates", async () => {
		const cookie = admin();
		const res = await createResource(
			adminReq(cookie, "POST", {
				identifier: `${API}/`,
				name: "API",
				availableRoles: ["admin", "reader"],
				defaultRole: "reader",
			}),
		);
		expect(res.status).toBe(201);
		const { resource } = (await res.json()) as {
			resource: { identifier: string; restrictClients: boolean };
		};
		expect(resource.identifier).toBe(API);
		expect(resource.restrictClients).toBe(true);

		const dup = await createResource(
			adminReq(cookie, "POST", { identifier: API, name: "again" }),
		);
		expect(dup.status).toBe(409);
	});

	test("a default role outside the role list is refused", async () => {
		const res = await createResource(
			adminReq(admin(), "POST", {
				identifier: API,
				name: "API",
				availableRoles: ["reader"],
				defaultRole: "admin",
			}),
		);
		expect(res.status).toBe(400);
	});

	test("clients and roles are validated against the resource", async () => {
		const cookie = admin();
		const id = String(seedResource({ roles: ["admin", "reader"] }));
		createUser({ username: "kieran" });
		const base = `http://localhost/api/admin/resources/${id}`;

		const badRole = await setResourceUserRole(
			adminReq(cookie, "PUT", { role: "owner" }, `${base}/users/kieran`),
			id,
			"kieran",
		);
		expect(badRole.status).toBe(400);

		const okRole = await setResourceUserRole(
			adminReq(cookie, "PUT", { role: "reader" }, `${base}/users/kieran`),
			id,
			"kieran",
		);
		expect(okRole.status).toBe(200);

		const okClient = await setResourceClient(
			adminReq(
				cookie,
				"PUT",
				{ clientId: "https://CLIENT.example", allowedRoles: ["reader"] },
				`${base}/clients`,
			),
			id,
		);
		expect(((await okClient.json()) as { clientId: string }).clientId).toBe(
			CLIENT_ID,
		);

		const removed = await removeResourceClient(
			adminReq(
				cookie,
				"DELETE",
				undefined,
				`${base}/clients?client_id=${encodeURIComponent(CLIENT_ID)}`,
			),
			id,
		);
		expect(removed.status).toBe(200);
	});

	test("deleting a resource revokes tokens bound to it, and only those", async () => {
		const cookie = admin();
		const userId = createUser({});
		const id = seedResource();
		seedToken(userId, API);
		seedToken(userId, `${OTHER_API} ${API}`);
		seedToken(userId, OTHER_API);
		seedToken(userId, `${API}/v2`);

		const res = await deleteResource(
			adminReq(cookie, "DELETE", undefined, `http://localhost/x/${id}`),
			String(id),
		);
		expect(res.status).toBe(200);

		const rows = db
			.query("SELECT resource, revoked FROM tokens ORDER BY id")
			.all() as { resource: string; revoked: number }[];
		expect(rows.map((r) => r.revoked)).toEqual([1, 1, 0, 0]);
	});
});

describe("home resource (an app's own roles)", () => {
	const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

	function homeApp(opts: Parameters<typeof seedResource>[0] = {}): number {
		seedApp();
		const id = seedResource({ identifier: "urn:indiko:app:test", ...opts });
		allowClient(id);
		db.query("UPDATE apps SET resource_id = ? WHERE client_id = ?").run(
			id,
			CLIENT_ID,
		);
		return id;
	}

	async function exchangeRole(userId: number): Promise<unknown> {
		const code = `code-${crypto.randomUUID()}`;
		db.query(
			`INSERT INTO authcodes (code, user_id, client_id, redirect_uri, scopes, code_challenge, expires_at, used)
			 VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
		).run(
			code,
			userId,
			CLIENT_ID,
			REDIRECT_URI,
			JSON.stringify(["profile"]),
			CHALLENGE,
			Math.floor(Date.now() / 1000) + 60,
		);
		const res = await token(
			new Request("http://localhost/auth/token", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					grant_type: "authorization_code",
					code,
					client_id: CLIENT_ID,
					redirect_uri: REDIRECT_URI,
					code_verifier: VERIFIER,
				}).toString(),
			}),
		);
		const body = (await res.json()) as { role?: string; error?: string };
		return body.error ?? body.role ?? null;
	}

	test("the token response carries the user's role there, or the default", async () => {
		const id = homeApp({ roles: ["admin", "viewer"], defaultRole: "viewer" });
		const admin = createUser({});
		assign(id, admin, "admin");
		expect(await exchangeRole(admin)).toBe("admin");
		expect(await exchangeRole(createUser({}))).toBe("viewer");
	});

	test("an app without a home resource carries no role", async () => {
		seedApp();
		expect(await exchangeRole(createUser({}))).toBeNull();
	});

	test("role required on the home resource gates sign-in with no resource param", async () => {
		homeApp({ assignment: true });
		const cookie = createSession(createUser({}));
		const url = new URL(authorizeUrl(API).url);
		url.searchParams.delete("resource");
		const res = await authorizeGet(
			new Request(url, { headers: { Cookie: `indiko_session=${cookie}` } }),
		);
		const location = new URL(res.headers.get("Location") ?? "");
		expect(location.searchParams.get("error")).toBe("access_denied");
	});

	test("introspection reports only audience roles, never the home role", async () => {
		const id = homeApp({ defaultRole: "viewer" });
		const userId = createUser({});
		assign(id, userId, "admin");
		const unscoped = seedToken(userId, null).access;
		const scoped = seedToken(userId, API).access;
		const plain = (await (await introspect(unscoped)).json()) as Record<
			string,
			unknown
		>;
		expect(plain.active).toBe(true);
		expect(plain.role).toBeUndefined();
		const withAud = (await (await introspect(scoped)).json()) as Record<
			string,
			unknown
		>;
		expect(withAud.aud).toBe(API);
		expect(withAud.role).toBeUndefined();
	});
});

describe("migration 019 (app roles to resources)", () => {
	test("moves app roles, grants and invite roles onto per-app resources", async () => {
		const { Database } = await import("bun:sqlite");
		const { getMigrations, migrate } = await import("bun-sqlite-migrations");
		const migrations = getMigrations("src/migrations");
		const old = new Database(":memory:");
		old.run("PRAGMA foreign_keys = ON;");
		migrate(old, migrations, 18);
		old.run(
			"INSERT INTO users (id, username, name) VALUES (1,'kieran','K'),(2,'alice','A')",
		);
		old.run(`INSERT INTO apps (id, client_id, redirect_uris, name, is_preregistered, available_roles, default_role) VALUES
			(1,'ikc_abc','[]','Grafana',1,'["admin","viewer"]','viewer'),
			(2,'https://blog.example/','[]','Blog',0,NULL,NULL),
			(3,'https://plain.example/','[]','Plain',0,NULL,NULL)`);
		old.run(`INSERT INTO permissions (user_id, client_id, scopes, role) VALUES
			(1,'ikc_abc','[]','admin'),(2,'ikc_abc','[]','viewer'),(1,'https://blog.example/','[]','editor')`);
		old.run(
			"INSERT INTO invites (id, code, max_uses, created_by) VALUES (1,'inv',1,1)",
		);
		old.run(
			"INSERT INTO invite_roles (invite_id, app_id, role) VALUES (1,1,'admin')",
		);

		migrate(old, migrations);

		expect(
			old
				.query(
					"SELECT r.identifier, r.default_role FROM apps a LEFT JOIN resources r ON r.id = a.resource_id ORDER BY a.id",
				)
				.all(),
		).toEqual([
			{ identifier: "urn:indiko:app:ikc_abc", default_role: "viewer" },
			{ identifier: "https://blog.example", default_role: null },
			{ identifier: null, default_role: null },
		]);
		expect(
			old
				.query(
					"SELECT r.identifier, rr.user_id, rr.role FROM resource_roles rr JOIN resources r ON r.id = rr.resource_id ORDER BY rr.role",
				)
				.all(),
		).toEqual([
			{ identifier: "urn:indiko:app:ikc_abc", user_id: 1, role: "admin" },
			{ identifier: "https://blog.example", user_id: 1, role: "editor" },
		]);
		expect(
			old.query("SELECT COUNT(*) AS n FROM resource_clients").get(),
		).toEqual({ n: 2 });
		expect(
			old.query("SELECT invite_id, role FROM invite_resource_roles").all(),
		).toEqual([{ invite_id: 1, role: "admin" }]);
	});
});
