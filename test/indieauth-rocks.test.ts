// Behaviors from the indieauth.rocks server test suite, keyed by test id so a
// failing case points straight at the published pass criterion.
import {
	afterAll,
	beforeAll,
	beforeEach,
	describe,
	expect,
	mock,
	test,
} from "bun:test";

const actualFetch = await import("../src/lib/ssrf-safe-fetch");

// Metadata documents the fake network will serve, keyed by URL.
const served = new Map<
	string,
	{ status: number; body: string; type: string }
>();

mock.module("../src/lib/ssrf-safe-fetch", () => ({
	...actualFetch,
	safeFetch: async (url: string) => {
		const hit = served.get(url);
		if (!hit) return { success: false, error: "no such host (test)" };
		return {
			success: true,
			data: new Response(hit.body, {
				status: hit.status,
				headers: { "content-type": hit.type },
			}),
		};
	},
}));

const { authorizeGet, authorizePost } = await import(
	"../src/routes/oauth/authorize"
);
const { token, tokenIntrospect, tokenRevoke } = await import(
	"../src/routes/oauth/token"
);
const { userinfo } = await import("../src/routes/oauth/userinfo");
const { corsPreflight, methodNotAllowed, withCors } = await import(
	"../src/lib/oauth/errors"
);
const { hashSecret } = await import("../src/lib/secrets");
const { csrfTokenFor } = await import("../src/lib/session");
const { createSession, createUser, db } = await import("./helpers/db");

afterAll(() => {
	mock.module("../src/lib/ssrf-safe-fetch", () => actualFetch);
});

const ORIGIN = process.env.ORIGIN || "http://localhost:3000";
const CLIENT_ID = "https://client-app.net/";
const REDIRECT_URI = "https://client-app.net/callback";
const OTHER_REDIRECT = "https://other-host.net/cb";
// RFC 7636 appendix B vector
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

function serveMetadata(clientId: string, doc: Record<string, unknown>) {
	served.set(clientId, {
		status: 200,
		type: "application/json",
		body: JSON.stringify({ client_id: clientId, ...doc }),
	});
}

function seedApp(redirects: string[] = [REDIRECT_URI], clientId = CLIENT_ID) {
	db.query(
		"INSERT INTO apps (client_id, redirect_uris, name, is_preregistered) VALUES (?, ?, ?, 0)",
	).run(clientId, JSON.stringify(redirects), "Test Client");
}

function authorizeUrl(params: Array<[string, string]>): string {
	const url = new URL("http://localhost/auth/authorize");
	for (const [k, v] of params) url.searchParams.append(k, v);
	return url.toString();
}

function validParams(
	overrides: Record<string, string | null> = {},
): Array<[string, string]> {
	const base: Record<string, string | null> = {
		response_type: "code",
		client_id: CLIENT_ID,
		redirect_uri: REDIRECT_URI,
		state: "st@te+with/odd chars=&?",
		code_challenge: CHALLENGE,
		code_challenge_method: "S256",
		scope: "profile",
		...overrides,
	};
	return Object.entries(base).filter(
		(e): e is [string, string] => e[1] !== null,
	);
}

function get(
	params: Array<[string, string]>,
	cookie?: string,
): Promise<Response> {
	return authorizeGet(
		new Request(authorizeUrl(params), {
			headers: cookie ? { Cookie: `indiko_session=${cookie}` } : {},
		}),
	);
}

function consentPost(body: Record<string, string>, cookie: string): Request {
	// CSRF tokens are bound to the session: the server recomputes the
	// expected value from the session cookie, so derive it the same way.
	const csrf = csrfTokenFor(cookie);
	return new Request("http://localhost/auth/authorize", {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			Cookie: `indiko_session=${cookie}; indiko_csrf=${csrf}`,
		},
		body: new URLSearchParams({ ...body, csrf_token: csrf }).toString(),
	});
}

function tokenReq(
	body: Record<string, string>,
	headers: Record<string, string> = {},
): Request {
	return new Request("http://localhost/auth/token", {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			...headers,
		},
		body: new URLSearchParams(body).toString(),
	});
}

function seedAuthCode(
	userId: number,
	overrides: { scopes?: string[]; me?: string | null } = {},
): string {
	const code = `code-${crypto.randomUUID()}`;
	db.query(
		`INSERT INTO authcodes (code, user_id, client_id, redirect_uri, scopes, code_challenge, expires_at, used, me)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`,
	).run(
		code,
		userId,
		CLIENT_ID,
		REDIRECT_URI,
		JSON.stringify(overrides.scopes ?? ["profile"]),
		CHALLENGE,
		Math.floor(Date.now() / 1000) + 60,
		overrides.me ?? null,
	);
	return code;
}

function exchange(code: string, extra: Record<string, string> = {}) {
	return token(
		tokenReq({
			grant_type: "authorization_code",
			code,
			client_id: CLIENT_ID,
			redirect_uri: REDIRECT_URI,
			code_verifier: VERIFIER,
			...extra,
		}),
	);
}

function location(res: Response): URL {
	return new URL(res.headers.get("Location") ?? "");
}

beforeAll(() => {
	process.env.NODE_ENV = "test";
});

beforeEach(() => {
	served.clear();
	db.query("DELETE FROM tokens").run();
	db.query("DELETE FROM authcodes").run();
	db.query("DELETE FROM permissions").run();
	db.query("DELETE FROM apps").run();
	db.query("DELETE FROM sessions").run();
	db.query("DELETE FROM users").run();
});

describe("S2xx authorization requests", () => {
	test("S201/S204: state survives byte-for-byte and the redirect keeps its query string", async () => {
		const withQuery = "https://client-app.net/callback?app=1&x=y";
		seedApp([withQuery]);
		const userId = createUser({ username: "kieran" });
		const cookie = createSession(userId);
		db.query(
			"INSERT INTO permissions (user_id, client_id, scopes) VALUES (?, ?, ?)",
		).run(userId, CLIENT_ID, JSON.stringify(["profile"]));

		const res = await get(validParams({ redirect_uri: withQuery }), cookie);
		expect(res.status).toBe(302);
		const url = location(res);
		expect(url.searchParams.get("app")).toBe("1");
		expect(url.searchParams.get("x")).toBe("y");
		expect(url.searchParams.get("code")).toBeTruthy();
		expect(url.searchParams.get("state")).toBe("st@te+with/odd chars=&?");
		expect(url.searchParams.get("iss")).toBe(ORIGIN);
	});

	test("S207: deny redirects with access_denied, state and iss", async () => {
		seedApp();
		const userId = createUser({ username: "kieran" });
		const cookie = createSession(userId);
		const res = await authorizePost(
			consentPost(
				{
					action: "deny",
					client_id: CLIENT_ID,
					redirect_uri: REDIRECT_URI,
					state: "s1",
					code_challenge: CHALLENGE,
				},
				cookie,
			),
		);
		const url = location(res);
		expect(url.searchParams.get("error")).toBe("access_denied");
		expect(url.searchParams.get("state")).toBe("s1");
		expect(url.searchParams.get("iss")).toBe(ORIGIN);
	});

	test("S208: unregistered cross-origin redirect_uri gets an error page, never a redirect", async () => {
		serveMetadata(CLIENT_ID, { redirect_uris: [OTHER_REDIRECT] });
		const res = await get(
			validParams({ redirect_uri: "https://evil-site.net/steal" }),
		);
		expect(res.status).toBe(400);
		expect(res.headers.get("Location")).toBeNull();
		expect(await res.text()).toContain("Unauthorized Redirect URI");
	});

	test("S209: registered cross-origin redirect_uri is accepted (deny lands there)", async () => {
		serveMetadata(CLIENT_ID, { redirect_uris: [OTHER_REDIRECT] });
		const userId = createUser({ username: "kieran" });
		const cookie = createSession(userId);

		const consent = await get(
			validParams({ redirect_uri: OTHER_REDIRECT }),
			cookie,
		);
		expect(consent.status).toBe(200);

		const res = await authorizePost(
			consentPost(
				{
					action: "deny",
					client_id: CLIENT_ID,
					redirect_uri: OTHER_REDIRECT,
					state: "s",
					code_challenge: CHALLENGE,
				},
				cookie,
			),
		);
		expect(res.status).toBe(302);
		expect(location(res).origin).toBe("https://other-host.net");
		expect(location(res).searchParams.get("error")).toBe("access_denied");
	});

	test("S210: a longer URL that starts with a registered redirect is not a match", async () => {
		serveMetadata(CLIENT_ID, { redirect_uris: [OTHER_REDIRECT] });
		const res = await get(
			validParams({ redirect_uri: `${OTHER_REDIRECT}/more` }),
		);
		expect(res.status).toBe(400);
		expect(res.headers.get("Location")).toBeNull();
	});

	test("S211: credentials in the authority do not make a foreign host look local", async () => {
		seedApp([]);
		const res = await get(
			validParams({
				redirect_uri: "https://client-app.net@evil-site.net/callback",
			}),
		);
		expect(res.status).toBe(400);
		expect(res.headers.get("Location")).toBeNull();
	});

	test("S212: metadata whose client_id does not match its URL is ignored", async () => {
		served.set(CLIENT_ID, {
			status: 200,
			type: "application/json",
			body: JSON.stringify({
				client_id: "https://someone-else.net/",
				redirect_uris: [OTHER_REDIRECT],
			}),
		});
		const res = await get(validParams({ redirect_uri: OTHER_REDIRECT }));
		expect(res.status).toBe(400);
		expect(res.headers.get("Location")).toBeNull();
	});

	test("S213: a repeated redirect_uri is refused outright", async () => {
		seedApp();
		const params = validParams();
		params.push(["redirect_uri", "https://evil-site.net/cb"]);
		const res = await get(params);
		expect(res.status).toBe(400);
		expect(res.headers.get("Location")).toBeNull();
		expect(await res.text()).toContain("repeats the redirect_uri");
	});

	test("S214: no client_id plus an unregistered redirect_uri is an error, not a redirect", async () => {
		const res = await get(
			validParams({ client_id: null, redirect_uri: "https://evil-site.net/" }),
		);
		expect(res.status).toBe(400);
		expect(res.headers.get("Location")).toBeNull();
	});

	test("S215: missing code_challenge is refused", async () => {
		seedApp();
		const res = await get(validParams({ code_challenge: null }));
		expect(res.status).toBe(302);
		expect(location(res).searchParams.get("error")).toBe("invalid_request");
		expect(location(res).searchParams.get("code")).toBeNull();
	});

	test("S216: plain PKCE is refused", async () => {
		seedApp();
		const res = await get(validParams({ code_challenge_method: "plain" }));
		expect(location(res).searchParams.get("error")).toBe("invalid_request");
	});

	test("S217: implicit flow is refused and no token appears in the URL", async () => {
		seedApp();
		const res = await get(validParams({ response_type: "token" }));
		expect(res.status).toBe(302);
		const url = location(res);
		expect(url.searchParams.get("error")).toBe("unsupported_response_type");
		expect(url.href).not.toContain("access_token");
		expect(url.hash).toBe("");
	});

	test("S218: missing state is refused", async () => {
		seedApp();
		const res = await get(validParams({ state: null }));
		expect(location(res).searchParams.get("error")).toBe("invalid_request");
	});

	test("S219: a client_id with a .. segment is refused before URL parsing hides it", async () => {
		seedApp();
		const res = await get(
			validParams({ client_id: "https://client-app.net/app/../" }),
		);
		expect(res.status).toBe(400);
		expect(res.headers.get("Location")).toBeNull();
		expect(await res.text()).toContain("Invalid Client ID");
	});

	test("S220: a me for someone else is not shown on consent and not stored", async () => {
		seedApp();
		const userId = createUser({ username: "kieran" });
		const cookie = createSession(userId);
		db.query(
			"INSERT INTO permissions (user_id, client_id, scopes) VALUES (?, ?, ?)",
		).run(userId, CLIENT_ID, JSON.stringify(["profile"]));

		const res = await get(
			validParams({ me: "https://victim-site.net/" }),
			cookie,
		);
		expect(res.status).toBe(302);
		const stored = db
			.query("SELECT me FROM authcodes WHERE client_id = ?")
			.get(CLIENT_ID) as { me: string | null };
		expect(stored.me).toBeNull();
	});

	test("S220: a me the user owns is honored as a hint", async () => {
		seedApp();
		const userId = createUser({ username: "kieran" });
		const cookie = createSession(userId);
		db.query(
			"INSERT INTO permissions (user_id, client_id, scopes) VALUES (?, ?, ?)",
		).run(userId, CLIENT_ID, JSON.stringify(["profile"]));

		await get(validParams({ me: `${ORIGIN}/u/kieran` }), cookie);
		const stored = db
			.query("SELECT me FROM authcodes WHERE client_id = ?")
			.get(CLIENT_ID) as { me: string | null };
		expect(stored.me).toBe(`${ORIGIN}/u/kieran`);
	});

	test("S221: code_challenge_method without a challenge is refused", async () => {
		seedApp();
		const res = await get(validParams({ code_challenge: null }));
		expect(location(res).searchParams.get("error")).toBe("invalid_request");
	});

	test("S222: a challenge without a method is refused (missing means plain)", async () => {
		seedApp();
		const res = await get(validParams({ code_challenge_method: null }));
		expect(res.status).toBe(302);
		expect(location(res).searchParams.get("error")).toBe("invalid_request");
	});

	test("S206: consent screen shows the client_id, not only a name", async () => {
		seedApp();
		const userId = createUser({ username: "kieran" });
		const cookie = createSession(userId);
		const res = await get(validParams(), cookie);
		expect(res.status).toBe(200);
		expect(await res.text()).toContain(CLIENT_ID);
	});

	test("S902: the signed-out authorization response cannot be framed", async () => {
		seedApp();
		const res = await get(validParams());
		expect(res.status).toBe(302);
		expect(res.headers.get("X-Frame-Options")).toBe("DENY");
		expect(res.headers.get("Content-Security-Policy")).toContain(
			"frame-ancestors 'none'",
		);
	});
});

describe("redirect_uri policy for URL clients", () => {
	test("a client that publishes nothing may redirect anywhere on its own origin", async () => {
		seedApp([]);
		const userId = createUser({ username: "kieran" });
		const cookie = createSession(userId);
		const res = await get(
			validParams({ redirect_uri: "https://client-app.net/other/path" }),
			cookie,
		);
		expect(res.status).toBe(200);
	});

	test("a client that publishes a list is held to it, even on its own origin", async () => {
		serveMetadata(CLIENT_ID, { redirect_uris: [REDIRECT_URI] });
		seedApp([REDIRECT_URI]);
		const res = await get(
			validParams({ redirect_uri: "https://client-app.net/other" }),
		);
		expect(res.status).toBe(400);
	});

	test("metadata is refreshed when the client adds a redirect URI later", async () => {
		seedApp([OTHER_REDIRECT]);
		const added = "https://other-host.net/new";
		serveMetadata(CLIENT_ID, {
			client_name: "Renamed",
			redirect_uris: [OTHER_REDIRECT, added],
		});
		const userId = createUser({ username: "kieran" });
		const cookie = createSession(userId);

		const res = await get(validParams({ redirect_uri: added }), cookie);
		expect(res.status).toBe(200);

		const row = db
			.query("SELECT redirect_uris, name FROM apps WHERE client_id = ?")
			.get(CLIENT_ID) as { redirect_uris: string; name: string };
		expect(JSON.parse(row.redirect_uris)).toEqual([OTHER_REDIRECT, added]);
		expect(row.name).toBe("Renamed");
	});

	test("S205: first sight of a client fetches its metadata and registers it", async () => {
		serveMetadata(CLIENT_ID, {
			client_name: "Rocks",
			redirect_uris: [REDIRECT_URI],
		});
		const userId = createUser({ username: "kieran" });
		const cookie = createSession(userId);
		const res = await get(validParams(), cookie);
		expect(res.status).toBe(200);
		expect(await res.text()).toContain("Rocks");
	});

	test("the consent POST applies the same policy to the hidden redirect_uri", async () => {
		seedApp([OTHER_REDIRECT]);
		const userId = createUser({ username: "kieran" });
		const cookie = createSession(userId);
		const res = await authorizePost(
			consentPost(
				{
					action: "allow",
					client_id: CLIENT_ID,
					redirect_uri: "https://other-host.net/cb/evil",
					state: "s",
					code_challenge: CHALLENGE,
					scope: "profile",
				},
				cookie,
			),
		);
		expect(res.status).toBe(400);
	});
});

describe("S32x scope-less sign-in", () => {
	test("a request with no scope shows an identity-only consent and stores an empty scope set", async () => {
		seedApp();
		const userId = createUser({ username: "kieran" });
		const cookie = createSession(userId);

		const consent = await get(validParams({ scope: null }), cookie);
		expect(consent.status).toBe(200);
		expect(await consent.text()).toContain("wants to know who you are");

		const res = await authorizePost(
			consentPost(
				{
					action: "allow",
					client_id: CLIENT_ID,
					redirect_uri: REDIRECT_URI,
					state: "s",
					code_challenge: CHALLENGE,
				},
				cookie,
			),
		);
		expect(res.status).toBe(302);
		const code = location(res).searchParams.get("code") ?? "";
		const row = db
			.query("SELECT scopes FROM authcodes WHERE code = ?")
			.get(code) as { scopes: string };
		expect(JSON.parse(row.scopes)).toEqual([]);
	});

	test("S320/S321: exchanging a scope-less code returns me and no access_token", async () => {
		seedApp();
		const userId = createUser({ username: "kieran" });
		const code = seedAuthCode(userId, { scopes: [] });

		const res = await exchange(code);
		expect(res.status).toBe(200);
		expect(res.headers.get("Cache-Control")).toContain("no-store");
		const body = (await res.json()) as Record<string, unknown>;
		expect(body.me).toBe(`${ORIGIN}/u/kieran`);
		expect(body.access_token).toBeUndefined();
		expect(body.refresh_token).toBeUndefined();
		const count = db.query("SELECT COUNT(*) AS n FROM tokens").get() as {
			n: number;
		};
		expect(count.n).toBe(0);
	});
});

describe("S3xx code redemption", () => {
	test("S303: replaying a code revokes the tokens it minted", async () => {
		seedApp();
		const userId = createUser({ username: "kieran" });
		const code = seedAuthCode(userId, {
			scopes: ["profile", "offline_access"],
		});

		const first = (await (await exchange(code)).json()) as {
			access_token: string;
			refresh_token: string;
		};
		const before = await userinfo(
			new Request("http://localhost/userinfo", {
				headers: { Authorization: `Bearer ${first.access_token}` },
			}),
		);
		expect(before.status).toBe(200);

		const replay = await exchange(code);
		expect(replay.status).toBe(400);
		expect(((await replay.json()) as { error: string }).error).toBe(
			"invalid_grant",
		);

		const after = await userinfo(
			new Request("http://localhost/userinfo", {
				headers: { Authorization: `Bearer ${first.access_token}` },
			}),
		);
		expect(after.status).toBe(401);

		const refresh = await token(
			tokenReq({
				grant_type: "refresh_token",
				refresh_token: first.refresh_token,
				client_id: CLIENT_ID,
			}),
		);
		expect(refresh.status).toBe(400);
	});

	test("S312: a code presented by another client is refused", async () => {
		seedApp();
		const userId = createUser({ username: "kieran" });
		const code = seedAuthCode(userId);
		const res = await exchange(code, { client_id: "https://other-host.net/" });
		expect(res.status).toBe(400);
	});

	test("S331: missing grant_type is invalid_request, password is unsupported_grant_type", async () => {
		const missing = await token(tokenReq({ code: "x" }));
		expect(missing.status).toBe(400);
		expect(((await missing.json()) as { error: string }).error).toBe(
			"invalid_request",
		);

		const password = await token(
			tokenReq({ grant_type: "password", username: "a", password: "b" }),
		);
		expect(password.status).toBe(400);
		expect(((await password.json()) as { error: string }).error).toBe(
			"unsupported_grant_type",
		);
	});

	test("S332: a malformed client_id is a JSON 400, not a 500", async () => {
		const res = await token(
			tokenReq({
				grant_type: "authorization_code",
				code: "x",
				client_id: "https://",
			}),
		);
		expect(res.status).toBe(400);
		expect(res.headers.get("Content-Type")).toContain("application/json");
		expect(((await res.json()) as { error: string }).error).toBe(
			"invalid_request",
		);
	});

	test("S333/S334: the route helpers refuse GET with JSON and answer preflight", async () => {
		const notAllowed = methodNotAllowed("POST");
		expect(notAllowed.status).toBe(405);
		expect(((await notAllowed.json()) as { error: string }).error).toBe(
			"invalid_request",
		);
		const preflight = corsPreflight();
		expect(preflight.status).toBe(204);
		expect(preflight.headers.get("Access-Control-Allow-Origin")).toBe("*");
		expect(
			preflight.headers.get("Access-Control-Allow-Credentials"),
		).toBeNull();
	});

	test("S906: CORS on token responses is never credentialed", async () => {
		const res = withCors(Response.json({ ok: true }));
		expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
		expect(res.headers.get("Access-Control-Allow-Credentials")).toBeNull();
	});
});

describe("S4xx token responses", () => {
	test("S401-S409: shape of a successful exchange", async () => {
		seedApp();
		const userId = createUser({ username: "kieran" });
		db.query("UPDATE users SET photo = ?, url = ? WHERE id = ?").run(
			"https://img-host.net/k.png",
			"https://kieran-site.net/",
			userId,
		);
		const code = seedAuthCode(userId, { scopes: ["profile"] });
		const res = await exchange(code);
		expect(res.status).toBe(200);
		expect(res.headers.get("Content-Type")).toContain("application/json");
		expect(res.headers.get("Cache-Control")).toContain("no-store");
		const body = (await res.json()) as Record<string, unknown>;
		expect(typeof body.access_token).toBe("string");
		expect((body.access_token as string).length).toBeGreaterThanOrEqual(22);
		expect((body.token_type as string).toLowerCase()).toBe("bearer");
		expect(body.expires_in as number).toBeGreaterThan(0);
		expect(body.scope).toBe("profile");
		expect(body.me).toBe("https://kieran-site.net/");
		const profile = body.profile as Record<string, unknown>;
		expect(typeof profile.name).toBe("string");
		expect(typeof profile.url).toBe("string");
		expect(typeof profile.photo).toBe("string");
		expect(body.iss).toBe(ORIGIN);
	});

	test("S220 at the token endpoint: the returned me is the verified identity", async () => {
		seedApp();
		const userId = createUser({ username: "kieran" });
		// A hint that slipped into the DB somehow is still not returned.
		const code = seedAuthCode(userId, { me: "https://victim-site.net/" });
		const res = await exchange(code);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { me: string };
		expect(body.me).toBe(`${ORIGIN}/u/kieran`);
	});
});

describe("S5xx refresh tokens", () => {
	async function issue(): Promise<{
		access_token: string;
		refresh_token: string;
	}> {
		seedApp();
		const userId = createUser({ username: "kieran" });
		const code = seedAuthCode(userId, {
			scopes: ["profile", "email", "offline_access"],
		});
		return (await (await exchange(code)).json()) as {
			access_token: string;
			refresh_token: string;
		};
	}

	test("S501: refresh returns a new access token, me, and no-store", async () => {
		const first = await issue();
		const res = await token(
			tokenReq({
				grant_type: "refresh_token",
				refresh_token: first.refresh_token,
				client_id: CLIENT_ID,
			}),
		);
		expect(res.status).toBe(200);
		expect(res.headers.get("Cache-Control")).toContain("no-store");
		const body = (await res.json()) as Record<string, unknown>;
		expect(body.access_token).not.toBe(first.access_token);
		expect(body.me).toBe(`${ORIGIN}/u/kieran`);
	});

	test("S503: a refresh cannot add scopes", async () => {
		const first = await issue();
		const res = await token(
			tokenReq({
				grant_type: "refresh_token",
				refresh_token: first.refresh_token,
				client_id: CLIENT_ID,
				scope: "profile email offline_access admin",
			}),
		);
		expect(res.status).toBe(400);
		expect(((await res.json()) as { error: string }).error).toBe(
			"invalid_scope",
		);
	});

	test("a refresh may narrow scopes", async () => {
		const first = await issue();
		const res = await token(
			tokenReq({
				grant_type: "refresh_token",
				refresh_token: first.refresh_token,
				client_id: CLIENT_ID,
				scope: "profile",
			}),
		);
		expect(res.status).toBe(200);
		expect(((await res.json()) as { scope: string }).scope).toBe("profile");
	});
});

describe("S6xx revocation and S7xx userinfo", () => {
	test("S601/S602/S604: revoke returns 200, token stops working, unknown tokens are fine", async () => {
		seedApp();
		const userId = createUser({ username: "kieran" });
		const code = seedAuthCode(userId);
		const { access_token } = (await (await exchange(code)).json()) as {
			access_token: string;
		};

		const revoke = await tokenRevoke(tokenReq({ token: access_token }));
		expect(revoke.status).toBe(200);

		const after = await userinfo(
			new Request("http://localhost/userinfo", {
				headers: { Authorization: `Bearer ${access_token}` },
			}),
		);
		expect(after.status).toBe(401);
		expect(after.headers.get("WWW-Authenticate")).toContain(
			'error="invalid_token"',
		);

		const unknown = await tokenRevoke(tokenReq({ token: "nope" }));
		expect(unknown.status).toBe(200);
	});

	test("S702/S703: userinfo without or with a bad token is 401", async () => {
		const none = userinfo(new Request("http://localhost/userinfo"));
		expect(none.status).toBe(401);
		const bad = userinfo(
			new Request("http://localhost/userinfo", {
				headers: { Authorization: "Bearer made-up" },
			}),
		);
		expect(bad.status).toBe(401);
		expect(bad.headers.get("WWW-Authenticate")).toContain(
			'error="invalid_token"',
		);
	});
});

describe("S8xx introspection", () => {
	async function issued(): Promise<string> {
		seedApp();
		const userId = createUser({ username: "kieran" });
		const code = seedAuthCode(userId);
		return ((await (await exchange(code)).json()) as { access_token: string })
			.access_token;
	}

	function introspect(
		body: Record<string, string>,
		headers: Record<string, string> = {},
	) {
		return tokenIntrospect(
			new Request("http://localhost/auth/token/introspect", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					...headers,
				},
				body: new URLSearchParams(body).toString(),
			}),
		);
	}

	test("S801/S802: unauthenticated introspection is 401 and reveals nothing", async () => {
		const accessToken = await issued();
		const res = await introspect({ token: accessToken });
		expect(res.status).toBe(401);
		const text = await res.text();
		expect(text).not.toContain('"active":true');
		expect(text).not.toContain("/u/kieran");
	});

	test("S803: a live access token authorizes introspection", async () => {
		const accessToken = await issued();
		const res = await introspect(
			{ token: accessToken },
			{ Authorization: `Bearer ${accessToken}` },
		);
		expect(res.status).toBe(200);
		const body = (await res.json()) as Record<string, unknown>;
		expect(body.active).toBe(true);
		expect(body.me).toBe(`${ORIGIN}/u/kieran`);
		expect(body.client_id).toBe(CLIENT_ID);
	});

	test("S804: an authenticated lookup of an unknown token is active:false", async () => {
		const accessToken = await issued();
		const res = await introspect(
			{ token: "made-up" },
			{ Authorization: `Bearer ${accessToken}` },
		);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ active: false });
	});

	test("confidential client credentials authorize introspection", async () => {
		const accessToken = await issued();
		db.query(
			"INSERT INTO apps (client_id, redirect_uris, name, is_preregistered, client_secret_hash) VALUES (?, ?, ?, 1, ?)",
		).run("ikc_rs", "[]", "Resource Server", hashSecret("s3cret"));

		const ok = await introspect({
			token: accessToken,
			client_id: "ikc_rs",
			client_secret: "s3cret",
		});
		expect(ok.status).toBe(200);
		expect(((await ok.json()) as { active: boolean }).active).toBe(true);

		const bad = await introspect({
			token: accessToken,
			client_id: "ikc_rs",
			client_secret: "wrong",
		});
		expect(bad.status).toBe(401);
	});

	test("a revoked token no longer authorizes introspection", async () => {
		const accessToken = await issued();
		await tokenRevoke(tokenReq({ token: accessToken }));
		const res = await introspect(
			{ token: accessToken },
			{ Authorization: `Bearer ${accessToken}` },
		);
		expect(res.status).toBe(401);
	});
});
