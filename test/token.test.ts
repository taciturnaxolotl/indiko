import { beforeEach, describe, expect, test } from "bun:test";
import { token } from "../src/routes/oauth/token";
import { createUser, db } from "./helpers/db";

const CLIENT_ID = "https://client.example/";
const REDIRECT_URI = "https://client.example/callback";
// RFC 7636 appendix B vector
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

function tokenReq(body: Record<string, string>): Request {
	return new Request("http://localhost/auth/token", {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams(body).toString(),
	});
}

function seedApp() {
	db.query(
		"INSERT INTO apps (client_id, redirect_uris, name, is_preregistered) VALUES (?, ?, ?, 0)",
	).run(CLIENT_ID, JSON.stringify([REDIRECT_URI]), "Test Client");
}

function seedAuthCode(
	userId: number,
	overrides: {
		code?: string;
		expiresAt?: number;
		used?: number;
		scopes?: string[];
	} = {},
): string {
	const code = overrides.code ?? `code-${crypto.randomUUID()}`;
	const expiresAt = overrides.expiresAt ?? Math.floor(Date.now() / 1000) + 60;

	db.query(
		`INSERT INTO authcodes (code, user_id, client_id, redirect_uri, scopes, code_challenge, expires_at, used)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
	).run(
		code,
		userId,
		CLIENT_ID,
		REDIRECT_URI,
		JSON.stringify(overrides.scopes ?? ["profile"]),
		CHALLENGE,
		expiresAt,
		overrides.used ?? 0,
	);

	return code;
}

function exchangeBody(code: string, extra: Record<string, string> = {}) {
	return {
		grant_type: "authorization_code",
		code,
		client_id: CLIENT_ID,
		redirect_uri: REDIRECT_URI,
		code_verifier: VERIFIER,
		...extra,
	};
}

beforeEach(() => {
	db.query("DELETE FROM tokens").run();
	db.query("DELETE FROM authcodes").run();
	db.query("DELETE FROM apps").run();
	db.query("DELETE FROM sessions").run();
	db.query("DELETE FROM users").run();
});

describe("token endpoint: authorization_code grant", () => {
	test("rejects unsupported grant_type", async () => {
		const res = await token(tokenReq({ grant_type: "client_credentials" }));
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("unsupported_grant_type");
	});

	test("rejects missing code_verifier (PKCE required)", async () => {
		const userId = createUser({});
		seedApp();
		const code = seedAuthCode(userId);

		const body = exchangeBody(code);
		delete (body as Record<string, string>).code_verifier;
		const res = await token(tokenReq(body));
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_request");
	});

	test("rejects unknown code", async () => {
		seedApp();
		const res = await token(tokenReq(exchangeBody("no-such-code")));
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_grant");
	});

	test("rejects already-used code", async () => {
		const userId = createUser({});
		seedApp();
		const code = seedAuthCode(userId, { used: 1 });

		const res = await token(tokenReq(exchangeBody(code)));
		expect(res.status).toBe(400);
		expect((await res.json()).error_description).toContain("already used");
	});

	test("rejects expired code", async () => {
		const userId = createUser({});
		seedApp();
		const code = seedAuthCode(userId, {
			expiresAt: Math.floor(Date.now() / 1000) - 5,
		});

		const res = await token(tokenReq(exchangeBody(code)));
		expect(res.status).toBe(400);
		expect((await res.json()).error_description).toContain("expired");
	});

	test("rejects redirect_uri mismatch", async () => {
		const userId = createUser({});
		seedApp();
		const code = seedAuthCode(userId);

		const res = await token(
			tokenReq(exchangeBody(code, { redirect_uri: "https://evil.example/cb" })),
		);
		expect(res.status).toBe(400);
		expect((await res.json()).error_description).toContain("redirect_uri");
	});

	test("rejects wrong code_verifier", async () => {
		const userId = createUser({});
		seedApp();
		const code = seedAuthCode(userId);

		const res = await token(
			tokenReq(exchangeBody(code, { code_verifier: "wrong-verifier" })),
		);
		expect(res.status).toBe(400);
		expect((await res.json()).error_description).toContain("code_verifier");
	});

	test("happy path: issues access + refresh tokens, marks code used", async () => {
		const userId = createUser({ username: "kieran" });
		seedApp();
		const code = seedAuthCode(userId, { scopes: ["profile"] });

		const res = await token(tokenReq(exchangeBody(code)));
		expect(res.status).toBe(200);
		expect(res.headers.get("Cache-Control")).toBe("no-store");

		const body = await res.json();
		expect(body.token_type).toBe("Bearer");
		expect(body.access_token).toBeString();
		expect(body.refresh_token).toBeString();
		expect(body.scope).toBe("profile");
		expect(body.me).toContain("/u/kieran");
		expect(body.profile.name).toBeString();

		const used = db
			.query("SELECT used FROM authcodes WHERE code = ?")
			.get(code) as { used: number };
		expect(used.used).toBe(1);

		const stored = db
			.query("SELECT user_id, client_id, scope FROM tokens WHERE token = ?")
			.get(body.access_token) as {
			user_id: number;
			client_id: string;
			scope: string;
		};
		expect(stored.user_id).toBe(userId);
		expect(stored.client_id).toBe(CLIENT_ID);
	});

	test("second exchange of same code fails (single use)", async () => {
		const userId = createUser({});
		seedApp();
		const code = seedAuthCode(userId);

		const first = await token(tokenReq(exchangeBody(code)));
		expect(first.status).toBe(200);

		const second = await token(tokenReq(exchangeBody(code)));
		expect(second.status).toBe(400);
	});
});

describe("token endpoint: refresh_token grant", () => {
	async function issueTokens(userId: number) {
		seedApp();
		const code = seedAuthCode(userId);
		const res = await token(tokenReq(exchangeBody(code)));
		return (await res.json()) as {
			access_token: string;
			refresh_token: string;
		};
	}

	test("rotates access + refresh tokens", async () => {
		const userId = createUser({});
		const issued = await issueTokens(userId);

		const res = await token(
			tokenReq({
				grant_type: "refresh_token",
				refresh_token: issued.refresh_token,
				client_id: CLIENT_ID,
			}),
		);
		expect(res.status).toBe(200);

		const body = await res.json();
		expect(body.access_token).toBeString();
		expect(body.access_token).not.toBe(issued.access_token);
		expect(body.refresh_token).toBeString();
		expect(body.refresh_token).not.toBe(issued.refresh_token);
	});

	test("rejects unknown refresh token", async () => {
		const res = await token(
			tokenReq({
				grant_type: "refresh_token",
				refresh_token: "nope",
				client_id: CLIENT_ID,
			}),
		);
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_grant");
	});

	test("rejects client_id mismatch", async () => {
		const userId = createUser({});
		const issued = await issueTokens(userId);

		const res = await token(
			tokenReq({
				grant_type: "refresh_token",
				refresh_token: issued.refresh_token,
				client_id: "https://other.example/",
			}),
		);
		expect(res.status).toBe(400);
		expect((await res.json()).error_description).toContain("client_id");
	});
});
