import { beforeEach, describe, expect, test } from "bun:test";
import { authorizeGet, authorizePost } from "../src/routes/oauth/authorize";
import { createSession, createUser, db } from "./helpers/db";

const CLIENT_ID = "https://client.example/";
const REDIRECT_URI = "https://client.example/callback";
const ORIGIN = process.env.ORIGIN || "http://localhost:3000";

function seedApp() {
	db.query(
		"INSERT INTO apps (client_id, redirect_uris, name, is_preregistered) VALUES (?, ?, ?, 0)",
	).run(CLIENT_ID, JSON.stringify([REDIRECT_URI]), "Test Client");
}

function authorizeUrl(params: Record<string, string>): string {
	const url = new URL("http://localhost/auth/authorize");
	for (const [k, v] of Object.entries(params)) {
		url.searchParams.set(k, v);
	}
	return url.toString();
}

function validParams(overrides: Record<string, string> = {}) {
	return {
		response_type: "code",
		client_id: CLIENT_ID,
		redirect_uri: REDIRECT_URI,
		state: "test-state",
		code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		code_challenge_method: "S256",
		scope: "profile",
		...overrides,
	};
}

function consentPost(body: Record<string, string>, cookie: string): Request {
	const csrfToken = "test-csrf";
	return new Request("http://localhost/auth/authorize", {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			Cookie: `indiko_session=${cookie}; indiko_csrf=${csrfToken}`,
		},
		body: new URLSearchParams({ ...body, csrf_token: csrfToken }).toString(),
	});
}

beforeEach(() => {
	db.query("DELETE FROM authcodes").run();
	db.query("DELETE FROM permissions").run();
	db.query("DELETE FROM apps").run();
	db.query("DELETE FROM sessions").run();
	db.query("DELETE FROM users").run();
});

describe("authorize: iss on error responses (RFC 9207)", () => {
	test("unsupported response_type redirect includes iss", async () => {
		seedApp();
		const res = await authorizeGet(
			new Request(authorizeUrl(validParams({ response_type: "token" }))),
		);
		expect(res.status).toBe(302);
		const location = res.headers.get("Location") ?? "";
		const url = new URL(location);
		expect(url.searchParams.get("error")).toBe("unsupported_response_type");
		expect(url.searchParams.get("iss")).toBe(ORIGIN);
	});

	test("missing state redirect includes iss", async () => {
		seedApp();
		const params = validParams();
		delete (params as Record<string, string>).state;
		const res = await authorizeGet(new Request(authorizeUrl(params)));
		expect(res.status).toBe(302);
		const url = new URL(res.headers.get("Location") ?? "");
		expect(url.searchParams.get("error")).toBe("invalid_request");
		expect(url.searchParams.get("iss")).toBe(ORIGIN);
	});

	test("missing code_challenge redirect includes iss", async () => {
		seedApp();
		const params = validParams();
		delete (params as Record<string, string>).code_challenge;
		const res = await authorizeGet(new Request(authorizeUrl(params)));
		expect(res.status).toBe(302);
		const url = new URL(res.headers.get("Location") ?? "");
		expect(url.searchParams.get("iss")).toBe(ORIGIN);
	});

	test("user deny (access_denied) redirect includes iss", async () => {
		seedApp();
		const userId = createUser({ username: "kieran" });
		const cookie = createSession(userId);

		const res = await authorizePost(
			consentPost(
				{
					action: "deny",
					client_id: CLIENT_ID,
					redirect_uri: REDIRECT_URI,
					state: "test-state",
					code_challenge: "challenge",
					scope: "profile",
				},
				cookie,
			),
		);

		expect(res.status).toBe(302);
		const url = new URL(res.headers.get("Location") ?? "");
		expect(url.searchParams.get("error")).toBe("access_denied");
		expect(url.searchParams.get("iss")).toBe(ORIGIN);
	});

	test("success path still includes iss", async () => {
		seedApp();
		const userId = createUser({ username: "kieran" });
		const cookie = createSession(userId);

		// Pre-grant permission so it auto-approves
		db.query(
			"INSERT INTO permissions (user_id, client_id, scopes) VALUES (?, ?, ?)",
		).run(userId, CLIENT_ID, JSON.stringify(["profile"]));

		const res = await authorizeGet(
			new Request(authorizeUrl(validParams()), {
				headers: { Cookie: `indiko_session=${cookie}` },
			}),
		);

		expect(res.status).toBe(302);
		const url = new URL(res.headers.get("Location") ?? "");
		expect(url.searchParams.get("code")).toBeTruthy();
		expect(url.searchParams.get("iss")).toBe(ORIGIN);
	});
});

describe("authorize: auto-approval and resource indicators (RFC 8707)", () => {
	function grant(userId: number, scopes: string[], resources: string | null) {
		db.query(
			"INSERT INTO permissions (user_id, client_id, scopes, resources) VALUES (?, ?, ?, ?)",
		).run(userId, CLIENT_ID, JSON.stringify(scopes), resources);
	}

	async function authorize(cookie: string, params: Record<string, string>) {
		return authorizeGet(
			new Request(authorizeUrl(validParams(params)), {
				headers: { Cookie: `indiko_session=${cookie}` },
			}),
		);
	}

	test("a resource the user never approved re-prompts instead of auto-approving", async () => {
		seedApp();
		const userId = createUser({ username: "kieran" });
		const cookie = createSession(userId);
		grant(userId, ["profile"], null);

		const res = await authorize(cookie, {
			resource: "https://api.example.com",
		});

		// Consent screen, not a redirect with a code
		expect(res.status).toBe(200);
		expect(await res.text()).toContain("api.example.com");
	});

	test("an already-approved resource still auto-approves", async () => {
		seedApp();
		const userId = createUser({ username: "kieran" });
		const cookie = createSession(userId);
		grant(userId, ["profile"], "https://api.example.com");

		const res = await authorize(cookie, {
			resource: "https://api.example.com/",
		});

		expect(res.status).toBe(302);
		const url = new URL(res.headers.get("Location") ?? "");
		expect(url.searchParams.get("code")).toBeTruthy();
	});

	test("consent records the approved resource so the next request is silent", async () => {
		seedApp();
		const userId = createUser({ username: "kieran" });
		const cookie = createSession(userId);

		const consent = await authorizePost(
			consentPost(
				{
					client_id: CLIENT_ID,
					redirect_uri: REDIRECT_URI,
					state: "test-state",
					code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
					scope: "profile",
					resource: "https://api.example.com",
					action: "approve",
				},
				cookie,
			),
		);
		expect(consent.status).toBe(302);

		const stored = db
			.query("SELECT resources FROM permissions WHERE user_id = ?")
			.get(userId) as { resources: string | null };
		expect(stored.resources).toBe("https://api.example.com");

		const res = await authorize(cookie, {
			resource: "https://api.example.com",
		});
		expect(res.status).toBe(302);
	});
});
