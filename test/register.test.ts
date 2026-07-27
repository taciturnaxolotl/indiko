import { beforeEach, describe, expect, test } from "bun:test";
import { hashSecret } from "../src/lib/secrets";
import { registerClient } from "../src/routes/oauth/register";
import { db } from "./helpers/db";

function registerReq(body: unknown): Request {
	return new Request("http://localhost/oauth/register", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
}

beforeEach(() => {
	db.query("DELETE FROM apps").run();
});

describe("POST /oauth/register (RFC 7591)", () => {
	test("registers a client and returns id + secret once", async () => {
		const res = await registerClient(
			registerReq({
				redirect_uris: ["https://myapp.example.com/callback"],
				client_name: "My App",
			}),
		);
		expect(res.status).toBe(201);

		const body = await res.json();
		expect(body.client_id).toStartWith("ikc_");
		expect(body.client_secret).toStartWith("iks_");
		expect(body.token_endpoint_auth_method).toBe("client_secret_post");
		expect(body.redirect_uris).toEqual(["https://myapp.example.com/callback"]);
		expect(body.client_name).toBe("My App");
		expect(body.client_id_issued_at).toBeNumber();

		// Secret stored hashed, not plaintext
		const row = db
			.query(
				"SELECT client_id, client_secret_hash, is_preregistered, redirect_uris FROM apps WHERE client_id = ?",
			)
			.get(body.client_id) as {
			client_id: string;
			client_secret_hash: string;
			is_preregistered: number;
			redirect_uris: string;
		};
		expect(row.is_preregistered).toBe(1);
		expect(row.client_secret_hash).toBe(hashSecret(body.client_secret));
		expect(row.client_secret_hash).not.toBe(body.client_secret);
	});

	test("rejects missing redirect_uris", async () => {
		const res = await registerClient(registerReq({ client_name: "x" }));
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_redirect_uri");
	});

	test("rejects empty redirect_uris array", async () => {
		const res = await registerClient(registerReq({ redirect_uris: [] }));
		expect(res.status).toBe(400);
	});

	test("rejects a malformed redirect_uri", async () => {
		const res = await registerClient(
			registerReq({ redirect_uris: ["not a url"] }),
		);
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_redirect_uri");
	});

	test("rejects non-array redirect_uris", async () => {
		const res = await registerClient(
			registerReq({ redirect_uris: "https://x.com/cb" }),
		);
		expect(res.status).toBe(400);
	});

	test("no-store cache header", async () => {
		const res = await registerClient(
			registerReq({ redirect_uris: ["https://x.com/cb"] }),
		);
		expect(res.headers.get("Cache-Control")).toBe("no-store");
	});
});
