import { beforeEach, describe, expect, test } from "bun:test";
import { deviceAuthorization } from "../src/routes/oauth/device";
import { token } from "../src/routes/oauth/token";
import { createUser, db } from "./helpers/db";

const CLIENT_ID = "https://client.example/";
const REDIRECT_URI = "https://client.example/callback";

function deviceReq(body: Record<string, string>): Request {
	return new Request("http://localhost/auth/device", {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams(body).toString(),
	});
}

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

async function requestDeviceCode(
	clientId = CLIENT_ID,
	scope = "profile",
): Promise<{
	device_code: string;
	user_code: string;
	verification_uri: string;
	verification_uri_complete: string;
	expires_in: number;
	interval: number;
}> {
	const res = await deviceAuthorization(
		deviceReq({ client_id: clientId, scope }),
	);
	expect(res.status).toBe(200);
	return (await res.json()) as {
		device_code: string;
		user_code: string;
		verification_uri: string;
		verification_uri_complete: string;
		expires_in: number;
		interval: number;
	};
}

function approveDeviceCode(userCode: string, userId: number) {
	db.query(
		"UPDATE device_codes SET status = 'approved', user_id = ? WHERE user_code = ?",
	).run(userId, userCode);
}

function pollToken(deviceCode: string, clientId = CLIENT_ID) {
	return token(
		tokenReq({
			grant_type: "urn:ietf:params:oauth:grant-type:device_code",
			device_code: deviceCode,
			client_id: clientId,
		}),
	);
}

beforeEach(() => {
	db.query("DELETE FROM device_codes").run();
	db.query("DELETE FROM tokens").run();
	db.query("DELETE FROM authcodes").run();
	db.query("DELETE FROM apps").run();
	db.query("DELETE FROM sessions").run();
	db.query("DELETE FROM users").run();
});

describe("POST /auth/device", () => {
	test("returns device_code, user_code, and verification URIs", async () => {
		seedApp();
		const res = await deviceAuthorization(
			deviceReq({ client_id: CLIENT_ID, scope: "profile email" }),
		);

		expect(res.status).toBe(200);
		expect(res.headers.get("Cache-Control")).toBe("no-store");

		const body = await res.json();
		expect(body.device_code).toBeString();
		expect(body.user_code).toMatch(/^[A-Z]{4}-[A-Z]{4}$/);
		expect(body.verification_uri).toContain("/device");
		expect(body.verification_uri_complete).toContain(body.user_code);
		expect(body.expires_in).toBe(600);
		expect(body.interval).toBe(5);
	});

	test("rejects missing client_id", async () => {
		const res = await deviceAuthorization(deviceReq({}));
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_request");
	});

	test("auto-registers unknown client (same-origin fallback)", async () => {
		// nonexistent.invalid can't be fetched, but ensureApp falls back to
		// same-origin redirect validation which passes for device flow
		const res = await deviceAuthorization(
			deviceReq({ client_id: "https://nonexistent.invalid/" }),
		);
		expect(res.status).toBe(200);

		// App should now exist in the database
		const app = db
			.query("SELECT client_id FROM apps WHERE client_id = ?")
			.get("https://nonexistent.invalid/") as { client_id: string };
		expect(app.client_id).toBe("https://nonexistent.invalid/");
	});

	test("stores device code in database", async () => {
		seedApp();
		const body = await requestDeviceCode();

		const row = db
			.query(
				"SELECT client_id, scope, status FROM device_codes WHERE device_code = ?",
			)
			.get(body.device_code) as {
			client_id: string;
			scope: string;
			status: string;
		};
		expect(row.client_id).toBe(CLIENT_ID);
		expect(row.scope).toBe("profile");
		expect(row.status).toBe("pending");
	});
});

describe("token endpoint: device_code grant", () => {
	test("returns authorization_pending for pending code", async () => {
		seedApp();
		const dc = await requestDeviceCode();

		const res = await pollToken(dc.device_code);
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("authorization_pending");
	});

	test("returns access_denied for denied code", async () => {
		seedApp();
		const dc = await requestDeviceCode();

		db.query(
			"UPDATE device_codes SET status = 'denied' WHERE device_code = ?",
		).run(dc.device_code);

		const res = await pollToken(dc.device_code);
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("access_denied");
	});

	test("returns expired_token for expired code", async () => {
		seedApp();
		const dc = await requestDeviceCode();

		db.query(
			"UPDATE device_codes SET expires_at = ? WHERE device_code = ?",
		).run(Math.floor(Date.now() / 1000) - 10, dc.device_code);

		const res = await pollToken(dc.device_code);
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("expired_token");
	});

	test("returns invalid_grant for unknown device_code", async () => {
		seedApp();
		const res = await pollToken("nonexistent-code");
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_grant");
	});

	test("returns invalid_grant for client_id mismatch", async () => {
		seedApp();
		const dc = await requestDeviceCode();

		const res = await pollToken(dc.device_code, "https://other.example/");
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_grant");
	});

	test("happy path: issues tokens after approval", async () => {
		const userId = createUser({ username: "kieran" });
		seedApp();
		const dc = await requestDeviceCode();

		approveDeviceCode(dc.user_code, userId);

		// First poll after approval should succeed
		// (need to clear last_polled_at to avoid rate limiting from earlier test setup)
		db.query(
			"UPDATE device_codes SET last_polled_at = NULL WHERE device_code = ?",
		).run(dc.device_code);

		const res = await pollToken(dc.device_code);
		expect(res.status).toBe(200);

		const body = await res.json();
		expect(body.access_token).toBeString();
		expect(body.token_type).toBe("Bearer");
		expect(body.refresh_token).toBeString();
		expect(body.me).toContain("/u/kieran");
		expect(body.scope).toBe("profile");

		// Device code should be cleaned up (single use)
		const row = db
			.query("SELECT id FROM device_codes WHERE device_code = ?")
			.get(dc.device_code);
		expect(row).toBeNull();

		// Token should be in the tokens table
		const storedToken = db
			.query("SELECT user_id, client_id FROM tokens WHERE token = ?")
			.get(body.access_token) as { user_id: number; client_id: string };
		expect(storedToken.user_id).toBe(userId);
		expect(storedToken.client_id).toBe(CLIENT_ID);
	});

	test("second poll after approval returns invalid_grant", async () => {
		const userId = createUser({});
		seedApp();
		const dc = await requestDeviceCode();

		approveDeviceCode(dc.user_code, userId);
		db.query(
			"UPDATE device_codes SET last_polled_at = NULL WHERE device_code = ?",
		).run(dc.device_code);

		const first = await pollToken(dc.device_code);
		expect(first.status).toBe(200);

		const second = await pollToken(dc.device_code);
		expect(second.status).toBe(400);
		expect((await second.json()).error).toBe("invalid_grant");
	});

	test("slow_down when polling too fast", async () => {
		seedApp();
		const dc = await requestDeviceCode();

		// First poll — should succeed (returns authorization_pending)
		const first = await pollToken(dc.device_code);
		expect((await first.json()).error).toBe("authorization_pending");

		// Immediate second poll — should be rate limited
		const second = await pollToken(dc.device_code);
		expect((await second.json()).error).toBe("slow_down");
	});

	test("interval increases after slow_down", async () => {
		seedApp();
		const dc = await requestDeviceCode();

		// First poll
		await pollToken(dc.device_code);
		// Second poll — rate limited, interval should increase
		await pollToken(dc.device_code);

		const row = db
			.query("SELECT interval FROM device_codes WHERE device_code = ?")
			.get(dc.device_code) as { interval: number };
		expect(row.interval).toBe(10); // 5 + 5 penalty
	});
});
