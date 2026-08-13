import crypto from "node:crypto";
import { db } from "../../db";
import { getClientIp } from "../../lib/client-ip";
import {
	DEVICE_GRANT_TYPE,
	verifyClientCredentials,
	verifyGrantAllowed,
} from "../../lib/oauth/client-auth";
import { ensureApp } from "../../lib/oauth/client-metadata";
import {
	NO_STORE_HEADERS,
	oauthError,
	parseBody,
} from "../../lib/oauth/errors";
import { resourcesToStored, validateResources } from "../../lib/oauth/resource";
import { canonicalizeURL } from "../../lib/oauth/urls";

const DEVICE_CODE_TTL = 600; // 10 minutes
const POLL_INTERVAL = 5; // seconds

// Rate limiting for device authorization — unauthenticated endpoint
// that inserts DB rows.
const DEVICE_WINDOW_MS = 60 * 1000; // 1 minute
const DEVICE_MAX = 10; // max requests per window per IP
const deviceAttempts = new Map<string, { count: number; resetAt: number }>();

function isDeviceRateLimited(ip: string): boolean {
	if (process.env.NODE_ENV === "test") return false;

	const now = Date.now();
	const entry = deviceAttempts.get(ip);
	if (!entry || now > entry.resetAt) {
		deviceAttempts.set(ip, { count: 1, resetAt: now + DEVICE_WINDOW_MS });
		return false;
	}
	entry.count++;
	return entry.count > DEVICE_MAX;
}

// Generate a human-typeable user code per RFC 8628 §6.1 recommendations.
// Uses unambiguous consonants (no vowels to avoid accidental words,
// no easily-confused characters like 0/O, 1/l/I).
const USER_CODE_CHARS = "BCDFGHJKLMNPQRSTVWXZ";

function generateUserCode(): string {
	const bytes = crypto.randomBytes(8);
	const chars: string[] = [];
	let i = 0;
	for (const byte of bytes) {
		if (i === 4) chars.push("-");
		chars.push(USER_CODE_CHARS[byte % USER_CODE_CHARS.length] as string);
		i++;
	}
	return chars.join("");
}

// POST /auth/device - RFC 8628 Device Authorization Request
export async function deviceAuthorization(req: Request): Promise<Response> {
	const clientIp = getClientIp(req);
	if (isDeviceRateLimited(clientIp)) {
		return oauthError(
			429,
			"invalid_request",
			"Too many requests. Please try again later.",
		);
	}

	try {
		const body = await parseBody(req);
		if (!body) {
			return oauthError(
				400,
				"invalid_request",
				"Content-Type must be application/json or application/x-www-form-urlencoded",
			);
		}

		const { client_id: rawClientId, scope, resource: rawResource } = body;

		// RFC 8707 resource indicator (device flow carries it from the start).
		const resources = validateResources(rawResource ? [rawResource] : []);
		if (resources === null) {
			return oauthError(
				400,
				"invalid_target",
				"resource must be an absolute URI without a fragment",
			);
		}
		const resourceStored = resourcesToStored(resources);

		if (!rawClientId) {
			return oauthError(
				400,
				"invalid_request",
				"client_id parameter is required",
			);
		}

		let clientId: string;
		try {
			clientId = canonicalizeURL(rawClientId);
		} catch {
			return oauthError(400, "invalid_request", "Invalid client_id URL format");
		}

		// RFC 8628 §3.1: the device authorization request carries the same client
		// authentication requirements as the token endpoint.
		const credentialError = verifyClientCredentials(
			clientId,
			body.client_secret,
		);
		if (credentialError) return credentialError;

		const grantError = verifyGrantAllowed(clientId, DEVICE_GRANT_TYPE);
		if (grantError) return grantError;

		// Auto-register the client if not already known (same as authorization flow).
		// Device flow has no redirect_uri, so pass a same-origin placeholder.
		const appResult = await ensureApp(clientId, `${clientId}callback`);
		if (appResult.error) {
			return oauthError(400, "invalid_client", appResult.error);
		}

		const deviceCode = crypto.randomBytes(32).toString("base64url");
		const userCode = generateUserCode();
		const now = Math.floor(Date.now() / 1000);
		const expiresAt = now + DEVICE_CODE_TTL;

		db.query(
			"INSERT INTO device_codes (device_code, user_code, client_id, scope, expires_at, interval, resource) VALUES (?, ?, ?, ?, ?, ?, ?)",
		).run(
			deviceCode,
			userCode,
			clientId,
			scope || "profile",
			expiresAt,
			POLL_INTERVAL,
			resourceStored,
		);

		const origin = process.env.ORIGIN || "http://localhost:3000";

		return Response.json(
			{
				device_code: deviceCode,
				user_code: userCode,
				verification_uri: `${origin}/device`,
				verification_uri_complete: `${origin}/device?code=${userCode}`,
				expires_in: DEVICE_CODE_TTL,
				interval: POLL_INTERVAL,
			},
			{ headers: NO_STORE_HEADERS },
		);
	} catch (error) {
		console.error("Device authorization error:", error);
		return oauthError(500, "server_error", "Internal server error");
	}
}
