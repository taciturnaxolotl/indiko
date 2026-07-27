import crypto from "node:crypto";
import { db } from "../../db";
import {
	NO_STORE_HEADERS,
	oauthError,
	parseBody,
	unauthorizedResponse,
} from "../../lib/oauth/errors";
import { canonicalizeURL, verifyPKCE } from "../../lib/oauth/urls";
import { verifySecret } from "../../lib/secrets";
import { signIDToken } from "../../oidc";

const ACCESS_TOKEN_TTL = 3600; // 1 hour
const REFRESH_TOKEN_TTL = 2592000; // 30 days

function generateToken(): string {
	return crypto.randomBytes(32).toString("base64url");
}

// POST /auth/token - Exchange authorization code or refresh token
export async function token(req: Request): Promise<Response> {
	try {
		const body = await parseBody(req);
		if (!body) {
			return oauthError(
				400,
				"invalid_request",
				"Content-Type must be application/json or application/x-www-form-urlencoded",
			);
		}

		const { grant_type } = body;

		if (
			grant_type !== "authorization_code" &&
			grant_type !== "refresh_token" &&
			grant_type !== "urn:ietf:params:oauth:grant-type:device_code"
		) {
			return oauthError(
				400,
				"unsupported_grant_type",
				"Supported grant types: authorization_code, refresh_token, urn:ietf:params:oauth:grant-type:device_code",
			);
		}

		if (grant_type === "refresh_token") {
			return handleRefreshTokenGrant(body);
		}
		if (grant_type === "urn:ietf:params:oauth:grant-type:device_code") {
			return handleDeviceCodeGrant(body);
		}
		return await handleAuthorizationCodeGrant(body);
	} catch (error) {
		console.error("Token exchange error:", error);
		return oauthError(500, "server_error", "Internal server error");
	}
}

async function handleRefreshTokenGrant(
	body: Record<string, string>,
): Promise<Response> {
	const { refresh_token } = body;

	if (!refresh_token) {
		return oauthError(
			400,
			"invalid_request",
			"refresh_token parameter is required",
		);
	}

	const client_id = body.client_id
		? canonicalizeURL(body.client_id)
		: undefined;

	const tokenData = db
		.query(
			"SELECT id, user_id, client_id, scope, refresh_expires_at, revoked FROM tokens WHERE refresh_token = ?",
		)
		.get(refresh_token) as
		| {
				id: number;
				user_id: number;
				client_id: string;
				scope: string;
				refresh_expires_at: number;
				revoked: number;
		  }
		| undefined;

	if (!tokenData || tokenData.revoked === 1) {
		return oauthError(400, "invalid_grant", "Invalid refresh token");
	}

	const now = Math.floor(Date.now() / 1000);
	if (tokenData.refresh_expires_at < now) {
		return oauthError(400, "invalid_grant", "Refresh token expired");
	}

	if (tokenData.client_id !== client_id) {
		return oauthError(400, "invalid_grant", "client_id mismatch");
	}

	// Rotate both tokens to prevent replay attacks
	const newAccessToken = generateToken();
	const expiresAt = now + ACCESS_TOKEN_TTL;
	const newRefreshToken = generateToken();
	const refreshExpiresAt = now + REFRESH_TOKEN_TTL;

	db.query(
		"UPDATE tokens SET token = ?, expires_at = ?, refresh_token = ?, refresh_expires_at = ? WHERE id = ?",
	).run(
		newAccessToken,
		expiresAt,
		newRefreshToken,
		refreshExpiresAt,
		tokenData.id,
	);

	const user = db
		.query("SELECT username, url FROM users WHERE id = ?")
		.get(tokenData.user_id) as
		| { username: string; url: string | null }
		| undefined;

	if (!user) {
		return oauthError(500, "server_error", "User not found");
	}

	const origin = process.env.ORIGIN || "http://localhost:3000";
	const meValue = user.url || `${origin}/u/${user.username}`;

	return Response.json(
		{
			access_token: newAccessToken,
			token_type: "Bearer",
			expires_in: ACCESS_TOKEN_TTL,
			refresh_token: newRefreshToken,
			me: meValue,
			scope: tokenData.scope,
			iss: origin,
		},
		{ headers: NO_STORE_HEADERS },
	);
}

// RFC 8628 §3.4: Device Access Token Request (polling)
async function handleDeviceCodeGrant(
	body: Record<string, string>,
): Promise<Response> {
	const { device_code, client_id: rawClientId } = body;

	if (!device_code) {
		return oauthError(
			400,
			"invalid_request",
			"device_code parameter is required",
		);
	}

	let clientId: string | undefined;
	try {
		clientId = rawClientId ? canonicalizeURL(rawClientId) : undefined;
	} catch {
		return oauthError(400, "invalid_request", "Invalid client_id URL format");
	}

	const deviceCode = db
		.query(
			"SELECT id, client_id, scope, expires_at, interval, last_polled_at, status, user_id FROM device_codes WHERE device_code = ?",
		)
		.get(device_code) as
		| {
				id: number;
				client_id: string;
				scope: string;
				expires_at: number;
				interval: number;
				last_polled_at: number | null;
				status: string;
				user_id: number | null;
		  }
		| undefined;

	if (!deviceCode) {
		return oauthError(400, "invalid_grant", "Invalid device_code");
	}

	const now = Math.floor(Date.now() / 1000);

	if (deviceCode.expires_at < now) {
		return oauthError(400, "expired_token", "The device_code has expired");
	}

	if (clientId && deviceCode.client_id !== clientId) {
		return oauthError(400, "invalid_grant", "client_id mismatch");
	}

	// Rate limiting: enforce minimum poll interval (RFC 8628 §3.5)
	if (deviceCode.last_polled_at) {
		const elapsed = now - deviceCode.last_polled_at;
		if (elapsed < deviceCode.interval) {
			// Increase the interval as penalty (RFC 8628 §3.5 slow_down)
			const newInterval = deviceCode.interval + 5;
			db.query(
				"UPDATE device_codes SET interval = ?, last_polled_at = ? WHERE id = ?",
			).run(newInterval, now, deviceCode.id);

			return oauthError(
				400,
				"slow_down",
				"Polling too frequently. Increase interval.",
			);
		}
	}

	// Update last poll time
	db.query("UPDATE device_codes SET last_polled_at = ? WHERE id = ?").run(
		now,
		deviceCode.id,
	);

	if (deviceCode.status === "denied") {
		return oauthError(
			400,
			"access_denied",
			"The user denied the authorization request",
		);
	}

	if (deviceCode.status === "pending") {
		return oauthError(
			400,
			"authorization_pending",
			"The user has not yet completed the authorization",
		);
	}

	// Status is "approved" — issue tokens
	if (!deviceCode.user_id) {
		return oauthError(500, "server_error", "Approved code missing user_id");
	}

	// Clean up the device code — single use after approval
	db.query("DELETE FROM device_codes WHERE id = ?").run(deviceCode.id);

	const user = db
		.query("SELECT username, name, email, photo, url FROM users WHERE id = ?")
		.get(deviceCode.user_id) as
		| {
				username: string;
				name: string;
				email: string | null;
				photo: string | null;
				url: string | null;
		  }
		| undefined;

	if (!user) {
		return oauthError(500, "server_error", "User not found");
	}

	const scopes = deviceCode.scope.split(" ").filter(Boolean);
	const origin = process.env.ORIGIN || "http://localhost:3000";
	const meValue = user.url || `${origin}/u/${user.username}`;

	const accessToken = generateToken();
	const expiresAt = now + ACCESS_TOKEN_TTL;
	const refreshToken = generateToken();
	const refreshExpiresAt = now + REFRESH_TOKEN_TTL;

	db.query(
		"INSERT INTO tokens (token, user_id, client_id, scope, expires_at, refresh_token, refresh_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
	).run(
		accessToken,
		deviceCode.user_id,
		deviceCode.client_id,
		deviceCode.scope,
		expiresAt,
		refreshToken,
		refreshExpiresAt,
	);

	const profile: Record<string, string> = {};
	if (scopes.includes("profile")) {
		profile.name = user.name;
		if (user.photo) profile.photo = user.photo;
		if (user.url) profile.url = user.url;
	}
	if (scopes.includes("email") && user.email) {
		profile.email = user.email;
	}

	return Response.json(
		{
			access_token: accessToken,
			token_type: "Bearer",
			expires_in: ACCESS_TOKEN_TTL,
			refresh_token: refreshToken,
			me: meValue,
			profile,
			scope: deviceCode.scope,
			iss: origin,
		},
		{ headers: NO_STORE_HEADERS },
	);
}

// Verify pre-registered client credentials; returns a Response on failure
function verifyClientCredentials(
	client_id: string | undefined,
	client_secret: string | undefined,
): Response | null {
	// No client_id means we can't look up the app; treat as public/unknown.
	if (!client_id) {
		return null;
	}

	const app = db
		.query(
			"SELECT is_preregistered, client_secret_hash FROM apps WHERE client_id = ?",
		)
		.get(client_id) as
		| { is_preregistered: number; client_secret_hash: string | null }
		| undefined;

	// client_secret sent for an unknown client
	if (client_secret && !app) {
		return oauthError(400, "invalid_client", "Unknown client");
	}

	if (app?.is_preregistered !== 1) {
		return null; // public client, nothing to check
	}

	if (!client_secret) {
		return unauthorizedResponse(
			"invalid_client",
			"client_secret is required for pre-registered clients",
		);
	}

	if (!app.client_secret_hash) {
		return oauthError(500, "server_error", "Client secret not configured");
	}

	if (!verifySecret(client_secret, app.client_secret_hash)) {
		return unauthorizedResponse("invalid_client", "Invalid client_secret");
	}

	return null;
}

async function handleAuthorizationCodeGrant(
	body: Record<string, string>,
): Promise<Response> {
	const {
		code,
		client_id: raw_client_id,
		client_secret,
		redirect_uri: raw_redirect_uri,
		code_verifier,
	} = body;

	// Canonicalize URLs for consistent comparison with stored values
	let client_id: string | undefined;
	let redirect_uri: string | undefined;
	try {
		client_id = raw_client_id ? canonicalizeURL(raw_client_id) : undefined;
		redirect_uri = raw_redirect_uri
			? canonicalizeURL(raw_redirect_uri)
			: undefined;
	} catch {
		return oauthError(
			400,
			"invalid_request",
			"Invalid client_id or redirect_uri URL format",
		);
	}

	const credentialError = verifyClientCredentials(client_id, client_secret);
	if (credentialError) return credentialError;

	if (!code || !client_id) {
		return oauthError(
			400,
			"invalid_request",
			"Missing required parameters (code, client_id)",
		);
	}

	// PKCE is required for all clients per IndieAuth spec
	if (!code_verifier) {
		return oauthError(
			400,
			"invalid_request",
			"code_verifier is required (PKCE)",
		);
	}

	const authcode = db
		.query(
			"SELECT user_id, client_id, redirect_uri, scopes, code_challenge, expires_at, used, me, nonce, auth_time FROM authcodes WHERE code = ?",
		)
		.get(code) as
		| {
				user_id: number;
				client_id: string;
				redirect_uri: string;
				scopes: string;
				code_challenge: string;
				expires_at: number;
				used: number;
				me: string | null;
				nonce: string | null;
				auth_time: number | null;
		  }
		| undefined;

	if (!authcode) {
		return oauthError(400, "invalid_grant", "Authorization code not found");
	}

	if (authcode.used) {
		return oauthError(400, "invalid_grant", "Authorization code already used");
	}

	const now = Math.floor(Date.now() / 1000);
	if (authcode.expires_at < now) {
		return oauthError(400, "invalid_grant", "Authorization code expired");
	}

	if (authcode.client_id !== client_id) {
		return oauthError(400, "invalid_grant", "client_id mismatch");
	}

	// redirect_uri is REQUIRED since it's always included in the authorization
	// request (per OAuth 2.0 RFC 6749 §4.1.3)
	if (!redirect_uri) {
		return oauthError(400, "invalid_request", "redirect_uri is required");
	}

	if (authcode.redirect_uri !== redirect_uri) {
		return oauthError(400, "invalid_grant", "redirect_uri mismatch");
	}

	if (!verifyPKCE(code_verifier, authcode.code_challenge)) {
		return oauthError(400, "invalid_grant", "Invalid code_verifier");
	}

	// Mark code as used
	db.query("UPDATE authcodes SET used = 1 WHERE code = ?").run(code);

	const user = db
		.query("SELECT username, name, email, photo, url FROM users WHERE id = ?")
		.get(authcode.user_id) as
		| {
				username: string;
				name: string;
				email: string | null;
				photo: string | null;
				url: string | null;
		  }
		| undefined;

	if (!user) {
		return oauthError(500, "server_error", "User not found");
	}

	const scopes = JSON.parse(authcode.scopes) as string[];
	const profile: Record<string, string> = {};

	if (scopes.includes("profile")) {
		profile.name = user.name;
		if (user.photo) profile.photo = user.photo;
		if (user.url) profile.url = user.url;
	}

	if (scopes.includes("email") && user.email) {
		profile.email = user.email;
	}

	// Get user's role for this app (if assigned)
	const permission = db
		.query("SELECT role FROM permissions WHERE user_id = ? AND client_id = ?")
		.get(authcode.user_id, client_id) as { role: string | null } | undefined;

	// Use custom domain as identity if user has verified one, otherwise indiko profile
	let meValue = `${process.env.ORIGIN}/u/${user.username}`;
	if (user.url) {
		meValue = user.url;
	}

	// Validate that the user controls the requested me parameter
	if (authcode.me && authcode.me !== meValue) {
		return oauthError(
			400,
			"invalid_grant",
			"The requested identity does not match the user's verified domain",
		);
	}

	const origin = process.env.ORIGIN || "http://localhost:3000";

	const accessToken = generateToken();
	const expiresAt = now + ACCESS_TOKEN_TTL;
	const refreshToken = generateToken();
	const refreshExpiresAt = now + REFRESH_TOKEN_TTL;

	db.query(
		"INSERT INTO tokens (token, user_id, client_id, scope, expires_at, refresh_token, refresh_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
	).run(
		accessToken,
		authcode.user_id,
		client_id,
		scopes.join(" "),
		expiresAt,
		refreshToken,
		refreshExpiresAt,
	);

	const response: Record<string, unknown> = {
		access_token: accessToken,
		token_type: "Bearer",
		expires_in: ACCESS_TOKEN_TTL,
		refresh_token: refreshToken,
		me: meValue,
		profile,
		scope: scopes.join(" "),
		iss: origin,
	};

	if (permission?.role) {
		response.role = permission.role;
	}

	// Generate OIDC id_token if openid scope is requested
	if (scopes.includes("openid")) {
		const idTokenClaims: Record<string, unknown> = {
			sub: meValue,
			aud: client_id,
		};

		if (authcode.nonce) {
			idTokenClaims.nonce = authcode.nonce;
		}

		if (authcode.auth_time) {
			idTokenClaims.auth_time = authcode.auth_time;
		}

		if (scopes.includes("profile")) {
			idTokenClaims.name = user.name;
			if (user.photo) idTokenClaims.picture = user.photo;
			if (user.url) idTokenClaims.website = user.url;
		}

		if (scopes.includes("email") && user.email) {
			idTokenClaims.email = user.email;
		}

		response.id_token = await signIDToken(
			origin,
			idTokenClaims as {
				sub: string;
				aud: string;
				nonce?: string;
				auth_time?: number;
				name?: string;
				email?: string;
				picture?: string;
				website?: string;
			},
		);
	}

	return Response.json(response, { headers: NO_STORE_HEADERS });
}

// POST /auth/token/introspect - Introspect access token
export async function tokenIntrospect(req: Request): Promise<Response> {
	try {
		const body = await parseBody(req);
		if (!body) {
			return oauthError(
				400,
				"invalid_request",
				"Content-Type must be application/json or application/x-www-form-urlencoded",
			);
		}

		const { token: tokenValue } = body;

		if (!tokenValue) {
			return oauthError(400, "invalid_request", "token parameter is required");
		}

		const tokenData = db
			.query(
				"SELECT t.user_id, t.client_id, t.scope, t.expires_at, t.revoked, t.created_at, u.username FROM tokens t JOIN users u ON t.user_id = u.id WHERE t.token = ?",
			)
			.get(tokenValue) as
			| {
					user_id: number;
					client_id: string;
					scope: string;
					expires_at: number;
					revoked: number;
					created_at: number;
					username: string;
			  }
			| undefined;

		if (!tokenData || tokenData.revoked === 1) {
			return Response.json({ active: false });
		}

		const now = Math.floor(Date.now() / 1000);
		if (tokenData.expires_at < now) {
			return Response.json({ active: false });
		}

		const user = db
			.query("SELECT url FROM users WHERE id = ?")
			.get(tokenData.user_id) as { url: string | null } | undefined;

		const origin = process.env.ORIGIN || "http://localhost:3000";
		const meValue = user?.url || `${origin}/u/${tokenData.username}`;

		return Response.json({
			active: true,
			sub: meValue,
			me: meValue,
			client_id: tokenData.client_id,
			scope: tokenData.scope,
			exp: tokenData.expires_at,
			iat: tokenData.created_at,
			username: tokenData.username,
		});
	} catch (error) {
		console.error("Token introspection error:", error);
		return oauthError(500, "server_error", "Internal server error");
	}
}

// POST /auth/token/revoke - Revoke access or refresh token
export async function tokenRevoke(req: Request): Promise<Response> {
	try {
		const body = await parseBody(req);
		if (!body) {
			return oauthError(
				400,
				"invalid_request",
				"Content-Type must be application/json or application/x-www-form-urlencoded",
			);
		}

		const { token: tokenValue } = body;

		if (!tokenValue) {
			return oauthError(400, "invalid_request", "token parameter is required");
		}

		// RFC 7009 §2.1: revoking a refresh token must also invalidate associated
		// access tokens, and vice versa. Here both live on one row, so revoking
		// either handle revokes the whole record.
		const refreshTokenData = db
			.query("SELECT id FROM tokens WHERE refresh_token = ?")
			.get(tokenValue) as { id: number } | undefined;

		if (refreshTokenData) {
			db.query("UPDATE tokens SET revoked = 1 WHERE id = ?").run(
				refreshTokenData.id,
			);
		} else {
			const accessTokenData = db
				.query("SELECT id FROM tokens WHERE token = ?")
				.get(tokenValue) as { id: number } | undefined;

			if (accessTokenData) {
				db.query("UPDATE tokens SET revoked = 1 WHERE id = ?").run(
					accessTokenData.id,
				);
			}
		}

		// Per RFC 7009, return 200 even if token doesn't exist
		return new Response(null, { status: 200 });
	} catch (error) {
		console.error("Token revocation error:", error);
		return oauthError(500, "server_error", "Internal server error");
	}
}
