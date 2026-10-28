import crypto from "node:crypto";
import { db } from "../../db";
import { getClientIp } from "../../lib/client-ip";
import {
	verifyClientCredentials,
	verifyGrantAllowed,
} from "../../lib/oauth/client-auth";
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

// Rate limiting for the token endpoint — per-IP sliding window.
const TOKEN_WINDOW_MS = 60 * 1000; // 1 minute
const TOKEN_MAX = 30; // max requests per window per IP
const tokenAttempts = new Map<string, { count: number; resetAt: number }>();

function isTokenRateLimited(ip: string): boolean {
	// Skip rate limiting in tests
	if (process.env.NODE_ENV === "test") return false;

	const now = Date.now();
	const entry = tokenAttempts.get(ip);
	if (!entry || now > entry.resetAt) {
		tokenAttempts.set(ip, { count: 1, resetAt: now + TOKEN_WINDOW_MS });
		return false;
	}
	entry.count++;
	return entry.count > TOKEN_MAX;
}

function generateToken(): string {
	return crypto.randomBytes(32).toString("base64url");
}

// POST /auth/token - Exchange authorization code or refresh token
export async function token(req: Request): Promise<Response> {
	const clientIp = getClientIp(req);

	if (isTokenRateLimited(clientIp)) {
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

		const { grant_type } = body;

		// RFC 6749 §5.2: a missing parameter is invalid_request; a grant we do
		// not issue is unsupported_grant_type.
		if (!grant_type) {
			return oauthError(
				400,
				"invalid_request",
				"grant_type parameter is required",
			);
		}

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

		// RFC 7591 §2: a client may only use the grants it registered for.
		if (body.client_id) {
			let clientId: string;
			try {
				clientId = canonicalizeURL(body.client_id);
			} catch {
				return oauthError(
					400,
					"invalid_request",
					"Invalid client_id URL format",
				);
			}
			const grantError = verifyGrantAllowed(clientId, grant_type);
			if (grantError) return grantError;
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

	if (!body.client_id) {
		return oauthError(400, "invalid_request", "client_id is required");
	}

	let client_id: string;
	try {
		client_id = canonicalizeURL(body.client_id);
	} catch {
		return oauthError(400, "invalid_request", "Invalid client_id URL format");
	}

	const tokenData = db
		.query(
			"SELECT id, user_id, client_id, scope, refresh_expires_at, revoked, rotated, family, resource FROM tokens WHERE refresh_token = ?",
		)
		.get(refresh_token) as
		| {
				id: number;
				user_id: number;
				client_id: string;
				scope: string;
				refresh_expires_at: number;
				revoked: number;
				rotated: number;
				family: string | null;
				resource: string | null;
		  }
		| undefined;

	if (!tokenData || tokenData.revoked === 1) {
		return oauthError(400, "invalid_grant", "Invalid refresh token");
	}

	// RFC 9700 §4.14.2: presenting an already-rotated refresh token means the
	// token leaked (either the attacker or the legit client is replaying a stale
	// one, and we can't tell which). Revoke the whole family to stop the attack.
	if (tokenData.rotated === 1) {
		if (tokenData.family) {
			db.query("UPDATE tokens SET revoked = 1 WHERE family = ?").run(
				tokenData.family,
			);
		} else {
			db.query("UPDATE tokens SET revoked = 1 WHERE id = ?").run(tokenData.id);
		}
		console.warn(
			`[token] refresh token reuse detected — family ${tokenData.family ?? tokenData.id} revoked (possible token leak)`,
		);
		return oauthError(400, "invalid_grant", "Refresh token was already used");
	}

	const now = Math.floor(Date.now() / 1000);
	if (tokenData.refresh_expires_at < now) {
		return oauthError(400, "invalid_grant", "Refresh token expired");
	}

	if (tokenData.client_id !== client_id) {
		return oauthError(400, "invalid_grant", "client_id mismatch");
	}

	// RFC 6749 §6: confidential clients must authenticate on refresh
	const credentialError = verifyClientCredentials(
		client_id,
		body.client_secret,
	);
	if (credentialError) {
		return credentialError;
	}

	// RFC 6749 §6: the requested scope may narrow the original grant but can
	// never widen it. Absent, the new token keeps the scope it had.
	const grantedScopes = tokenData.scope.split(" ").filter(Boolean);
	let newScope = tokenData.scope;
	if (body.scope !== undefined && body.scope.trim() !== "") {
		const requested = [...new Set(body.scope.split(" ").filter(Boolean))];
		const extra = requested.filter((sc) => !grantedScopes.includes(sc));
		if (extra.length > 0) {
			return oauthError(
				400,
				"invalid_scope",
				`Refresh cannot add scopes not in the original grant: ${extra.join(" ")}`,
			);
		}
		newScope = requested.join(" ");
	}

	// Rotate: issue a new row in the same family, mark this one rotated.
	// The UPDATE must be atomic (WHERE rotated = 0) — otherwise two concurrent
	// refreshes both win and reuse detection is defeated.
	const newAccessToken = generateToken();
	const expiresAt = now + ACCESS_TOKEN_TTL;
	const newRefreshToken = generateToken();
	const refreshExpiresAt = now + REFRESH_TOKEN_TTL;
	const family = tokenData.family ?? crypto.randomUUID();

	const rotateResult = db
		.query("UPDATE tokens SET rotated = 1 WHERE id = ? AND rotated = 0")
		.run(tokenData.id);

	if (rotateResult.changes === 0) {
		// Someone else rotated first — this is a replay of a stale token.
		// Revoke the whole family per RFC 9700 §4.14.2.
		if (tokenData.family) {
			db.query("UPDATE tokens SET revoked = 1 WHERE family = ?").run(
				tokenData.family,
			);
		} else {
			db.query("UPDATE tokens SET revoked = 1 WHERE id = ?").run(tokenData.id);
		}
		console.warn(
			`[token] refresh token race lost — family ${tokenData.family ?? tokenData.id} revoked`,
		);
		return oauthError(400, "invalid_grant", "Refresh token was already used");
	}

	db.query(
		"INSERT INTO tokens (token, user_id, client_id, scope, expires_at, refresh_token, refresh_expires_at, family, resource) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
	).run(
		newAccessToken,
		tokenData.user_id,
		tokenData.client_id,
		newScope,
		expiresAt,
		newRefreshToken,
		refreshExpiresAt,
		family,
		tokenData.resource, // RFC 8707: a refreshed token keeps its audience
	);

	const user = db
		.query("SELECT username, url, status FROM users WHERE id = ?")
		.get(tokenData.user_id) as
		| { username: string; url: string | null; status: string }
		| undefined;

	if (!user) {
		return oauthError(500, "server_error", "User not found");
	}

	if (user.status !== "active") {
		return oauthError(400, "invalid_grant", "User account is not active");
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
			scope: newScope,
			iss: origin,
		},
		{ headers: NO_STORE_HEADERS },
	);
}

// RFC 8628 §3.4: Device Access Token Request (polling)
async function handleDeviceCodeGrant(
	body: Record<string, string>,
): Promise<Response> {
	const { device_code, client_id: rawClientId, client_secret } = body;

	if (!device_code) {
		return oauthError(
			400,
			"invalid_request",
			"device_code parameter is required",
		);
	}

	// RFC 8628 §3.4: client_id is required for public clients polling the
	// token endpoint. Without it the device_code isn't bound to its client.
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

	const deviceCode = db
		.query(
			"SELECT id, client_id, scope, expires_at, interval, last_polled_at, status, user_id, resource FROM device_codes WHERE device_code = ?",
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
				resource: string | null;
		  }
		| undefined;

	if (!deviceCode) {
		return oauthError(400, "invalid_grant", "Invalid device_code");
	}

	const now = Math.floor(Date.now() / 1000);

	if (deviceCode.expires_at < now) {
		return oauthError(400, "expired_token", "The device_code has expired");
	}

	if (deviceCode.client_id !== clientId) {
		return oauthError(400, "invalid_grant", "client_id mismatch");
	}

	// For a public client the device_code is itself high-entropy proof of
	// possession and the client_id binding above is the security boundary. A
	// client issued a secret is confidential on every grant, though: RFC 8628
	// §3.4 carries RFC 6749 §3.2.1's authentication requirement to device_code
	// polling, so knowing the client_id must not be enough to collect its token.
	const credentialError = verifyClientCredentials(clientId, client_secret);
	if (credentialError) return credentialError;

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
		.query(
			"SELECT username, name, email, photo, url, status FROM users WHERE id = ?",
		)
		.get(deviceCode.user_id) as
		| {
				username: string;
				name: string;
				email: string | null;
				photo: string | null;
				url: string | null;
				status: string;
		  }
		| undefined;

	if (!user) {
		return oauthError(500, "server_error", "User not found");
	}

	if (user.status !== "active") {
		return oauthError(400, "invalid_grant", "User account is not active");
	}

	const scopes = deviceCode.scope.split(" ").filter(Boolean);
	const origin = process.env.ORIGIN || "http://localhost:3000";
	const meValue = user.url || `${origin}/u/${user.username}`;

	const accessToken = generateToken();
	const expiresAt = now + ACCESS_TOKEN_TTL;

	const issueRefresh = scopes.includes("offline_access");
	const refreshToken = issueRefresh ? generateToken() : null;
	const refreshExpiresAt = issueRefresh ? now + REFRESH_TOKEN_TTL : null;

	db.query(
		"INSERT INTO tokens (token, user_id, client_id, scope, expires_at, refresh_token, refresh_expires_at, family, resource) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
	).run(
		accessToken,
		deviceCode.user_id,
		deviceCode.client_id,
		deviceCode.scope,
		expiresAt,
		refreshToken,
		refreshExpiresAt,
		crypto.randomUUID(),
		deviceCode.resource,
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

	const deviceResponse: Record<string, unknown> = {
		access_token: accessToken,
		token_type: "Bearer",
		expires_in: ACCESS_TOKEN_TTL,
		me: meValue,
		profile,
		scope: deviceCode.scope,
		iss: origin,
	};

	if (refreshToken) {
		deviceResponse.refresh_token = refreshToken;
	}

	return Response.json(deviceResponse, { headers: NO_STORE_HEADERS });
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

	// RFC 7636 §4.1: code_verifier must be 43-128 characters
	if (code_verifier.length < 43 || code_verifier.length > 128) {
		return oauthError(
			400,
			"invalid_request",
			"code_verifier must be 43-128 characters (RFC 7636 §4.1)",
		);
	}

	const authcode = db
		.query(
			"SELECT user_id, client_id, redirect_uri, scopes, code_challenge, expires_at, used, me, nonce, auth_time, resource, family, issue_refresh FROM authcodes WHERE code = ?",
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
				resource: string | null;
				family: string | null;
				issue_refresh: number;
		  }
		| undefined;

	if (!authcode) {
		return oauthError(400, "invalid_grant", "Authorization code not found");
	}

	if (authcode.used) {
		// RFC 6749 §4.1.2 / RFC 9700 §4.5: a replayed code means it leaked.
		// Whoever holds the tokens it minted (us or the attacker) loses them.
		if (authcode.family) {
			db.query("UPDATE tokens SET revoked = 1 WHERE family = ?").run(
				authcode.family,
			);
			console.warn(
				`[token] authorization code reuse detected — family ${authcode.family} revoked`,
			);
		}
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

	// Mark code as used — atomic guard prevents double-use race.
	// Two concurrent exchanges with the same code: the first UPDATE
	// sets used=1 and returns changes=1; the second gets changes=0.
	// The family recorded here is what a later replay revokes.
	const family = crypto.randomUUID();
	const markResult = db
		.query(
			"UPDATE authcodes SET used = 1, family = ? WHERE code = ? AND used = 0",
		)
		.run(family, code);

	if (markResult.changes === 0) {
		return oauthError(400, "invalid_grant", "Authorization code already used");
	}

	const user = db
		.query(
			"SELECT username, name, email, photo, url, status FROM users WHERE id = ?",
		)
		.get(authcode.user_id) as
		| {
				username: string;
				name: string;
				email: string | null;
				photo: string | null;
				url: string | null;
				status: string;
		  }
		| undefined;

	if (!user) {
		return oauthError(500, "server_error", "User not found");
	}

	// Reject token issuance for suspended/inactive users
	if (user.status !== "active") {
		return oauthError(400, "invalid_grant", "User account is not active");
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

	const origin = process.env.ORIGIN || "http://localhost:3000";

	// The identity we return is always the one we verified: the user's own
	// domain when they have proven one, otherwise their indiko profile. The
	// `me` the client asked for was only ever a hint (checked at authorization
	// time to be one of the user's identities) and is honored when it was.
	let meValue = user.url || `${origin}/u/${user.username}`;
	if (authcode.me) {
		const own = [`${origin}/u/${user.username}`, user.url].filter(Boolean);
		if (own.includes(authcode.me)) meValue = authcode.me;
	}

	// IndieAuth §5.3.3: a code issued without any scope is exchanged for the
	// user's identity only. No access token exists, so nothing is stored.
	if (scopes.length === 0) {
		return Response.json(
			{ me: meValue, iss: origin },
			{ headers: NO_STORE_HEADERS },
		);
	}

	const accessToken = generateToken();
	const expiresAt = now + ACCESS_TOKEN_TTL;

	// A refresh token is issued when the client asked for offline_access (OIDC
	// Core §11) or when the person ticked "stay signed in" on the consent
	// screen for an IndieAuth client, which has no scope to ask with
	// (IndieAuth §5.5 leaves this to the server). Otherwise the grant is
	// one-shot: an access token and nothing more.
	const issueRefresh =
		scopes.includes("offline_access") || authcode.issue_refresh === 1;
	const refreshToken = issueRefresh ? generateToken() : null;
	const refreshExpiresAt = issueRefresh ? now + REFRESH_TOKEN_TTL : null;

	db.query(
		"INSERT INTO tokens (token, user_id, client_id, scope, expires_at, refresh_token, refresh_expires_at, family, resource) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
	).run(
		accessToken,
		authcode.user_id,
		client_id,
		scopes.join(" "),
		expiresAt,
		refreshToken,
		refreshExpiresAt,
		family,
		authcode.resource, // RFC 8707: bind the token to the requested audience
	);

	const response: Record<string, unknown> = {
		access_token: accessToken,
		token_type: "Bearer",
		expires_in: ACCESS_TOKEN_TTL,
		me: meValue,
		profile,
		scope: scopes.join(" "),
		iss: origin,
	};

	if (refreshToken) {
		response.refresh_token = refreshToken;
	}

	if (permission?.role) {
		response.role = permission.role;
	}

	// Generate OIDC id_token if openid scope is requested
	if (scopes.includes("openid")) {
		// sub must be stable and unique per OIDC Core §8 — use the canonical
		// profile URL, not the user-mutable website URL.
		const stableSub = `${origin}/u/${user.username}`;
		const idTokenClaims: Record<string, unknown> = {
			sub: stableSub,
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
			accessToken,
		);
	}

	return Response.json(response, { headers: NO_STORE_HEADERS });
}

/**
 * IndieAuth §6.1: the introspection endpoint MUST require authorization, or
 * it becomes an oracle that confirms any token it is shown. Two credentials
 * are accepted: a live indiko access token as a Bearer credential (the usual
 * case for a resource server, which may present the very token it received),
 * or the client_id and client_secret of a confidential client.
 */
function introspectionCallerAuthorized(
	req: Request,
	body: Record<string, string>,
): boolean {
	const authHeader = req.headers.get("Authorization");
	if (authHeader?.startsWith("Bearer ")) {
		const credential = authHeader.substring(7).trim();
		if (!credential) return false;
		const row = db
			.query(
				"SELECT t.expires_at, t.revoked, u.status FROM tokens t JOIN users u ON t.user_id = u.id WHERE t.token = ?",
			)
			.get(credential) as
			| { expires_at: number; revoked: number; status: string }
			| undefined;
		if (!row || row.revoked === 1 || row.status !== "active") return false;
		return row.expires_at >= Math.floor(Date.now() / 1000);
	}

	if (body.client_id && body.client_secret) {
		let clientId: string;
		try {
			clientId = canonicalizeURL(body.client_id);
		} catch {
			return false;
		}
		const app = db
			.query(
				"SELECT client_secret_hash FROM apps WHERE client_id = ? AND is_preregistered = 1",
			)
			.get(clientId) as { client_secret_hash: string | null } | undefined;
		if (!app?.client_secret_hash) return false;
		return verifySecret(body.client_secret, app.client_secret_hash);
	}

	return false;
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

		if (!introspectionCallerAuthorized(req, body)) {
			// RFC 7662 §2.3: say nothing about the token, not even active:false.
			return unauthorizedResponse(
				"invalid_token",
				"Introspection requires a valid Bearer access token or client credentials",
			);
		}

		const { token: tokenValue } = body;

		if (!tokenValue) {
			return oauthError(400, "invalid_request", "token parameter is required");
		}

		const tokenData = db
			.query(
				"SELECT t.user_id, t.client_id, t.scope, t.expires_at, t.revoked, t.created_at, t.resource, u.username FROM tokens t JOIN users u ON t.user_id = u.id WHERE t.token = ?",
			)
			.get(tokenValue) as
			| {
					user_id: number;
					client_id: string;
					scope: string;
					expires_at: number;
					revoked: number;
					created_at: number;
					resource: string | null;
					username: string;
			  }
			| undefined;

		if (!tokenData || tokenData.revoked === 1) {
			return Response.json({ active: false }, { headers: NO_STORE_HEADERS });
		}

		const now = Math.floor(Date.now() / 1000);
		if (tokenData.expires_at < now) {
			return Response.json({ active: false }, { headers: NO_STORE_HEADERS });
		}

		const user = db
			.query("SELECT url FROM users WHERE id = ?")
			.get(tokenData.user_id) as { url: string | null } | undefined;

		const origin = process.env.ORIGIN || "http://localhost:3000";
		const meValue = user?.url || `${origin}/u/${tokenData.username}`;

		// RFC 8707 / 7662: echo the token's audience so a resource server can
		// confirm the token was minted for it. One resource → a string, several →
		// an array; omitted entirely when the token is unscoped.
		const resources = tokenData.resource
			? tokenData.resource.split(" ").filter(Boolean)
			: [];
		const aud =
			resources.length === 1
				? resources[0]
				: resources.length > 1
					? resources
					: undefined;

		return Response.json(
			{
				active: true,
				sub: meValue,
				me: meValue,
				client_id: tokenData.client_id,
				scope: tokenData.scope,
				exp: tokenData.expires_at,
				iat: tokenData.created_at,
				username: tokenData.username,
				...(aud ? { aud } : {}),
			},
			{ headers: NO_STORE_HEADERS },
		);
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
