import { nanoid } from "nanoid";
import { db } from "../../db";
import { getClientIp } from "../../lib/client-ip";
import { SUPPORTED_GRANT_TYPES } from "../../lib/oauth/client-auth";
import { NO_STORE_HEADERS, oauthError } from "../../lib/oauth/errors";
import { hashSecret } from "../../lib/secrets";

function generateClientId(): string {
	return `ikc_${nanoid(21)}`; // indiko client
}

function generateClientSecret(): string {
	return `iks_${nanoid(43)}`; // indiko secret
}

// Rate limiting for dynamic registration — unauthenticated endpoint
// that inserts DB rows, so cap per-IP to prevent flooding.
const REGISTER_WINDOW_MS = 60 * 1000; // 1 minute
const REGISTER_MAX = 5; // max registrations per window
const registerAttempts = new Map<string, { count: number; resetAt: number }>();

function isRegisterRateLimited(ip: string): boolean {
	// Skip rate limiting in tests
	if (process.env.NODE_ENV === "test") return false;

	const now = Date.now();
	const entry = registerAttempts.get(ip);
	if (!entry || now > entry.resetAt) {
		registerAttempts.set(ip, { count: 1, resetAt: now + REGISTER_WINDOW_MS });
		return false;
	}
	entry.count++;
	return entry.count > REGISTER_MAX;
}

interface RegisterBody {
	redirect_uris?: unknown;
	client_name?: unknown;
	logo_uri?: unknown;
	client_uri?: unknown;
	token_endpoint_auth_method?: unknown;
	grant_types?: unknown;
}

// RFC 7591 §2 defaults grant_types to ["authorization_code"]. We add
// refresh_token so a client that omits the field keeps the behaviour it had
// before the field was read at all.
const DEFAULT_GRANT_TYPES = ["authorization_code", "refresh_token"];

function asStringArray(value: unknown): string[] | null {
	if (!Array.isArray(value)) return null;
	const out: string[] = [];
	for (const item of value) {
		if (typeof item !== "string" || !item.trim()) return null;
		out.push(item);
	}
	return out;
}

function isValidRedirectUri(uri: string): boolean {
	try {
		const url = new URL(uri);
		// Allow http only for loopback (localhost dev)
		if (url.protocol === "http:") {
			return (
				url.hostname === "localhost" ||
				url.hostname === "127.0.0.1" ||
				url.hostname === "[::1]"
			);
		}
		return url.protocol === "https:";
	} catch {
		return false;
	}
}

// POST /oauth/register — RFC 7591 Dynamic Client Registration.
// Registers a confidential client (opaque client_id + client_secret).
// Rate-limited per IP to prevent DB flooding.
export async function registerClient(req: Request): Promise<Response> {
	const clientIp = getClientIp(req);

	if (isRegisterRateLimited(clientIp)) {
		return oauthError(
			429,
			"invalid_client_metadata",
			"Too many registration requests. Please try again later.",
		);
	}

	let body: RegisterBody;
	try {
		body = (await req.json()) as RegisterBody;
	} catch {
		return oauthError(400, "invalid_client_metadata", "Body must be JSON");
	}

	let grantTypes = DEFAULT_GRANT_TYPES;
	if (body.grant_types !== undefined) {
		const requested = asStringArray(body.grant_types);
		if (!requested || requested.length === 0) {
			return oauthError(
				400,
				"invalid_client_metadata",
				"grant_types must be a non-empty array of strings",
			);
		}
		const unsupported = requested.filter(
			(g) => !SUPPORTED_GRANT_TYPES.includes(g as never),
		);
		if (unsupported.length > 0) {
			return oauthError(
				400,
				"invalid_client_metadata",
				`Unsupported grant_types: ${unsupported.join(", ")}`,
			);
		}
		grantTypes = requested;
	}

	// RFC 7591 §2: redirect_uris is required for clients using redirect-based
	// flows. A device-only client has nothing honest to put there, so don't make
	// it invent a placeholder.
	const redirectsRequired = grantTypes.includes("authorization_code");

	// A present-but-malformed redirect_uris is still an error, even when the
	// grant types make it optional. Absent is the only way to skip it.
	const parsedRedirects =
		body.redirect_uris === undefined ? [] : asStringArray(body.redirect_uris);
	if (!parsedRedirects) {
		return oauthError(
			400,
			"invalid_redirect_uri",
			"redirect_uris must be an array of URI strings",
		);
	}
	const redirectUris = parsedRedirects;

	if (redirectsRequired && redirectUris.length === 0) {
		return oauthError(
			400,
			"invalid_redirect_uri",
			"redirect_uris must be a non-empty array of URIs for the authorization_code grant",
		);
	}

	if (redirectUris.length > 10) {
		return oauthError(
			400,
			"invalid_redirect_uri",
			"redirect_uris must contain at most 10 URIs",
		);
	}

	for (const uri of redirectUris) {
		if (!isValidRedirectUri(uri)) {
			return oauthError(
				400,
				"invalid_redirect_uri",
				`Invalid redirect_uri: ${uri}`,
			);
		}
	}

	const clientName =
		typeof body.client_name === "string" ? body.client_name : null;
	const logoUri = typeof body.logo_uri === "string" ? body.logo_uri : null;

	// RFC 7591 §2 / RFC 6749 §2.1: a client that cannot keep a secret should say
	// so and register as public. A CLI shipping one secret in its binary is
	// public no matter what it claims, and a decorative password is worse than
	// none — it invites everyone to treat the client as authenticated.
	const authMethod =
		body.token_endpoint_auth_method === undefined
			? "client_secret_post"
			: body.token_endpoint_auth_method;
	if (authMethod !== "client_secret_post" && authMethod !== "none") {
		return oauthError(
			400,
			"invalid_client_metadata",
			"token_endpoint_auth_method must be client_secret_post or none",
		);
	}
	const isConfidential = authMethod === "client_secret_post";

	const clientId = generateClientId();
	const clientSecret = isConfidential ? generateClientSecret() : null;
	const clientSecretHash = clientSecret ? hashSecret(clientSecret) : null;
	const now = Math.floor(Date.now() / 1000);

	db.query(
		"INSERT INTO apps (client_id, redirect_uris, name, logo_url, is_preregistered, client_secret_hash, grant_types, first_seen, last_used) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)",
	).run(
		clientId,
		JSON.stringify(redirectUris),
		clientName,
		logoUri,
		clientSecretHash,
		JSON.stringify(grantTypes),
		now,
		now,
	);

	const origin = process.env.ORIGIN || "http://localhost:3000";

	// RFC 7591 §3.2.1 registration response. client_secret is returned once,
	// in plaintext, only here; it is never stored or shown again.
	return Response.json(
		{
			client_id: clientId,
			client_secret: clientSecret ?? undefined,
			client_id_issued_at: now,
			// RFC 7591 §3.2.1: client_secret_expires_at only applies when a secret
			// was issued.
			client_secret_expires_at: clientSecret ? 0 : undefined, // 0 = never
			redirect_uris: redirectUris,
			client_name: clientName ?? undefined,
			logo_uri: logoUri ?? undefined,
			token_endpoint_auth_method: authMethod,
			grant_types: grantTypes,
			// RFC 7591 §2: response_types pairs with the authorization_code grant.
			// A device-only client never gets an authorization response.
			response_types: redirectsRequired ? ["code"] : [],
			issuer: origin,
		},
		{ status: 201, headers: NO_STORE_HEADERS },
	);
}
