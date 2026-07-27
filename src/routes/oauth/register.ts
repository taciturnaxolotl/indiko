import { nanoid } from "nanoid";
import { db } from "../../db";
import { NO_STORE_HEADERS, oauthError } from "../../lib/oauth/errors";
import { hashSecret } from "../../lib/secrets";

function generateClientId(): string {
	return `ikc_${nanoid(21)}`; // indiko client
}

function generateClientSecret(): string {
	return `iks_${nanoid(43)}`; // indiko secret
}

interface RegisterBody {
	redirect_uris?: unknown;
	client_name?: unknown;
	logo_uri?: unknown;
	client_uri?: unknown;
	token_endpoint_auth_method?: unknown;
}

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
		return url.protocol === "https:" || url.protocol === "http:";
	} catch {
		return false;
	}
}

// POST /oauth/register — RFC 7591 Dynamic Client Registration.
// Registers a confidential client (opaque client_id + client_secret).
// No auth required per RFC 7591; rate limiting is out of scope here.
export async function registerClient(req: Request): Promise<Response> {
	let body: RegisterBody;
	try {
		body = (await req.json()) as RegisterBody;
	} catch {
		return oauthError(400, "invalid_client_metadata", "Body must be JSON");
	}

	const redirectUris = asStringArray(body.redirect_uris);
	if (!redirectUris || redirectUris.length === 0) {
		return oauthError(
			400,
			"invalid_redirect_uri",
			"redirect_uris must be a non-empty array of URIs",
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

	const clientId = generateClientId();
	const clientSecret = generateClientSecret();
	const clientSecretHash = hashSecret(clientSecret);
	const now = Math.floor(Date.now() / 1000);

	db.query(
		"INSERT INTO apps (client_id, redirect_uris, name, logo_url, is_preregistered, client_secret_hash, first_seen, last_used) VALUES (?, ?, ?, ?, 1, ?, ?, ?)",
	).run(
		clientId,
		JSON.stringify(redirectUris),
		clientName,
		logoUri,
		clientSecretHash,
		now,
		now,
	);

	const origin = process.env.ORIGIN || "http://localhost:3000";

	// RFC 7591 §3.2.1 registration response. client_secret is returned once,
	// in plaintext, only here; it is never stored or shown again.
	return Response.json(
		{
			client_id: clientId,
			client_secret: clientSecret,
			client_id_issued_at: now,
			client_secret_expires_at: 0, // never expires
			redirect_uris: redirectUris,
			client_name: clientName ?? undefined,
			logo_uri: logoUri ?? undefined,
			token_endpoint_auth_method: "client_secret_post",
			grant_types: ["authorization_code", "refresh_token"],
			response_types: ["code"],
			issuer: origin,
		},
		{ status: 201, headers: NO_STORE_HEADERS },
	);
}
