import { db } from "../../db";
import { verifySecret } from "../secrets";
import { oauthError, unauthorizedResponse } from "./errors";

// Grants indiko can issue tokens for. A DCR client registers a subset.
export const SUPPORTED_GRANT_TYPES = [
	"authorization_code",
	"refresh_token",
	"urn:ietf:params:oauth:grant-type:device_code",
] as const;

export const DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

/**
 * Verify pre-registered client credentials; returns a Response on failure.
 *
 * RFC 6749 §3.2.1: a client that was issued credentials MUST authenticate at
 * the token endpoint. RFC 8628 §3.1 and §3.4 carry that requirement to the
 * device authorization request and to device_code polling, so this applies to
 * every grant, not just authorization_code. Auto-registered (URL) clients are
 * public and have nothing to prove.
 */
export function verifyClientCredentials(
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
		return null; // auto-registered URL client, nothing to check
	}

	// Holding a secret hash is what makes a client confidential. A client that
	// registered with token_endpoint_auth_method "none" — a CLI that cannot keep
	// a secret, say — has none to verify and authenticates by other means: PKCE
	// on the auth-code grant, the device_code itself on the device grant.
	if (!app.client_secret_hash) {
		return null;
	}

	if (!client_secret) {
		return unauthorizedResponse(
			"invalid_client",
			"client_secret is required for this client",
		);
	}

	if (!verifySecret(client_secret, app.client_secret_hash)) {
		return unauthorizedResponse("invalid_client", "Invalid client_secret");
	}

	return null;
}

/**
 * Enforce the grant types a client registered for (RFC 7591 §2).
 *
 * Only DCR clients carry a registered list; NULL means unrestricted, which is
 * every auto-registered URL client and every app that predates the column.
 */
export function verifyGrantAllowed(
	client_id: string | undefined,
	grant: string,
): Response | null {
	if (!client_id) return null;

	const app = db
		.query("SELECT grant_types FROM apps WHERE client_id = ?")
		.get(client_id) as { grant_types: string | null } | undefined;

	if (!app?.grant_types) return null;

	const allowed = JSON.parse(app.grant_types) as string[];
	if (allowed.includes(grant)) return null;

	return oauthError(
		400,
		"unauthorized_client",
		`Client is not registered for grant type ${grant}`,
	);
}
