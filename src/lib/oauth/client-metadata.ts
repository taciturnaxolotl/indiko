import { db } from "../../db";
import {
	readBodyCapped,
	safeFetch,
	validateExternalURL,
} from "../ssrf-safe-fetch";
import { canonicalizeURL, isLoopbackURL, validateClientURL } from "./urls";

export interface ClientMetadata {
	client_id: string;
	client_name?: string;
	client_uri?: string;
	logo_uri?: string;
	redirect_uris?: string[];
	token_endpoint_auth_method?: string;
	[key: string]: unknown;
}

// Per the Client ID Metadata Document draft, a public client publishing
// metadata at its URL must not claim a shared-secret auth method.
const SECRET_AUTH_METHODS = new Set([
	"client_secret_post",
	"client_secret_basic",
	"client_secret_jwt",
	"private_key_jwt",
]);

// Draft recommends bounding the metadata document size.
const MAX_METADATA_BYTES = 5 * 1024;
// HTML pages (rel=redirect_uri / rel=me discovery) only need their <head>,
// but sites put a lot before it; 256 KB is generous without being unbounded.
const MAX_HTML_BYTES = 256 * 1024;

// Validate a fetched metadata document against the client_id URL it came
// from. Pure so it's directly testable without a live fetch.
export function validateMetadataDocument(
	text: string,
	clientId: string,
): { success: boolean; metadata?: ClientMetadata; error?: string } {
	if (text.length > MAX_METADATA_BYTES) {
		return { success: false, error: "Client metadata document too large" };
	}

	let metadata: ClientMetadata;
	try {
		metadata = JSON.parse(text) as ClientMetadata;
	} catch {
		return { success: false, error: "Invalid JSON in client metadata" };
	}

	if (metadata.client_id && metadata.client_id !== clientId) {
		return {
			success: false,
			error: "client_id in metadata does not match URL",
		};
	}

	// Public clients publishing metadata must not request a shared-secret
	// auth method; there's no registration step to establish one.
	if (
		metadata.token_endpoint_auth_method &&
		SECRET_AUTH_METHODS.has(metadata.token_endpoint_auth_method)
	) {
		return {
			success: false,
			error: `token_endpoint_auth_method "${metadata.token_endpoint_auth_method}" is not allowed for URL-based clients`,
		};
	}

	// Validate metadata URL fields to prevent SSRF via later fetches
	if (metadata.logo_uri) {
		const logoValidation = validateExternalURL(metadata.logo_uri);
		if (!logoValidation.safe) {
			delete metadata.logo_uri;
		}
	}

	if (metadata.client_uri) {
		const clientUriValidation = validateExternalURL(metadata.client_uri);
		if (!clientUriValidation.safe) {
			delete metadata.client_uri;
		}
	}

	return { success: true, metadata };
}

export async function fetchClientMetadata(clientId: string): Promise<{
	success: boolean;
	metadata?: ClientMetadata;
	error?: string;
}> {
	const urlValidation = validateExternalURL(clientId);
	if (!urlValidation.safe) {
		return {
			success: false,
			error: urlValidation.error || "Invalid client_id URL",
		};
	}

	// IndieAuth spec: MUST NOT fetch loopback addresses
	if (isLoopbackURL(clientId)) {
		return {
			success: false,
			error: "Cannot fetch metadata from loopback addresses",
		};
	}

	const fetchResult = await safeFetch(clientId, { timeout: 5000 });
	if (!fetchResult.success) {
		return {
			success: false,
			error: `Failed to fetch client metadata: ${fetchResult.error}`,
		};
	}

	const response = fetchResult.data;

	if (!response.ok) {
		return {
			success: false,
			error: `Failed to fetch client metadata: HTTP ${response.status}`,
		};
	}

	const contentType = response.headers.get("content-type") || "";

	if (contentType.includes("application/json")) {
		// Read one byte past the cap so an oversized document is still
		// reported as too large rather than silently truncated into validity.
		const body = await readBodyCapped(response, MAX_METADATA_BYTES + 1);
		if (!body) {
			return { success: false, error: "Timed out reading client metadata" };
		}
		return validateMetadataDocument(body.text, clientId);
	}

	// HTML: look for <link rel="redirect_uri"> tags
	if (contentType.includes("text/html")) {
		const body = await readBodyCapped(response, MAX_HTML_BYTES);
		if (!body) {
			return { success: false, error: "Timed out reading client page" };
		}
		const html = body.text;

		const redirectUris: string[] = [];
		const linkTagRegex = /<link\s+[^>]*>/gi;

		for (const tagMatch of html.matchAll(linkTagRegex)) {
			const tag = tagMatch[0];
			const rel = tag.match(/rel=["']?([^"'\s>]+)["']?/i)?.[1];
			if (!rel) continue;
			if (!rel.split(/\s+/).includes("redirect_uri")) continue;

			const rawHref = tag.match(/href=["']?([^"'\s>]+)["']?/i)?.[1];
			if (!rawHref) continue;
			let href: string;
			try {
				// rel=redirect_uri links may be relative to the client_id document
				href = new URL(rawHref, clientId).toString();
			} catch {
				continue;
			}
			if (!redirectUris.includes(href)) {
				redirectUris.push(href);
			}
		}

		if (redirectUris.length > 0) {
			return {
				success: true,
				metadata: {
					client_id: clientId,
					redirect_uris: redirectUris,
				},
			};
		}

		return {
			success: false,
			error: "No client metadata or redirect_uri links found in HTML",
		};
	}

	return { success: false, error: "Unsupported content type" };
}

// Verify domain has rel="me" link back to user profile (with SSRF protection)
export async function verifyDomain(
	domainUrl: string,
	indikoProfileUrl: string,
): Promise<{
	success: boolean;
	error?: string;
}> {
	const urlValidation = validateExternalURL(domainUrl);
	if (!urlValidation.safe) {
		return {
			success: false,
			error: urlValidation.error || "Invalid domain URL",
		};
	}

	const fetchResult = await safeFetch(domainUrl, {
		timeout: 5000,
		headers: {
			Accept: "text/html",
			"User-Agent": "indiko/1.0 (+https://indiko.dunkirk.sh/)",
		},
	});

	if (!fetchResult.success) {
		console.error(
			`[verifyDomain] Failed to fetch ${domainUrl}: ${fetchResult.error}`,
		);
		return {
			success: false,
			error: `Failed to fetch domain: ${fetchResult.error}`,
		};
	}

	const response = fetchResult.data;

	if (!response.ok) {
		const errorBody = await readBodyCapped(response, 1024);
		console.error(
			`[verifyDomain] Failed to fetch ${domainUrl}: HTTP ${response.status}`,
			{
				status: response.status,
				contentType: response.headers.get("content-type"),
				bodyPreview: (errorBody?.text ?? "").substring(0, 200),
			},
		);
		return {
			success: false,
			error: `Failed to fetch domain: HTTP ${response.status}`,
		};
	}

	const body = await readBodyCapped(response, MAX_HTML_BYTES);
	if (!body) {
		return { success: false, error: "Timed out reading your site" };
	}
	const html = body.text;

	// Find all <link> and <a> tags with rel containing "me", collect their hrefs
	const relMeLinks: string[] = [];
	const tagRegex = /<(?:link|a)\s+[^>]*>/gi;

	for (const tagMatch of html.matchAll(tagRegex)) {
		const tag = tagMatch[0];
		const rel = tag.match(/rel=["']?([^"'\s>]+)["']?/i)?.[1];
		if (!rel) continue;
		if (!rel.split(/\s+/).includes("me")) continue;

		const href = tag.match(/href=["']?([^"'\s>]+)["']?/i)?.[1];
		if (href && !relMeLinks.includes(href)) {
			relMeLinks.push(href);
		}
	}

	const normalizedIndikoUrl = canonicalizeURL(indikoProfileUrl);
	const hasRelMe = relMeLinks.some((link) => {
		try {
			return canonicalizeURL(link) === normalizedIndikoUrl;
		} catch {
			return false;
		}
	});

	if (!hasRelMe) {
		console.error(
			`[verifyDomain] No rel="me" link found on ${domainUrl} pointing to ${indikoProfileUrl}`,
			{
				foundLinks: relMeLinks,
				normalizedTarget: normalizedIndikoUrl,
			},
		);
		return {
			success: false,
			error: `Your site must link back to ${indikoProfileUrl} with rel="me" to verify you own it. Add a link tag or anchor with rel="me" pointing to that URL, then try again.`,
		};
	}

	return { success: true };
}

export interface AppRecord {
	name: string | null;
	redirect_uris: string;
	logo_url?: string | null;
	is_preregistered?: number;
}

export type EnsureAppErrorCode = "invalid_client" | "invalid_redirect";

/**
 * True when two http(s) URLs share scheme, host and port. Credentials in the
 * authority (https://client-host@other-host/) do not count: URL parsing puts
 * them in username/password, and `origin` ignores them.
 */
export function sameOrigin(a: string, b: string): boolean {
	try {
		const urlA = new URL(a);
		const urlB = new URL(b);
		if (urlA.origin === "null" || urlB.origin === "null") return false;
		return urlA.origin === urlB.origin;
	} catch {
		return false;
	}
}

/**
 * Decide whether a redirect_uri may be used with a client, given the client's
 * published redirect list (IndieAuth §4.2.2, Client ID Metadata Document).
 *
 * - A pre-registered (admin-created) client gets exact matching only.
 * - A URL client that publishes a redirect_uris list is held to that list,
 *   exactly: prefix matches and extra query parameters are not matches.
 * - A URL client that publishes nothing may only redirect back to its own
 *   origin, which is the only place the spec lets us trust without a list.
 */
export function isRedirectAllowed(
	app: { is_preregistered?: number; redirect_uris: string },
	clientId: string,
	redirectUri: string,
): boolean {
	let published: string[];
	try {
		published = JSON.parse(app.redirect_uris) as string[];
	} catch {
		published = [];
	}
	if (!Array.isArray(published)) published = [];

	// The request side arrives canonicalized; hold the registered side to the
	// same form so a hostname case or a bare-origin slash cannot split them.
	const listed = published.some((entry) => {
		if (typeof entry !== "string") return false;
		if (entry === redirectUri) return true;
		try {
			return canonicalizeURL(entry) === redirectUri;
		} catch {
			return false;
		}
	});

	if (app.is_preregistered === 1 || published.length > 0) {
		return listed;
	}
	return sameOrigin(clientId, redirectUri);
}

// Re-fetching metadata on every miss would let a client_id turn the auth
// endpoint into a fetch amplifier. One refresh per client per minute is plenty:
// a client that just published a new redirect URI can wait that long.
const METADATA_REFRESH_INTERVAL_MS = 60 * 1000;
const metadataLastFetched = new Map<string, number>();

function canRefreshMetadata(clientId: string): boolean {
	if (process.env.NODE_ENV === "test") return true;
	const last = metadataLastFetched.get(clientId) ?? 0;
	return Date.now() - last > METADATA_REFRESH_INTERVAL_MS;
}

/**
 * Fetch the client's metadata and fold it into the apps row. Returns the
 * published redirect list (empty when the client publishes none), or null
 * when the document could not be fetched or was not trustworthy.
 */
async function refreshClientMetadata(
	clientId: string,
	existing: boolean,
): Promise<string[] | null> {
	metadataLastFetched.set(clientId, Date.now());
	const result = await fetchClientMetadata(clientId);
	if (!result.success || !result.metadata) {
		return null;
	}

	const published = Array.isArray(result.metadata.redirect_uris)
		? result.metadata.redirect_uris.filter((u) => typeof u === "string")
		: [];
	const name = result.metadata.client_name || null;
	const logo = result.metadata.logo_uri || null;
	const now = Math.floor(Date.now() / 1000);

	if (existing) {
		db.query(
			"UPDATE apps SET redirect_uris = ?, name = ?, logo_url = ?, last_used = ? WHERE client_id = ? AND is_preregistered = 0",
		).run(JSON.stringify(published), name, logo, now, clientId);
	} else {
		db.query(
			"INSERT INTO apps (client_id, redirect_uris, name, logo_url, is_preregistered, registration, first_seen, last_used) VALUES (?, ?, ?, ?, 0, 'url', ?, ?)",
		).run(clientId, JSON.stringify(published), name, logo, now, now);
	}

	return published;
}

function loadApp(clientId: string): AppRecord | undefined {
	// bun:sqlite returns null for a miss; normalize so callers can use `?.`
	// and truthiness without caring which empty value they got.
	return (
		(db
			.query(
				"SELECT name, redirect_uris, logo_url, is_preregistered FROM apps WHERE client_id = ?",
			)
			.get(clientId) as AppRecord | null) ?? undefined
	);
}

/**
 * Resolve the client for an authorization request and decide whether the
 * requested redirect_uri belongs to it. On success the returned app is the
 * current row; on failure `code` says whether the client or the redirect was
 * the problem so the caller can pick the right error page.
 *
 * URL clients are registered on first sight and their metadata is refreshed
 * whenever a redirect_uri is not already covered, so a client that publishes a
 * new redirect URI does not stay frozen at what it said the first time.
 */
export async function ensureApp(
	clientId: string,
	redirectUri: string | null,
): Promise<{
	error?: string;
	code?: EnsureAppErrorCode;
	app?: AppRecord;
}> {
	const existing = loadApp(clientId);
	const allowed = (app: AppRecord): boolean =>
		redirectUri === null || isRedirectAllowed(app, clientId, redirectUri);

	if (existing?.is_preregistered === 1) {
		db.query("UPDATE apps SET last_used = ? WHERE client_id = ?").run(
			Math.floor(Date.now() / 1000),
			clientId,
		);
		if (!allowed(existing)) {
			return {
				code: "invalid_redirect",
				error: "redirect_uri is not registered for this client",
			};
		}
		return { app: existing };
	}

	// Validate client URL per IndieAuth spec
	const validation = validateClientURL(clientId);
	if (!validation.valid) {
		return {
			code: "invalid_client",
			error: validation.error || "Invalid client URL",
		};
	}

	if (existing) {
		db.query("UPDATE apps SET last_used = ? WHERE client_id = ?").run(
			Math.floor(Date.now() / 1000),
			clientId,
		);
		if (allowed(existing)) {
			return { app: existing };
		}
		if (!canRefreshMetadata(clientId)) {
			return {
				code: "invalid_redirect",
				error: `redirect_uri is not in the client's published redirect_uris, and ${redirectUri} is not on the client's origin.`,
			};
		}
	}

	const published = await refreshClientMetadata(clientId, Boolean(existing));

	if (published === null) {
		// Nothing trustworthy to go on: only the client's own origin is safe.
		if (redirectUri !== null && !sameOrigin(clientId, redirectUri)) {
			return {
				code: "invalid_redirect",
				error:
					"Could not fetch client metadata to verify redirect_uri. For security, redirect_uri must have the same origin as client_id, or the client must publish redirect_uris.",
			};
		}
		if (!existing) {
			const now = Math.floor(Date.now() / 1000);
			db.query(
				"INSERT INTO apps (client_id, redirect_uris, name, logo_url, is_preregistered, registration, first_seen, last_used) VALUES (?, ?, NULL, NULL, 0, 'url', ?, ?)",
			).run(clientId, "[]", now, now);
		} else {
			// Rows written before metadata was refreshed on demand stored the
			// first redirect seen rather than the published list. When that
			// stored list is all same-origin anyway, fold it into the
			// same-origin rule so the next sibling path does not wait a minute.
			const stored = JSON.parse(existing.redirect_uris) as string[];
			if (stored.length > 0 && stored.every((u) => sameOrigin(clientId, u))) {
				db.query(
					"UPDATE apps SET redirect_uris = '[]' WHERE client_id = ? AND is_preregistered = 0",
				).run(clientId);
			}
		}
		return { app: loadApp(clientId) };
	}

	const fresh = loadApp(clientId);
	if (!fresh || !allowed(fresh)) {
		return {
			code: "invalid_redirect",
			error:
				published.length > 0
					? `redirect_uri not registered in client metadata. The client published a list of allowed redirect URIs, but ${redirectUri} is not in that list.`
					: "The client publishes no redirect_uris, so redirect_uri must have the same origin as client_id.",
		};
	}

	return { app: fresh };
}
