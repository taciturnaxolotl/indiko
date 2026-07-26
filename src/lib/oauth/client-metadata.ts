import { db } from "../../db";
import { safeFetch, validateExternalURL } from "../ssrf-safe-fetch";
import { canonicalizeURL, isLoopbackURL, validateClientURL } from "./urls";

export interface ClientMetadata {
	client_id: string;
	client_name?: string;
	client_uri?: string;
	logo_uri?: string;
	redirect_uris?: string[];
}

// Fetch client metadata from client_id URL (with SSRF protection)
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
		try {
			const metadata = (await response.json()) as ClientMetadata;

			if (metadata.client_id && metadata.client_id !== clientId) {
				return {
					success: false,
					error: "client_id in metadata does not match URL",
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
		} catch {
			return { success: false, error: "Invalid JSON in client metadata" };
		}
	}

	// HTML: look for <link rel="redirect_uri"> tags
	if (contentType.includes("text/html")) {
		const html = await response.text();

		const redirectUris: string[] = [];
		const linkTagRegex = /<link\s+[^>]*>/gi;

		for (const tagMatch of html.matchAll(linkTagRegex)) {
			const tag = tagMatch[0];
			const rel = tag.match(/rel=["']?([^"'\s>]+)["']?/i)?.[1];
			if (!rel) continue;
			if (!rel.split(/\s+/).includes("redirect_uri")) continue;

			const href = tag.match(/href=["']?([^"'\s>]+)["']?/i)?.[1];
			if (href && !redirectUris.includes(href)) {
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
		const errorBody = await response.text();
		console.error(
			`[verifyDomain] Failed to fetch ${domainUrl}: HTTP ${response.status}`,
			{
				status: response.status,
				contentType: response.headers.get("content-type"),
				bodyPreview: errorBody.substring(0, 200),
			},
		);
		return {
			success: false,
			error: `Failed to fetch domain: HTTP ${response.status}`,
		};
	}

	const html = await response.text();

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
}

// Validate and register app with client information discovery
export async function ensureApp(
	clientId: string,
	redirectUri: string,
): Promise<{
	error?: string;
	app?: AppRecord;
}> {
	const existing = db
		.query("SELECT name, redirect_uris, logo_url FROM apps WHERE client_id = ?")
		.get(clientId) as
		| { name: string | null; redirect_uris: string; logo_url?: string | null }
		| undefined;

	if (existing) {
		db.query("UPDATE apps SET last_used = ? WHERE client_id = ?").run(
			Math.floor(Date.now() / 1000),
			clientId,
		);
		return { app: existing };
	}

	// Validate client URL per IndieAuth spec
	const validation = validateClientURL(clientId);
	if (!validation.valid) {
		return { error: validation.error || "Invalid client URL" };
	}

	const canonicalClientId = validation.canonicalUrl;
	if (!canonicalClientId) {
		return { error: "Invalid client URL" };
	}

	// Fetch client metadata per IndieAuth spec
	const metadataResult = await fetchClientMetadata(canonicalClientId);

	let clientName: string | null = null;
	let logoUrl: string | null = null;
	let allowedRedirectUris: string[] = [];

	const hostsDiffer = (a: string, b: string): boolean => {
		const urlA = new URL(a);
		const urlB = new URL(b);
		return (
			urlA.protocol !== urlB.protocol ||
			urlA.hostname !== urlB.hostname ||
			urlA.port !== urlB.port
		);
	};

	if (metadataResult.success && metadataResult.metadata) {
		clientName = metadataResult.metadata.client_name || null;
		logoUrl = metadataResult.metadata.logo_uri || null;
		allowedRedirectUris = metadataResult.metadata.redirect_uris || [];

		if (allowedRedirectUris.length > 0) {
			if (hostsDiffer(canonicalClientId, redirectUri)) {
				// MUST verify redirect_uri is in published list
				if (!allowedRedirectUris.includes(redirectUri)) {
					return {
						error: `redirect_uri not registered in client metadata. The client published a list of allowed redirect URIs, but ${redirectUri} is not in that list.`,
					};
				}
			} else if (!allowedRedirectUris.includes(redirectUri)) {
				allowedRedirectUris.push(redirectUri);
			}
		} else {
			allowedRedirectUris = [redirectUri];
		}
	} else {
		// Could not fetch metadata - allow only same-host redirects
		if (hostsDiffer(canonicalClientId, redirectUri)) {
			return {
				error: `Could not fetch client metadata to verify redirect_uri. For security, redirect_uri must have same host as client_id, or client must publish redirect_uris. Error: ${metadataResult.error}`,
			};
		}

		allowedRedirectUris = [redirectUri];
	}

	db.query(
		"INSERT INTO apps (client_id, redirect_uris, name, logo_url, is_preregistered, first_seen, last_used) VALUES (?, ?, ?, ?, 0, ?, ?)",
	).run(
		canonicalClientId,
		JSON.stringify(allowedRedirectUris),
		clientName,
		logoUrl,
		Math.floor(Date.now() / 1000),
		Math.floor(Date.now() / 1000),
	);

	const newApp = db
		.query("SELECT name, redirect_uris, logo_url FROM apps WHERE client_id = ?")
		.get(canonicalClientId) as {
		name: string | null;
		redirect_uris: string;
		logo_url?: string | null;
	};

	return { app: newApp };
}
