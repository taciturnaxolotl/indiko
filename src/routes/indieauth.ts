import crypto from "crypto";
import { db } from "../db";

interface SessionUser {
	username: string;
	userId: number;
	isAdmin: boolean;
}

// Helper to get authenticated user from session token
function getSessionUser(req: Request): SessionUser | Response {
	const authHeader = req.headers.get("Authorization");

	if (!authHeader || !authHeader.startsWith("Bearer ")) {
		return Response.json({ error: "Unauthorized" }, { status: 401 });
	}

	const token = authHeader.substring(7);

	const session = db
		.query(
			`SELECT s.expires_at, u.id, u.username, u.is_admin, u.status 
			FROM sessions s 
			JOIN users u ON s.user_id = u.id 
			WHERE s.token = ?`,
		)
		.get(token) as
		| {
				expires_at: number;
				id: number;
				username: string;
				is_admin: number;
				status: string;
		  }
		| undefined;

	if (!session) {
		return Response.json({ error: "Invalid session" }, { status: 401 });
	}

	const now = Math.floor(Date.now() / 1000);
	if (session.expires_at < now) {
		return Response.json({ error: "Session expired" }, { status: 401 });
	}

	if (session.status !== "active") {
		return Response.json({ error: "Account is suspended" }, { status: 403 });
	}

	return {
		username: session.username,
		userId: session.id,
		isAdmin: session.is_admin === 1,
	};
}

// Helper to get user from session cookie
function getUserFromCookie(req: Request): SessionUser | null {
	const cookieHeader = req.headers.get("Cookie");
	if (!cookieHeader) return null;

	const cookies = Object.fromEntries(
		cookieHeader.split("; ").map((c) => {
			const [key, ...v] = c.split("=");
			return [key, v.join("=")];
		}),
	);

	const sessionToken = cookies["indiko_session"];
	if (!sessionToken) return null;

	const session = db
		.query(
			`SELECT s.expires_at, u.id, u.username, u.is_admin, u.status 
			FROM sessions s 
			JOIN users u ON s.user_id = u.id 
			WHERE s.token = ?`,
		)
		.get(sessionToken) as
		| {
				expires_at: number;
				id: number;
				username: string;
				is_admin: number;
				status: string;
		  }
		| undefined;

	if (!session) return null;

	const now = Math.floor(Date.now() / 1000);
	if (session.expires_at < now) return null;

	if (session.status !== "active") return null;

	return {
		username: session.username,
		userId: session.id,
		isAdmin: session.is_admin === 1,
	};
}

// Verify PKCE code challenge
function verifyPKCE(verifier: string, challenge: string): boolean {
	const hash = crypto.createHash("sha256").update(verifier).digest("base64url");
	return hash === challenge;
}

// Canonicalize URL per IndieAuth spec
function canonicalizeURL(urlString: string): string {
	const url = new URL(urlString);
	// Lowercase hostname per spec
	url.hostname = url.hostname.toLowerCase();
	// Add / path if missing
	if (!url.pathname || url.pathname === "") {
		url.pathname = "/";
	}
	return url.toString();
}

// Validate profile URL per IndieAuth spec
function validateProfileURL(urlString: string): { valid: boolean; error?: string; canonicalUrl?: string } {
	let url: URL;
	try {
		url = new URL(urlString);
	} catch {
		return { valid: false, error: "Invalid URL format" };
	}

	// MUST use http or https scheme
	if (url.protocol !== "http:" && url.protocol !== "https:") {
		return { valid: false, error: "Profile URL must use http or https scheme" };
	}

	// MUST contain path component (/ is valid)
	if (!url.pathname) {
		url.pathname = "/";
	}

	// MUST NOT contain fragments
	if (url.hash) {
		return { valid: false, error: "Profile URL must not contain fragments" };
	}

	// MUST NOT contain username/password
	if (url.username || url.password) {
		return { valid: false, error: "Profile URL must not contain username or password" };
	}

	// MUST NOT contain ports
	if (url.port) {
		return { valid: false, error: "Profile URL must not contain ports" };
	}

	// MUST NOT use IP addresses
	const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
	const ipv6Regex = /^\[?[0-9a-fA-F:]+\]?$/;
	if (ipv4Regex.test(url.hostname) || ipv6Regex.test(url.hostname)) {
		return { valid: false, error: "Profile URL must use domain names, not IP addresses" };
	}

	// MUST NOT contain single-dot or double-dot path segments
	const pathSegments = url.pathname.split("/");
	if (pathSegments.includes(".") || pathSegments.includes("..")) {
		return { valid: false, error: "Profile URL must not contain . or .. path segments" };
	}

	return { valid: true, canonicalUrl: canonicalizeURL(urlString) };
}

// Validate client URL per IndieAuth spec
function validateClientURL(urlString: string): { valid: boolean; error?: string; canonicalUrl?: string } {
	let url: URL;
	try {
		url = new URL(urlString);
	} catch {
		return { valid: false, error: "Invalid URL format" };
	}

	// MUST use http or https scheme
	if (url.protocol !== "http:" && url.protocol !== "https:") {
		return { valid: false, error: "Client URL must use http or https scheme" };
	}

	// MUST contain path component (/ is valid)
	if (!url.pathname) {
		url.pathname = "/";
	}

	// MUST NOT contain fragments
	if (url.hash) {
		return { valid: false, error: "Client URL must not contain fragments" };
	}

	// MUST NOT contain username/password
	if (url.username || url.password) {
		return { valid: false, error: "Client URL must not contain username or password" };
	}

	// MUST NOT contain single-dot or double-dot path segments
	const pathSegments = url.pathname.split("/");
	if (pathSegments.includes(".") || pathSegments.includes("..")) {
		return { valid: false, error: "Client URL must not contain . or .. path segments" };
	}

	// MAY use loopback interface, but not other IP addresses
	const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
	const ipv6Regex = /^\[?([0-9a-fA-F:]+)\]?$/;
	if (ipv4Regex.test(url.hostname)) {
		// Allow 127.0.0.1 (loopback), reject others
		if (!url.hostname.startsWith("127.")) {
			return { valid: false, error: "Client URL must use domain names, not IP addresses (except loopback)" };
		}
	} else if (ipv6Regex.test(url.hostname)) {
		// Allow ::1 (loopback), reject others
		const ipv6Match = url.hostname.match(ipv6Regex);
		if (ipv6Match && ipv6Match[1] !== "::1") {
			return { valid: false, error: "Client URL must use domain names, not IP addresses (except loopback)" };
		}
	}

	return { valid: true, canonicalUrl: canonicalizeURL(urlString) };
}

// Check if URL is a loopback address
function isLoopbackURL(urlString: string): boolean {
	try {
		const url = new URL(urlString);
		return url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]" || url.hostname.startsWith("127.");
	} catch {
		return false;
	}
}

// Fetch client metadata from client_id URL
async function fetchClientMetadata(clientId: string): Promise<{
	success: boolean;
	metadata?: {
		client_id: string;
		client_name?: string;
		client_uri?: string;
		logo_uri?: string;
		redirect_uris?: string[];
	};
	error?: string;
}> {
	// MUST NOT fetch loopback addresses (security requirement)
	if (isLoopbackURL(clientId)) {
		return { success: false, error: "Cannot fetch metadata from loopback addresses" };
	}

	try {
		// Set timeout for fetch to prevent hanging
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout

		const response = await fetch(clientId, {
			method: "GET",
			headers: {
				Accept: "application/json, text/html",
			},
			signal: controller.signal,
		});

		clearTimeout(timeoutId);

		if (!response.ok) {
			return { success: false, error: `Failed to fetch client metadata: HTTP ${response.status}` };
		}

		const contentType = response.headers.get("content-type") || "";

		// Try to parse as JSON first
		if (contentType.includes("application/json")) {
			const metadata = await response.json();

			// Verify client_id matches
			if (metadata.client_id && metadata.client_id !== clientId) {
				return { success: false, error: "client_id in metadata does not match URL" };
			}

			return { success: true, metadata };
		}

		// If HTML, look for <link rel="redirect_uri"> tags
		if (contentType.includes("text/html")) {
			const html = await response.text();

			// Extract redirect URIs from link tags
			const redirectUriRegex = /<link\s+[^>]*rel=["']redirect_uri["'][^>]*href=["']([^"']+)["'][^>]*>/gi;
			const redirectUris: string[] = [];
			let match: RegExpExecArray | null;

			while ((match = redirectUriRegex.exec(html)) !== null) {
				redirectUris.push(match[1]);
			}

			// Also try reverse order (href before rel)
			const redirectUriRegex2 = /<link\s+[^>]*href=["']([^"']+)["'][^>]*rel=["']redirect_uri["'][^>]*>/gi;
			while ((match = redirectUriRegex2.exec(html)) !== null) {
				if (!redirectUris.includes(match[1])) {
					redirectUris.push(match[1]);
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

			return { success: false, error: "No client metadata or redirect_uri links found in HTML" };
		}

		return { success: false, error: "Unsupported content type" };
	} catch (error) {
		if (error instanceof Error) {
			if (error.name === "AbortError") {
				return { success: false, error: "Timeout fetching client metadata" };
			}
			return { success: false, error: `Failed to fetch client metadata: ${error.message}` };
		}
		return { success: false, error: "Failed to fetch client metadata" };
	}
}

// Verify domain has rel="me" link back to user profile
export async function verifyDomain(domainUrl: string, indikoProfileUrl: string): Promise<{
	success: boolean;
	error?: string;
}> {
	try {
		// Set timeout for fetch
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 5000);

		const response = await fetch(domainUrl, {
			method: "GET",
			headers: {
				Accept: "text/html",
				"User-Agent": "indiko/1.0 (+https://indiko.dunkirk.sh/)",
			},
			signal: controller.signal,
		});

		clearTimeout(timeoutId);

		if (!response.ok) {
			const errorBody = await response.text();
			console.error(`[verifyDomain] Failed to fetch ${domainUrl}: HTTP ${response.status}`, {
				status: response.status,
				contentType: response.headers.get("content-type"),
				bodyPreview: errorBody.substring(0, 200),
			});
			return { success: false, error: `Failed to fetch domain: HTTP ${response.status}` };
		}

		const html = await response.text();

		// Extract rel="me" links using regex
		// Matches both <link> and <a> tags with rel attribute containing "me"
		const relMeLinks: string[] = [];

		// Simpler approach: find all link and a tags, then check if they have rel="me" and href
		const linkRegex = /<link\s+[^>]*>/gi;
		const aRegex = /<a\s+[^>]*>/gi;

		const processTag = (tagHtml: string) => {
			// Check if has rel containing "me" (handle quoted and unquoted attributes)
			const relMatch = tagHtml.match(/rel=["']?([^"'\s>]+)["']?/i);
			if (!relMatch) return null;

			const relValue = relMatch[1];
			// Check if "me" is a separate word in the rel attribute
			if (!relValue.split(/\s+/).includes("me")) return null;

			// Extract href (handle quoted and unquoted attributes)
			const hrefMatch = tagHtml.match(/href=["']?([^"'\s>]+)["']?/i);
			if (!hrefMatch) return null;

			return hrefMatch[1];
		};

		// Process all link tags
		let linkMatch;
		while ((linkMatch = linkRegex.exec(html)) !== null) {
			const href = processTag(linkMatch[0]);
			if (href && !relMeLinks.includes(href)) {
				relMeLinks.push(href);
			}
		}

		// Process all a tags
		let aMatch;
		while ((aMatch = aRegex.exec(html)) !== null) {
			const href = processTag(aMatch[0]);
			if (href && !relMeLinks.includes(href)) {
				relMeLinks.push(href);
			}
		}

		// Check if any rel="me" link matches the indiko profile URL
		const normalizedIndikoUrl = canonicalizeURL(indikoProfileUrl);
		const hasRelMe = relMeLinks.some(link => {
			try {
				const normalizedLink = canonicalizeURL(link);
				return normalizedLink === normalizedIndikoUrl;
			} catch {
				return false;
			}
		});

		if (!hasRelMe) {
			console.error(`[verifyDomain] No rel="me" link found on ${domainUrl} pointing to ${indikoProfileUrl}`, {
				foundLinks: relMeLinks,
				normalizedTarget: normalizedIndikoUrl,
			});
			return {
				success: false,
				error: `Domain must have <link rel="me" href="${indikoProfileUrl}" /> or <a rel="me" href="${indikoProfileUrl}">...</a> to verify ownership`,
			};
		}

		return { success: true };
	} catch (error) {
		if (error instanceof Error) {
			if (error.name === "AbortError") {
				console.error(`[verifyDomain] Timeout verifying ${domainUrl}`);
				return { success: false, error: "Timeout verifying domain" };
			}
			console.error(`[verifyDomain] Error verifying ${domainUrl}: ${error.message}`, {
				name: error.name,
				stack: error.stack,
			});
			return { success: false, error: `Failed to verify domain: ${error.message}` };
		}
		console.error(`[verifyDomain] Unknown error verifying ${domainUrl}:`, error);
		return { success: false, error: "Failed to verify domain" };
	}
}

// Validate and register app with client information discovery
async function ensureApp(
	clientId: string,
	redirectUri: string,
): Promise<{
	error?: string;
	app?: { name: string | null; redirect_uris: string; logo_url?: string | null };
}> {
	const existing = db
		.query("SELECT name, redirect_uris, logo_url FROM apps WHERE client_id = ?")
		.get(clientId) as
		| { name: string | null; redirect_uris: string; logo_url?: string | null }
		| undefined;

	if (!existing) {
		// Validate client URL per IndieAuth spec
		const validation = validateClientURL(clientId);
		if (!validation.valid) {
			return {
				error: validation.error || "Invalid client URL",
			};
		}

		const canonicalClientId = validation.canonicalUrl!;

		// Fetch client metadata per IndieAuth spec
		const metadataResult = await fetchClientMetadata(canonicalClientId);

		let clientName: string | null = null;
		let logoUrl: string | null = null;
		let allowedRedirectUris: string[] = [];

		if (metadataResult.success && metadataResult.metadata) {
			// Use metadata from client
			clientName = metadataResult.metadata.client_name || null;
			logoUrl = metadataResult.metadata.logo_uri || null;
			allowedRedirectUris = metadataResult.metadata.redirect_uris || [];

			// Validate redirect_uri if client published redirect_uris
			if (allowedRedirectUris.length > 0) {
				// Check if redirect_uri host differs from client_id host
				const clientUrl = new URL(canonicalClientId);
				const redirectUrl = new URL(redirectUri);

				const hostsDiffer =
					clientUrl.protocol !== redirectUrl.protocol ||
					clientUrl.hostname !== redirectUrl.hostname ||
					clientUrl.port !== redirectUrl.port;

				if (hostsDiffer) {
					// MUST verify redirect_uri is in published list
					if (!allowedRedirectUris.includes(redirectUri)) {
						return {
							error: `redirect_uri not registered in client metadata. The client published a list of allowed redirect URIs, but ${redirectUri} is not in that list.`,
						};
					}
				} else {
					// Same host - add to allowed list if not present
					if (!allowedRedirectUris.includes(redirectUri)) {
						allowedRedirectUris.push(redirectUri);
					}
				}
			} else {
				// No redirect_uris published - allow this one
				allowedRedirectUris = [redirectUri];
			}
		} else {
			// Could not fetch metadata - allow for now but only same-host redirects
			const clientUrl = new URL(canonicalClientId);
			const redirectUrl = new URL(redirectUri);

			const hostsDiffer =
				clientUrl.protocol !== redirectUrl.protocol ||
				clientUrl.hostname !== redirectUrl.hostname ||
				clientUrl.port !== redirectUrl.port;

			if (hostsDiffer) {
				return {
					error: `Could not fetch client metadata to verify redirect_uri. For security, redirect_uri must have same host as client_id, or client must publish redirect_uris. Error: ${metadataResult.error}`,
				};
			}

			allowedRedirectUris = [redirectUri];
		}

		// New app - auto-register
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

		// Fetch the newly created app
		const newApp = db
			.query("SELECT name, redirect_uris, logo_url FROM apps WHERE client_id = ?")
			.get(canonicalClientId) as { name: string | null; redirect_uris: string; logo_url?: string | null };

		return { app: newApp };
	}

	// Update last_used
	db.query("UPDATE apps SET last_used = ? WHERE client_id = ?").run(
		Math.floor(Date.now() / 1000),
		clientId,
	);

	return { app: existing };
}

// GET /auth/authorize - Authorization request
export async function authorizeGet(req: Request): Promise<Response> {
	const url = new URL(req.url);
	const params = url.searchParams;

	// Validate required OAuth 2.0 parameters
	const responseType = params.get("response_type");
	const clientId = params.get("client_id");
	const redirectUri = params.get("redirect_uri");
	const state = params.get("state");
	const codeChallenge = params.get("code_challenge");
	const codeChallengeMethod = params.get("code_challenge_method");
	const scope = params.get("scope") || "profile";
	const me = params.get("me");

	if (responseType !== "code") {
		return new Response("Unsupported response_type", { status: 400 });
	}

	if (!clientId || !redirectUri || !state || !codeChallenge) {
		return new Response("Missing required parameters", { status: 400 });
	}

	// Validate redirect_uri is a valid URL
	try {
		new URL(redirectUri);
	} catch {
		return new Response(
			`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Invalid Redirect URI • Indiko</title>
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300..700&display=swap" rel="stylesheet">
	<style>
		:root {
			--mahogany: #26242b;
			--lavender: #d9d0de;
			--old-rose: #bc8da0;
			--rosewood: #a04668;
			--berry-crush: #ab4967;
		}
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body {
			font-family: "Space Grotesk", sans-serif;
			background: var(--mahogany);
			color: var(--lavender);
			min-height: 100vh;
			display: flex;
			align-items: center;
			justify-content: center;
			padding: 2rem;
		}
		.error-box {
			max-width: 500px;
			background: rgba(188, 141, 160, 0.05);
			border: 2px solid var(--rosewood);
			padding: 2.5rem;
		}
		h1 {
			font-size: 2rem;
			font-weight: 700;
			background: linear-gradient(135deg, var(--old-rose), var(--rosewood));
			-webkit-background-clip: text;
			-webkit-text-fill-color: transparent;
			background-clip: text;
			margin-bottom: 1.5rem;
			letter-spacing: -0.05rem;
		}
		p {
			line-height: 1.8;
			margin-bottom: 1rem;
			color: var(--lavender);
		}
		code {
			background: rgba(12, 23, 19, 0.8);
			padding: 0.25rem 0.5rem;
			color: var(--berry-crush);
			font-size: 0.875rem;
			word-break: break-all;
			display: inline-block;
			max-width: 100%;
		}
		.error-details {
			background: rgba(160, 70, 104, 0.1);
			border-left: 4px solid var(--rosewood);
			padding: 1rem;
			margin-top: 1.5rem;
		}
		.error-details strong {
			display: block;
			margin-bottom: 0.5rem;
			color: var(--old-rose);
		}
	</style>
</head>
<body>
	<div class="error-box">
		<h1>Invalid Redirect URI</h1>
		<p>
			The OAuth authorization request failed because the provided <code>redirect_uri</code> is not a valid URL.
		</p>
		<div class="error-details">
			<strong>Provided redirect_uri:</strong>
			<code>${redirectUri}</code>
		</div>
		<p style="margin-top: 1.5rem; font-size: 0.875rem; color: var(--old-rose);">
			The redirect URI must be a valid, absolute URL (e.g., https://example.com/callback).
		</p>
	</div>
</body>
</html>`,
			{
				status: 400,
				headers: { "Content-Type": "text/html" },
			},
		);
	}

	if (codeChallengeMethod && codeChallengeMethod !== "S256") {
		return new Response("Only S256 code_challenge_method supported", {
			status: 400,
		});
	}

	// Verify app is registered
	const appResult = await ensureApp(clientId, redirectUri);

	if (appResult.error) {
		return new Response(
			`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Invalid Client ID • Indiko</title>
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300..700&display=swap" rel="stylesheet">
	<style>
		:root {
			--mahogany: #26242b;
			--lavender: #d9d0de;
			--old-rose: #bc8da0;
			--rosewood: #a04668;
			--berry-crush: #ab4967;
		}
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body {
			font-family: "Space Grotesk", sans-serif;
			background: var(--mahogany);
			color: var(--lavender);
			min-height: 100vh;
			display: flex;
			align-items: center;
			justify-content: center;
			padding: 2rem;
		}
		.error-box {
			max-width: 600px;
			background: rgba(188, 141, 160, 0.05);
			border: 2px solid var(--rosewood);
			padding: 2.5rem;
		}
		h1 {
			font-size: 2rem;
			font-weight: 700;
			background: linear-gradient(135deg, var(--old-rose), var(--rosewood));
			-webkit-background-clip: text;
			-webkit-text-fill-color: transparent;
			background-clip: text;
			margin-bottom: 1.5rem;
			letter-spacing: -0.05rem;
		}
		p {
			line-height: 1.8;
			margin-bottom: 1rem;
			color: var(--lavender);
		}
		code {
			background: rgba(12, 23, 19, 0.8);
			padding: 0.25rem 0.5rem;
			color: var(--berry-crush);
			font-size: 0.875rem;
			word-break: break-all;
			display: inline-block;
			max-width: 100%;
		}
		.error-details {
			background: rgba(160, 70, 104, 0.1);
			border-left: 4px solid var(--rosewood);
			padding: 1rem;
			margin: 1.5rem 0;
		}
		.error-details strong {
			display: block;
			margin-bottom: 0.5rem;
			color: var(--old-rose);
		}
	</style>
</head>
<body>
	<div class="error-box">
		<h1>Invalid Client ID</h1>
		<p>
			The OAuth authorization request failed because the provided <code>client_id</code> is not valid.
		</p>
		<div class="error-details">
			<strong>Error:</strong>
			<p>${appResult.error}</p>
		</div>
		<div class="error-details">
			<strong>Provided client_id:</strong>
			<code>${clientId}</code>
		</div>
		<p style="margin-top: 1.5rem; font-size: 0.875rem; color: var(--old-rose);">
			For auto-registration, the client_id must be a valid URL (e.g., https://example.com). 
			Non-URL client IDs (like <code>ikc_xxxxx</code>) must be pre-registered by an administrator.
		</p>
	</div>
</body>
</html>`,
			{
				status: 400,
				headers: { "Content-Type": "text/html" },
			},
		);
	}

	const app = appResult.app!;

	const allowedRedirects = JSON.parse(app.redirect_uris) as string[];
	if (!allowedRedirects.includes(redirectUri)) {
		const appName = app.name || clientId;
		return new Response(
			`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Unauthorized Redirect URI • Indiko</title>
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300..700&display=swap" rel="stylesheet">
	<style>
		:root {
			--mahogany: #26242b;
			--lavender: #d9d0de;
			--old-rose: #bc8da0;
			--rosewood: #a04668;
			--berry-crush: #ab4967;
		}
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body {
			font-family: "Space Grotesk", sans-serif;
			background: var(--mahogany);
			color: var(--lavender);
			min-height: 100vh;
			display: flex;
			align-items: center;
			justify-content: center;
			padding: 2rem;
		}
		.error-box {
			max-width: 600px;
			background: rgba(188, 141, 160, 0.05);
			border: 2px solid var(--rosewood);
			padding: 2.5rem;
		}
		h1 {
			font-size: 2rem;
			font-weight: 700;
			background: linear-gradient(135deg, var(--old-rose), var(--rosewood));
			-webkit-background-clip: text;
			-webkit-text-fill-color: transparent;
			background-clip: text;
			margin-bottom: 1.5rem;
			letter-spacing: -0.05rem;
		}
		p {
			line-height: 1.8;
			margin-bottom: 1rem;
			color: var(--lavender);
		}
		code {
			background: rgba(12, 23, 19, 0.8);
			padding: 0.25rem 0.5rem;
			color: var(--berry-crush);
			font-size: 0.875rem;
			word-break: break-all;
			display: inline-block;
			max-width: 100%;
		}
		.error-details {
			background: rgba(160, 70, 104, 0.1);
			border-left: 4px solid var(--rosewood);
			padding: 1rem;
			margin: 1.5rem 0;
		}
		.error-details strong {
			display: block;
			margin-bottom: 0.5rem;
			color: var(--old-rose);
		}
	</style>
</head>
<body>
	<div class="error-box">
		<h1>Unauthorized Redirect URI</h1>
		<p>
			The OAuth authorization request failed because the provided <code>redirect_uri</code> is not registered for this client application.
		</p>
		<div class="error-details">
			<strong>Requested redirect_uri:</strong>
			<code>${redirectUri}</code>
		</div>
		<p style="margin-top: 1.5rem; font-size: 0.875rem; color: var(--old-rose);">
			The redirect_uri must exactly match a registered URI for <strong>${appName}</strong>. If you are the application developer, please ensure your redirect_uri matches the one registered with this authorization server.
		</p>
	</div>
</body>
</html>`,
			{
				status: 400,
				headers: { "Content-Type": "text/html" },
			},
		);
	}

	// Check if user is logged in
	const user = getUserFromCookie(req);

	if (!user) {
		// Not logged in - redirect to login with return URL
		const returnUrl = `/auth/authorize${url.search}`;
		return Response.redirect(`/login?return=${encodeURIComponent(returnUrl)}`);
	}

	// Verify app is registered
	const appCheckResult = await ensureApp(clientId, redirectUri);

	if (appCheckResult.error) {
		return new Response(appCheckResult.error, { status: 400 });
	}

	// Check if user has previously granted permission to this app
	const permission = db
		.query("SELECT scopes FROM permissions WHERE user_id = ? AND client_id = ?")
		.get(user.userId, clientId) as { scopes: string } | undefined;

	const requestedScopes = scope.split(" ").filter(Boolean);

	// If permission exists and covers all requested scopes, auto-approve
	if (permission) {
		const grantedScopes = JSON.parse(permission.scopes) as string[];
		const hasAllScopes = requestedScopes.every((s) =>
			grantedScopes.includes(s),
		);

		if (hasAllScopes) {
			// Auto-approve - create auth code and redirect
			const code = crypto.randomBytes(32).toString("base64url");
			const expiresAt = Math.floor(Date.now() / 1000) + 60; // 60 seconds

			db.query(
				"INSERT INTO authcodes (code, user_id, client_id, redirect_uri, scopes, code_challenge, expires_at, me) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
			).run(
				code,
				user.userId,
				clientId,
				redirectUri,
				JSON.stringify(requestedScopes),
				codeChallenge,
				expiresAt,
				me,
			);

			// Update permission last_used
			db.query(
				"UPDATE permissions SET last_used = ? WHERE user_id = ? AND client_id = ?",
			).run(Math.floor(Date.now() / 1000), user.userId, clientId);

			const origin = process.env.ORIGIN || "http://localhost:3000";
			return Response.redirect(`${redirectUri}?code=${code}&state=${state}&iss=${encodeURIComponent(origin)}`);
		}
	}

	// Show consent screen
	return showConsentScreen(
		user,
		clientId,
		redirectUri,
		state,
		codeChallenge,
		requestedScopes,
		me,
	);
}

function showConsentScreen(
	user: SessionUser,
	clientId: string,
	redirectUri: string,
	state: string,
	codeChallenge: string,
	scopes: string[],
	me: string | null,
): Response {
	// Load app metadata if pre-registered
	const appData = db
		.query("SELECT name, logo_url, description FROM apps WHERE client_id = ?")
		.get(clientId) as
		| {
				name: string | null;
				logo_url: string | null;
				description: string | null;
		  }
		| undefined;

	// Determine app name and URL - custom apps have ikc_ prefix and should use name from DB
	let appName: string;
	let appUrl: string | null = null;

	if (clientId.startsWith("ikc_")) {
		// Custom app with generated ID
		appName = appData?.name || clientId;
	} else {
		// URL-based client ID (anonymous app)
		try {
			const parsedUrl = new URL(clientId);
			appName = appData?.name || parsedUrl.hostname;
			appUrl = parsedUrl.hostname;
		} catch {
			// Fallback if URL parsing fails
			appName = appData?.name || clientId;
		}
	}

	const appLogo = appData?.logo_url;
	const appDescription = appData?.description;

	const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>authorize app • indiko</title>
  <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300..700&display=swap" rel="stylesheet">
  <style>
    :root {
      --mahogany: #26242b;
      --lavender: #d9d0de;
      --old-rose: #bc8da0;
      --rosewood: #a04668;
      --berry-crush: #ab4967;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: "Space Grotesk", sans-serif;
      background: var(--mahogany);
      color: var(--lavender);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 2rem 1rem;
    }
    .consent-box {
      max-width: 32rem;
      width: 100%;
      background: rgba(188, 141, 160, 0.05);
      border: 1px solid var(--old-rose);
      padding: 2.5rem;
    }
    .app-header {
      display: flex;
      gap: 1.5rem;
      align-items: flex-start;
      margin-bottom: 2rem;
      padding-bottom: 2rem;
      border-bottom: 1px solid var(--old-rose);
    }
    .app-logo {
      width: 5rem;
      height: 5rem;
      border-radius: 0.5rem;
      background: rgba(188, 141, 160, 0.2);
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      overflow: hidden;
      font-size: 2rem;
    }
    .app-logo img {
      width: 100%;
      height: 100%;
      object-fit: cover;
    }
    .app-info {
      flex: 1;
    }
    .app-name {
      font-size: 1.5rem;
      font-weight: 700;
      color: var(--lavender);
      margin-bottom: 0.5rem;
    }
    .app-url {
      font-size: 0.875rem;
      color: var(--old-rose);
      font-family: monospace;
      margin-bottom: 0.75rem;
    }
    .app-description {
      font-size: 0.9375rem;
      color: var(--old-rose);
      line-height: 1.6;
    }
    .user-badge {
      display: inline-block;
      background: rgba(188, 141, 160, 0.1);
      border-left: 3px solid var(--berry-crush);
      padding: 0.75rem 1rem;
      font-size: 0.875rem;
      color: var(--old-rose);
      margin-bottom: 2rem;
    }
    .user-badge strong {
      color: var(--lavender);
    }
    .request-text {
      font-size: 1.125rem;
      color: var(--lavender);
      margin-bottom: 1.5rem;
      line-height: 1.6;
    }
    .scopes {
      margin-bottom: 2rem;
      padding: 1.5rem;
      background: rgba(12, 23, 19, 0.4);
      border: 1px solid var(--old-rose);
    }
    .scope-title {
      font-size: 0.75rem;
      color: var(--old-rose);
      text-transform: uppercase;
      letter-spacing: 0.1rem;
      margin-bottom: 1rem;
    }
    .scope-list {
      list-style: none;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }
    .scope-list li {
      color: var(--lavender);
      font-size: 0.9375rem;
      line-height: 1.5;
    }
    .scope-list label {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      cursor: pointer;
      padding: 0.75rem;
      transition: background 0.2s;
      border: 1px solid transparent;
    }
    .scope-list label:hover {
      background: rgba(188, 141, 160, 0.1);
      border-color: var(--old-rose);
    }
    .scope-list input[type="checkbox"] {
      appearance: none;
      width: 1.5rem;
      height: 1.5rem;
      border: 2px solid var(--old-rose);
      background: rgba(12, 23, 19, 0.6);
      cursor: pointer;
      flex-shrink: 0;
      position: relative;
      transition: all 0.2s;
    }
    .scope-list input[type="checkbox"]:checked {
      background: var(--berry-crush);
      border-color: var(--berry-crush);
    }
    .scope-list input[type="checkbox"]:checked::after {
      content: "✓";
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      color: var(--lavender);
      font-size: 1rem;
      font-weight: 700;
    }
    .scope-list input[type="checkbox"]:disabled {
      cursor: not-allowed;
    }
    .scope-required {
      font-size: 0.75rem;
      color: var(--old-rose);
      margin-left: 2.25rem;
      margin-top: -0.25rem;
      margin-bottom: 0.25rem;
    }
    .buttons {
      display: flex;
      gap: 1rem;
    }
    button {
      flex: 1;
      padding: 1rem 1.5rem;
      border: 4px solid var(--mahogany);
      font-family: "Space Grotesk", sans-serif;
      font-size: 1rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.1rem;
      cursor: pointer;
      transition: all 0.15s ease;
      box-shadow: 6px 6px 0 var(--mahogany);
      position: relative;
    }
    button::before {
      content: '';
      position: absolute;
      top: -4px; left: -4px; right: -4px; bottom: -4px;
      background: transparent;
      border: 4px solid;
      pointer-events: none;
      transition: all 0.15s ease;
    }
    button:hover {
      transform: translate(3px, 3px);
      box-shadow: 3px 3px 0 var(--mahogany);
    }
    button:hover::before {
      top: -7px;
      left: -7px;
      right: -7px;
      bottom: -7px;
    }
    button:active {
      transform: translate(6px, 6px);
      box-shadow: 0 0 0 var(--mahogany);
    }
    .allow {
      background: var(--berry-crush);
      color: var(--lavender);
    }
    .allow::before {
      border-color: var(--rosewood);
    }
    .deny {
      background: transparent;
      color: var(--old-rose);
    }
    .deny::before {
      border-color: var(--old-rose);
    }
  </style>
</head>
<body>
  <div class="consent-box">
    <div class="user-badge">
      <span>Signing in as</span>
      <strong>${user.username}</strong>
    </div>

    <div class="app-header">
      <div class="app-logo">
        ${appLogo ? `<img src="${appLogo}" alt="${appName}" />` : "🔐"}
      </div>
      <div class="app-info">
        <div class="app-name">${appName}</div>
        ${appUrl ? `<div class="app-url">${appUrl}</div>` : ""}
        ${appDescription ? `<div class="app-description">${appDescription}</div>` : ""}
      </div>
    </div>

    <div class="request-text">
      This app would like to access the following information:
    </div>

    <div class="scopes">
      <div class="scope-title">requested permissions</div>
      <ul class="scope-list">
        ${scopes
					.map((scope) => {
						const isProfile = scope === "profile";
						const description =
							scope === "profile"
								? "Your profile (name, photo, URL)"
								: scope === "email"
									? "Your email address"
									: scope;
						const required = isProfile
							? ' <span style="color: var(--old-rose); font-size: 0.875rem; margin-left: 0.5rem;">(required)</span>'
							: "";
						return `
          <li>
            <label>
              <input type="checkbox" name="scope" value="${scope}" ${isProfile ? "checked disabled" : "checked"} />
              <span>${description}${required}</span>
            </label>
          </li>
        `;
					})
					.join("")}
      </ul>
    </div>

    <form method="POST" action="/auth/authorize">
      <input type="hidden" name="client_id" value="${clientId}" />
      <input type="hidden" name="redirect_uri" value="${redirectUri}" />
      <input type="hidden" name="state" value="${state}" />
      <input type="hidden" name="code_challenge" value="${codeChallenge}" />
      ${me ? `<input type="hidden" name="me" value="${me}" />` : ""}
      <!-- Always include profile scope as it's required -->
      <input type="hidden" name="scope" value="profile" />
      
      <div class="buttons">
        <button type="submit" name="action" value="deny" class="deny">deny</button>
        <button type="submit" name="action" value="allow" class="allow">allow</button>
      </div>
    </form>
  </div>
</body>
</html>`;

	return new Response(html, {
		headers: { "Content-Type": "text/html" },
	});
}

// POST /auth/authorize - Consent form submission
export async function authorizePost(req: Request): Promise<Response> {
	const contentType = req.headers.get("Content-Type");
	
	// Parse the request body
	let body: Record<string, string>;
	let formData: FormData;

	if (contentType?.includes("application/x-www-form-urlencoded")) {
		formData = await req.formData();
		body = Object.fromEntries(formData.entries()) as Record<string, string>;
	} else {
		body = await req.json();
		// Create a fake FormData for JSON requests
		formData = new FormData();
		Object.entries(body).forEach(([key, value]) => {
			formData.append(key, value);
		});
	}

	const grantType = body.grant_type;
	
	// If grant_type is present, this is a token exchange request (IndieAuth profile scope only)
	if (grantType === "authorization_code") {
		// Create a mock request for token() function
		const mockReq = new Request(req.url, {
			method: "POST",
			headers: req.headers,
			body: contentType?.includes("application/x-www-form-urlencoded") 
				? new URLSearchParams(body).toString()
				: JSON.stringify(body),
		});
		return token(mockReq);
	}

	// Otherwise it's a consent form submission
	const user = getUserFromCookie(req);

	if (!user) {
		return new Response("Unauthorized", { status: 401 });
	}

	const action = body.action;
	const clientId = body.client_id;
	const redirectUri = body.redirect_uri;
	const state = body.state;
	const codeChallenge = body.code_challenge;
	const me = body.me || null;

	if (!clientId || !redirectUri || !state || !codeChallenge) {
		return new Response("Missing required parameters", { status: 400 });
	}

	if (action === "deny") {
		return Response.redirect(
			`${redirectUri}?error=access_denied&state=${state}`,
		);
	}

	// Get the scopes the user actually approved (from checkboxes)
	const approvedScopes = formData.getAll("scope") as string[];

	// Profile scope is always required and included via hidden input
	if (approvedScopes.length === 0 || !approvedScopes.includes("profile")) {
		return new Response("Invalid scope selection", { status: 400 });
	}

	// Create authorization code
	const code = crypto.randomBytes(32).toString("base64url");
	const expiresAt = Math.floor(Date.now() / 1000) + 60; // 60 seconds

	db.query(
		"INSERT INTO authcodes (code, user_id, client_id, redirect_uri, scopes, code_challenge, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
	).run(
		code,
		user.userId,
		clientId,
		redirectUri,
		JSON.stringify(approvedScopes),
		codeChallenge,
		expiresAt,
	);

	// Store or update permission grant
	const existing = db
		.query("SELECT id FROM permissions WHERE user_id = ? AND client_id = ?")
		.get(user.userId, clientId);

	if (existing) {
		db.query(
			"UPDATE permissions SET scopes = ?, last_used = ? WHERE user_id = ? AND client_id = ?",
		).run(
			JSON.stringify(approvedScopes),
			Math.floor(Date.now() / 1000),
			user.userId,
			clientId,
		);
	} else {
		// Get app's default role for new permissions
		const app = db
			.query("SELECT default_role FROM apps WHERE client_id = ?")
			.get(clientId) as { default_role: string | null } | undefined;

		db.query(
			"INSERT INTO permissions (user_id, client_id, scopes, role) VALUES (?, ?, ?, ?)",
		).run(
			user.userId,
			clientId,
			JSON.stringify(approvedScopes),
			app?.default_role || null,
		);
	}

	// Update app last_used
	db.query("UPDATE apps SET last_used = ? WHERE client_id = ?").run(
		Math.floor(Date.now() / 1000),
		clientId,
	);

	const origin = process.env.ORIGIN || "http://localhost:3000";
	return Response.redirect(
		`${redirectUri}?code=${code}&state=${state}&iss=${encodeURIComponent(origin)}`,
	);
}

// POST /auth/token - Exchange authorization code for user identity
export async function token(req: Request): Promise<Response> {
	try {
		const contentType = req.headers.get("Content-Type");
		let body: Record<string, string>;

		// Support both JSON and form-encoded requests
		if (contentType?.includes("application/json")) {
			body = await req.json();
		} else if (contentType?.includes("application/x-www-form-urlencoded")) {
			const formData = await req.formData();
			body = Object.fromEntries(formData.entries()) as Record<string, string>;
		} else {
			console.error("Token endpoint: unsupported content type:", contentType);
			return Response.json(
				{
					error: "invalid_request",
					error_description:
						"Content-Type must be application/json or application/x-www-form-urlencoded",
				},
				{ status: 400 },
			);
		}

		const {
			grant_type,
			code,
			client_id,
			client_secret,
			redirect_uri,
			code_verifier,
		} = body;

		if (grant_type !== "authorization_code") {
			return Response.json(
				{
					error: "unsupported_grant_type",
					error_description: "Only authorization_code grant type is supported",
				},
				{ status: 400 },
			);
		}

		// Check if client is pre-registered and requires secret
		const app = db
			.query(
				"SELECT is_preregistered, client_secret_hash FROM apps WHERE client_id = ?",
			)
			.get(client_id) as
			| { is_preregistered: number; client_secret_hash: string | null }
			| undefined;

		// If client is pre-registered, verify client secret
		if (app && app.is_preregistered === 1) {
			if (!client_secret) {
				return Response.json(
					{
						error: "invalid_client",
						error_description:
							"client_secret is required for pre-registered clients",
					},
					{ status: 401 },
				);
			}

			if (!app.client_secret_hash) {
				return Response.json(
					{
						error: "server_error",
						error_description: "Client secret not configured",
					},
					{ status: 500 },
				);
			}

			// Verify client secret
			const providedSecretHash = crypto
				.createHash("sha256")
				.update(client_secret)
				.digest("hex");

			if (providedSecretHash !== app.client_secret_hash) {
				return Response.json(
					{
						error: "invalid_client",
						error_description: "Invalid client_secret",
					},
					{ status: 401 },
				);
			}
		}

		if (!code || !client_id || !redirect_uri) {
			console.error("Token endpoint: missing parameters", {
				code: !!code,
				client_id: !!client_id,
				redirect_uri: !!redirect_uri,
			});
			return Response.json(
				{
					error: "invalid_request",
					error_description: "Missing required parameters",
				},
				{ status: 400 },
			);
		}

		// PKCE is required for all clients per IndieAuth spec
		if (!code_verifier) {
			return Response.json(
				{
					error: "invalid_request",
					error_description: "code_verifier is required (PKCE)",
				},
				{ status: 400 },
			);
		}

		// Look up authorization code
		const authcode = db
			.query(
				"SELECT user_id, client_id, redirect_uri, scopes, code_challenge, expires_at, used, me FROM authcodes WHERE code = ?",
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
			  }
			| undefined;

		if (!authcode) {
			return Response.json(
				{
					error: "invalid_grant",
					error_description: "Authorization code not found",
				},
				{ status: 400 },
			);
		}

		// Check if already used
		if (authcode.used) {
			return Response.json(
				{
					error: "invalid_grant",
					error_description: "Authorization code already used",
				},
				{ status: 400 },
			);
		}

		// Check if expired
		const now = Math.floor(Date.now() / 1000);
		if (authcode.expires_at < now) {
			return Response.json(
				{
					error: "invalid_grant",
					error_description: "Authorization code expired",
				},
				{ status: 400 },
			);
		}

		// Verify client_id matches
		if (authcode.client_id !== client_id) {
			return Response.json(
				{
					error: "invalid_grant",
					error_description: "client_id mismatch",
				},
				{ status: 400 },
			);
		}

		// Verify redirect_uri matches
		if (authcode.redirect_uri !== redirect_uri) {
			return Response.json(
				{
					error: "invalid_grant",
					error_description: "redirect_uri mismatch",
				},
				{ status: 400 },
			);
		}

		// Verify PKCE code_verifier (required for all clients per IndieAuth spec)
		if (!verifyPKCE(code_verifier, authcode.code_challenge)) {
			return Response.json(
				{
					error: "invalid_grant",
					error_description: "Invalid code_verifier",
				},
				{ status: 400 },
			);
		}

		// Mark code as used
		db.query("UPDATE authcodes SET used = 1 WHERE code = ?").run(code);

		// Get user profile
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
			return Response.json(
				{
					error: "server_error",
					error_description: "User not found",
				},
				{ status: 500 },
			);
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

		// Use custom domain as identity if user has verified one, otherwise use indiko profile
		let meValue = `${process.env.ORIGIN}/u/${user.username}`;
		if (user.url) {
			// User has verified custom domain - use it as their identity
			meValue = user.url;
		}

		// Validate that the user controls the requested me parameter
		if (authcode.me && authcode.me !== meValue) {
			return Response.json(
				{
					error: "invalid_grant",
					error_description: "The requested identity does not match the user's verified domain",
				},
				{ status: 400 },
			);
		}

		const origin = process.env.ORIGIN || "http://localhost:3000";
		
		const response: Record<string, unknown> = {
			me: meValue,
			profile,
			scope: scopes.join(" "),
			iss: origin,
		};

		// Include role if assigned
		if (permission?.role) {
			response.role = permission.role;
		}



		return Response.json(response, {
			headers: {
				"Content-Type": "application/json",
				"Cache-Control": "no-store",
				"Pragma": "no-cache",
			},
		});
	} catch (error) {
		console.error("Token exchange error:", error);
		return Response.json(
			{
				error: "server_error",
				error_description: "Internal server error",
			},
			{ status: 500 },
		);
	}
}

// POST /auth/logout - Clear session
export function logout(req: Request): Response {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	const authHeader = req.headers.get("Authorization");
	const token = authHeader?.substring(7);

	if (token) {
		db.query("DELETE FROM sessions WHERE token = ?").run(token);
	}

	return Response.json({ success: true });
}

// GET /u/:username - Public user profile (h-card)
export function userProfile(req: Request): Response {
	const username = (req as any).params?.username;
	if (!username) {
		return new Response("Username required", { status: 400 });
	}

	const user = db
		.query(
			"SELECT username, name, email, photo, url FROM users WHERE username = ?",
		)
		.get(username) as
		| {
				username: string;
				name: string;
				email: string | null;
				photo: string | null;
				url: string | null;
		  }
		| undefined;

	if (!user) {
		return new Response("User not found", { status: 404 });
	}

	const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${user.name} • indiko</title>
  <meta name="description" content="${user.name}'s profile on Indiko${user.url ? ` - ${user.url}` : ""}" />
  <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
  <link rel="indieauth-metadata" href="${process.env.ORIGIN}/.well-known/oauth-authorization-server" />
  <link rel="authorization_endpoint" href="${process.env.ORIGIN}/auth/authorize" />
  <link rel="token_endpoint" href="${process.env.ORIGIN}/auth/token" />
  ${user.url ? `<link rel="me" href="${user.url}" />` : ""}
  
  <!-- Open Graph / Facebook -->
  <meta property="og:type" content="profile" />
  <meta property="og:title" content="${user.name}" />
  <meta property="og:description" content="${user.name}'s profile on Indiko" />
  <meta property="og:url" content="${user.url || `${process.env.ORIGIN}/u/${user.username}`}" />
  ${user.photo ? `<meta property="og:image" content="${user.photo}" />` : ""}
  <meta property="profile:username" content="${user.username}" />
  
  <!-- Twitter -->
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content="${user.name}" />
  <meta name="twitter:description" content="${user.name}'s profile on Indiko" />
  ${user.photo ? `<meta name="twitter:image" content="${user.photo}" />` : ""}
  
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300..700&display=swap" rel="stylesheet">
  <style>
    :root {
      --mahogany: #26242b;
      --lavender: #d9d0de;
      --old-rose: #bc8da0;
      --rosewood: #a04668;
      --berry-crush: #ab4967;
    }
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      font-family: "Space Grotesk", sans-serif;
      background: var(--mahogany);
      color: var(--lavender);
      min-height: 100vh;
      padding: 2.5rem 1.25rem;
    }
    .container {
      max-width: 600px;
      margin: 0 auto;
    }
    .h-card {
      background: rgba(188, 141, 160, 0.05);
      border: 1px solid var(--old-rose);
      padding: 2rem;
      margin-bottom: 2rem;
      display: flex;
      flex-direction: column;
      align-items: center;
      text-align: center;
    }
    .u-photo {
      width: 128px;
      height: 128px;
      border-radius: 50%;
      object-fit: cover;
      margin-bottom: 1rem;
      border: 3px solid var(--berry-crush);
    }
    .p-name {
      font-size: 1.5rem;
      font-weight: 700;
      text-decoration: none;
      color: var(--lavender);
      margin-bottom: 0.5rem;
    }
    .p-name:hover {
      color: var(--berry-crush);
    }
    .u-email, .u-url-link {
      color: var(--old-rose);
      text-decoration: none;
      margin-top: 0.5rem;
      font-size: 0.875rem;
    }
    .u-email:hover, .u-url-link:hover {
      color: var(--berry-crush);
    }
    .links {
      display: flex;
      gap: 1rem;
      margin-top: 0.5rem;
    }
    .identity-info {
      margin-top: 1rem;
      padding: 1rem;
      background: rgba(12, 23, 19, 0.6);
      border: 1px solid var(--rosewood);
      font-size: 0.875rem;
      color: var(--old-rose);
    }
    .identity-info code {
      color: var(--berry-crush);
      font-family: "Space Grotesk", monospace;
    }
    .indieauth-info {
      background: rgba(188, 141, 160, 0.05);
      border: 1px solid var(--old-rose);
      padding: 2rem;
    }
    .indieauth-info h2 {
      font-size: 1.25rem;
      font-weight: 600;
      margin-bottom: 1rem;
      color: var(--lavender);
    }
    .indieauth-info p {
      margin-bottom: 1rem;
      color: var(--old-rose);
      line-height: 1.6;
    }
    .indieauth-info code {
      color: var(--berry-crush);
      font-family: "Space Grotesk", monospace;
    }
    .code-box {
      background: rgba(12, 23, 19, 0.6);
      border: 2px solid var(--rosewood);
      padding: 1rem;
      margin: 1rem 0;
      font-family: "Space Grotesk", monospace;
      font-size: 0.875rem;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .html-tag {
      color: var(--berry-crush);
    }
    .html-attr {
      color: #81c784;
    }
    .html-value {
      color: #a5d6a7;
    }
    .back-link {
      text-align: center;
      margin-top: 2rem;
      font-size: 0.875rem;
    }
    .back-link a {
      color: var(--berry-crush);
      text-decoration: none;
    }
    .back-link a:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="h-card">
      ${user.photo ? `<img class="u-photo" src="${user.photo}" alt="${user.name}" />` : ""}
      <h1 class="p-name">${user.name}</h1>
      <div class="links">
        ${user.url ? `<a class="u-url u-url-link" rel="me" href="${user.url}">website</a>` : ""}
        ${user.email ? `<a class="u-email" rel="me" href="mailto:${user.email}">email</a>` : ""}
      </div>
      <div class="identity-info">
        IndieAuth identity: <code>${user.url || `${process.env.ORIGIN}/u/${user.username}`}</code>
      </div>
    </div>

    <div class="indieauth-info">
      <h2>Use This Identity on Your Website</h2>
      <p>
        You can delegate IndieAuth to this server from your own website. Add these tags to your site's <code>&lt;head&gt;</code>:
      </p>
      <div class="code-box"><span class="html-tag">&lt;link</span> <span class="html-attr">rel</span>=<span class="html-value">"indieauth-metadata"</span> <span class="html-attr">href</span>=<span class="html-value">"${process.env.ORIGIN}/.well-known/oauth-authorization-server"</span> <span class="html-tag">/&gt;</span>
<span class="html-tag">&lt;link</span> <span class="html-attr">rel</span>=<span class="html-value">"authorization_endpoint"</span> <span class="html-attr">href</span>=<span class="html-value">"${process.env.ORIGIN}/auth/authorize"</span> <span class="html-tag">/&gt;</span>
<span class="html-tag">&lt;link</span> <span class="html-attr">rel</span>=<span class="html-value">"token_endpoint"</span> <span class="html-attr">href</span>=<span class="html-value">"${process.env.ORIGIN}/auth/token"</span> <span class="html-tag">/&gt;</span>
<span class="html-tag">&lt;link</span> <span class="html-attr">rel</span>=<span class="html-value">"me"</span> <span class="html-attr">href</span>=<span class="html-value">"${process.env.ORIGIN}/u/${user.username}"</span> <span class="html-tag">/&gt;</span></div>
      <p>
        This lets you sign in to IndieAuth-compatible sites using your own domain while this server handles the authentication.
      </p>
    </div>

    <div class="back-link">
      <a href="/">← back to dashboard</a>
    </div>
  </div>
</body>
</html>`;

	const origin = process.env.ORIGIN || "http://localhost:3000";
	return new Response(html, {
		headers: {
			"Content-Type": "text/html",
			Link: `<${origin}/.well-known/oauth-authorization-server>; rel="indieauth-metadata"`,
		},
	});
}

// POST /api/invites/create - Create invite link (admin only)
export async function createInvite(req: Request): Promise<Response> {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.isAdmin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	const body = (await req.json()) as {
		maxUses?: number;
		expiresAt?: number | null;
		note?: string | null;
		message?: string | null;
		appRoles?: Array<{ appId: number; role: string }>;
	};

	const inviteCode = crypto.randomBytes(16).toString("base64url");
	const maxUses = body.maxUses || 1;
	const expiresAt = body.expiresAt || null;
	const note = body.note || null;
	const message = body.message || null;

	const result = db
		.query(
			"INSERT INTO invites (code, created_by, max_uses, expires_at, note, message) VALUES (?, ?, ?, ?, ?, ?)",
		)
		.run(inviteCode, user.userId, maxUses, expiresAt, note, message);

	const inviteId = Number(result.lastInsertRowid);

	// Insert app role assignments if provided
	if (body.appRoles && body.appRoles.length > 0) {
		const stmt = db.prepare(
			"INSERT INTO invite_roles (invite_id, app_id, role) VALUES (?, ?, ?)",
		);
		for (const appRole of body.appRoles) {
			stmt.run(inviteId, appRole.appId, appRole.role);
		}
	}

	return Response.json({
		inviteCode,
		inviteUrl: `${process.env.ORIGIN}/login?invite=${inviteCode}`,
	});
}

// GET /api/invites - List all invites (admin only)
export function listInvites(req: Request): Response {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.isAdmin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	const invites = db
		.query(`
		SELECT i.id, i.code, i.max_uses, i.current_uses, i.expires_at, i.note, i.message, i.created_at,
			creator.username as created_by_username
		FROM invites i
		LEFT JOIN users creator ON i.created_by = creator.id
		ORDER BY i.created_at DESC
	`)
		.all() as Array<{
		id: number;
		code: string;
		max_uses: number;
		current_uses: number;
		expires_at: number | null;
		note: string | null;
		message: string | null;
		created_at: number;
		created_by_username: string;
	}>;

	// Get app roles for each invite
	const inviteRoles = db
		.query(`
		SELECT ir.invite_id, ir.app_id, ir.role, a.client_id, a.name
		FROM invite_roles ir
		JOIN apps a ON ir.app_id = a.id
	`)
		.all() as Array<{
		invite_id: number;
		app_id: number;
		role: string;
		client_id: string;
		name: string | null;
	}>;

	// Get users who used each invite
	const inviteUses = db
		.query(`
		SELECT iu.invite_id, iu.used_at, u.username
		FROM invite_uses iu
		JOIN users u ON iu.user_id = u.id
		ORDER BY iu.used_at DESC
	`)
		.all() as Array<{
		invite_id: number;
		used_at: number;
		username: string;
	}>;

	const now = Math.floor(Date.now() / 1000);

	return Response.json({
		invites: invites.map((inv) => ({
			id: inv.id,
			code: inv.code,
			maxUses: inv.max_uses,
			currentUses: inv.current_uses,
			isExpired: inv.expires_at ? inv.expires_at < now : false,
			isFullyUsed: inv.current_uses >= inv.max_uses,
			expiresAt: inv.expires_at,
			note: inv.note,
			message: inv.message,
			createdAt: inv.created_at,
			createdBy: inv.created_by_username,
			inviteUrl: `${process.env.ORIGIN}/login?invite=${inv.code}`,
			appRoles: inviteRoles
				.filter((r) => r.invite_id === inv.id)
				.map((r) => ({
					appId: r.app_id,
					clientId: r.client_id,
					name: r.name,
					role: r.role,
				})),
			usedBy: inviteUses
				.filter((u) => u.invite_id === inv.id)
				.map((u) => ({
					username: u.username,
					usedAt: u.used_at,
				})),
		})),
	});
}

// PATCH /api/invites/:id - Update invite (admin only)
export async function updateInvite(req: Request): Promise<Response> {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.isAdmin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	const url = new URL(req.url);
	const parts = url.pathname.split("/");
	const inviteId = parts[parts.length - 1];

	if (!inviteId || Number.isNaN(Number(inviteId))) {
		return Response.json({ error: "Invalid invite ID" }, { status: 400 });
	}

	const body = (await req.json()) as {
		maxUses?: number | null;
		expiresAt?: number | null;
		note?: string | null;
		message?: string | null;
	};

	const updates: string[] = [];
	const values: (number | string | null)[] = [];

	if (body.maxUses !== undefined) {
		updates.push("max_uses = ?");
		values.push(body.maxUses);
	}
	if (body.expiresAt !== undefined) {
		updates.push("expires_at = ?");
		values.push(body.expiresAt);
	}
	if (body.note !== undefined) {
		updates.push("note = ?");
		values.push(body.note);
	}
	if (body.message !== undefined) {
		updates.push("message = ?");
		values.push(body.message);
	}

	if (updates.length === 0) {
		return Response.json({ error: "No fields to update" }, { status: 400 });
	}

	values.push(inviteId);

	db.query(`UPDATE invites SET ${updates.join(", ")} WHERE id = ?`).run(
		...values,
	);

	return Response.json({ success: true });
}

// DELETE /api/invites/:id - Delete an invite (admin only)
export function deleteInvite(req: Request): Response {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.isAdmin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	const url = new URL(req.url);
	const parts = url.pathname.split("/");
	const inviteId = parts[parts.length - 1];

	if (!inviteId || Number.isNaN(Number(inviteId))) {
		return Response.json({ error: "Invalid invite ID" }, { status: 400 });
	}

	// Delete invite (cascade will handle invite_roles and invite_uses)
	db.query("DELETE FROM invites WHERE id = ?").run(inviteId);

	return Response.json({ success: true });
}

// GET /.well-known/oauth-authorization-server - IndieAuth metadata endpoint
export function indieauthMetadata(): Response {
	const origin = process.env.ORIGIN || "http://localhost:3000";

	const metadata = {
		issuer: origin,
		authorization_endpoint: `${origin}/auth/authorize`,
		token_endpoint: `${origin}/auth/token`,
		code_challenge_methods_supported: ["S256"],
		scopes_supported: ["profile", "email"],
		response_types_supported: ["code"],
		grant_types_supported: ["authorization_code"],
		service_documentation: `${origin}/docs`,
	};

	return Response.json(metadata, {
		headers: {
			"Content-Type": "application/json",
			"Access-Control-Allow-Origin": "*",
		},
	});
}
