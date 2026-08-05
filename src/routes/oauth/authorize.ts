import crypto from "node:crypto";
import { db } from "../../db";
import { ensureApp } from "../../lib/oauth/client-metadata";
import { consentPage, errorPage, escapeHtml } from "../../lib/oauth/pages";
import {
	type ResourceInfo,
	resourceDisplay,
	resourcesToStored,
	validateResources,
} from "../../lib/oauth/resource";
import { canonicalizeURL } from "../../lib/oauth/urls";
import { getCsrfToken, getUserFromCookie } from "../../lib/session";
import { token } from "./token";

const AUTH_CODE_TTL = 60; // seconds

// GET /auth/authorize - Authorization request
export async function authorizeGet(req: Request): Promise<Response> {
	const url = new URL(req.url);
	const params = url.searchParams;

	const responseType = params.get("response_type");
	const rawClientId = params.get("client_id");
	const rawRedirectUri = params.get("redirect_uri");
	const state = params.get("state");
	const codeChallenge = params.get("code_challenge");
	const codeChallengeMethod = params.get("code_challenge_method");
	const scope = params.get("scope") || "profile";
	const me = params.get("me");
	const nonce = params.get("nonce"); // OIDC nonce parameter

	// RFC 8707 resource indicators (may repeat). A malformed one is invalid_target.
	const requestedResources = validateResources(params.getAll("resource"));
	if (requestedResources === null) {
		return errorPage({
			title: "Invalid Resource",
			message:
				"The authorization request included a resource parameter that is not an absolute URI (or carries a fragment).",
			hint: "Each resource must be an absolute https URI with no fragment, e.g. https://api.example.com.",
		});
	}
	const resourceStored = resourcesToStored(requestedResources);

	// Step 1: client_id and redirect_uri must exist (can't redirect without them)
	if (!rawClientId || !rawRedirectUri) {
		return new Response(
			"Missing required parameters: client_id and redirect_uri",
			{ status: 400 },
		);
	}

	// Step 2: Canonicalize URLs (if malformed, can't trust redirect_uri)
	let clientId: string;
	let redirectUri: string;
	try {
		clientId = canonicalizeURL(rawClientId);
		redirectUri = canonicalizeURL(rawRedirectUri);
	} catch {
		const details: Array<{ label: string; value: string; isCode?: boolean }> = [
			{
				label: "Provided redirect_uri:",
				value: rawRedirectUri,
				isCode: true,
			},
		];
		if (me)
			details.push({
				label: "Requested identity (me):",
				value: me,
				isCode: true,
			});
		return errorPage({
			title: "Invalid Redirect URI",
			message:
				"The OAuth authorization request failed because the provided redirect_uri is not a valid URL.",
			details,
			hint: "The redirect URI must be a valid, absolute URL (e.g., https://example.com/callback).",
		});
	}

	// Step 3: Verify app is registered (can't trust redirect_uri if client is invalid)
	const appResult = await ensureApp(clientId, redirectUri);

	if (appResult.error) {
		const details: Array<{ label: string; value: string; isCode?: boolean }> = [
			{ label: "Error:", value: appResult.error },
			{ label: "Provided client_id:", value: clientId, isCode: true },
		];
		if (me)
			details.push({
				label: "Requested identity (me):",
				value: me,
				isCode: true,
			});
		return errorPage({
			title: "Invalid Client ID",
			message:
				"The OAuth authorization request failed because the provided client_id is not valid.",
			details,
			hint: "For auto-registration, the client_id must be a valid URL (e.g., https://example.com). Non-URL client IDs (like <code>ikc_xxxxx</code>) must be pre-registered by an administrator.",
		});
	}

	const app = appResult.app;
	if (!app) {
		return errorPage({
			title: "Invalid Client ID",
			message: "The client application could not be loaded.",
		});
	}

	// Step 4: Verify redirect_uri is allowed for this app
	const allowedRedirects = JSON.parse(app.redirect_uris) as string[];
	if (!allowedRedirects.includes(redirectUri)) {
		const appName = app.name || clientId;
		const details: Array<{ label: string; value: string; isCode?: boolean }> = [
			{
				label: "Requested redirect_uri:",
				value: redirectUri,
				isCode: true,
			},
		];
		if (me)
			details.push({
				label: "Requested identity (me):",
				value: me,
				isCode: true,
			});
		return errorPage({
			title: "Unauthorized Redirect URI",
			message:
				"The OAuth authorization request failed because the provided redirect_uri is not registered for this client application.",
			details,
			hint: `The redirect_uri must exactly match a registered URI for <strong>${escapeHtml(appName)}</strong>. If you are the application developer, please ensure your redirect_uri matches the one registered with this authorization server.`,
		});
	}

	// Step 5: redirect_uri is now trusted — report remaining errors via
	// redirect per RFC 6749 §4.1.2.1
	const redirectError = (error: string, description: string): Response => {
		const origin = process.env.ORIGIN || "http://localhost:3000";
		const errorUrl = new URL(redirectUri);
		errorUrl.searchParams.set("error", error);
		errorUrl.searchParams.set("error_description", description);
		// RFC 9207: iss must be present on error responses too
		errorUrl.searchParams.set("iss", origin);
		if (state) errorUrl.searchParams.set("state", state);
		return Response.redirect(errorUrl.toString(), 302);
	};

	if (responseType !== "code") {
		return redirectError(
			"unsupported_response_type",
			"Only response_type=code is supported",
		);
	}

	if (!codeChallenge) {
		return redirectError(
			"invalid_request",
			"Missing required parameter: code_challenge",
		);
	}

	if (codeChallengeMethod && codeChallengeMethod !== "S256") {
		return redirectError(
			"invalid_request",
			"Only S256 code_challenge_method is supported",
		);
	}

	if (!state) {
		return redirectError(
			"invalid_request",
			"Missing required parameter: state",
		);
	}

	// Check if user is logged in
	const user = getUserFromCookie(req);

	if (!user) {
		const returnUrl = `/auth/authorize${url.search}`;
		return Response.redirect(`/login?return=${encodeURIComponent(returnUrl)}`);
	}

	// Check if user has previously granted permission to this app
	const permission = db
		.query("SELECT scopes FROM permissions WHERE user_id = ? AND client_id = ?")
		.get(user.userId, clientId) as { scopes: string } | undefined;

	const requestedScopes = scope.split(" ").filter(Boolean);

	// Auto-approve when existing permission covers all requested scopes
	if (permission) {
		const grantedScopes = JSON.parse(permission.scopes) as string[];
		const hasAllScopes = requestedScopes.every((s) =>
			grantedScopes.includes(s),
		);

		if (hasAllScopes) {
			const code = crypto.randomBytes(32).toString("base64url");
			const now = Math.floor(Date.now() / 1000);
			const expiresAt = now + AUTH_CODE_TTL;

			db.query(
				"INSERT INTO authcodes (code, user_id, client_id, redirect_uri, scopes, code_challenge, expires_at, me, nonce, auth_time, resource) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			).run(
				code,
				user.userId,
				clientId,
				redirectUri,
				JSON.stringify(requestedScopes),
				codeChallenge,
				expiresAt,
				me,
				nonce,
				now, // auth_time - user already authenticated
				resourceStored,
			);

			db.query(
				"UPDATE permissions SET last_used = ? WHERE user_id = ? AND client_id = ?",
			).run(Math.floor(Date.now() / 1000), user.userId, clientId);

			const origin = process.env.ORIGIN || "http://localhost:3000";
			const autoApproveUrl = new URL(redirectUri);
			autoApproveUrl.searchParams.set("code", code);
			autoApproveUrl.searchParams.set("state", state);
			autoApproveUrl.searchParams.set("iss", origin);
			return Response.redirect(autoApproveUrl.toString(), 302);
		}
	}

	// Show consent screen
	return showConsentScreen(
		req,
		user,
		clientId,
		redirectUri,
		state,
		codeChallenge,
		requestedScopes,
		me,
		nonce,
		requestedResources,
	);
}

async function showConsentScreen(
	req: Request,
	user: { username: string },
	clientId: string,
	redirectUri: string,
	state: string,
	codeChallenge: string,
	scopes: string[],
	me: string | null,
	nonce: string | null,
	resources: string[],
): Promise<Response> {
	const appData = db
		.query("SELECT name, logo_url, description FROM apps WHERE client_id = ?")
		.get(clientId) as
		| {
				name: string | null;
				logo_url: string | null;
				description: string | null;
		  }
		| undefined;

	// Pre-registered apps (ikc_ prefix) use the name from DB;
	// URL-based client IDs fall back to hostname
	let appName: string;
	let appUrl: string | null = null;

	if (clientId.startsWith("ikc_")) {
		appName = appData?.name || clientId;
	} else {
		try {
			const parsedUrl = new URL(clientId);
			appName = appData?.name || parsedUrl.hostname;
			appUrl = parsedUrl.hostname;
		} catch {
			appName = appData?.name || clientId;
		}
	}

	// Resolve the requested resources to friendly name + icon (via their PRM) so
	// the consent screen shows WHAT kloe is being granted access to, not a URL.
	const resourceInfos: ResourceInfo[] = resources.length
		? await resourceDisplay(resources)
		: [];

	return consentPage({
		username: user.username,
		appName,
		appUrl,
		appLogo: appData?.logo_url,
		appDescription: appData?.description,
		scopes,
		clientId,
		redirectUri,
		state,
		codeChallenge,
		me,
		nonce,
		resources: resourceInfos,
		csrfToken: getCsrfToken(req) || "",
	});
}

// POST /auth/authorize - Consent form submission (or profile-scope token exchange)
export async function authorizePost(req: Request): Promise<Response> {
	const contentType = req.headers.get("Content-Type");

	let body: Record<string, string>;
	let formData: FormData;

	if (contentType?.includes("application/x-www-form-urlencoded")) {
		formData = await req.formData();
		body = Object.fromEntries(formData.entries()) as Record<string, string>;
	} else {
		body = await req.json();
		formData = new FormData();
		for (const [key, value] of Object.entries(body)) {
			formData.append(key, value);
		}
	}

	// If grant_type is present, this is a token exchange request
	// (IndieAuth profile scope only flow posts to the authorization endpoint)
	if (body.grant_type === "authorization_code") {
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

	// Validate CSRF token from the form field against the cookie
	const formCsrf = body.csrf_token;
	const cookieCsrf = getCsrfToken(req);
	if (!formCsrf || !cookieCsrf || formCsrf !== cookieCsrf) {
		return new Response("CSRF token mismatch", { status: 403 });
	}

	const action = body.action;
	const rawClientId = body.client_id;
	const rawRedirectUri = body.redirect_uri;
	const state = body.state;
	const codeChallenge = body.code_challenge;
	const me = body.me || null;
	const nonce = body.nonce || null; // OIDC nonce

	if (!rawClientId || !rawRedirectUri || !state || !codeChallenge) {
		return new Response("Missing required parameters", { status: 400 });
	}

	let clientId: string;
	let redirectUri: string;
	try {
		clientId = canonicalizeURL(rawClientId);
		redirectUri = canonicalizeURL(rawRedirectUri);
	} catch {
		return new Response("Invalid client_id or redirect_uri URL format", {
			status: 400,
		});
	}

	// Re-validate redirect_uri against the app's registered set — the consent
	// form POSTs attacker-controllable hidden fields, so we must not trust the
	// submitted redirect_uri without checking it against the registered list.
	const app = db
		.query("SELECT redirect_uris FROM apps WHERE client_id = ?")
		.get(clientId) as { redirect_uris: string } | undefined;

	if (!app) {
		return new Response("Invalid client_id", { status: 400 });
	}

	const allowedRedirects = JSON.parse(app.redirect_uris) as string[];
	if (!allowedRedirects.includes(redirectUri)) {
		return new Response("redirect_uri not registered for this client", {
			status: 400,
		});
	}

	if (action === "deny") {
		const origin = process.env.ORIGIN || "http://localhost:3000";
		const denyUrl = new URL(redirectUri);
		denyUrl.searchParams.set("error", "access_denied");
		denyUrl.searchParams.set("state", state);
		denyUrl.searchParams.set("iss", origin);
		return Response.redirect(denyUrl.toString(), 302);
	}

	// Get the scopes the user actually approved (from checkboxes)
	const approvedScopes = formData.getAll("scope") as string[];

	// Resource indicators carried through the consent form (hidden fields).
	// Re-validate — the POST body is attacker-controllable.
	const approvedResources = validateResources(
		formData.getAll("resource") as string[],
	);
	if (approvedResources === null) {
		return new Response("invalid_target", { status: 400 });
	}
	const resourceStored = resourcesToStored(approvedResources);

	// Profile scope is always required and included via hidden input
	if (approvedScopes.length === 0 || !approvedScopes.includes("profile")) {
		return new Response("Invalid scope selection", { status: 400 });
	}

	const code = crypto.randomBytes(32).toString("base64url");
	const now = Math.floor(Date.now() / 1000);
	const expiresAt = now + AUTH_CODE_TTL;

	db.query(
		"INSERT INTO authcodes (code, user_id, client_id, redirect_uri, scopes, code_challenge, expires_at, me, nonce, auth_time, resource) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	).run(
		code,
		user.userId,
		clientId,
		redirectUri,
		JSON.stringify(approvedScopes),
		codeChallenge,
		expiresAt,
		me,
		nonce,
		now, // auth_time
		resourceStored,
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

	db.query("UPDATE apps SET last_used = ? WHERE client_id = ?").run(
		Math.floor(Date.now() / 1000),
		clientId,
	);

	const origin = process.env.ORIGIN || "http://localhost:3000";
	const successUrl = new URL(redirectUri);
	successUrl.searchParams.set("code", code);
	successUrl.searchParams.set("state", state);
	successUrl.searchParams.set("iss", origin);
	return Response.redirect(successUrl.toString(), 302);
}
