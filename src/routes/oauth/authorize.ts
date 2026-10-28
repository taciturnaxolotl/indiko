import crypto from "node:crypto";
import { db } from "../../db";
import { ensureApp, isRedirectAllowed } from "../../lib/oauth/client-metadata";
import {
	consentPage,
	errorPage,
	escapeHtml,
	FRAME_DENY_HEADERS,
} from "../../lib/oauth/pages";
import {
	type ResourceInfo,
	resourceDisplay,
	resourcesToStored,
	storedToResources,
	validateResources,
} from "../../lib/oauth/resource";
import { canonicalizeURL, validateClientURL } from "../../lib/oauth/urls";
import {
	csrfTokenMatches,
	getCsrfToken,
	getUserFromCookie,
} from "../../lib/session";
import { token } from "./token";

const AUTH_CODE_TTL = 60; // seconds

// RFC 6749 §3.1: request parameters MUST NOT be included more than once.
// A repeated redirect_uri in particular is a trick to get one value validated
// and the other used, so refuse rather than pick.
const SINGLE_VALUE_PARAMS = [
	"response_type",
	"client_id",
	"redirect_uri",
	"state",
	"code_challenge",
	"code_challenge_method",
	"scope",
	"me",
	"nonce",
] as const;

function findDuplicateParam(params: URLSearchParams): string | null {
	for (const name of SINGLE_VALUE_PARAMS) {
		if (params.getAll(name).length > 1) return name;
	}
	return null;
}

/** The profile URLs this user may be returned as `me`. */
function userIdentities(userId: number): string[] {
	const origin = process.env.ORIGIN || "http://localhost:3000";
	const row = db
		.query("SELECT username, url FROM users WHERE id = ?")
		.get(userId) as { username: string; url: string | null } | undefined;
	if (!row) return [];
	const ids = [`${origin}/u/${row.username}`];
	if (row.url) ids.push(row.url);
	return ids;
}

// The `me` parameter is a hint about who the user expects to sign in as. It
// is never trusted: a value that is not one of this user's own identities is
// dropped, and the token response always carries the verified identity.
function trustedMeHint(me: string | null, userId: number): string | null {
	if (!me) return null;
	let canonical: string;
	try {
		canonical = canonicalizeURL(me);
	} catch {
		return null;
	}
	return userIdentities(userId).some((id) => canonicalizeURL(id) === canonical)
		? canonical
		: null;
}

// GET /auth/authorize - Authorization request
export async function authorizeGet(req: Request): Promise<Response> {
	const url = new URL(req.url);
	const params = url.searchParams;

	const duplicate = findDuplicateParam(params);
	if (duplicate) {
		return errorPage({
			title: "Invalid Request",
			message: `The authorization request repeats the ${duplicate} parameter. Each parameter may appear only once.`,
			hint: "Send each OAuth parameter exactly once (RFC 6749 §3.1).",
		});
	}

	const responseType = params.get("response_type");
	const rawClientId = params.get("client_id");
	const rawRedirectUri = params.get("redirect_uri");
	const state = params.get("state");
	const codeChallenge = params.get("code_challenge");
	const codeChallengeMethod = params.get("code_challenge_method");
	// No scope means the client only wants to know who signed in (IndieAuth
	// §5.3.3): the code is exchanged for a profile URL, not an access token.
	const scope = params.get("scope") ?? "";
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
		return errorPage({
			title: "Invalid Request",
			message:
				"The authorization request is missing client_id or redirect_uri, so there is nowhere safe to send you back to.",
			hint: "Both client_id and redirect_uri are required.",
		});
	}

	// Step 2: Validate and canonicalize URLs. The raw client_id is checked
	// before canonicalizing because URL parsing quietly collapses "..", and a
	// client_id with dot segments is not a valid client identifier (§3.3).
	if (
		(rawClientId.startsWith("http://") || rawClientId.startsWith("https://")) &&
		!validateClientURL(rawClientId).valid
	) {
		return errorPage({
			title: "Invalid Client ID",
			message:
				"The OAuth authorization request failed because the provided client_id is not a valid client identifier.",
			details: [
				{ label: "Provided client_id:", value: rawClientId, isCode: true },
			],
			hint: "A client_id must be an absolute http(s) URL with no fragment, credentials, or . / .. path segments.",
		});
	}

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

	// Step 3: Resolve the client and check the redirect_uri belongs to it. We
	// cannot redirect any error until this passes.
	const appResult = await ensureApp(clientId, redirectUri);

	if (appResult.error && appResult.code === "invalid_redirect") {
		const appName = clientId;
		const details: Array<{ label: string; value: string; isCode?: boolean }> = [
			{ label: "Error:", value: appResult.error },
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
			hint: `The redirect_uri must exactly match a URI registered for <strong>${escapeHtml(appName)}</strong>. If you are the application developer, publish the redirect_uri in your client metadata or use one on the same origin as your client_id.`,
		});
	}

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

	// Step 4: redirect_uri is now trusted — report remaining errors via
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

	// RFC 7636 §4.3: a missing method means "plain", which is not supported
	// here, so the method must be sent and must be S256.
	if (codeChallengeMethod !== "S256") {
		return redirectError(
			"invalid_request",
			codeChallengeMethod
				? "Only S256 code_challenge_method is supported"
				: "code_challenge_method is required and must be S256",
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
		return new Response(null, {
			status: 302,
			headers: {
				Location: `/login?return=${encodeURIComponent(returnUrl)}`,
				...FRAME_DENY_HEADERS,
			},
		});
	}

	const meHint = trustedMeHint(me, user.userId);

	// Check if user has previously granted permission to this app
	const permission = db
		.query(
			"SELECT scopes, resources FROM permissions WHERE user_id = ? AND client_id = ?",
		)
		.get(user.userId, clientId) as
		| { scopes: string; resources: string | null }
		| undefined;

	const requestedScopes = scope.split(" ").filter(Boolean);

	// Auto-approve only when the existing grant covers both the requested scopes
	// and the requested audiences. A new resource is an escalation the user has
	// not seen, so it re-prompts even though the scopes are unchanged.
	if (permission) {
		const grantedScopes = JSON.parse(permission.scopes) as string[];
		const hasAllScopes = requestedScopes.every((s) =>
			grantedScopes.includes(s),
		);

		const grantedResources = storedToResources(permission.resources);
		const hasAllResources = requestedResources.every((r) =>
			grantedResources.includes(r),
		);

		if (hasAllScopes && hasAllResources) {
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
				meHint,
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
		meHint,
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
	// URL-based client IDs fall back to hostname. The full client_id is shown
	// alongside either way so a borrowed name cannot impersonate another app.
	let appName: string;

	if (clientId.startsWith("ikc_")) {
		appName = appData?.name || clientId;
	} else {
		try {
			const parsedUrl = new URL(clientId);
			appName = appData?.name || parsedUrl.hostname;
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
		try {
			body = (await req.json()) as Record<string, string>;
		} catch {
			return errorPage({
				title: "Invalid Request",
				message: "The consent submission was not valid JSON.",
			});
		}
		formData = new FormData();
		for (const [key, value] of Object.entries(body)) {
			formData.append(key, String(value));
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
		return errorPage({
			title: "Signed Out",
			message:
				"Your session ended before the consent form was submitted. Start the sign-in again from the app.",
			status: 401,
		});
	}

	// The form's CSRF token must be the one derived from this session cookie.
	if (!csrfTokenMatches(body.csrf_token, getCsrfToken(req))) {
		return errorPage({
			title: "Stale Consent Form",
			message:
				"This consent form does not belong to your current session, so it was not accepted. Start the sign-in again from the app.",
			status: 403,
		});
	}

	const action = body.action;
	const rawClientId = body.client_id;
	const rawRedirectUri = body.redirect_uri;
	const state = body.state;
	const codeChallenge = body.code_challenge;
	// Re-checked against the signed-in user: hidden fields are attacker-editable.
	const me = trustedMeHint(body.me || null, user.userId);
	const nonce = body.nonce || null; // OIDC nonce

	if (!rawClientId || !rawRedirectUri || !state || !codeChallenge) {
		return errorPage({
			title: "Invalid Request",
			message:
				"The consent submission is missing client_id, redirect_uri, state or code_challenge.",
		});
	}

	let clientId: string;
	let redirectUri: string;
	try {
		clientId = canonicalizeURL(rawClientId);
		redirectUri = canonicalizeURL(rawRedirectUri);
	} catch {
		return errorPage({
			title: "Invalid Request",
			message:
				"The consent submission carried a client_id or redirect_uri that is not a valid URL.",
		});
	}

	// Re-validate redirect_uri against the app's registered set — the consent
	// form POSTs attacker-controllable hidden fields, so we must not trust the
	// submitted redirect_uri without checking it against the registered list.
	const app = db
		.query(
			"SELECT redirect_uris, is_preregistered FROM apps WHERE client_id = ?",
		)
		.get(clientId) as
		| { redirect_uris: string; is_preregistered: number }
		| undefined;

	if (!app) {
		return errorPage({
			title: "Invalid Client ID",
			message: "The consent submission names a client that is not registered.",
			details: [
				{ label: "Provided client_id:", value: clientId, isCode: true },
			],
		});
	}

	if (!isRedirectAllowed(app, clientId, redirectUri)) {
		return errorPage({
			title: "Unauthorized Redirect URI",
			message:
				"The consent submission carried a redirect_uri that is not registered for this client, so you were not redirected.",
			details: [
				{ label: "Requested redirect_uri:", value: redirectUri, isCode: true },
			],
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

	// Get the scopes the user actually approved (from checkboxes). An empty
	// set is a valid grant: the client only asked who the user is.
	const approvedScopes = [
		...new Set(
			(formData.getAll("scope") as string[])
				.map((s) => s.trim())
				.filter(
					(s) => s.length > 0 && s.length <= 64 && /^[\x21-\x7e]+$/.test(s),
				),
		),
	];

	// Resource indicators carried through the consent form (hidden fields).
	// Re-validate — the POST body is attacker-controllable.
	const approvedResources = validateResources(
		formData.getAll("resource") as string[],
	);
	if (approvedResources === null) {
		return errorPage({
			title: "Invalid Resource",
			message:
				"The consent submission included a resource that is not an absolute https URI.",
		});
	}
	const resourceStored = resourcesToStored(approvedResources);

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
		.query(
			"SELECT resources FROM permissions WHERE user_id = ? AND client_id = ?",
		)
		.get(user.userId, clientId) as { resources: string | null } | undefined;

	if (existing) {
		// Union the newly approved audiences with the ones already granted, so
		// approving a second resource doesn't silently drop the first.
		const merged = resourcesToStored([
			...new Set([
				...storedToResources(existing.resources),
				...approvedResources,
			]),
		]);

		db.query(
			"UPDATE permissions SET scopes = ?, resources = ?, last_used = ? WHERE user_id = ? AND client_id = ?",
		).run(
			JSON.stringify(approvedScopes),
			merged,
			Math.floor(Date.now() / 1000),
			user.userId,
			clientId,
		);
	} else {
		const app = db
			.query("SELECT default_role FROM apps WHERE client_id = ?")
			.get(clientId) as { default_role: string | null } | undefined;

		db.query(
			"INSERT INTO permissions (user_id, client_id, scopes, resources, role) VALUES (?, ?, ?, ?, ?)",
		).run(
			user.userId,
			clientId,
			JSON.stringify(approvedScopes),
			resourceStored,
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
