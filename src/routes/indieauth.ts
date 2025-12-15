import { db } from "../db";
import crypto from "crypto";

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
			`SELECT s.expires_at, u.id, u.username, u.is_admin 
			FROM sessions s 
			JOIN users u ON s.user_id = u.id 
			WHERE s.token = ?`,
		)
		.get(token) as
		| { expires_at: number; id: number; username: string; is_admin: number }
		| undefined;

	if (!session) {
		return Response.json({ error: "Invalid session" }, { status: 401 });
	}

	const now = Math.floor(Date.now() / 1000);
	if (session.expires_at < now) {
		return Response.json({ error: "Session expired" }, { status: 401 });
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
			`SELECT s.expires_at, u.id, u.username, u.is_admin 
			FROM sessions s 
			JOIN users u ON s.user_id = u.id 
			WHERE s.token = ?`,
		)
		.get(sessionToken) as
		| { expires_at: number; id: number; username: string; is_admin: number }
		| undefined;

	if (!session) return null;

	const now = Math.floor(Date.now() / 1000);
	if (session.expires_at < now) return null;

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

// Auto-register app if it doesn't exist
function ensureApp(clientId: string, redirectUri: string): void {
	const existing = db
		.query("SELECT id FROM apps WHERE client_id = ?")
		.get(clientId);

	if (!existing) {
		// New app - auto-register
		db.query(
			"INSERT INTO apps (client_id, redirect_uris, last_used) VALUES (?, ?, ?)",
		).run(clientId, JSON.stringify([redirectUri]), Math.floor(Date.now() / 1000));
	} else {
		// Update last_used
		db.query("UPDATE apps SET last_used = ? WHERE client_id = ?").run(
			Math.floor(Date.now() / 1000),
			clientId,
		);
	}
}

// GET /auth/authorize - Authorization request
export function authorizeGet(req: Request): Response {
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

	if (responseType !== "code") {
		return new Response("Unsupported response_type", { status: 400 });
	}

	if (!clientId || !redirectUri || !state || !codeChallenge) {
		return new Response("Missing required parameters", { status: 400 });
	}

	if (codeChallengeMethod && codeChallengeMethod !== "S256") {
		return new Response("Only S256 code_challenge_method supported", {
			status: 400,
		});
	}

	// Check if user is logged in
	const user = getUserFromCookie(req);

	if (!user) {
		// Not logged in - redirect to login with return URL
		const returnUrl = `/auth/authorize${url.search}`;
		return Response.redirect(`/login?return=${encodeURIComponent(returnUrl)}`);
	}

	// Auto-register app
	ensureApp(clientId, redirectUri);

	// Check if user has previously granted permission to this app
	const permission = db
		.query(
			"SELECT scopes FROM permissions WHERE user_id = ? AND client_id = ?",
		)
		.get(user.userId, clientId) as { scopes: string } | undefined;

	const requestedScopes = scope.split(" ").filter(Boolean);

	// If permission exists and covers all requested scopes, auto-approve
	if (permission) {
		const grantedScopes = JSON.parse(permission.scopes) as string[];
		const hasAllScopes = requestedScopes.every((s) => grantedScopes.includes(s));

		if (hasAllScopes) {
			// Auto-approve - create auth code and redirect
			const code = crypto.randomBytes(32).toString("base64url");
			const expiresAt = Math.floor(Date.now() / 1000) + 60; // 60 seconds

			db.query(
				"INSERT INTO authcodes (code, user_id, client_id, redirect_uri, scopes, code_challenge, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			).run(
				code,
				user.userId,
				clientId,
				redirectUri,
				JSON.stringify(requestedScopes),
				codeChallenge,
				expiresAt,
			);

			// Update permission last_used
			db.query(
				"UPDATE permissions SET last_used = ? WHERE user_id = ? AND client_id = ?",
			).run(Math.floor(Date.now() / 1000), user.userId, clientId);

			return Response.redirect(`${redirectUri}?code=${code}&state=${state}`);
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
	);
}

function showConsentScreen(
	user: SessionUser,
	clientId: string,
	redirectUri: string,
	state: string,
	codeChallenge: string,
	scopes: string[],
): Response {
	const appName = new URL(clientId).hostname;

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
      max-width: 28rem;
      width: 100%;
      background: rgba(188, 141, 160, 0.05);
      border: 1px solid var(--old-rose);
      padding: 2rem;
    }
    h1 {
      font-size: 1.5rem;
      font-weight: 700;
      color: var(--lavender);
      margin-bottom: 1rem;
    }
    .app-name {
      color: var(--berry-crush);
      font-weight: 700;
    }
    .scopes {
      margin: 1.5rem 0;
      padding: 1rem;
      background: rgba(12, 23, 19, 0.6);
      border: 1px solid var(--rosewood);
    }
    .scope-title {
      font-size: 0.875rem;
      color: var(--old-rose);
      text-transform: uppercase;
      letter-spacing: 0.05rem;
      margin-bottom: 0.75rem;
    }
    .scope-list {
      list-style: none;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }
    .scope-list li {
      color: var(--lavender);
      padding-left: 1.5rem;
      position: relative;
    }
    .scope-list li::before {
      content: "✓";
      position: absolute;
      left: 0;
      color: var(--berry-crush);
    }
    .buttons {
      display: flex;
      gap: 1rem;
      margin-top: 1.5rem;
    }
    button {
      flex: 1;
      padding: 1rem;
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
      pointer-events: none;
      transition: all 0.15s ease;
    }
    button:hover {
      transform: translate(3px, 3px);
      box-shadow: 3px 3px 0 var(--mahogany);
    }
    .allow {
      background: var(--berry-crush);
      color: var(--lavender);
    }
    .allow::before {
      border: 4px solid var(--rosewood);
    }
    .deny {
      background: transparent;
      color: var(--old-rose);
      box-shadow: 4px 4px 0 var(--mahogany);
    }
    .deny::before {
      border: 4px solid var(--old-rose);
    }
    .user-info {
      margin-bottom: 1.5rem;
      padding: 1rem;
      background: rgba(188, 141, 160, 0.1);
      border-left: 3px solid var(--berry-crush);
      font-size: 0.875rem;
      color: var(--old-rose);
    }
  </style>
</head>
<body>
  <div class="consent-box">
    <h1>authorize app</h1>
    
    <div class="user-info">
      Signing in as <strong>${user.username}</strong>
    </div>

    <p style="margin-bottom: 1rem;">
      <span class="app-name">${appName}</span> is requesting access to:
    </p>

    <div class="scopes">
      <div class="scope-title">permissions</div>
      <ul class="scope-list">
        ${scopes
					.map(
						(scope) => `
          <li>${scope === "profile" ? "Your profile (name, photo, URL)" : scope === "email" ? "Your email address" : scope}</li>
        `,
					)
					.join("")}
      </ul>
    </div>

    <form method="POST" action="/auth/authorize">
      <input type="hidden" name="client_id" value="${clientId}" />
      <input type="hidden" name="redirect_uri" value="${redirectUri}" />
      <input type="hidden" name="state" value="${state}" />
      <input type="hidden" name="code_challenge" value="${codeChallenge}" />
      <input type="hidden" name="scopes" value="${scopes.join(" ")}" />
      
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
	const user = getUserFromCookie(req);

	if (!user) {
		return new Response("Unauthorized", { status: 401 });
	}

	const formData = await req.formData();
	const action = formData.get("action") as string;
	const clientId = formData.get("client_id") as string;
	const redirectUri = formData.get("redirect_uri") as string;
	const state = formData.get("state") as string;
	const codeChallenge = formData.get("code_challenge") as string;
	const scopesStr = formData.get("scopes") as string;

	if (!clientId || !redirectUri || !state || !codeChallenge || !scopesStr) {
		return new Response("Missing required parameters", { status: 400 });
	}

	if (action === "deny") {
		return Response.redirect(
			`${redirectUri}?error=access_denied&state=${state}`,
		);
	}

	const scopes = scopesStr.split(" ").filter(Boolean);

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
		JSON.stringify(scopes),
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
		).run(JSON.stringify(scopes), Math.floor(Date.now() / 1000), user.userId, clientId);
	} else {
		db.query(
			"INSERT INTO permissions (user_id, client_id, scopes) VALUES (?, ?, ?)",
		).run(user.userId, clientId, JSON.stringify(scopes));
	}

	// Update app last_used
	db.query("UPDATE apps SET last_used = ? WHERE client_id = ?").run(
		Math.floor(Date.now() / 1000),
		clientId,
	);

	return Response.redirect(`${redirectUri}?code=${code}&state=${state}`);
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
					error_description: "Content-Type must be application/json or application/x-www-form-urlencoded",
				},
				{ status: 400 },
			);
		}
		
		const {
			grant_type,
			code,
			client_id,
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

		if (!code || !client_id || !redirect_uri || !code_verifier) {
			console.error("Token endpoint: missing parameters", { code: !!code, client_id: !!client_id, redirect_uri: !!redirect_uri, code_verifier: !!code_verifier });
			return Response.json(
				{
					error: "invalid_request",
					error_description: "Missing required parameters",
				},
				{ status: 400 },
			);
		}

		// Look up authorization code
		const authcode = db
			.query(
				"SELECT user_id, client_id, redirect_uri, scopes, code_challenge, expires_at, used FROM authcodes WHERE code = ?",
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

		// Verify PKCE code_verifier
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
			.query(
				"SELECT username, name, email, photo, url FROM users WHERE id = ?",
			)
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

		return Response.json({
			me: `${process.env.ORIGIN}/u/${user.username}`,
			profile,
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
export function userProfile(req: Request, username: string): Response {
	const user = db
		.query("SELECT username, name, email, photo, url FROM users WHERE username = ?")
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
  <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
  <link rel="authorization_endpoint" href="${process.env.ORIGIN}/auth/authorize" />
  <link rel="token_endpoint" href="${process.env.ORIGIN}/auth/token" />
  ${user.url ? `<link rel="me" href="${user.url}" />` : ""}
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
    .u-email {
      color: var(--old-rose);
      text-decoration: none;
      margin-top: 0.5rem;
      font-size: 0.875rem;
    }
    .u-email:hover {
      color: var(--berry-crush);
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
      <a class="p-name u-url" href="${user.url || `${process.env.ORIGIN}/u/${user.username}`}">${user.name}</a>
      ${user.email ? `<a class="u-email" href="mailto:${user.email}">email</a>` : ""}
      <div class="identity-info">
        IndieAuth identity: <code>${process.env.ORIGIN}/u/${user.username}</code>
      </div>
    </div>

    <div class="indieauth-info">
      <h2>Use This Identity on Your Website</h2>
      <p>
        You can delegate IndieAuth to this server from your own website. Add these tags to your site's <code>&lt;head&gt;</code>:
      </p>
      <div class="code-box"><span class="html-tag">&lt;link</span> <span class="html-attr">rel</span>=<span class="html-value">"authorization_endpoint"</span> <span class="html-attr">href</span>=<span class="html-value">"${process.env.ORIGIN}/auth/authorize"</span> <span class="html-tag">/&gt;</span>
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

	return new Response(html, {
		headers: { "Content-Type": "text/html" },
	});
}

// POST /api/invites/create - Create invite link (admin only)
export function createInvite(req: Request): Response {
	const user = getSessionUser(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.isAdmin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	const inviteCode = crypto.randomBytes(16).toString("base64url");

	db.query(
		"INSERT INTO invites (code, created_by) VALUES (?, ?)",
	).run(inviteCode, user.userId);

	return Response.json({
		inviteCode,
		inviteUrl: `${process.env.ORIGIN}/login?invite=${inviteCode}`,
	});
}
