// Server-rendered HTML pages for the OAuth flow (errors, consent).

export function escapeHtml(value: string): string {
	return value
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");
}

export const BASE_STYLES = `
	* { margin: 0; padding: 0; box-sizing: border-box; }
	body {
		font-family: var(--font);
		background: var(--ink);
		color: var(--paper);
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 2rem;
	}
	h1 {
		font-size: 2rem;
		font-weight: 700;
		color: var(--accent);
		margin-bottom: 1.5rem;
		letter-spacing: -0.05rem;
	}
	p {
		line-height: 1.8;
		margin-bottom: 1rem;
		color: var(--paper);
	}
	code {
		background: rgba(12, 23, 19, 0.8);
		padding: 0.25rem 0.5rem;
		color: var(--accent);
		font-size: 0.875rem;
		word-break: break-all;
		display: inline-block;
		max-width: 100%;
	}
	.box {
		max-width: 600px;
		background: rgba(188, 141, 160, 0.05);
		border: 2px solid var(--accent-deep);
		padding: 2.5rem;
	}
	.error-details {
		background: rgba(160, 70, 104, 0.1);
		border-left: 4px solid var(--accent-deep);
		padding: 1rem;
		margin: 1.5rem 0;
	}
	.error-details strong {
		display: block;
		margin-bottom: 0.5rem;
		color: var(--paper-dim);
	}
	.hint {
		margin-top: 1.5rem;
		font-size: 0.875rem;
		color: var(--paper-dim);
	}
	button {
		position: relative;
		padding: 1rem 1.5rem;
		border: 4px solid var(--ink-sunken);
		font-family: var(--font);
		font-size: 1rem;
		font-weight: 700;
		text-transform: uppercase;
		letter-spacing: 0.1rem;
		cursor: pointer;
		transition: all 0.15s ease;
		box-shadow: var(--shadow-hard);
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
		box-shadow: var(--shadow-hard-hover);
	}
	button:hover::before {
		top: -7px; left: -7px; right: -7px; bottom: -7px;
	}
	button:active {
		transform: translate(6px, 6px);
		box-shadow: 0 0 0 var(--ink-sunken);
	}
`;

// RFC 9700 §4.16: prevent clickjacking on the authorization endpoint
export const FRAME_DENY_HEADERS = {
	"X-Frame-Options": "DENY",
	"Content-Security-Policy": "frame-ancestors 'none'",
};

function page(title: string, styles: string, body: string): Response {
	const html = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>${escapeHtml(title)} • Indiko</title>
	<link rel="icon" href="/favicon.svg" type="image/svg+xml" />
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300..700&display=swap" rel="stylesheet">
	<link rel="stylesheet" href="/ds/tokens.css">
	<style>${BASE_STYLES}${styles}</style>
</head>
<body>
${body}
</body>
</html>`;

	return new Response(html, {
		status: 400,
		headers: { "Content-Type": "text/html", ...FRAME_DENY_HEADERS },
	});
}

export interface ErrorPageOptions {
	title: string;
	message: string;
	details?: Array<{ label: string; value: string; isCode?: boolean }>;
	hint?: string;
}

// Branded error page for authorization failures that cannot be redirected
// (i.e. redirect_uri itself is not yet trusted).
export function errorPage(opts: ErrorPageOptions): Response {
	const details = (opts.details ?? [])
		.map(
			(d) => `
		<div class="error-details">
			<strong>${escapeHtml(d.label)}</strong>
			${d.isCode ? `<code>${escapeHtml(d.value)}</code>` : `<p>${escapeHtml(d.value)}</p>`}
		</div>`,
		)
		.join("");

	return page(
		opts.title,
		"",
		`	<div class="box">
		<h1>${escapeHtml(opts.title)}</h1>
		<p>${escapeHtml(opts.message)}</p>
		${details}
		${opts.hint ? `<p class="hint">${opts.hint}</p>` : ""}
	</div>`,
	);
}

const CONSENT_STYLES = `
	body { padding: 2rem 1rem; }
	.consent {
		max-width: 30rem;
		width: 100%;
		background: rgba(188, 141, 160, 0.05);
		border: 1px solid var(--paper-dim);
		padding: 2.5rem;
	}
	.app-header {
		display: flex;
		gap: 1.25rem;
		align-items: center;
		margin-bottom: 1.25rem;
	}
	.app-logo {
		width: 4rem;
		height: 4rem;
		border-radius: 0.5rem;
		background: rgba(188, 141, 160, 0.2);
		display: flex;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
		overflow: hidden;
		font-size: 1.75rem;
	}
	.app-logo img {
		width: 100%;
		height: 100%;
		object-fit: cover;
	}
	.app-info { flex: 1; min-width: 0; }
	.app-name {
		font-size: 1.375rem;
		font-weight: 700;
		color: var(--paper);
		line-height: 1.2;
	}
	.app-url {
		font-size: 0.875rem;
		color: var(--paper-dim);
		font-family: monospace;
		margin-top: 0.25rem;
	}
	.app-description {
		font-size: 0.9375rem;
		color: var(--paper-dim);
		line-height: 1.6;
		margin-top: 0.5rem;
	}
	.request-text {
		font-size: 1rem;
		color: var(--paper-dim);
		margin-bottom: 1.5rem;
		line-height: 1.6;
	}
	.scopes {
		margin-bottom: 1.75rem;
		padding: 1.25rem;
		background: rgba(12, 23, 19, 0.4);
		border: 1px solid var(--paper-dim);
	}
	.scope-title {
		font-size: 0.75rem;
		color: var(--paper-dim);
		text-transform: uppercase;
		letter-spacing: 0.1rem;
		margin-bottom: 0.75rem;
	}
	.scope-list {
		list-style: none;
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}
	.scope-list li {
		color: var(--paper);
		font-size: 0.9375rem;
		line-height: 1.5;
	}
	.scope-list label {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		cursor: pointer;
		padding: 0.625rem;
		transition: background 0.2s;
		border: 1px solid transparent;
	}
	.scope-list label:hover {
		background: rgba(188, 141, 160, 0.1);
		border-color: var(--paper-dim);
	}
	.scope-list input[type="checkbox"] {
		appearance: none;
		width: 1.25rem;
		height: 1.25rem;
		border: 2px solid var(--paper-dim);
		background: rgba(12, 23, 19, 0.6);
		cursor: pointer;
		flex-shrink: 0;
		position: relative;
		transition: all 0.2s;
		margin: 0;
	}
	.scope-list input[type="checkbox"]:checked {
		background: var(--accent);
		border-color: var(--accent);
	}
	.scope-list input[type="checkbox"]:checked::after {
		content: "✓";
		position: absolute;
		inset: 0;
		display: grid;
		place-items: center;
		color: var(--paper);
		font-size: 0.875rem;
		font-weight: 700;
	}
	.scope-list input[type="checkbox"]:disabled { cursor: not-allowed; opacity: 0.7; }
	.req {
		font-style: normal;
		color: var(--paper-dim);
		font-size: 0.75rem;
		margin-left: 0.5rem;
	}
	.buttons {
		display: flex;
		gap: 1rem;
		margin-top: 1.75rem;
	}
	.buttons button { flex: 1; }
	.allow {
		background: var(--accent);
		color: var(--paper);
	}
	.allow::before { border-color: var(--accent-deep); }
	.deny {
		background: transparent;
		color: var(--paper-dim);
	}
	.deny::before { border-color: var(--paper-dim); }
	.who {
		margin-top: 1.5rem;
		text-align: center;
		font-size: 0.8125rem;
		color: var(--paper-dim);
	}
	.who strong { color: var(--paper); font-weight: 600; }
	.me-identity {
		margin-top: 1rem;
		padding: 0.75rem 1rem;
		background: rgba(12, 23, 19, 0.4);
		border: 1px solid var(--paper-dim);
		font-size: 0.8125rem;
		color: var(--paper-dim);
		text-align: center;
	}
	.me-identity code {
		color: var(--accent);
		font-size: 0.8125rem;
	}
`;

export interface ConsentPageOptions {
	username: string;
	appName: string;
	appUrl: string | null;
	appLogo: string | null | undefined;
	appDescription: string | null | undefined;
	scopes: string[];
	clientId: string;
	redirectUri: string;
	state: string;
	codeChallenge: string;
	me: string | null;
	nonce: string | null;
	csrfToken: string;
}

const SCOPE_DESCRIPTIONS: Record<string, string> = {
	profile: "See your profile (name, photo, URL)",
	email: "See your email address",
	openid: "Sign you in with OpenID Connect",
	offline_access: "Keep you signed in long-term",
};

export function consentPage(opts: ConsentPageOptions): Response {
	const scopeItems = opts.scopes
		.map((scope) => {
			const isProfile = scope === "profile";
			const description = escapeHtml(SCOPE_DESCRIPTIONS[scope] ?? scope);
			const required = isProfile ? ' <em class="req">required</em>' : "";
			return `
          <li>
            <label>
              <input type="checkbox" name="scope" value="${escapeHtml(scope)}" ${isProfile ? "checked disabled" : "checked"} />
              <span>${description}${required}</span>
            </label>
          </li>`;
		})
		.join("");

	const body = `  <main class="consent">
    <div class="app-header">
      <div class="app-logo">
        ${opts.appLogo ? `<img src="${escapeHtml(opts.appLogo)}" alt="" />` : "🔐"}
      </div>
      <div class="app-info">
        <div class="app-name">${escapeHtml(opts.appName)}</div>
        ${opts.appUrl ? `<div class="app-url">${escapeHtml(opts.appUrl)}</div>` : ""}
        ${opts.appDescription ? `<div class="app-description">${escapeHtml(opts.appDescription)}</div>` : ""}
      </div>
    </div>

    <p class="request-text">wants to access your account</p>
    ${opts.me ? `<div class="me-identity">requesting identity <code>${escapeHtml(opts.me)}</code></div>` : ""}

    <form method="POST" action="/auth/authorize">
      <div class="scopes">
        <div class="scope-title">requested permissions</div>
        <ul class="scope-list">${scopeItems}
        </ul>
      </div>

      <input type="hidden" name="csrf_token" value="${escapeHtml(opts.csrfToken)}" />
      <input type="hidden" name="client_id" value="${escapeHtml(opts.clientId)}" />
      <input type="hidden" name="redirect_uri" value="${escapeHtml(opts.redirectUri)}" />
      <input type="hidden" name="state" value="${escapeHtml(opts.state)}" />
      <input type="hidden" name="code_challenge" value="${escapeHtml(opts.codeChallenge)}" />
      ${opts.me ? `<input type="hidden" name="me" value="${escapeHtml(opts.me)}" />` : ""}
      ${opts.nonce ? `<input type="hidden" name="nonce" value="${escapeHtml(opts.nonce)}" />` : ""}
      <!-- Always include profile scope as it's required -->
      <input type="hidden" name="scope" value="profile" />

      <div class="buttons">
        <button type="submit" name="action" value="deny" class="deny">deny</button>
        <button type="submit" name="action" value="allow" class="allow">allow</button>
      </div>
    </form>

    <div class="who">
      signing in as <strong>${escapeHtml(opts.username)}</strong>
    </div>
  </main>`;

	const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>authorize ${escapeHtml(opts.appName)} • indiko</title>
  <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300..700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/ds/tokens.css">
  <style>${BASE_STYLES}${CONSENT_STYLES}</style>
</head>
<body>
${body}
</body>
</html>`;

	return new Response(html, {
		headers: { "Content-Type": "text/html", ...FRAME_DENY_HEADERS },
	});
}
