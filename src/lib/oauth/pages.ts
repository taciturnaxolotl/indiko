// Server-rendered HTML pages for the OAuth flow (errors, consent).

export function escapeHtml(value: string): string {
	return value
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");
}

const BASE_STYLES = `
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
	.box {
		max-width: 600px;
		background: rgba(188, 141, 160, 0.05);
		border: 2px solid var(--rosewood);
		padding: 2.5rem;
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
	.hint {
		margin-top: 1.5rem;
		font-size: 0.875rem;
		color: var(--old-rose);
	}
	button {
		position: relative;
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
		top: -7px; left: -7px; right: -7px; bottom: -7px;
	}
	button:active {
		transform: translate(6px, 6px);
		box-shadow: 0 0 0 var(--mahogany);
	}
`;

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
	<style>${BASE_STYLES}${styles}</style>
</head>
<body>
${body}
</body>
</html>`;

	return new Response(html, {
		status: 400,
		headers: { "Content-Type": "text/html" },
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
	.app-info { flex: 1; }
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
	.user-badge strong { color: var(--lavender); }
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
	.scope-list input[type="checkbox"]:disabled { cursor: not-allowed; }
	.buttons {
		display: flex;
		gap: 1rem;
	}
	.buttons button { flex: 1; }
	.allow {
		background: var(--berry-crush);
		color: var(--lavender);
	}
	.allow::before { border-color: var(--rosewood); }
	.deny {
		background: transparent;
		color: var(--old-rose);
	}
	.deny::before { border-color: var(--old-rose); }
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
}

const SCOPE_DESCRIPTIONS: Record<string, string> = {
	profile: "Your profile (name, photo, URL)",
	email: "Your email address",
	openid: "Authenticate with OpenID Connect (issues an id_token)",
};

export function consentPage(opts: ConsentPageOptions): Response {
	const scopeItems = opts.scopes
		.map((scope) => {
			const isProfile = scope === "profile";
			const description = escapeHtml(SCOPE_DESCRIPTIONS[scope] ?? scope);
			const required = isProfile
				? ' <span style="color: var(--old-rose); font-size: 0.875rem; margin-left: 0.5rem;">(required)</span>'
				: "";
			return `
          <li>
            <label>
              <input type="checkbox" name="scope" value="${escapeHtml(scope)}" ${isProfile ? "checked disabled" : "checked"} />
              <span>${description}${required}</span>
            </label>
          </li>`;
		})
		.join("");

	const body = `  <div class="consent-box">
    <div class="user-badge">
      <span>Signing in as</span>
      <strong>${escapeHtml(opts.username)}</strong>
    </div>

    <div class="app-header">
      <div class="app-logo">
        ${opts.appLogo ? `<img src="${escapeHtml(opts.appLogo)}" alt="${escapeHtml(opts.appName)}" />` : "🔐"}
      </div>
      <div class="app-info">
        <div class="app-name">${escapeHtml(opts.appName)}</div>
        ${opts.appUrl ? `<div class="app-url">${escapeHtml(opts.appUrl)}</div>` : ""}
        ${opts.appDescription ? `<div class="app-description">${escapeHtml(opts.appDescription)}</div>` : ""}
      </div>
    </div>

    <div class="request-text">
      This app would like to access the following information:
    </div>

    <div class="scopes">
      <div class="scope-title">requested permissions</div>
      <ul class="scope-list">${scopeItems}
      </ul>
    </div>

    <form method="POST" action="/auth/authorize">
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
  </div>`;

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
  <style>${BASE_STYLES}${CONSENT_STYLES}</style>
</head>
<body>
${body}
</body>
</html>`;

	return new Response(html, {
		headers: { "Content-Type": "text/html" },
	});
}
