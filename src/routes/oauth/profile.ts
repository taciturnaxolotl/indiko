import { db } from "../../db";
import { escapeHtml } from "../../lib/oauth/pages";

// GET /u/:username - Public user profile (h-card)
export function userProfile(req: Request): Response {
	const username = (req as Request & { params?: { username?: string } }).params
		?.username;
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

	const origin = process.env.ORIGIN || "http://localhost:3000";
	const profileUrl = user.url || `${origin}/u/${user.username}`;

	const name = escapeHtml(user.name);
	const photo = user.photo ? escapeHtml(user.photo) : null;
	const email = user.email ? escapeHtml(user.email) : null;
	const website = user.url ? escapeHtml(user.url) : null;
	const escapedProfileUrl = escapeHtml(profileUrl);

	const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${name} • indiko</title>
  <meta name="description" content="${name}'s profile on Indiko${website ? ` - ${website}` : ""}" />
  <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
  <link rel="indieauth-metadata" href="${origin}/.well-known/oauth-authorization-server" />
  <link rel="authorization_endpoint" href="${origin}/auth/authorize" />
  <link rel="token_endpoint" href="${origin}/auth/token" />
  ${website ? `<link rel="me" href="${website}" />` : ""}

  <!-- Open Graph / Facebook -->
  <meta property="og:type" content="profile" />
  <meta property="og:title" content="${name}" />
  <meta property="og:description" content="${name}'s profile on Indiko" />
  <meta property="og:url" content="${escapedProfileUrl}" />
  ${photo ? `<meta property="og:image" content="${photo}" />` : ""}
  <meta property="profile:username" content="${escapeHtml(user.username)}" />

  <!-- Twitter -->
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content="${name}" />
  <meta name="twitter:description" content="${name}'s profile on Indiko" />
  ${photo ? `<meta name="twitter:image" content="${photo}" />` : ""}

  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300..700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/ds/tokens.css">
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      font-family: var(--font);
      background: var(--ink);
      color: var(--paper);
      min-height: 100vh;
      padding: 2.5rem 1.25rem;
    }
    .container {
      max-width: 600px;
      margin: 0 auto;
    }
    .h-card {
      background: rgba(188, 141, 160, 0.05);
      border: 1px solid var(--paper-dim);
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
      border: 3px solid var(--accent);
    }
    .p-name {
      font-size: 1.5rem;
      font-weight: 700;
      text-decoration: none;
      color: var(--paper);
      margin-bottom: 0.5rem;
    }
    .p-name:hover {
      color: var(--accent);
    }
    .u-email, .u-url-link {
      color: var(--paper-dim);
      text-decoration: none;
      margin-top: 0.5rem;
      font-size: 0.875rem;
    }
    .u-email:hover, .u-url-link:hover {
      color: var(--accent);
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
      border: 1px solid var(--accent-deep);
      font-size: 0.875rem;
      color: var(--paper-dim);
    }
    .identity-info code {
      color: var(--accent);
      font-family: var(--font), monospace;
    }
    .indieauth-info {
      background: rgba(188, 141, 160, 0.05);
      border: 1px solid var(--paper-dim);
      padding: 2rem;
    }
    .indieauth-info h2 {
      font-size: 1.25rem;
      font-weight: 600;
      margin-bottom: 1rem;
      color: var(--paper);
    }
    .indieauth-info p {
      margin-bottom: 1rem;
      color: var(--paper-dim);
      line-height: 1.6;
    }
    .indieauth-info code {
      color: var(--accent);
      font-family: var(--font), monospace;
    }
    .code-box {
      background: rgba(12, 23, 19, 0.6);
      border: 2px solid var(--accent-deep);
      padding: 1rem;
      margin: 1rem 0;
      font-family: var(--font), monospace;
      font-size: 0.875rem;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .html-tag {
      color: var(--accent);
    }
    .html-attr {
      color: var(--paper-dim);
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
      color: var(--accent);
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
      ${photo ? `<img class="u-photo" src="${photo}" alt="${name}" />` : ""}
      <h1 class="p-name">${name}</h1>
      <div class="links">
        ${website ? `<a class="u-url u-url-link" rel="me" href="${website}">website</a>` : ""}
        ${email ? `<a class="u-email" rel="me" href="mailto:${email}">email</a>` : ""}
      </div>
      <div class="identity-info">
        IndieAuth identity: <code>${escapedProfileUrl}</code>
      </div>
    </div>

    <div class="indieauth-info">
      <h2>Use This Identity on Your Website</h2>
      <p>
        You can delegate IndieAuth to this server from your own website. Add these tags to your site's <code>&lt;head&gt;</code>:
      </p>
      <div class="code-box"><span class="html-tag">&lt;link</span> <span class="html-attr">rel</span>=<span class="html-value">"indieauth-metadata"</span> <span class="html-attr">href</span>=<span class="html-value">"${origin}/.well-known/oauth-authorization-server"</span> <span class="html-tag">/&gt;</span>
<span class="html-tag">&lt;link</span> <span class="html-attr">rel</span>=<span class="html-value">"authorization_endpoint"</span> <span class="html-attr">href</span>=<span class="html-value">"${origin}/auth/authorize"</span> <span class="html-tag">/&gt;</span>
<span class="html-tag">&lt;link</span> <span class="html-attr">rel</span>=<span class="html-value">"token_endpoint"</span> <span class="html-attr">href</span>=<span class="html-value">"${origin}/auth/token"</span> <span class="html-tag">/&gt;</span>
<span class="html-tag">&lt;link</span> <span class="html-attr">rel</span>=<span class="html-value">"me"</span> <span class="html-attr">href</span>=<span class="html-value">"${origin}/u/${escapeHtml(user.username)}"</span> <span class="html-tag">/&gt;</span></div>
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
		headers: {
			"Content-Type": "text/html",
			Link: `<${origin}/.well-known/oauth-authorization-server>; rel="indieauth-metadata"`,
			"X-Frame-Options": "DENY",
			"Content-Security-Policy": "frame-ancestors 'none'",
		},
	});
}
