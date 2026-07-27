import { getRawMarkdown, renderDocs } from "../lib/docs-renderer";
import { escapeHtml } from "../lib/oauth/pages";

// Bundle the docs client once at startup so the server-rendered page can
// reference a real script URL (the other pages get this via bun's html
// bundler, which this hand-rendered page bypasses).
const docsJsPromise = Bun.build({
	entrypoints: ["./src/client/docs.ts"],
	target: "browser",
}).then((out) => out.outputs[0]?.text() ?? "");

export async function docsJs(): Promise<Response> {
	const js = await docsJsPromise;
	return new Response(js, {
		headers: { "Content-Type": "text/javascript; charset=utf-8" },
	});
}

// Wrap each top-level (##) section in a .section div for the card styling.
function wrapSections(html: string): string {
	// Split on <h2 ...> boundaries, keeping the h2 with its content
	const parts = html.split(/(?=<h2 )/);
	return parts
		.map((part) => {
			const trimmed = part.trim();
			if (!trimmed) return "";
			if (trimmed.startsWith("<h2")) {
				return `<section class="section">${trimmed}</section>\n`;
			}
			// Content before the first h2 (intro), keep as a section too
			return `<section class="section">${trimmed}</section>\n`;
		})
		.join("");
}

function testerIsland(): string {
	return `
	<section id="tester" class="section">
		<h2>OAuth tester</h2>
		<p>
			Test the OAuth flow with a live interactive client. This simulates how your app would integrate with Indiko.
		</p>

		<div id="testerForm">
			<label for="clientId">client id (your app's URL)</label>
			<input type="url" id="clientId" value="" placeholder="https://example.com" />

			<label for="redirectUri">redirect uri (callback URL)</label>
			<input type="url" id="redirectUri" value="" placeholder="https://example.com/callback" />

			<div class="checkbox-group">
				<label>scopes to request:</label>
				<label>
					<input type="checkbox" name="scope" value="profile" checked />
					<span>profile (name, photo, URL)</span>
				</label>
				<label>
					<input type="checkbox" name="scope" value="email" />
					<span>email</span>
				</label>
			</div>

			<button type="button" id="startBtn">start oauth flow</button>
		</div>

		<div id="callbackSection" style="display: none;">
			<h3>callback received</h3>
			<div class="info-box">
				You've been redirected back with an authorization code. Click below to exchange it for user data.
			</div>
			<div id="callbackInfo"></div>
			<button type="button" id="exchangeBtn">exchange code for profile</button>
		</div>

		<div id="resultSection" style="display: none;">
			<h3>result</h3>
			<div id="result" class="result"></div>
		</div>

		<div class="info-box" style="margin-top: 2rem;">
			<strong>How it works:</strong>
			This page uses the current URL as the redirect URI. After authorization, the code is automatically detected and
			you can exchange it for user profile data.
		</div>
	</section>`;
}

export function docsPage(req: Request): Response {
	// Content negotiation: a client asking for markdown/plain text gets the
	// raw source instead of the rendered page.
	const accept = req.headers.get("Accept") ?? "";
	const wantsMarkdown =
		accept.includes("text/markdown") ||
		accept.includes("text/x-markdown") ||
		(accept.includes("text/plain") && !accept.includes("text/html"));

	if (wantsMarkdown) {
		return docsMarkdown();
	}

	const origin = process.env.ORIGIN || "http://localhost:3000";
	const { title, subtitle, html, toc } = renderDocs(origin);

	// Build a nested tree: top-level (h2) items with their h3 children indented.
	function tocTree(entries: typeof toc): string {
		const items: string[] = [];
		let openSub = false;
		for (const e of entries) {
			if (e.level === 2) {
				if (openSub) {
					items.push("</ul></li>");
					openSub = false;
				}
				items.push(`<li><a href="#${e.id}">${escapeHtml(e.text)}</a>`);
			} else {
				if (!openSub) {
					items.push("<ul>");
					openSub = true;
				}
				items.push(`<li><a href="#${e.id}">${escapeHtml(e.text)}</a></li>`);
			}
		}
		if (openSub) items.push("</ul></li>");
		else items.push("</li>");
		return items.join("");
	}

	const tocHtml = `
		<nav class="toc">
			<h3>table of contents</h3>
			<ul>
				${tocTree(toc)}
				<li><a href="#tester">oauth tester</a></li>
			</ul>
		</nav>`;

	const body = `${tocHtml}\n${wrapSections(html)}\n${testerIsland()}`;

	const page = `<!doctype html>
<html lang="en">
<head>
	<meta charset="UTF-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1.0" />
	<title>${escapeHtml(title)} • indiko</title>
	<meta name="description" content="IndieAuth/OAuth 2.0 server documentation and interactive API testing" />
	<link rel="icon" href="/favicon.svg" type="image/svg+xml" />
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300..700&display=swap" rel="stylesheet">
	<link rel="stylesheet" href="/ds/tokens.css">
	<link rel="stylesheet" href="/ds/components.css">
	<link rel="stylesheet" href="/styles.css">
	<link rel="stylesheet" href="/docs.css">
</head>
<body>
	<i-nav active="docs"></i-nav>
	<div class="container">
		<header>
			<div class="header-row">
				<h1>${escapeHtml(title)}</h1>
				<button type="button" id="copyMdBtn" class="copy-btn md-btn">copy as markdown</button>
			</div>
			<p class="subtitle">${escapeHtml(subtitle)}</p>
		</header>
		${body}
		<div class="back-link">
			<a href="/">← back to dashboard</a>
		</div>
	</div>
	<script type="module" src="/docs.js"></script>
</body>
</html>`;

	return new Response(page, {
		headers: { "Content-Type": "text/html; charset=utf-8" },
	});
}

export function docsMarkdown(): Response {
	return new Response(getRawMarkdown(), {
		headers: { "Content-Type": "text/markdown; charset=utf-8" },
	});
}
