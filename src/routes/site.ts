// Public site surface: landing page, trust pages, and the machine-readable
// files agents look for (robots.txt, sitemap.xml, llms.txt) plus a 404 that
// tells a lost crawler where to go instead.

import { Marked } from "marked";
import { negotiate } from "../lib/accept";
import {
	CONTACT_EMAIL,
	CONTENT_PAGES,
	type ContentPage,
	getContentPage,
	lastModified,
	REPO_URL,
	renderContentPage,
	renderMarkdown,
	SECURITY_EMAIL,
} from "../lib/content-pages";
import { docsLastModified } from "../lib/docs-renderer";
import { escapeHtml } from "../lib/oauth/pages";
import { getUserFromCookie } from "../lib/session";

const HTML = "text/html";
const MARKDOWN = "text/markdown";
const PLAIN = "text/plain";
// Order matters: it decides the winner when a client accepts several equally.
const OFFERS = [HTML, MARKDOWN, PLAIN];

const VARY = "Accept, Accept-Encoding";

function origin(): string {
	return process.env.ORIGIN || "http://localhost:3000";
}

function notAcceptable(): Response {
	return new Response(
		`Not Acceptable. This URL is available as ${OFFERS.join(", ")}.\n`,
		{
			status: 406,
			headers: {
				"Content-Type": "text/plain; charset=utf-8",
				Vary: VARY,
			},
		},
	);
}

function methodNotAllowed(): Response {
	return new Response("Method not allowed", {
		status: 405,
		headers: { Allow: "GET, HEAD" },
	});
}

/**
 * Serve one markdown-backed page as HTML or markdown, per the Accept header.
 * See https://acceptmarkdown.com.
 */
export function contentResponse(page: ContentPage, req: Request): Response {
	if (req.method !== "GET" && req.method !== "HEAD") return methodNotAllowed();

	const chosen = negotiate(req.headers.get("Accept"), OFFERS);
	if (!chosen) return notAcceptable();

	const body =
		chosen === HTML ? renderContentPage(page, origin()) : renderMarkdown(page);

	return new Response(body, {
		headers: {
			"Content-Type": `${chosen}; charset=utf-8`,
			Vary: VARY,
			"Last-Modified": lastModified(page).toUTCString(),
		},
	});
}

function pageHandler(slug: string) {
	return (req: Request): Response => {
		const page = getContentPage(slug);
		if (!page) return notFound(req);
		return contentResponse(page, req);
	};
}

/**
 * `/` is a signpost, not a page: people go to their dashboard or the login
 * screen, and anything asking for markdown is sent to the docs, which are
 * the only thing at this origin worth reading as text.
 */
export function homePage(req: Request): Response {
	if (req.method !== "GET" && req.method !== "HEAD") return methodNotAllowed();

	const wantsMarkdown = negotiate(req.headers.get("Accept"), OFFERS) !== HTML;
	const target = wantsMarkdown
		? "/docs"
		: getUserFromCookie(req)
			? "/dashboard"
			: "/login";

	return new Response(null, {
		status: 302,
		headers: { Location: target, Vary: "Accept, Cookie" },
	});
}

export const aboutPage = pageHandler("about");
export const contactPage = pageHandler("contact");
export const privacyPage = pageHandler("privacy");

// Private or pointless-to-crawl surfaces. Everything else is fair game.
const DISALLOWED = [
	"/admin",
	"/api/",
	"/auth/",
	"/device",
	"/apps",
	"/dashboard",
	"/login",
];

export function robotsTxt(): Response {
	const rules = [
		...DISALLOWED.map((path) => `Disallow: ${path}`),
		"Allow: /",
	].join("\n");

	return new Response(
		`# indiko — IndieAuth / OAuth 2.0 / OIDC provider
# Public pages, docs, and machine-readable metadata are open to crawlers.
# Cloudflare appends its own managed block below covering AI crawlers; this
# file deliberately names no AI user-agents so the two cannot contradict
# each other. Agents that are allowed through start at /llms.txt.

User-agent: *
${rules}

Sitemap: ${origin()}/sitemap.xml
`,
		{ headers: { "Content-Type": "text/plain; charset=utf-8" } },
	);
}

interface SitemapEntry {
	path: string;
	lastmod?: Date;
	priority: string;
	changefreq: string;
}

function sitemapEntries(): SitemapEntry[] {
	const entries: SitemapEntry[] = CONTENT_PAGES.map((page) => ({
		path: page.path,
		lastmod: lastModified(page),
		priority: page.priority,
		changefreq: "monthly",
	}));
	entries.push({
		path: "/docs",
		lastmod: docsLastModified(),
		priority: "0.9",
		changefreq: "monthly",
	});
	entries.push({
		path: "/docs.md",
		lastmod: docsLastModified(),
		priority: "0.6",
		changefreq: "monthly",
	});
	return entries;
}

export function sitemapXml(): Response {
	const base = origin();
	const urls = sitemapEntries()
		.map((entry) => {
			const lastmod = entry.lastmod
				? `\n\t\t<lastmod>${entry.lastmod.toISOString().slice(0, 10)}</lastmod>`
				: "";
			return `\t<url>\n\t\t<loc>${escapeHtml(`${base}${entry.path}`)}</loc>${lastmod}\n\t\t<changefreq>${entry.changefreq}</changefreq>\n\t\t<priority>${entry.priority}</priority>\n\t</url>`;
		})
		.join("\n");

	return new Response(
		`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls}
</urlset>
`,
		{ headers: { "Content-Type": "application/xml; charset=utf-8" } },
	);
}

export function llmsTxt(): Response {
	const base = origin();
	const body = `# indiko

> indiko is a self-hosted IndieAuth, OAuth 2.0, and OpenID Connect identity provider that signs people in with passkeys. This instance, ${base}, is the authentication provider for the dunkirk.sh homelab and side projects. The software is open source and anyone can run their own copy. Its root URL is a redirect, not a page: start at the documentation below.

**When to use indiko.** Reach for these pages when a task involves any of the following:

- Integrating an app with this server: you need the authorization, token, userinfo, or JWKS endpoints, the scopes it supports, or a worked example of the authorization code flow with PKCE. Start with ${base}/docs, or fetch ${base}/docs.md for the same text as raw markdown.
- Signing in a device without a browser (a CLI, a TV, a microcontroller): use the OAuth 2.0 device authorization grant documented in the docs, starting at ${base}/auth/device.
- Discovering capabilities programmatically: fetch ${base}/.well-known/oauth-authorization-server for IndieAuth and OAuth 2.0 metadata, or ${base}/.well-known/openid-configuration for OIDC. Both are JSON and are the authoritative answer about supported grant types, scopes, and endpoints.
- Answering questions about what indiko is, who runs it, or what it stores: use ${base}/about and ${base}/privacy rather than inferring from the sign-in page that ${base}/ redirects to.
- Reporting a vulnerability or reaching a human: ${base}/contact, or ${SECURITY_EMAIL} for security and ${CONTACT_EMAIL} for everything else.

**How to call it.** Every documented endpoint speaks HTTP with JSON responses and standard OAuth error codes. Public clients identify themselves by URL (IndieAuth style) and are registered on first use; confidential clients are created by an admin and authenticate with \`client_secret_post\`. PKCE with \`S256\` is required, authorization codes are single-use and expire after sixty seconds, and \`/auth/token\` is the only endpoint that issues tokens.

**What not to expect.** indiko is not a hosted sign-up service. Accounts on this instance are invite-only and there is no registration form, so do not send people here to create an account. It has no public data API: ${base}/api/* requires a session and returns 401 without one. To use indiko yourself, run your own instance from the source repository.

Every page below is available as markdown by sending \`Accept: text/markdown\`.

## Docs

- [Documentation](${base}/docs): full integration guide, endpoint reference, scopes, roles, device flow, and OIDC claims.
- [Documentation as markdown](${base}/docs.md): the same guide as raw markdown, best for direct ingestion.

## About this instance

- [About](${base}/about): what indiko is, who runs it, and which specifications it implements.
- [Contact](${base}/contact): email addresses for support, security reports, and bugs.
- [Privacy](${base}/privacy): exactly what is stored, for how long, and how to delete it.

## Machine-readable metadata

- [OAuth 2.0 / IndieAuth server metadata](${base}/.well-known/oauth-authorization-server): JSON discovery document.
- [OpenID Connect discovery](${base}/.well-known/openid-configuration): JSON discovery document.
- [JWKS](${base}/jwks): public keys for verifying ID tokens.
- [security.txt](${base}/.well-known/security.txt): security contact and policy.
- [Sitemap](${base}/sitemap.xml): every public URL.

## Optional

- [Source repository](${REPO_URL}): install instructions, issue tracker, and license.
- [Health check](${base}/health): JSON status of the running instance.
`;

	return new Response(body, {
		headers: {
			"Content-Type": "text/markdown; charset=utf-8",
			Vary: VARY,
		},
	});
}

const marked = new Marked();

/**
 * 404 that an agent can act on: a short markdown body pointing at the places
 * worth trying next, served as HTML or markdown depending on Accept.
 */
export function notFound(req: Request): Response {
	const base = origin();
	const path = new URL(req.url).pathname;
	const body = `# 404 — page not found

\`${path}\` does not exist on this server.

Where to look next:

- [Documentation](${base}/docs) — integration guide (raw markdown at [${base}/docs.md](${base}/docs.md))
- [llms.txt](${base}/llms.txt) — agent-friendly index of this site
- [sitemap.xml](${base}/sitemap.xml) — every public URL
- [OAuth 2.0 server metadata](${base}/.well-known/oauth-authorization-server) — endpoints and capabilities as JSON
- [Contact](${base}/contact) — reach a human

If you followed a link to get here, the [contact page](${base}/contact) has an address for reporting it.
`;

	const chosen = negotiate(req.headers.get("Accept"), OFFERS);
	const headers = { Vary: VARY };

	if (!chosen || chosen !== HTML) {
		return new Response(body, {
			status: 404,
			headers: {
				...headers,
				"Content-Type": `${chosen ?? PLAIN}; charset=utf-8`,
			},
		});
	}

	const html = marked.parse(body, { async: false }) as string;
	const page = `<!doctype html>
<html lang="en">

<head>
	<meta charset="UTF-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1.0" />
	<title>404 • indiko</title>
	<meta name="description" content="That page does not exist on indiko. Here is where to look instead." />
	<meta name="robots" content="noindex" />
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
	<div class="container">
		<section class="section">${html}</section>
	</div>
</body>

</html>`;

	return new Response(page, {
		status: 404,
		headers: { ...headers, "Content-Type": "text/html; charset=utf-8" },
	});
}
