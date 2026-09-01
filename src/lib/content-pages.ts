// Public, server-rendered markdown pages (landing, about, contact, privacy).
//
// Each page is a markdown file in src/content/. The same source is served as
// HTML to browsers and as raw markdown to agents that ask for text/markdown,
// so the two can never drift apart.

import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { Marked, type RendererObject, type Tokens } from "marked";
import { parseFrontmatter } from "./frontmatter";
import { escapeHtml } from "./oauth/pages";

const CONTENT_DIR = join(import.meta.dir, "../content");

export const SITE_NAME = "indiko";
export const CONTACT_EMAIL = "hello@dunkirk.sh";
export const SECURITY_EMAIL = "security@dunkirk.sh";
export const REPO_URL = "https://tangled.org/@dunkirk.sh/indiko";
export const SAME_AS = [
	REPO_URL,
	"https://github.com/taciturnaxolotl/indiko",
	"https://dunkirk.sh",
];

export interface ContentPage {
	slug: string;
	/** URL path this page is served at. */
	path: string;
	file: string;
	/** Sitemap priority for this page. */
	priority: string;
}

export const CONTENT_PAGES: ContentPage[] = [
	{ slug: "about", path: "/about", file: "about.md", priority: "0.8" },
	{ slug: "contact", path: "/contact", file: "contact.md", priority: "0.7" },
	{ slug: "privacy", path: "/privacy", file: "privacy.md", priority: "0.5" },
];

export function getContentPage(slug: string): ContentPage | undefined {
	return CONTENT_PAGES.find((page) => page.slug === slug);
}

interface ParsedPage {
	title: string;
	subtitle: string;
	description: string;
	body: string;
}

function readPage(page: ContentPage): ParsedPage {
	const raw = readFileSync(join(CONTENT_DIR, page.file), "utf8");
	const { fm, body } = parseFrontmatter(raw);
	return {
		title: fm.title ?? SITE_NAME,
		subtitle: fm.subtitle ?? "",
		description: fm.description ?? fm.subtitle ?? "",
		body,
	};
}

export function lastModified(page: ContentPage): Date {
	return statSync(join(CONTENT_DIR, page.file)).mtime;
}

/**
 * The markdown an agent gets from `Accept: text/markdown`. Frontmatter is
 * replaced by the heading and summary it describes, so the document stands
 * on its own.
 */
export function renderMarkdown(page: ContentPage): string {
	const { title, subtitle, body } = readPage(page);
	const summary = subtitle ? `> ${subtitle}\n\n` : "";
	return `# ${title}\n\n${summary}${body}`;
}

/** Wrap each top-level (##) section in a .section card, matching the docs page. */
export function wrapSections(html: string): string {
	return html
		.split(/(?=<h2 )/)
		.map((part) => {
			const trimmed = part.trim();
			if (!trimmed) return "";
			return `<section class="section">${trimmed}</section>\n`;
		})
		.join("");
}

function slugify(text: string): string {
	return text
		.toLowerCase()
		.replace(/<[^>]+>/g, "")
		.replace(/[^\w\s-]/g, "")
		.trim()
		.replace(/\s+/g, "-");
}

// Headings keep their level so h1 -> h2 -> h3 stays sequential, and get ids
// so agents (and people) can link to a section.
const renderer: RendererObject = {
	heading({ tokens, depth }: Tokens.Heading): string {
		const text = this.parser.parseInline(tokens);
		const id = slugify(text);
		return `<h${depth} id="${id}">${text}</h${depth}>\n`;
	},
	table({ header, rows }: Tokens.Table): string {
		const head = header
			.map((cell) => `<th>${this.parser.parseInline(cell.tokens)}</th>`)
			.join("");
		const body = rows
			.map(
				(row) =>
					`<tr>${row
						.map((cell) => `<td>${this.parser.parseInline(cell.tokens)}</td>`)
						.join("")}</tr>`,
			)
			.join("");
		return `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>\n`;
	},
	blockquote({ tokens }: Tokens.Blockquote): string {
		const inner = this.parser.parse(tokens);
		return `<div class="info-box">${inner}</div>\n`;
	},
};

const marked = new Marked({ renderer });

function organizationNode(origin: string) {
	return {
		"@type": "Organization",
		"@id": `${origin}/#organization`,
		name: SITE_NAME,
		url: `${origin}/`,
		logo: `${origin}/logo.svg`,
		image: `${origin}/og.png`,
		email: CONTACT_EMAIL,
		description:
			"Self-hosted IndieAuth, OAuth 2.0, and OpenID Connect identity provider with passkey authentication.",
		founder: {
			"@type": "Person",
			name: "Kieran Klukas",
			url: "https://dunkirk.sh",
		},
		address: {
			"@type": "PostalAddress",
			addressLocality: "Westerville",
			addressRegion: "OH",
			postalCode: "43081",
			addressCountry: "US",
		},
		contactPoint: [
			{
				"@type": "ContactPoint",
				contactType: "technical support",
				email: CONTACT_EMAIL,
				url: `${origin}/contact`,
				availableLanguage: ["English"],
			},
			{
				"@type": "ContactPoint",
				contactType: "security",
				email: SECURITY_EMAIL,
				url: `${origin}/.well-known/security.txt`,
				availableLanguage: ["English"],
			},
		],
		sameAs: SAME_AS,
	};
}

function structuredData(
	page: ContentPage,
	parsed: ParsedPage,
	origin: string,
): string {
	const url = `${origin}${page.path}`;
	const graph: Record<string, unknown>[] = [
		organizationNode(origin),
		{
			"@type": "WebSite",
			"@id": `${origin}/#website`,
			name: SITE_NAME,
			url: `${origin}/`,
			description: parsed.description,
			inLanguage: "en",
			publisher: { "@id": `${origin}/#organization` },
		},
		{
			"@type": "WebPage",
			"@id": `${url}#webpage`,
			url,
			name: parsed.title,
			description: parsed.description,
			inLanguage: "en",
			isPartOf: { "@id": `${origin}/#website` },
			about: { "@id": `${origin}/#software` },
			primaryImageOfPage: `${origin}/og.png`,
		},
	];

	if (page.slug === "about") {
		graph.push({
			"@type": "SoftwareApplication",
			"@id": `${origin}/#software`,
			name: "Indiko",
			url: `${origin}/`,
			description: parsed.description,
			applicationCategory: "SecurityApplication",
			applicationSubCategory: "Identity provider",
			operatingSystem: "Linux, macOS",
			softwareRequirements: "Bun",
			softwareHelp: `${origin}/docs`,
			license: "https://tangled.org/@dunkirk.sh/indiko/blob/main/LICENSE.md",
			codeRepository: REPO_URL,
			image: `${origin}/og.png`,
			author: {
				"@type": "Person",
				name: "Kieran Klukas",
				url: "https://dunkirk.sh",
			},
			publisher: { "@id": `${origin}/#organization` },
			offers: {
				"@type": "Offer",
				price: "0",
				priceCurrency: "USD",
				availability: "https://schema.org/InStock",
			},
		});
	}

	const json = JSON.stringify({
		"@context": "https://schema.org",
		"@graph": graph,
	});
	// `</script>` inside JSON would close the block early; nothing else can.
	return json.replace(/<\//g, "<\\/");
}

function footer(): string {
	return `
	<footer class="site-footer">
		<nav aria-label="site">
			<a href="/docs">docs</a>
			<a href="/about">about</a>
			<a href="/contact">contact</a>
			<a href="/privacy">privacy</a>
			<a href="/llms.txt">llms.txt</a>
			<a href="${REPO_URL}" rel="noopener">source</a>
		</nav>
		<p>indiko — self-hosted IndieAuth, OAuth 2.0, and OpenID Connect, secured with passkeys.</p>
	</footer>`;
}

const FOOTER_STYLES = `
	.site-footer {
		text-align: left;
		max-width: var(--page-width);
		margin: 3rem auto 0;
		padding-top: 1.5rem;
		border-top: 1px solid var(--accent-deep);
		color: var(--paper-dim);
		font-size: var(--text-sm);
	}
	.site-footer nav {
		display: flex;
		flex-wrap: wrap;
		gap: 1rem;
		margin-bottom: 0.75rem;
	}
	i-nav .brand {
		margin-right: auto;
	}
	.page-header {
		max-width: var(--page-width);
		margin: 0 auto 2rem;
	}
	.page-header .subtitle {
		margin-top: 0.5rem;
	}`;

function siteNav(): string {
	// Hand-written rather than the <i-nav> component: these pages are for
	// signed-out readers and agents, so they carry no session chip and no
	// script. The i-nav element is kept as the scope root so the design
	// system's nav styles still apply. Navigation lives in the footer, so
	// this is just the brand and a way in.
	return `<i-nav>
		<nav class="nav">
			<a href="/" class="brand"><img src="/logo.svg" alt="indiko" /></a>
			<div class="who"><a href="/login" class="user">sign in</a></div>
		</nav>
	</i-nav>`;
}

/** Render a content page as a full HTML document. */
export function renderContentPage(page: ContentPage, origin: string): string {
	const parsed = readPage(page);
	const html = marked.parse(parsed.body, { async: false }) as string;
	const url = `${origin}${page.path}`;
	const title = `${parsed.title} • indiko`;

	return `<!doctype html>
<html lang="en">

<head>
	<meta charset="UTF-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1.0" />
	<title>${escapeHtml(title)}</title>
	<meta name="description" content="${escapeHtml(parsed.description)}" />
	<link rel="canonical" href="${url}" />
	<link rel="icon" href="/favicon.svg" type="image/svg+xml" />
	<link rel="alternate" type="text/markdown" href="${url}" title="${escapeHtml(parsed.title)} as markdown" />
	<link rel="sitemap" type="application/xml" href="/sitemap.xml" />

	<meta property="og:type" content="website" />
	<meta property="og:site_name" content="indiko" />
	<meta property="og:url" content="${url}" />
	<meta property="og:title" content="${escapeHtml(title)}" />
	<meta property="og:description" content="${escapeHtml(parsed.description)}" />
	<meta property="og:image" content="${origin}/og.png" />
	<meta property="og:image:width" content="1200" />
	<meta property="og:image:height" content="630" />
	<meta property="og:image:alt" content="The indiko wordmark on a dark background" />
	<meta name="twitter:card" content="summary_large_image" />
	<meta name="twitter:title" content="${escapeHtml(title)}" />
	<meta name="twitter:description" content="${escapeHtml(parsed.description)}" />
	<meta name="twitter:image" content="${origin}/og.png" />

	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300..700&display=swap" rel="stylesheet">
	<link rel="stylesheet" href="/ds/tokens.css">
	<link rel="stylesheet" href="/ds/components.css">
	<link rel="stylesheet" href="/styles.css">
	<link rel="stylesheet" href="/docs.css">
	<style>${FOOTER_STYLES}</style>
	<script type="application/ld+json">${structuredData(page, parsed, origin)}</script>
</head>

<body>
	${siteNav()}
	<header class="page-header">
		<h1>${escapeHtml(parsed.title)}</h1>
		<p class="subtitle">${escapeHtml(parsed.subtitle)}</p>
	</header>
	<div class="container">
		${wrapSections(html)}
	</div>
	${footer()}
</body>

</html>`;
}
