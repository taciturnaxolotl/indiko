import { readFileSync } from "node:fs";
import { join } from "node:path";
import hljs from "highlight.js/lib/core";
import css from "highlight.js/lib/languages/css";
import http from "highlight.js/lib/languages/http";
import json from "highlight.js/lib/languages/json";
import xml from "highlight.js/lib/languages/xml";
import { Marked, type RendererObject, type Tokens } from "marked";

hljs.registerLanguage("json", json);
hljs.registerLanguage("http", http);
hljs.registerLanguage("css", css);
hljs.registerLanguage("xml", xml);
hljs.registerLanguage("html", xml);

const MD_PATH = join(import.meta.dir, "../content/docs.md");

interface Frontmatter {
	title: string;
	subtitle: string;
}

function parseFrontmatter(raw: string): { fm: Frontmatter; body: string } {
	const match = raw.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
	if (!match) {
		return { fm: { title: "documentation", subtitle: "" }, body: raw };
	}
	const fmText = match[1] ?? "";
	const body = match[2] ?? raw;
	const fm: Record<string, string> = {};
	for (const line of fmText.split("\n")) {
		const idx = line.indexOf(":");
		if (idx > 0) {
			fm[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
		}
	}
	return {
		fm: {
			title: fm.title ?? "documentation",
			subtitle: fm.subtitle ?? "",
		},
		body,
	};
}

function slugify(text: string): string {
	return text
		.toLowerCase()
		.replace(/<[^>]+>/g, "")
		.replace(/[^\w\s-]/g, "")
		.trim()
		.replace(/\s+/g, "-");
}

// Custom hljs grammar for the stylized request examples (not wire-format
// http). hljs composes the tokens correctly, so no fragile regex stacking.
// keyword=method, string=url, number=param-name, attribute=header-name.
hljs.registerLanguage("oauthreq", () => ({
	name: "oauthreq",
	contains: [
		{ className: "keyword", begin: "^[A-Z]{2,7}(?=\\s)" }, // GET / POST
		{ className: "attribute", begin: "^[A-Z][A-Za-z-]+(?=:)" }, // Header-Name:
		{ className: "string", begin: "https?://[^\\s?&]+" }, // url (stops at query)
		{ className: "number", begin: "(?<=[?&])[A-Za-z_][A-Za-z0-9_]*(?==)" }, // param name
	],
}));

function highlight(code: string, lang: string): string {
	if (lang === "http") {
		return hljs.highlight(code, { language: "oauthreq" }).value;
	}
	if (lang && hljs.getLanguage(lang)) {
		return hljs.highlight(code, { language: lang }).value;
	}
	return hljs.highlightAuto(code).value;
}

interface TocEntry {
	level: number;
	id: string;
	text: string;
}

export function renderDocs(origin: string): {
	title: string;
	subtitle: string;
	html: string;
	toc: TocEntry[];
} {
	const raw = readFileSync(MD_PATH, "utf8");
	const { fm, body } = parseFrontmatter(raw);

	// Substitute server-known values so examples show the real origin
	const source = body.replaceAll("{{origin}}", origin);

	const toc: TocEntry[] = [];
	const usedIds = new Map<string, number>();

	const renderer: RendererObject = {
		heading({ tokens, depth }: Tokens.Heading): string {
			const text = this.parser.parseInline(tokens);
			const plain = text.replace(/<[^>]+>/g, "");
			// Dedupe slugs so repeated headings (e.g. "key features") get unique anchors
			const base = slugify(plain);
			const seen = usedIds.get(base) ?? 0;
			usedIds.set(base, seen + 1);
			const id = seen === 0 ? base : `${base}-${seen}`;
			if (depth === 2 || depth === 3) {
				toc.push({ level: depth, id, text: plain });
			}
			return `<h${depth} id="${id}">${text}</h${depth}>\n`;
		},

		code({ text, lang }: Tokens.Code): string {
			const language = lang ?? "";
			const highlighted = highlight(text, language);
			const langClass = language ? ` language-${language}` : "";
			return `<pre><code class="hljs${langClass}">${highlighted}</code></pre>\n`;
		},

		// > blockquotes become styled info-boxes (matches current docs look)
		blockquote({ tokens }: Tokens.Blockquote): string {
			const inner = this.parser.parse(tokens);
			return `<div class="info-box">${inner}</div>\n`;
		},

		codespan({ text }: Tokens.Codespan): string {
			// marked passes codespan text through unescaped, so a backticked
			// `<link>` would parse as a real element. Escape it back to text.
			const escaped = text
				.replace(/&/g, "&amp;")
				.replace(/</g, "&lt;")
				.replace(/>/g, "&gt;");
			return `<code>${escaped}</code>`;
		},

		table({ header, rows }: Tokens.Table): string {
			const head = header
				.map((cell) => `<th>${this.parser.parseInline(cell.tokens)}</th>`)
				.join("");
			const bodyRows = rows
				.map(
					(row) =>
						`<tr>${row
							.map((cell) => `<td>${this.parser.parseInline(cell.tokens)}</td>`)
							.join("")}</tr>`,
				)
				.join("");
			return `<table><thead><tr>${head}</tr></thead><tbody>${bodyRows}</tbody></table>\n`;
		},
	};

	const marked = new Marked({ renderer });
	let html = marked.parse(source, { async: false }) as string;

	// Bespoke injection points the md leaves as placeholders. The button
	// snippet and demo button are client-rendered (they're code that documents
	// code, and the demo is interactive), so we drop markers the client fills.
	html = html.replace(
		/<p>:::demo-button<\/p>/,
		`<div class="demo-button-wrapper"><a href="#" id="demoButton" class="indiko-demo-button">Sign in with Indiko</a></div>`,
	);
	html = html.replace(
		/<p>:::button-code<\/p>/,
		`<pre><code id="buttonCode"></code></pre>\n<button type="button" id="copyButtonCode" class="copy-btn">copy button code</button>`,
	);

	return { title: fm.title, subtitle: fm.subtitle, html, toc };
}

export function getRawMarkdown(): string {
	return readFileSync(MD_PATH, "utf8");
}
