import { beforeAll, describe, expect, test } from "bun:test";
import { createSession, createUser } from "./helpers/db";

const ORIGIN = "https://indiko.test";
process.env.ORIGIN = ORIGIN;

const {
	aboutPage,
	contactPage,
	homePage,
	llmsTxt,
	notFound,
	privacyPage,
	robotsTxt,
	sitemapXml,
} = await import("../src/routes/site");

function get(path: string, accept?: string, cookie?: string): Request {
	const headers = new Headers();
	if (accept) headers.set("Accept", accept);
	if (cookie) headers.set("Cookie", cookie);
	return new Request(`${ORIGIN}${path}`, { headers });
}

/** Visible text an agent would extract from raw HTML. */
function textContent(html: string): string {
	return html
		.replace(/<script[\s\S]*?<\/script>/g, " ")
		.replace(/<style[\s\S]*?<\/style>/g, " ")
		.replace(/<[^>]+>/g, " ")
		.replace(/\s+/g, " ")
		.trim();
}

describe("root", () => {
	test("sends signed-out visitors to the login screen", () => {
		const res = homePage(get("/"));
		expect(res.status).toBe(302);
		expect(res.headers.get("Location")).toBe("/login");
	});

	test("sends signed-in visitors to their dashboard", () => {
		const userId = createUser({ username: "homepage-user" });
		const token = createSession(userId);
		const res = homePage(get("/", "text/html", `indiko_session=${token}`));
		expect(res.status).toBe(302);
		expect(res.headers.get("Location")).toBe("/dashboard");
	});

	test("sends anything asking for markdown to the docs", () => {
		for (const accept of ["text/markdown", "text/plain"]) {
			const res = homePage(get("/", accept));
			expect(res.status).toBe(302);
			expect(res.headers.get("Location")).toBe("/docs");
		}
	});

	test("markdown wins over a session, so agents never land on a redirect loop", () => {
		const userId = createUser({ username: "markdown-user" });
		const token = createSession(userId);
		const res = homePage(get("/", "text/markdown", `indiko_session=${token}`));
		expect(res.headers.get("Location")).toBe("/docs");
	});

	test("varies on both Accept and Cookie", () => {
		expect(homePage(get("/")).headers.get("Vary")).toBe("Accept, Cookie");
	});

	test("rejects non-GET methods", () => {
		const res = homePage(new Request(`${ORIGIN}/`, { method: "POST" }));
		expect(res.status).toBe(405);
	});
});

describe("trust anchor pages", () => {
	const pages: [string, (req: Request) => Response][] = [
		["/about", aboutPage],
		["/contact", contactPage],
		["/privacy", privacyPage],
	];

	for (const [path, handler] of pages) {
		test(`${path} has real content and a canonical URL`, async () => {
			const res = handler(get(path));
			expect(res.status).toBe(200);

			const html = await res.text();
			expect(textContent(html).length).toBeGreaterThan(500);
			expect(html).toContain(
				`<link rel="canonical" href="${ORIGIN}${path}" />`,
			);
			expect(html).toContain("<h1>");
		});

		test(`${path} is available as markdown`, async () => {
			const res = handler(get(path, "text/markdown"));
			expect(res.headers.get("Content-Type")).toBe(
				"text/markdown; charset=utf-8",
			);
			expect((await res.text()).length).toBeGreaterThan(500);
		});
	}

	test("about page carries the JSON-LD identity graph", async () => {
		const html = await aboutPage(get("/about")).text();
		const match = html.match(
			/<script type="application\/ld\+json">([\s\S]*?)<\/script>/,
		);
		expect(match).not.toBeNull();

		const data = JSON.parse(match?.[1] as string);
		const types = data["@graph"].map(
			(node: { "@type": string }) => node["@type"],
		);
		expect(types).toContain("SoftwareApplication");
		expect(types).toContain("Organization");

		const org = data["@graph"].find(
			(node: { "@type": string }) => node["@type"] === "Organization",
		);
		expect(org.contactPoint[0].email).toBeTruthy();
		expect(org.contactPoint[0].contactType).toBeTruthy();
		expect(org.address["@type"]).toBe("PostalAddress");
	});

	test("pages declare og:image and a single h1", async () => {
		const html = await aboutPage(get("/about")).text();
		expect(html).toContain(
			`<meta property="og:image" content="${ORIGIN}/og.png" />`,
		);
		expect(html).toContain('<html lang="en">');
		expect(html.match(/<h1[ >]/g)).toHaveLength(1);
	});

	test("contact page names both mailboxes", async () => {
		const md = await contactPage(get("/contact", "text/markdown")).text();
		expect(md).toContain("hello@dunkirk.sh");
		expect(md).toContain("security@dunkirk.sh");
	});
});

describe("404", () => {
	test("returns a real 404 with a markdown body agents can follow", async () => {
		const res = notFound(get("/nope", "text/markdown"));
		expect(res.status).toBe(404);
		expect(res.headers.get("Content-Type")).toBe(
			"text/markdown; charset=utf-8",
		);

		const md = await res.text();
		expect(md).toContain("# 404");
		expect(md).toContain("/nope");
		expect(md).toContain(`${ORIGIN}/llms.txt`);
		expect(md).toContain(`${ORIGIN}/sitemap.xml`);
		expect(md).toContain(`${ORIGIN}/docs`);
	});

	test("browsers get an HTML 404 with the same links", async () => {
		const res = notFound(get("/nope", "text/html"));
		expect(res.status).toBe(404);
		expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");

		const html = await res.text();
		expect(html).toContain(`href="${ORIGIN}/llms.txt"`);
		expect(html).toContain("404");
	});

	test("still 404s when the client accepts nothing we serve", () => {
		const res = notFound(get("/nope", "application/json"));
		expect(res.status).toBe(404);
	});
});

describe("robots.txt", () => {
	let body: string;

	beforeAll(async () => {
		body = await robotsTxt().text();
	});

	test("names no AI user-agents, leaving those to Cloudflare's block", () => {
		for (const ua of [
			"ChatGPT-User",
			"ClaudeBot",
			"GPTBot",
			"Google-Extended",
		]) {
			expect(body).not.toContain(ua);
		}
	});

	test("allows the homepage and points at the sitemap", () => {
		expect(body).toContain("User-agent: *");
		expect(body).toContain("Allow: /");
		expect(body).toContain(`Sitemap: ${ORIGIN}/sitemap.xml`);
	});

	test("keeps private surfaces out of the index", () => {
		expect(body).toContain("Disallow: /admin");
		expect(body).toContain("Disallow: /api/");
	});
});

describe("sitemap.xml", () => {
	test("lists every public URL with a lastmod date", async () => {
		const res = sitemapXml();
		expect(res.headers.get("Content-Type")).toBe(
			"application/xml; charset=utf-8",
		);

		const xml = await res.text();
		expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>')).toBe(true);
		expect(xml).toContain(
			'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
		);
		for (const path of ["/about", "/contact", "/privacy", "/docs"]) {
			expect(xml).toContain(`<loc>${ORIGIN}${path}</loc>`);
		}
		expect(xml).not.toContain(`<loc>${ORIGIN}/</loc>`);
		expect(xml).toMatch(/<lastmod>\d{4}-\d{2}-\d{2}<\/lastmod>/);
	});
});

describe("llms.txt", () => {
	test("follows the llmstxt.org shape and says when to use indiko", async () => {
		const res = llmsTxt();
		expect(res.headers.get("Content-Type")).toBe(
			"text/markdown; charset=utf-8",
		);

		const body = await res.text();
		expect(body.startsWith("# indiko\n")).toBe(true);
		expect(body).toContain("\n> ");
		expect(body).toContain("**When to use indiko.**");
		expect(body).toContain("**How to call it.**");
		expect(body).toContain(`[Documentation](${ORIGIN}/docs)`);
		expect(body).toContain("root URL is a redirect");
		expect(body).toContain("## Optional");
	});
});
