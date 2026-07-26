import { describe, expect, test } from "bun:test";
import { consentPage, errorPage, escapeHtml } from "../src/lib/oauth/pages";

describe("escapeHtml", () => {
	test("escapes the dangerous five", () => {
		expect(escapeHtml(`<script>"x"&'y'`)).toBe(
			"&lt;script&gt;&quot;x&quot;&amp;&#39;y&#39;",
		);
	});
});

describe("errorPage", () => {
	test("renders title, message, and escaped details", async () => {
		const res = errorPage({
			title: "Invalid Client ID",
			message: "The client_id is not valid.",
			details: [
				{ label: "Provided client_id", value: "<img src=x>", isCode: true },
			],
		});

		expect(res.status).toBe(400);
		const html = await res.text();
		expect(html).toContain("Invalid Client ID");
		expect(html).toContain("&lt;img src=x&gt;");
		expect(html).not.toContain("<img src=x>");
	});
});

describe("consentPage", () => {
	const base = {
		username: "kieran",
		appName: "Test App",
		appUrl: "example.com",
		appLogo: null,
		appDescription: null,
		scopes: ["profile", "email"],
		clientId: "https://example.com/",
		redirectUri: "https://example.com/cb",
		state: "abc",
		codeChallenge: "challenge",
		me: null,
		nonce: null,
	};

	test("escapes app metadata (stored-XSS guard)", async () => {
		const res = consentPage({
			...base,
			appName: `<script>alert(1)</script>`,
			appDescription: `<img src=x onerror=alert(1)>`,
		});
		const html = await res.text();
		expect(html).not.toContain("<script>alert(1)</script>");
		expect(html).toContain("&lt;script&gt;");
		expect(html).not.toContain("<img src=x");
	});

	test("profile scope is checked and disabled, email is checked", async () => {
		const html = await consentPage(base).text();
		expect(html).toContain('value="profile" checked disabled');
		expect(html).toContain('value="email" checked');
	});

	test("hidden inputs round-trip flow params", async () => {
		const html = await consentPage({
			...base,
			me: "https://me.example/",
			nonce: "n-1",
		}).text();
		expect(html).toContain('name="state" value="abc"');
		expect(html).toContain('name="code_challenge" value="challenge"');
		expect(html).toContain('name="me" value="https://me.example/"');
		expect(html).toContain('name="nonce" value="n-1"');
	});
});
