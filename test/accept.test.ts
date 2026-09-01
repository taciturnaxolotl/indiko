import { describe, expect, test } from "bun:test";
import { negotiate, parseAccept } from "../src/lib/accept";

const OFFERS = ["text/html", "text/markdown", "text/plain"];

describe("parseAccept", () => {
	test("reads types and q-values", () => {
		expect(parseAccept("text/html;q=0.8, text/markdown")).toEqual([
			{ type: "text/html", q: 0.8 },
			{ type: "text/markdown", q: 1 },
		]);
	});

	test("treats a missing header as no preference", () => {
		expect(parseAccept(null)).toEqual([]);
	});
});

describe("negotiate", () => {
	test("defaults to the first offer without a header", () => {
		expect(negotiate(null, OFFERS)).toBe("text/html");
		expect(negotiate("", OFFERS)).toBe("text/html");
	});

	test("*/* takes our preferred offer", () => {
		expect(negotiate("*/*", OFFERS)).toBe("text/html");
	});

	test("serves markdown when asked for markdown", () => {
		expect(negotiate("text/markdown", OFFERS)).toBe("text/markdown");
		expect(negotiate("text/markdown, */*;q=0.1", OFFERS)).toBe("text/markdown");
	});

	test("honours q-values", () => {
		expect(negotiate("text/html;q=0.5, text/markdown;q=0.9", OFFERS)).toBe(
			"text/markdown",
		);
		expect(negotiate("text/markdown;q=0.2, text/html;q=0.9", OFFERS)).toBe(
			"text/html",
		);
	});

	test("q=0 rejects a type even when a wildcard would accept it", () => {
		expect(negotiate("text/html;q=0, text/markdown", OFFERS)).toBe(
			"text/markdown",
		);
		expect(negotiate("*/*;q=0", OFFERS)).toBeNull();
	});

	test("a subtype wildcard matches the whole family", () => {
		expect(negotiate("text/*", OFFERS)).toBe("text/html");
	});

	test("returns null when nothing on offer is acceptable", () => {
		expect(negotiate("application/json", OFFERS)).toBeNull();
		expect(negotiate("image/png, application/pdf", OFFERS)).toBeNull();
	});

	test("browser Accept headers still get HTML", () => {
		const chrome =
			"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
		expect(negotiate(chrome, OFFERS)).toBe("text/html");
	});
});
