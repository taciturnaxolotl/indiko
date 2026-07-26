import { describe, expect, test } from "bun:test";
import {
	canonicalizeURL,
	isLoopbackURL,
	validateClientURL,
	validateProfileURL,
	verifyPKCE,
} from "../src/lib/oauth/urls";

describe("canonicalizeURL", () => {
	test("lowercases hostname", () => {
		expect(canonicalizeURL("https://EXAMPLE.com/Path")).toBe(
			"https://example.com/Path",
		);
	});

	test("adds trailing slash when path missing", () => {
		expect(canonicalizeURL("https://example.com")).toBe("https://example.com/");
	});

	test("passes through non-URL identifiers (ikc_ clients)", () => {
		expect(canonicalizeURL("ikc_abc123")).toBe("ikc_abc123");
	});
});

describe("validateProfileURL", () => {
	test("accepts a plain https URL", () => {
		const result = validateProfileURL("https://example.com");
		expect(result.valid).toBe(true);
		expect(result.canonicalUrl).toBe("https://example.com/");
	});

	test("rejects fragments", () => {
		expect(validateProfileURL("https://example.com/#me").valid).toBe(false);
	});

	test("rejects userinfo", () => {
		expect(validateProfileURL("https://user:pass@example.com/").valid).toBe(
			false,
		);
	});

	test("rejects ports", () => {
		expect(validateProfileURL("https://example.com:8443/").valid).toBe(false);
	});

	test("rejects IP addresses", () => {
		expect(validateProfileURL("https://192.168.1.1/").valid).toBe(false);
	});

	test("rejects dot segments", () => {
		expect(validateProfileURL("https://example.com/../etc").valid).toBe(false);
	});

	test("rejects non-http schemes", () => {
		expect(validateProfileURL("ftp://example.com/").valid).toBe(false);
	});
});

describe("validateClientURL", () => {
	test("accepts https URL", () => {
		expect(validateClientURL("https://app.example.com").valid).toBe(true);
	});

	test("allows ipv4 loopback", () => {
		expect(validateClientURL("http://127.0.0.1:8080/callback").valid).toBe(
			true,
		);
	});

	test("rejects non-loopback ipv4", () => {
		expect(validateClientURL("http://8.8.8.8/callback").valid).toBe(false);
	});

	test("rejects dot segments in raw path", () => {
		expect(validateClientURL("https://app.example.com/a/../b").valid).toBe(
			false,
		);
	});

	test("allows legit dots in filenames", () => {
		expect(validateClientURL("https://app.example.com/app.json").valid).toBe(
			true,
		);
	});
});

describe("isLoopbackURL", () => {
	test("localhost", () => {
		expect(isLoopbackURL("http://localhost:3000/x")).toBe(true);
	});

	test("127.x", () => {
		expect(isLoopbackURL("http://127.0.0.5/")).toBe(true);
	});

	test("rejects normal hosts", () => {
		expect(isLoopbackURL("https://example.com/")).toBe(false);
	});

	test("rejects garbage", () => {
		expect(isLoopbackURL("not a url")).toBe(false);
	});
});

describe("verifyPKCE", () => {
	test("accepts a valid verifier/challenge pair", () => {
		// RFC 7636 appendix B test vector
		const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
		const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
		expect(verifyPKCE(verifier, challenge)).toBe(true);
	});

	test("rejects wrong verifier", () => {
		expect(
			verifyPKCE("wrong", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
		).toBe(false);
	});
});
