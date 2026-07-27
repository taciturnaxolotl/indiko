import { describe, expect, test } from "bun:test";
import { hashSecret, verifySecret } from "../src/lib/secrets";

describe("hashSecret", () => {
	test("produces a sha256 hex digest", () => {
		expect(hashSecret("iks_test")).toMatch(/^[0-9a-f]{64}$/);
	});

	test("is deterministic", () => {
		expect(hashSecret("abc")).toBe(hashSecret("abc"));
	});
});

describe("verifySecret", () => {
	test("accepts the correct secret", () => {
		const hash = hashSecret("iks_correct-horse-battery-staple");
		expect(verifySecret("iks_correct-horse-battery-staple", hash)).toBe(true);
	});

	test("rejects a wrong secret", () => {
		const hash = hashSecret("correct");
		expect(verifySecret("wrong", hash)).toBe(false);
	});

	test("rejects a secret differing only in the last char (no early-exit leak)", () => {
		const hash = hashSecret("almost-the-same-secret");
		expect(verifySecret("almost-the-same-secreX", hash)).toBe(false);
	});

	test("handles a malformed stored hash without throwing", () => {
		expect(verifySecret("anything", "not-valid-hex")).toBe(false);
	});
});
