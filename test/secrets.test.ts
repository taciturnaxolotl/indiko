import { describe, expect, test } from "bun:test";
import { backfillTokenHashes } from "../src/db";
import { hashSecret, verifySecret } from "../src/lib/secrets";
import { createUser, db } from "./helpers/db";

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

describe("backfillTokenHashes", () => {
	function seed(token: string, refresh: string | null) {
		const userId = createUser({});
		db.query(
			"INSERT INTO tokens (token, user_id, client_id, scope, expires_at, refresh_token) VALUES (?, ?, ?, ?, ?, ?)",
		).run(
			token,
			userId,
			"https://app.example/",
			"profile",
			9999999999,
			refresh,
		);
	}

	test("hashes plaintext rows once and leaves digests alone", () => {
		db.query("DELETE FROM tokens").run();
		const access = "a".repeat(43);
		const refresh = "r".repeat(43);
		seed(access, refresh);
		seed(hashSecret("already"), null);

		expect(backfillTokenHashes(db)).toBe(1);
		expect(backfillTokenHashes(db)).toBe(0);

		const rows = db
			.query("SELECT token, refresh_token FROM tokens ORDER BY id")
			.all() as { token: string; refresh_token: string | null }[];
		expect(rows).toEqual([
			{ token: hashSecret(access), refresh_token: hashSecret(refresh) },
			{ token: hashSecret("already"), refresh_token: null },
		]);
	});
});
