import { describe, expect, test } from "bun:test";
import { validateMetadataDocument } from "../src/lib/oauth/client-metadata";

const CID = "https://app.example/";

function doc(fields: Record<string, unknown>): string {
	return JSON.stringify({ client_id: CID, ...fields });
}

describe("validateMetadataDocument (Client ID Metadata Document)", () => {
	test("accepts a valid document", () => {
		const res = validateMetadataDocument(
			doc({ client_name: "My App", redirect_uris: ["https://app.example/cb"] }),
			CID,
		);
		expect(res.success).toBe(true);
		expect(res.metadata?.client_name).toBe("My App");
	});

	test("rejects client_id mismatch", () => {
		const res = validateMetadataDocument(doc({}), "https://other.example/");
		expect(res.success).toBe(false);
		expect(res.error).toContain("does not match");
	});

	test("rejects secret-based token_endpoint_auth_method", () => {
		for (const method of [
			"client_secret_post",
			"client_secret_basic",
			"client_secret_jwt",
			"private_key_jwt",
		]) {
			const res = validateMetadataDocument(
				doc({ token_endpoint_auth_method: method }),
				CID,
			);
			expect(res.success).toBe(false);
			expect(res.error).toContain("not allowed");
		}
	});

	test("allows token_endpoint_auth_method none", () => {
		const res = validateMetadataDocument(
			doc({ token_endpoint_auth_method: "none" }),
			CID,
		);
		expect(res.success).toBe(true);
	});

	test("rejects oversized documents", () => {
		const big = doc({ pad: "x".repeat(6000) });
		const res = validateMetadataDocument(big, CID);
		expect(res.success).toBe(false);
		expect(res.error).toContain("too large");
	});

	test("rejects invalid JSON", () => {
		const res = validateMetadataDocument("{ not json", CID);
		expect(res.success).toBe(false);
		expect(res.error).toContain("Invalid JSON");
	});

	test("strips unsafe logo_uri and client_uri", () => {
		const res = validateMetadataDocument(
			doc({
				logo_uri: "http://169.254.169.254/latest",
				client_uri: "file:///etc/passwd",
			}),
			CID,
		);
		expect(res.success).toBe(true);
		expect(res.metadata?.logo_uri).toBeUndefined();
		expect(res.metadata?.client_uri).toBeUndefined();
	});
});
