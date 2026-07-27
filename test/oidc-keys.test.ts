import { beforeEach, describe, expect, test } from "bun:test";
import { getActiveKey, getJWKS, signIDToken } from "../src/oidc";
import { db } from "./helpers/db";

beforeEach(() => {
	db.query("DELETE FROM oidc_keys").run();
});

describe("oidc key generation (fresh install)", () => {
	test("generates and stores an RS256 key on an empty table", async () => {
		// Regression: generateKeyPair must be extractable or exportKeyToPem
		// throws InvalidAccessError on first-ever key generation.
		const key = await getActiveKey();

		expect(key.kid).toStartWith("indiko-oidc-key-");
		expect(key.private_key).toContain("BEGIN PRIVATE KEY");
		expect(key.public_key).toContain("BEGIN PUBLIC KEY");
		expect(key.is_active).toBe(1);
	});

	test("reuses the stored key on subsequent calls", async () => {
		const first = await getActiveKey();
		const second = await getActiveKey();
		expect(second.kid).toBe(first.kid);
	});

	test("jwks exposes the public key with a matching kid", async () => {
		const key = await getActiveKey();
		const jwks = await getJWKS();

		expect(jwks.keys.length).toBeGreaterThan(0);
		const jwk = jwks.keys.find((k) => k.kid === key.kid);
		expect(jwk).toBeDefined();
		expect(jwk?.kty).toBe("RSA");
		expect(jwk?.alg).toBe("RS256");
		expect(jwk?.use).toBe("sig");
	});

	test("signs an id token that references the key id", async () => {
		const key = await getActiveKey();
		const jwt = await signIDToken("https://issuer.example", {
			sub: "https://issuer.example/u/kieran",
			aud: "ikc_test",
		});

		const [headerB64] = jwt.split(".");
		const header = JSON.parse(Buffer.from(headerB64, "base64url").toString());
		expect(header.alg).toBe("RS256");
		expect(header.kid).toBe(key.kid);
		expect(jwt.split(".").length).toBe(3);
	});
});
