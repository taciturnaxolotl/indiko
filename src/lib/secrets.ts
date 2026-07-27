import crypto from "node:crypto";

// Client secrets are stored as sha256 hex digests.
export function hashSecret(secret: string): string {
	return crypto.createHash("sha256").update(secret).digest("hex");
}

// Compare a presented secret against a stored sha256 hex digest in constant
// time. String equality short-circuits on the first differing byte, which
// leaks how much of the secret is correct; compare the raw digests instead.
export function verifySecret(presented: string, storedHashHex: string): boolean {
	const presentedHash = crypto
		.createHash("sha256")
		.update(presented)
		.digest();

	const storedHash = Buffer.from(storedHashHex, "hex");

	// Different lengths can't match, but still burn a comparison to avoid
	// leaking length via early return.
	if (storedHash.length !== presentedHash.length) {
		crypto.timingSafeEqual(presentedHash, presentedHash);
		return false;
	}

	return crypto.timingSafeEqual(presentedHash, storedHash);
}
