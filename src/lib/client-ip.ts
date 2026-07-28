/**
 * Extract the real client IP from a request, accounting for trusted proxies.
 *
 * Only trusts CF-Connecting-IP / X-Forwarded-For when the request shows
 * evidence of actually passing through that proxy. Without this, an attacker
 * can spoof these headers to bypass rate limiting.
 *
 * Set TRUSTED_PROXY=cloudflare to trust CF-Connecting-IP (requires CF-Ray).
 * Set TRUSTED_PROXY=xff to trust X-Forwarded-For (last entry).
 * Default: no proxy trust — rate limiters key on a placeholder.
 */
export function getClientIp(req: Request): string {
	const trustProxy = process.env.TRUSTED_PROXY || "";

	if (trustProxy === "cloudflare") {
		// Only trust CF-Connecting-IP when CF-Ray is also present —
		// Cloudflare sets both, so a direct client can't forge just one.
		const cfRay = req.headers.get("cf-ray");
		const cfIp = req.headers.get("cf-connecting-ip");
		if (cfRay && cfIp) return cfIp;
	}

	if (trustProxy === "cloudflare" || trustProxy === "xff") {
		const xff = req.headers.get("x-forwarded-for");
		if (xff) {
			// Take the rightmost entry (closest to the server = most trustworthy)
			const parts = xff.split(",").map((s) => s.trim());
			const ip = parts[parts.length - 1];
			if (ip) return ip;
		}
	}

	// No proxy trust — we can't get the socket IP from a Request object,
	// so use a constant key. This means all direct connections share one
	// rate limit bucket, which is overly restrictive but safe.
	return "direct";
}
