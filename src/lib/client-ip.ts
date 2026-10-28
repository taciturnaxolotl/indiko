/**
 * Extract the real client IP from a request, accounting for trusted proxies.
 *
 * The base is always the TCP peer address reported by Bun's
 * `server.requestIP(req)` (registered once via `setServer`). Proxy headers
 * are only honoured when TRUSTED_PROXY opts in, and even then we fall back
 * to the socket IP when the headers are absent.
 *
 * Set TRUSTED_PROXY=cloudflare to trust CF-Connecting-IP (requires CF-Ray).
 * Set TRUSTED_PROXY=xff to trust X-Forwarded-For (rightmost entry).
 * Default: no proxy trust — the socket peer IP is used.
 *
 * NOTE: `cloudflare`/`xff` modes trust headers any direct-to-origin client
 * can forge. Only enable them when the origin is firewalled so that only
 * the proxy can reach it.
 */

/** Minimal shape of what we need from Bun.Server. */
interface RequestIpServer {
	requestIP(req: Request): { address: string } | null;
}

let server: RequestIpServer | null = null;

/** Register the running Bun server so getClientIp can read socket peers. */
export function setServer(s: RequestIpServer | null): void {
	server = s;
}

function socketIp(req: Request): string | null {
	if (!server) return null;
	try {
		return server.requestIP(req)?.address || null;
	} catch {
		return null;
	}
}

export function getClientIp(req: Request): string {
	const trustProxy = process.env.TRUSTED_PROXY || "";

	if (trustProxy === "cloudflare") {
		// Only trust CF-Connecting-IP when CF-Ray is also present.
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

	// No usable proxy header — use the TCP peer address. When no server has
	// been registered (unit tests, scripts) fall back to a shared bucket.
	return socketIp(req) ?? "direct";
}
