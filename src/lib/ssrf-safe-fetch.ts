/**
 * SSRF-safe fetch implementation.
 *
 * Prevents Server-Side Request Forgery attacks by:
 * 1. Blocking private/internal IP addresses in URLs
 * 2. Blocking local hostnames (.local, .localhost, .internal, etc.)
 * 3. Resolving DNS and validating every returned IP before connecting
 * 4. Handling redirects manually, validating each hop (URL + DNS)
 *
 * @see https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
 */

import { resolve4, resolve6 } from "node:dns/promises";

export type SafeFetchResult<T> =
	| { success: true; data: T }
	| { success: false; error: string };

/**
 * Check if an IP address is in a private/reserved range.
 * Covers all ranges that should not be accessed from the internet.
 */
function isPrivateIP(ip: string): boolean {
	// IPv4 private/reserved ranges
	const ipv4Patterns = [
		/^0\./, // 0.0.0.0/8 - Current network
		/^10\./, // 10.0.0.0/8 - Private
		/^127\./, // 127.0.0.0/8 - Loopback
		/^169\.254\./, // 169.254.0.0/16 - Link-local (including AWS metadata 169.254.169.254)
		/^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12 - Private
		/^192\.0\.0\./, // 192.0.0.0/24 - IETF Protocol Assignments
		/^192\.0\.2\./, // 192.0.2.0/24 - TEST-NET-1
		/^192\.88\.99\./, // 192.88.99.0/24 - 6to4 Relay Anycast
		/^192\.168\./, // 192.168.0.0/16 - Private
		/^198\.1[8-9]\./, // 198.18.0.0/15 - Benchmarking
		/^198\.51\.100\./, // 198.51.100.0/24 - TEST-NET-2
		/^203\.0\.113\./, // 203.0.113.0/24 - TEST-NET-3
		/^22[4-9]\./, // 224.0.0.0/4 - Multicast
		/^23[0-9]\./, // 224.0.0.0/4 - Multicast
		/^24[0-9]\./, // 240.0.0.0/4 - Reserved
		/^25[0-5]\./, // 240.0.0.0/4 - Reserved (including broadcast 255.255.255.255)
	];

	for (const pattern of ipv4Patterns) {
		if (pattern.test(ip)) {
			return true;
		}
	}

	// IPv6 private/reserved - handle both bracketed [::1] and plain ::1
	const ipv6 = ip.replace(/^\[|\]$/g, "").toLowerCase();

	// Loopback ::1
	if (ipv6 === "::1") return true;

	// Unspecified ::
	if (ipv6 === "::") return true;

	// Link-local fe80::/10
	if (
		ipv6.startsWith("fe80:") ||
		ipv6.startsWith("fe8") ||
		ipv6.startsWith("fe9") ||
		ipv6.startsWith("fea") ||
		ipv6.startsWith("feb")
	) {
		return true;
	}

	// Unique local fc00::/7 (includes fd00::/8)
	if (ipv6.startsWith("fc") || ipv6.startsWith("fd")) {
		return true;
	}

	// IPv4-mapped IPv6 addresses ::ffff:x.x.x.x (dotted-quad form)
	const ipv4MappedMatch = ipv6.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
	if (ipv4MappedMatch?.[1]) {
		return isPrivateIP(ipv4MappedMatch[1]);
	}

	// IPv4-mapped IPv6 in hex form (::ffff:a01:101 = ::ffff:10.1.1.1)
	const hexMappedMatch = ipv6.match(
		/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i,
	);
	if (hexMappedMatch?.[1] && hexMappedMatch[2]) {
		const hi = Number.parseInt(hexMappedMatch[1], 16);
		const lo = Number.parseInt(hexMappedMatch[2], 16);
		const dotted = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
		return isPrivateIP(dotted);
	}

	// NAT64 (RFC 6052): 64:ff9b::/96 embeds an IPv4 address in the last 32 bits
	const nat64Match = ipv6.match(/^64:ff9b::([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
	if (nat64Match?.[1] && nat64Match[2]) {
		const hi = Number.parseInt(nat64Match[1], 16);
		const lo = Number.parseInt(nat64Match[2], 16);
		const dotted = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
		return isPrivateIP(dotted);
	}

	// 6to4 (RFC 3056): 2002::/16 embeds an IPv4 address in bits 16-48
	if (ipv6.startsWith("2002:")) {
		const parts = ipv6.split(":");
		if (parts.length >= 3) {
			const hiStr = parts[1];
			const loStr = parts[2];
			if (hiStr && loStr) {
				const hi = Number.parseInt(hiStr, 16);
				const lo = Number.parseInt(loStr, 16);
				if (!Number.isNaN(hi) && !Number.isNaN(lo)) {
					const dotted = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
					return isPrivateIP(dotted);
				}
			}
		}
		return true; // Can't parse — block to be safe
	}

	// Teredo (RFC 4380): 2001:0000::/32 — block the whole prefix
	if (ipv6.startsWith("2001:0:") || ipv6.startsWith("2001:0000:")) {
		return true;
	}

	// Documentation range (RFC 3849) — non-routable
	if (ipv6.startsWith("2001:db8:")) return true;

	// Site-local (deprecated, RFC 3879) fec0::/10
	if (ipv6.startsWith("fec")) return true;

	// Multicast ff00::/8
	if (ipv6.startsWith("ff")) return true;

	// Discard-only 100::/64
	if (ipv6.startsWith("100::")) return true;

	return false;
}

/**
 * Check if a hostname is a local/internal hostname that should not be fetched.
 */
function isLocalHostname(hostname: string): boolean {
	const lower = hostname.toLowerCase();

	// Exact matches for localhost variants
	if (lower === "localhost" || lower === "localhost.localdomain") {
		return true;
	}

	// Check for local TLDs and suffixes
	const localSuffixes = [
		".local",
		".localhost",
		".localdomain",
		".internal",
		".home",
		".lan",
		".corp",
		".test",
		".invalid",
		".example",
		// Cloud provider metadata hostnames
		".metadata.google.internal",
		".compute.internal",
	];

	for (const suffix of localSuffixes) {
		if (lower.endsWith(suffix)) {
			return true;
		}
	}

	// AWS/cloud metadata hostnames
	if (
		lower === "metadata.google.internal" ||
		lower === "instance-data" ||
		lower === "metadata"
	) {
		return true;
	}

	return false;
}

/**
 * Validate that a URL is safe to fetch (not pointing to internal resources).
 */
export function validateExternalURL(urlString: string): {
	safe: boolean;
	error?: string;
} {
	let url: URL;
	try {
		url = new URL(urlString);
	} catch {
		return { safe: false, error: "Invalid URL" };
	}

	// Must be HTTP or HTTPS
	if (url.protocol !== "http:" && url.protocol !== "https:") {
		return { safe: false, error: "URL must use http or https protocol" };
	}

	// Check for credentials in URL (potential abuse vector)
	if (url.username || url.password) {
		return { safe: false, error: "URL must not contain credentials" };
	}

	const hostname = url.hostname;

	// Check if hostname is a local hostname
	if (isLocalHostname(hostname)) {
		return { safe: false, error: "Cannot fetch from local/internal hostnames" };
	}

	// Check if hostname is an IP address in private range
	// IPv4 check
	if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
		if (isPrivateIP(hostname)) {
			return {
				safe: false,
				error: "Cannot fetch from private/reserved IP addresses",
			};
		}
	}

	// IPv6 check (bracketed in URLs)
	if (hostname.startsWith("[") && hostname.endsWith("]")) {
		if (isPrivateIP(hostname)) {
			return {
				safe: false,
				error: "Cannot fetch from private/reserved IP addresses",
			};
		}
	}

	// Check port - block common internal service ports
	const blockedPorts = [
		"22", // SSH
		"23", // Telnet
		"25", // SMTP
		"53", // DNS
		"110", // POP3
		"143", // IMAP
		"445", // SMB
		"3306", // MySQL
		"5432", // PostgreSQL
		"6379", // Redis
		"11211", // Memcached
		"27017", // MongoDB
	];

	if (url.port && blockedPorts.includes(url.port)) {
		return { safe: false, error: `Port ${url.port} is not allowed` };
	}

	return { safe: true };
}

/**
 * Resolve a hostname and validate every returned IP against the private range
 * blocklist. Returns an error if any resolved IP is private — we don't try to
 * pick a "safe" one because the resolver may round-robin.
 *
 * Note: there is an inherent TOCTOU gap between this check and the actual
 * TCP connect (Bun's fetch resolves DNS independently). An attacker with
 * sub-second DNS TTL switching could theoretically rebind between the two
 * resolutions. In practice this raises the bar from "one A record" to
 * "precisely-timed DNS race," and the manual redirect handling ensures
 * every hop is re-validated.
 */
async function resolveAndValidateIPs(hostname: string): Promise<{
	safe: boolean;
	error?: string;
}> {
	// Literal IPs don't need resolution — validate directly.
	if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
		return isPrivateIP(hostname)
			? {
					safe: false,
					error: "Cannot fetch from private/reserved IP addresses",
				}
			: { safe: true };
	}

	if (hostname.startsWith("[") && hostname.endsWith("]")) {
		return isPrivateIP(hostname)
			? {
					safe: false,
					error: "Cannot fetch from private/reserved IP addresses",
				}
			: { safe: true };
	}

	try {
		const [ipv4s, ipv6s] = await Promise.allSettled([
			resolve4(hostname),
			resolve6(hostname),
		]);

		const addresses: string[] = [];
		if (ipv4s.status === "fulfilled") addresses.push(...ipv4s.value);
		if (ipv6s.status === "fulfilled") addresses.push(...ipv6s.value);

		if (addresses.length === 0) {
			return { safe: false, error: "DNS resolution returned no addresses" };
		}

		for (const addr of addresses) {
			if (isPrivateIP(addr)) {
				return {
					safe: false,
					error: `Hostname resolves to private/reserved IP ${addr}`,
				};
			}
		}

		return { safe: true };
	} catch {
		return { safe: false, error: "DNS resolution failed" };
	}
}

const MAX_REDIRECTS = 5;

/**
 * Perform a fetch with SSRF protection.
 *
 * Validates the URL, resolves DNS and checks every returned IP, then follows
 * redirects manually — validating URL + DNS for each hop before connecting.
 */
export async function safeFetch(
	url: string,
	options: {
		timeout?: number;
		headers?: Record<string, string>;
	} = {},
): Promise<SafeFetchResult<Response>> {
	const { timeout = 5000, headers = {} } = options;

	let currentUrl = url;

	for (let redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount++) {
		// Validate URL structure (protocol, credentials, hostname, port)
		const validation = validateExternalURL(currentUrl);
		if (!validation.safe) {
			return {
				success: false,
				error: validation.error || "URL validation failed",
			};
		}

		// Resolve DNS and validate every returned IP
		const parsedUrl = new URL(currentUrl);
		const dnsValidation = await resolveAndValidateIPs(parsedUrl.hostname);
		if (!dnsValidation.safe) {
			return {
				success: false,
				error: dnsValidation.error || "DNS validation failed",
			};
		}

		try {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), timeout);

			const response = await fetch(currentUrl, {
				method: "GET",
				headers: {
					Accept: "application/json, text/html",
					"User-Agent": "Indiko/1.0 (OAuth Client Metadata Fetcher)",
					...headers,
				},
				signal: controller.signal,
				redirect: "manual",
			});

			clearTimeout(timeoutId);

			// Follow redirects manually so each hop gets URL + DNS validation
			if (
				response.status >= 300 &&
				response.status < 400 &&
				response.headers.get("location")
			) {
				const location = response.headers.get("location") as string;
				// Resolve relative redirects against the current URL
				currentUrl = new URL(location, currentUrl).toString();
				continue;
			}

			return { success: true, data: response };
		} catch (error) {
			if (error instanceof Error) {
				if (error.name === "AbortError") {
					return { success: false, error: "Request timed out" };
				}
				return { success: false, error: `Fetch failed: ${error.message}` };
			}
			return { success: false, error: "Fetch failed: Unknown error" };
		}
	}

	return { success: false, error: "Too many redirects" };
}
