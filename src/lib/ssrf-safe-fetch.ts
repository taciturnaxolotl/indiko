/**
 * SSRF-safe fetch implementation.
 *
 * Prevents Server-Side Request Forgery attacks by:
 * 1. Blocking private/internal IP addresses in URLs
 * 2. Blocking local hostnames (.local, .localhost, .internal, etc.)
 * 3. Validating redirect targets
 *
 * @see https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
 */

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

	// IPv4-mapped IPv6 addresses ::ffff:x.x.x.x
	const ipv4MappedMatch = ipv6.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
	if (ipv4MappedMatch?.[1]) {
		return isPrivateIP(ipv4MappedMatch[1]);
	}

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
 * Perform a fetch with SSRF protection.
 *
 * This validates the URL before fetching and adds additional protections.
 */
export async function safeFetch(
	url: string,
	options: {
		timeout?: number;
		headers?: Record<string, string>;
	} = {},
): Promise<SafeFetchResult<Response>> {
	// Validate URL before fetching
	const validation = validateExternalURL(url);
	if (!validation.safe) {
		return {
			success: false,
			error: validation.error || "URL validation failed",
		};
	}

	const { timeout = 5000, headers = {} } = options;

	try {
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), timeout);

		const response = await fetch(url, {
			method: "GET",
			headers: {
				Accept: "application/json, text/html",
				"User-Agent": "Indiko/1.0 (OAuth Client Metadata Fetcher)",
				...headers,
			},
			signal: controller.signal,
			redirect: "follow",
		});

		clearTimeout(timeoutId);

		// After redirect, validate the final URL
		if (response.url && response.url !== url) {
			const finalValidation = validateExternalURL(response.url);
			if (!finalValidation.safe) {
				return {
					success: false,
					error: `Redirect to unsafe URL: ${finalValidation.error}`,
				};
			}
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
