// Canonicalize URL per IndieAuth spec (only for actual URLs, not internal IDs)
export function canonicalizeURL(urlString: string): string {
	// Only canonicalize if it looks like a URL
	if (!urlString.startsWith("http://") && !urlString.startsWith("https://")) {
		return urlString;
	}
	const url = new URL(urlString);
	// Lowercase hostname per spec
	url.hostname = url.hostname.toLowerCase();
	// Add / path if missing
	if (!url.pathname || url.pathname === "") {
		url.pathname = "/";
	}
	return url.toString();
}

// Validate profile URL per IndieAuth spec
export function validateProfileURL(urlString: string): {
	valid: boolean;
	error?: string;
	canonicalUrl?: string;
} {
	let url: URL;
	try {
		url = new URL(urlString);
	} catch {
		return { valid: false, error: "Invalid URL format" };
	}

	// MUST use http or https scheme
	if (url.protocol !== "http:" && url.protocol !== "https:") {
		return { valid: false, error: "Profile URL must use http or https scheme" };
	}

	// MUST contain path component (/ is valid)
	if (!url.pathname) {
		url.pathname = "/";
	}

	// MUST NOT contain fragments
	if (url.hash) {
		return { valid: false, error: "Profile URL must not contain fragments" };
	}

	// MUST NOT contain username/password
	if (url.username || url.password) {
		return {
			valid: false,
			error: "Profile URL must not contain username or password",
		};
	}

	// MUST NOT contain ports
	if (url.port) {
		return { valid: false, error: "Profile URL must not contain ports" };
	}

	// MUST NOT use IP addresses
	const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
	const ipv6Regex = /^\[?[0-9a-fA-F:]+\]?$/;
	if (ipv4Regex.test(url.hostname) || ipv6Regex.test(url.hostname)) {
		return {
			valid: false,
			error: "Profile URL must use domain names, not IP addresses",
		};
	}

	// MUST NOT contain single-dot or double-dot path segments.
	// Check the raw string: `new URL` normalizes "/../" away before we can see it.
	if (hasDotSegments(urlString)) {
		return {
			valid: false,
			error: "Profile URL must not contain . or .. path segments",
		};
	}

	return { valid: true, canonicalUrl: canonicalizeURL(urlString) };
}

// Detect . or .. path segments in the raw URL string (pre-normalization).
// `new URL` collapses them, so inspect the string directly: strip the
// scheme://authority prefix, query, and hash, then split the raw path.
function hasDotSegments(urlString: string): boolean {
	const withoutHash = urlString.split("#", 1)[0] ?? "";
	const withoutQuery = withoutHash.split("?", 1)[0] ?? "";
	const authorityEnd = withoutQuery.indexOf("://");
	if (authorityEnd === -1) return false;
	const pathStart = withoutQuery.indexOf("/", authorityEnd + 3);
	if (pathStart === -1) return false;
	const segments = withoutQuery.slice(pathStart).split("/");
	return segments.includes(".") || segments.includes("..");
}

// Validate client URL per IndieAuth spec
export function validateClientURL(urlString: string): {
	valid: boolean;
	error?: string;
	canonicalUrl?: string;
} {
	let url: URL;
	try {
		url = new URL(urlString);
	} catch {
		return { valid: false, error: "Invalid URL format" };
	}

	// MUST use http or https scheme
	if (url.protocol !== "http:" && url.protocol !== "https:") {
		return { valid: false, error: "Client URL must use http or https scheme" };
	}

	// MUST contain path component (/ is valid)
	if (!url.pathname) {
		url.pathname = "/";
	}

	// MUST NOT contain fragments
	if (url.hash) {
		return { valid: false, error: "Client URL must not contain fragments" };
	}

	// MUST NOT contain username/password
	if (url.username || url.password) {
		return {
			valid: false,
			error: "Client URL must not contain username or password",
		};
	}

	// MUST NOT contain single-dot or double-dot path segments (raw string,
	// since `new URL` normalizes them away)
	if (hasDotSegments(urlString)) {
		return {
			valid: false,
			error: "Client URL must not contain . or .. path segments",
		};
	}

	// MAY use loopback interface, but not other IP addresses
	const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
	const ipv6Regex = /^\[?([0-9a-fA-F:]+)\]?$/;
	if (ipv4Regex.test(url.hostname)) {
		// Allow 127.0.0.1 (loopback), reject others
		if (!url.hostname.startsWith("127.")) {
			return {
				valid: false,
				error:
					"Client URL must use domain names, not IP addresses (except loopback)",
			};
		}
	} else if (ipv6Regex.test(url.hostname)) {
		// Allow ::1 (loopback), reject others
		const ipv6Match = url.hostname.match(ipv6Regex);
		if (ipv6Match && ipv6Match[1] !== "::1") {
			return {
				valid: false,
				error:
					"Client URL must use domain names, not IP addresses (except loopback)",
			};
		}
	}

	return { valid: true, canonicalUrl: canonicalizeURL(urlString) };
}

// Check if URL is a loopback address
export function isLoopbackURL(urlString: string): boolean {
	try {
		const url = new URL(urlString);
		return (
			url.hostname === "localhost" ||
			url.hostname === "127.0.0.1" ||
			url.hostname === "[::1]" ||
			url.hostname.startsWith("127.")
		);
	} catch {
		return false;
	}
}

// Verify PKCE code challenge
export function verifyPKCE(verifier: string, challenge: string): boolean {
	const digest = new Bun.CryptoHasher("sha256").update(verifier).digest();
	return Buffer.from(digest).toString("base64url") === challenge;
}
