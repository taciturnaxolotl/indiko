/**
 * Fetch wrapper that includes the CSRF token header for mutating requests.
 * The session cookie is sent automatically by the browser.
 */

function getCsrfToken(): string | null {
	const match = document.cookie.match(/indiko_csrf=([^;]+)/);
	return match?.[1] ?? null;
}

export async function apiFetch(
	url: string,
	options: RequestInit = {},
): Promise<Response> {
	const method = (options.method || "GET").toUpperCase();
	const headers = new Headers(options.headers);

	const mutating =
		method !== "GET" && method !== "HEAD" && method !== "OPTIONS";

	// Include CSRF token on mutating requests
	if (mutating) {
		const csrf = getCsrfToken();
		if (csrf) {
			headers.set("X-CSRF-Token", csrf);
		}
	}

	const response = await fetch(url, { ...options, headers });

	// A 403 for a stale CSRF cookie comes back with a corrected cookie, so one
	// retry with the fresh value is all it takes. Bodies that were streams
	// cannot be replayed; everything in this app sends strings or nothing.
	if (
		mutating &&
		response.status === 403 &&
		typeof (options.body ?? "") === "string"
	) {
		const body = await response
			.clone()
			.json()
			.catch(() => null as { code?: string } | null);
		const fresh = getCsrfToken();
		if (
			body?.code === "csrf" &&
			fresh &&
			fresh !== headers.get("X-CSRF-Token")
		) {
			headers.set("X-CSRF-Token", fresh);
			return fetch(url, { ...options, headers });
		}
	}

	return response;
}
