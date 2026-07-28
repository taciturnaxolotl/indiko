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

	// Include CSRF token on mutating requests
	if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
		const csrf = getCsrfToken();
		if (csrf) {
			headers.set("X-CSRF-Token", csrf);
		}
	}

	return fetch(url, { ...options, headers });
}
