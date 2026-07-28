/**
 * Security headers for HTML pages and API responses.
 * Applied per-route since Bun's routes object doesn't support middleware.
 */

const isProduction = process.env.NODE_ENV === "production";

export const SECURITY_HEADERS: Record<string, string> = {
	"X-Content-Type-Options": "nosniff",
	"Referrer-Policy": "strict-origin-when-cross-origin",
	"X-Frame-Options": "DENY",
	"Content-Security-Policy": "frame-ancestors 'none'",
	...(isProduction
		? { "Strict-Transport-Security": "max-age=31536000; includeSubDomains" }
		: {}),
};

/** Wrap a Response with security headers (mutates and returns it). */
export function withSecurityHeaders(response: Response): Response {
	for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
		if (!response.headers.has(key)) {
			response.headers.set(key, value);
		}
	}
	return response;
}
