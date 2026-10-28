/**
 * Human-friendly label for an OAuth client.
 *
 * URL clients (IndieAuth) fall back to their hostname when they have no
 * registered name. Opaque clients (`ikc_…` from the admin UI or dynamic
 * registration) are not URLs, so `new URL()` would throw; a single nameless
 * opaque client must never be able to take down an admin list. Never throws.
 */
export function clientDisplayName(
	clientId: string,
	name: string | null | undefined,
): string {
	if (typeof name === "string" && name.trim()) return name;
	try {
		const host = new URL(clientId).hostname;
		return host || clientId;
	} catch {
		return clientId;
	}
}

/**
 * How a client row came to exist. `is_preregistered = 0` rows are always
 * IndieAuth URL clients that were auto-registered on first authorization, so
 * that is derived here regardless of what the `registration` column says
 * (code paths that create those rows may not stamp the column).
 */
export type ClientRegistration = "admin" | "dcr" | "url";

export function clientRegistration(row: {
	is_preregistered: number;
	registration?: string | null;
}): ClientRegistration {
	if (row.is_preregistered !== 1) return "url";
	return row.registration === "dcr" ? "dcr" : "admin";
}
