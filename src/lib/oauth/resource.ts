import { safeFetch, validateExternalURL } from "../ssrf-safe-fetch";

// RFC 8707 Resource Indicators.
//
// A `resource` value identifies the resource server (audience) a token is meant
// for. §2 requires each to be an absolute URI WITHOUT a fragment. We normalize
// (origin + path, drop a trailing slash) so the string a client sends, the value
// we stamp as the token's audience, and the id the resource server checks all
// compare byte-for-byte.

/** Validate + normalize requested resources. Returns the list (deduped, may be
 * empty) or null if ANY value is malformed (→ the caller should reply
 * `invalid_target`). */
export function validateResources(values: string[]): string[] | null {
	const out: string[] = [];
	for (const raw of values) {
		if (!raw) continue;
		let u: URL;
		try {
			u = new URL(raw);
		} catch {
			return null;
		}
		if ((u.protocol !== "https:" && u.protocol !== "http:") || u.hash) return null;
		const norm = u.origin + u.pathname.replace(/\/+$/, "");
		if (!out.includes(norm)) out.push(norm);
	}
	return out;
}

/** DB storage form: a space-separated list (URIs never contain spaces), or null. */
export function resourcesToStored(resources: string[]): string | null {
	return resources.length > 0 ? resources.join(" ") : null;
}

/** Read the stored form back into a list. */
export function storedToResources(stored: string | null | undefined): string[] {
	return stored ? stored.split(" ").filter(Boolean) : [];
}

export interface ResourceInfo {
	id: string;
	name: string;
	host: string;
	logo?: string;
}

/**
 * Resolve requested resources to friendly display info for the consent screen
 * via each resource's RFC 9728 Protected Resource Metadata (`resource_name` and
 * an optional `logo_uri`). Best-effort + SSRF-safe: a resource with no PRM, an
 * unreachable one, or a bad logo URL just falls back to its hostname.
 */
export async function resourceDisplay(resources: string[]): Promise<ResourceInfo[]> {
	return Promise.all(resources.map(fetchResourceInfo));
}

async function fetchResourceInfo(id: string): Promise<ResourceInfo> {
	let host = id;
	try {
		host = new URL(id).host;
	} catch {
		/* keep id as host */
	}
	const info: ResourceInfo = { id, name: host, host };
	try {
		const prmUrl = `${id.replace(/\/+$/, "")}/.well-known/oauth-protected-resource`;
		const res = await safeFetch(prmUrl, { timeout: 3000, headers: { accept: "application/json" } });
		if (!res.success) return info;
		const prm = (await res.data.json()) as { resource_name?: string; logo_uri?: string };
		if (prm.resource_name) info.name = prm.resource_name;
		if (prm.logo_uri && validateExternalURL(prm.logo_uri).safe) info.logo = prm.logo_uri;
	} catch {
		/* best-effort: hostname fallback already set */
	}
	return info;
}
