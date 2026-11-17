// Field validators shared by the admin and profile JSON APIs.

export const MAX_URL_LENGTH = 2048;

export type Checked<T> = { ok: true; value: T } | { ok: false; error: string };

export function isHttpUrl(value: string): boolean {
	try {
		const u = new URL(value);
		return u.protocol === "http:" || u.protocol === "https:";
	} catch {
		return false;
	}
}

/** `undefined` means omitted, `null` means cleared. */
export function optionalText(
	value: unknown,
	label: string,
	max: number,
): Checked<string | null | undefined> {
	if (value === undefined) return { ok: true, value: undefined };
	if (value === null || value === "") return { ok: true, value: null };
	if (typeof value !== "string") {
		return { ok: false, error: `${label} must be a string` };
	}
	if (value.length > max) {
		return { ok: false, error: `${label} must be at most ${max} characters` };
	}
	return { ok: true, value };
}

export function optionalHttpUrl(
	value: unknown,
	label: string,
): Checked<string | null | undefined> {
	const text = optionalText(value, label, MAX_URL_LENGTH);
	if (!text.ok) return text;
	if (typeof text.value === "string" && !isHttpUrl(text.value)) {
		return { ok: false, error: `${label} must be an http(s) URL` };
	}
	return text;
}
