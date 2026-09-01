// HTTP content negotiation for the markdown-or-HTML pages.
// See https://acceptmarkdown.com — agents ask for `text/markdown`, browsers
// ask for `text/html`, and anything we cannot serve gets a 406.

interface MediaRange {
	type: string;
	q: number;
}

export function parseAccept(header: string | null): MediaRange[] {
	if (!header) return [];
	const ranges: MediaRange[] = [];
	for (const part of header.split(",")) {
		const [rawType, ...params] = part.split(";");
		const type = (rawType ?? "").trim().toLowerCase();
		if (!type) continue;
		let q = 1;
		for (const param of params) {
			const [key, value] = param.split("=");
			if (key?.trim().toLowerCase() === "q") {
				const parsed = Number.parseFloat(value ?? "");
				if (!Number.isNaN(parsed)) q = parsed;
			}
		}
		ranges.push({ type, q });
	}
	return ranges;
}

function specificity(range: string): number {
	if (range === "*/*") return 0;
	if (range.endsWith("/*")) return 1;
	return 2;
}

function matches(range: string, offer: string): boolean {
	if (range === "*/*") return true;
	if (range.endsWith("/*")) return offer.startsWith(`${range.slice(0, -1)}`);
	return range === offer;
}

/**
 * Pick the best offer for an Accept header, honouring q-values.
 * Returns null when the client explicitly accepts none of the offers (406).
 * A missing or empty Accept header means "anything", so the first offer wins.
 */
export function negotiate(
	header: string | null,
	offers: string[],
): string | null {
	const ranges = parseAccept(header);
	if (ranges.length === 0) return offers[0] ?? null;

	let best: { offer: string; q: number } | null = null;
	for (const offer of offers) {
		// Per RFC 7231 the most specific matching range decides an offer's q.
		let match: MediaRange | null = null;
		for (const range of ranges) {
			if (!matches(range.type, offer)) continue;
			if (!match || specificity(range.type) > specificity(match.type)) {
				match = range;
			}
		}
		if (!match) continue;
		// Ties go to the earlier offer, so our own preference order wins.
		if (!best || match.q > best.q) best = { offer, q: match.q };
	}

	if (!best || best.q <= 0) return null;
	return best.offer;
}
