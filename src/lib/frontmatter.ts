// Minimal `---` frontmatter parser shared by the markdown-backed pages.
// Values are plain strings; nothing here needs YAML.

export function parseFrontmatter(raw: string): {
	fm: Record<string, string>;
	body: string;
} {
	const match = raw.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
	if (!match) return { fm: {}, body: raw };

	const fm: Record<string, string> = {};
	for (const line of (match[1] ?? "").split("\n")) {
		const idx = line.indexOf(":");
		if (idx > 0) {
			fm[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
		}
	}
	return { fm, body: match[2] ?? raw };
}
