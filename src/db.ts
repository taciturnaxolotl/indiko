import { Database } from "bun:sqlite";
import { getMigrations, migrate } from "bun-sqlite-migrations";
import { hashSecret } from "./lib/secrets";

const dbPath = process.env.DATABASE_URL || "data/indiko.db";

if (dbPath !== ":memory:") {
	Bun.write("data/.gitkeep", "");
}
const db = new Database(dbPath);

db.run("PRAGMA journal_mode = WAL;");
db.run("PRAGMA foreign_keys = ON;");
db.run("PRAGMA synchronous = NORMAL;");

migrate(db, getMigrations("src/migrations"));
backfillTokenHashes(db);

/** Hash legacy plaintext tokens (43 chars) in place; digests are 64. SQLite has no sha256. */
export function backfillTokenHashes(database: Database): number {
	const rows = database
		.query(
			"SELECT id, token, refresh_token FROM tokens WHERE length(token) != 64 OR length(refresh_token) != 64",
		)
		.all() as { id: number; token: string; refresh_token: string | null }[];
	const digest = (value: string) =>
		value.length === 64 ? value : hashSecret(value);
	const update = database.query(
		"UPDATE tokens SET token = ?, refresh_token = ? WHERE id = ?",
	);
	database.transaction(() => {
		for (const row of rows) {
			update.run(
				digest(row.token),
				row.refresh_token && digest(row.refresh_token),
				row.id,
			);
		}
	})();
	return rows.length;
}

export { db };
