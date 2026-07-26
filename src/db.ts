import { Database } from "bun:sqlite";
import { getMigrations, migrate } from "bun-sqlite-migrations";

const dbPath = process.env.DATABASE_URL || "data/indiko.db";

if (dbPath !== ":memory:") {
	Bun.write("data/.gitkeep", "");
}
const db = new Database(dbPath);

db.run("PRAGMA journal_mode = WAL;");
db.run("PRAGMA foreign_keys = ON;");
db.run("PRAGMA synchronous = NORMAL;");

migrate(db, getMigrations("src/migrations"));

export { db };
