import { Database } from "bun:sqlite";
import { getMigrations, migrate } from "bun-sqlite-migrations";

Bun.write("data/.gitkeep", "");

const dbPath = process.env.DATABASE_URL || "data/indiko.db";
const db = new Database(dbPath);

db.run("PRAGMA journal_mode = WAL;");
db.run("PRAGMA foreign_keys = ON;");
db.run("PRAGMA synchronous = NORMAL;");

migrate(db, getMigrations("src/migrations"));

export { db };
