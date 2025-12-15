import { Database } from "bun:sqlite";
import { getMigrations, migrate } from "bun-sqlite-migrations";

Bun.write("data/.gitkeep", "");

const db = new Database("data/indiko.db");

db.run("PRAGMA journal_mode = WAL;");
db.run("PRAGMA foreign_keys = ON;");
db.run("PRAGMA synchronous = NORMAL;");

migrate(db, getMigrations("src/migrations"));

export { db };
