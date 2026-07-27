// Force tests onto an in-memory database BEFORE any src/ module is imported.
//
// This MUST run as a bunfig [test] preload. Setting the env var inside
// test/helpers/db.ts is too late: test files statically import src/ routes
// (which import src/db) before the helper body runs, so src/db would already
// have opened the real data/indiko.db. A preload runs first, guaranteeing
// src/db sees :memory: on its very first evaluation.
process.env.DATABASE_URL = ":memory:";
