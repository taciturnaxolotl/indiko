/**
 * Seed the dev database with realistic data so the UI has something to show.
 *
 * Usage:
 *   bun scripts/seed-dev.ts           # insert seed data
 *   bun scripts/seed-dev.ts --reset  # wipe users/apps/etc first, then seed
 *
 * Does NOT touch oidc_keys or migrations. Only inserts into:
 *   users, credentials, sessions, apps, permissions, invites, tokens
 */

import { Database } from "bun:sqlite";
import * as path from "node:path";

const dbPath = path.join(import.meta.dir, "..", "data", "indiko.db");
const db = new Database(dbPath);
db.run("PRAGMA foreign_keys = ON;");

const reset = process.argv.includes("--reset");
if (reset) {
	console.log("resetting tables...");
	for (const table of [
		"tokens",
		"permissions",
		"invite_uses",
		"invite_roles",
		"invites",
		"authcodes",
		"challenges",
		"sessions",
		"credentials",
		"apps",
		"users",
	]) {
		db.run(`DELETE FROM ${table};`);
	}
	// Reset autoincrement counters
	db.run("DELETE FROM sqlite_sequence WHERE name IN ('users','credentials','sessions','apps','permissions','invites','tokens','invite_roles','invite_uses','authcodes','challenges');");
	console.log("done.");
}

const now = Math.floor(Date.now() / 1000);

// --- Users ---
const users = [
	{ username: "kieran", name: "Kieran Klukas", email: "kieran@dunkirk.sh", tier: "admin", status: "active" },
	{ username: "alice", name: "Alice Carter", email: "alice@example.com", tier: "developer", status: "active" },
	{ username: "bob", name: "Bob Nguyen", email: "bob@example.com", tier: "user", status: "active" },
	{ username: "charlie", name: "Charlie Park", email: "charlie@example.com", tier: "user", status: "suspended" },
	{ username: "dana", name: "Dana Williams", email: "dana@example.com", tier: "developer", status: "active" },
	{ username: "eve", name: "Eve Martinez", email: null, tier: "user", status: "active" },
];

const userIds: number[] = [];
for (const u of users) {
	const isAdmin = u.tier === "admin" ? 1 : 0;
	const res = db
		.query(
			`INSERT INTO users (username, name, email, tier, status, is_admin, created_at, url)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		)
		.run(
			u.username,
			u.name,
			u.email,
			u.tier,
			u.status,
			isAdmin,
			now - Math.floor(Math.random() * 30 * 86400),
			`https://${u.username}.example.com`,
		);
	userIds.push(Number(res.lastInsertRowid));
}
console.log(`inserted ${userIds.length} users`);

// --- Credentials (fake passkeys) ---
let credCount = 0;
for (const [i, uid] of userIds.entries()) {
	const numCreds = i === 0 ? 3 : i % 2 === 0 ? 2 : 1;
	for (let j = 0; j < numCreds; j++) {
		const credId = crypto.getRandomValues(new Uint8Array(32));
		const pubKey = crypto.getRandomValues(new Uint8Array(64));
		db.query(
			`INSERT INTO credentials (user_id, credential_id, public_key, counter, name, created_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
		).run(
			uid,
			Buffer.from(credId),
			Buffer.from(pubKey),
			Math.floor(Math.random() * 100),
			j === 0 ? "Main device" : `Backup ${j + 1}`,
			now - Math.floor(Math.random() * 60 * 86400),
		);
		credCount++;
	}
}
console.log(`inserted ${credCount} credentials`);

// --- Sessions (valid for 24h so you can actually log in) ---
const sessionToken = "dev-session-kieran";
db.query(
	"INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
).run(sessionToken, userIds[0], now + 86400);
console.log("inserted 1 dev session (token: dev-session-kieran)");

// --- Apps (OAuth clients) ---
const apps = [
	{
		client_id: "https://auth.dunkirk.sh",
		redirect_uris: '["https://auth.dunkirk.sh/callback"]',
		name: "Dunkirk Auth",
		logo_url: null,
		description: "Personal OAuth provider for dunkirk.sh",
		is_preregistered: 1,
		client_secret_hash: null,
		available_roles: '["admin","editor","viewer"]',
		default_role: "viewer",
	},
	{
		client_id: "https://blog.dunkirk.sh",
		redirect_uris: '["https://blog.dunkirk.sh/auth/callback","https://blog.dunkirk.sh/indieauth"]',
		name: "Dunkirk Blog",
		logo_url: null,
		description: "IndieWeb blog with Micropub support",
		is_preregistered: 0,
		client_secret_hash: null,
		available_roles: null,
		default_role: null,
	},
	{
		client_id: "https://infra.dunkirk.sh",
		redirect_uris: '["https://infra.dunkirk.sh/callback"]',
		name: "Infra Dashboard",
		logo_url: null,
		description: "Homelab status page and monitoring",
		is_preregistered: 1,
		client_secret_hash: null,
		available_roles: '["admin","operator"]',
		default_role: "operator",
	},
	{
		client_id: "https://webring.dunkirk.sh",
		redirect_uris: '["https://webring.dunkirk.sh/indieauth"]',
		name: "Webring",
		logo_url: null,
		description: null,
		is_preregistered: 0,
		client_secret_hash: null,
		available_roles: null,
		default_role: null,
	},
	{
		client_id: "https://photos.kieranklukas.com",
		redirect_uris: '["https://photos.kieranklukas.com/auth"]',
		name: "Photo Gallery",
		logo_url: null,
		description: "Photography portfolio site",
		is_preregistered: 1,
		client_secret_hash: null,
		available_roles: '["admin","editor"]',
		default_role: "editor",
	},
];

for (const a of apps) {
	db.query(
		`INSERT INTO apps (client_id, redirect_uris, name, logo_url, description, is_preregistered, client_secret_hash, available_roles, default_role, first_seen, last_used)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	).run(
		a.client_id,
		a.redirect_uris,
		a.name,
		a.logo_url,
		a.description,
		a.is_preregistered,
		a.client_secret_hash,
		a.available_roles,
		a.default_role,
		now - Math.floor(Math.random() * 90 * 86400),
		now - Math.floor(Math.random() * 7 * 86400),
	);
}
console.log(`inserted ${apps.length} apps`);

// --- Permissions (user -> app links) ---
const perms = [
	// Kieran has access to everything
	{ user: 0, client: "https://auth.dunkirk.sh", scopes: '["profile","email","openid"]', role: "admin" },
	{ user: 0, client: "https://blog.dunkirk.sh", scopes: '["profile","create","update"]', role: null },
	{ user: 0, client: "https://infra.dunkirk.sh", scopes: '["profile","email"]', role: "admin" },
	{ user: 0, client: "https://webring.dunkirk.sh", scopes: '["profile"]', role: null },
	{ user: 0, client: "https://photos.kieranklukas.com", scopes: '["profile","email","upload"]', role: "admin" },
	// Alice has access to a few
	{ user: 1, client: "https://auth.dunkirk.sh", scopes: '["profile","email"]', role: "editor" },
	{ user: 1, client: "https://blog.dunkirk.sh", scopes: '["profile","create"]', role: null },
	{ user: 1, client: "https://photos.kieranklukas.com", scopes: '["profile","upload"]', role: "editor" },
	// Bob has access to 2
	{ user: 2, client: "https://blog.dunkirk.sh", scopes: '["profile"]', role: null },
	{ user: 2, client: "https://infra.dunkirk.sh", scopes: '["profile","email"]', role: "operator" },
	// Dana has access to 3
	{ user: 4, client: "https://auth.dunkirk.sh", scopes: '["profile","email"]', role: "viewer" },
	{ user: 4, client: "https://photos.kieranklukas.com", scopes: '["profile","upload"]', role: "editor" },
	{ user: 4, client: "https://webring.dunkirk.sh", scopes: '["profile"]', role: null },
	// Eve has access to 1
	{ user: 5, client: "https://blog.dunkirk.sh", scopes: '["profile","email"]', role: null },
];

for (const p of perms) {
	const clientId = p.client;
	db.query(
		`INSERT INTO permissions (user_id, client_id, scopes, role, granted_at, last_used)
		 VALUES (?, ?, ?, ?, ?, ?)`,
	).run(
		userIds[p.user],
		clientId,
		p.scopes,
		p.role,
		now - Math.floor(Math.random() * 60 * 86400),
		now - Math.floor(Math.random() * 3 * 86400),
	);
}
console.log(`inserted ${perms.length} permissions`);

// --- Tokens (active access tokens) ---
const tokens = [
	{ user: 0, client: "https://auth.dunkirk.sh", scope: "profile email openid" },
	{ user: 0, client: "https://blog.dunkirk.sh", scope: "profile create update" },
	{ user: 1, client: "https://photos.kieranklukas.com", scope: "profile upload" },
	{ user: 2, client: "https://infra.dunkirk.sh", scope: "profile email" },
];

for (const t of tokens) {
	const tokStr = `tok_${crypto.randomUUID().replace(/-/g, "")}`;
	db.query(
		`INSERT INTO tokens (token, user_id, client_id, scope, created_at, expires_at, revoked)
		 VALUES (?, ?, ?, ?, ?, ?, 0)`,
	).run(tokStr, userIds[t.user], t.client, t.scope, now - 3600, now + 86400);
}
console.log(`inserted ${tokens.length} tokens`);

// --- Invites ---
const invites = [
	{ code: "invite-alpha-001", createdBy: 0, maxUses: 5, currentUses: 2, expiresAt: now + 7 * 86400, note: "general community invite", message: "Welcome to Indiko!" },
	{ code: "invite-beta-002", createdBy: 0, maxUses: 1, currentUses: 1, expiresAt: now - 86400, note: "for Bob", message: null },
	{ code: "invite-gamma-003", createdBy: 0, maxUses: 10, currentUses: 0, expiresAt: null, note: "open invite for team", message: "Hey, come join us!" },
	{ code: "invite-delta-004", createdBy: 1, maxUses: 3, currentUses: 1, expiresAt: now + 30 * 86400, note: null, message: null },
	{ code: "invite-epsilon-005", createdBy: 0, maxUses: 1, currentUses: 0, expiresAt: now + 3 * 86400, note: "for the new dev", message: "Welcome aboard!" },
];

for (const inv of invites) {
	db.query(
		`INSERT INTO invites (code, created_by, used, max_uses, current_uses, expires_at, note, message, created_at)
		 VALUES (?, ?, 0, ?, ?, ?, ?, ?, ?)`,
	).run(
		inv.code,
		userIds[inv.createdBy],
		inv.maxUses,
		inv.currentUses,
		inv.expiresAt,
		inv.note,
		inv.message,
		now - Math.floor(Math.random() * 14 * 86400),
	);
}
console.log(`inserted ${invites.length} invites`);

// Mark one invite as used by Bob
const bobInvite = db.query("SELECT id FROM invites WHERE code = 'invite-beta-002'").get() as { id: number };
db.query(
	"UPDATE invites SET used = 1, used_by = ?, used_at = ? WHERE id = ?",
).run(userIds[2], now - 86400, bobInvite.id);
db.query(
	"INSERT INTO invite_uses (invite_id, user_id, used_at) VALUES (?, ?, ?)",
).run(bobInvite.id, userIds[2], now - 86400);

// Mark one as used by Dana
const danaInvite = db.query("SELECT id FROM invites WHERE code = 'invite-delta-004'").get() as { id: number };
db.query(
	"UPDATE invites SET used = 1, used_by = ?, used_at = ? WHERE id = ?",
).run(userIds[4], now - 2 * 86400, danaInvite.id);
db.query(
	"INSERT INTO invite_uses (invite_id, user_id, used_at) VALUES (?, ?, ?)",
).run(danaInvite.id, userIds[4], now - 2 * 86400);

console.log("marked 2 invites as used");

console.log("\nseed complete!");
console.log("login token: dev-session-kieran");
console.log("admin user: kieran");
