#!/usr/bin/env bun
/**
 * Passkey Reset Script
 *
 * Resets a user's passkey credentials and generates a one-time reset link.
 * The user can use this link to register a new passkey while preserving
 * their existing account, permissions, and app authorizations.
 *
 * Usage: bun scripts/reset-passkey.ts <username>
 *
 * Example:
 *   bun scripts/reset-passkey.ts kieran
 *
 * The script will:
 * 1. Verify the user exists
 * 2. Delete all their existing passkey credentials
 * 3. Invalidate all active sessions (logs them out)
 * 4. Create a single-use reset invite locked to their username
 * 5. Output a reset link
 *
 * IMPORTANT: This preserves:
 * - User account and profile data
 * - All app permissions and authorizations
 * - Role assignments
 * - Admin status
 */

import { Database } from "bun:sqlite";
import * as path from "node:path";
import { resetPasskeys } from "../src/lib/passkey-reset";

// Load database
// Same resolution as the server: DATABASE_URL, relative to the working directory.
const dbPath = path.resolve(
	process.env.DATABASE_URL ||
		path.join(import.meta.dir, "..", "data", "indiko.db"),
);
let db: Database;
try {
	db = new Database(dbPath, { readwrite: true, create: false });
} catch (error) {
	console.error(`❌ Cannot open database at ${dbPath}: ${error}`);
	console.error("   Set DATABASE_URL to the server's database file.");
	process.exit(1);
}

const ORIGIN = process.env.ORIGIN || "http://localhost:3000";

interface User {
	id: number;
	username: string;
	name: string;
	email: string | null;
	status: string;
	is_admin: number;
}

interface Credential {
	id: number;
	name: string | null;
	created_at: number;
}

function getUser(username: string): User | null {
	return db
		.query(
			"SELECT id, username, name, email, status, is_admin FROM users WHERE username = ? COLLATE NOCASE",
		)
		.get(username) as User | null;
}

function getCredentials(userId: number): Credential[] {
	return db
		.query("SELECT id, name, created_at FROM credentials WHERE user_id = ?")
		.all(userId) as Credential[];
}

function getAdminUser(): User | null {
	return db
		.query(
			"SELECT id, username, name, email, status, is_admin FROM users WHERE is_admin = 1 LIMIT 1",
		)
		.get() as User | null;
}

async function main() {
	const args = process.argv.slice(2);

	if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
		console.log(`
Passkey Reset Script

Usage: bun scripts/reset-passkey.ts <username>

Options:
  --help, -h     Show this help message
  --dry-run      Show what would happen without making changes
  --force        Skip confirmation prompt

Example:
  bun scripts/reset-passkey.ts kieran
  bun scripts/reset-passkey.ts kieran --dry-run
`);
		process.exit(0);
	}

	const username = args.find((arg) => !arg.startsWith("--"));
	const dryRun = args.includes("--dry-run");
	const force = args.includes("--force");

	if (!username) {
		console.error("❌ Error: Username is required");
		process.exit(1);
	}

	console.log(`\n🔐 Passkey Reset for: ${username}`);
	console.log("─".repeat(50));

	// Look up user
	const user = getUser(username);
	if (!user) {
		console.error(`\n❌ Error: User '${username}' not found in ${dbPath}`);
		process.exit(1);
	}

	console.log(`\n📋 User Details:`);
	console.log(`   • ID: ${user.id}`);
	console.log(`   • Name: ${user.name}`);
	console.log(`   • Email: ${user.email || "(not set)"}`);
	console.log(`   • Status: ${user.status}`);
	console.log(`   • Admin: ${user.is_admin ? "Yes" : "No"}`);

	// Get existing credentials
	const credentials = getCredentials(user.id);
	console.log(`\n🔑 Existing Passkeys: ${credentials.length}`);
	credentials.forEach((cred, idx) => {
		const date = new Date(cred.created_at * 1000).toISOString().split("T")[0];
		console.log(`   ${idx + 1}. ${cred.name || "(unnamed)"} - created ${date}`);
	});

	if (credentials.length === 0) {
		console.log(
			"\n⚠️  User has no passkeys registered. Creating reset link anyway...",
		);
	}

	if (dryRun) {
		console.log("\n🔄 DRY RUN - No changes will be made");
		console.log("\nWould perform:");
		console.log(`   • Delete ${credentials.length} passkey(s)`);
		console.log("   • Invalidate all active sessions");
		console.log("   • Create single-use reset invite");
		process.exit(0);
	}

	// Confirmation prompt (unless --force)
	if (!force) {
		console.log("\n⚠️  This will:");
		console.log(
			`   • Delete ALL ${credentials.length} passkey(s) for this user`,
		);
		console.log("   • Log them out of all sessions");
		console.log("   • Generate a 24-hour reset link\n");

		process.stdout.write("Continue? [y/N] ");

		for await (const line of console) {
			const answer = line.trim().toLowerCase();
			if (answer !== "y" && answer !== "yes") {
				console.log("Cancelled.");
				process.exit(0);
			}
			break;
		}
	}

	// Get admin user for creating invite
	const admin = getAdminUser();
	if (!admin) {
		console.error("\n❌ Error: No admin user found to create invite");
		process.exit(1);
	}

	// Perform reset
	console.log("\n🔄 Performing reset...");

	const reset = resetPasskeys(db, user, admin.id, ORIGIN);
	console.log(`   ✅ Deleted ${reset.passkeys} passkey(s)`);
	console.log(`   ✅ Invalidated ${reset.sessions} session(s)`);
	console.log("   ✅ Created reset invite");
	const resetUrl = reset.url;

	console.log("\n" + "═".repeat(50));
	console.log("✨ PASSKEY RESET COMPLETE");
	console.log("═".repeat(50));
	console.log(`\n📧 Send this link to ${user.name || username}:\n`);
	console.log(`   ${resetUrl}`);
	console.log(`\n⏰ This link expires in 24 hours and can only be used once.`);
	console.log(`\n💡 The user must register with username: ${user.username}`);
}

main().catch((error) => {
	console.error("\n❌ Error:", error instanceof Error ? error.message : error);
	process.exit(1);
});
