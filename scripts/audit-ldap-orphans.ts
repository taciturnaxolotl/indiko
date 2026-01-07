/**
 * LDAP Orphan Account Audit Script
 *
 * This script identifies Indiko accounts provisioned via LDAP that no longer exist in LDAP.
 * Useful for detecting when users have been removed from LDAP but their Indiko accounts remain active.
 *
 * Usage: bun scripts/audit-ldap-orphans.ts [--suspend | --deactivate | --dry-run]
 *
 * Flags:
 *   --dry-run      Show what would be done without making changes (default)
 *   --suspend      Set status to 'suspended' for orphaned accounts
 *   --deactivate   Set status to 'inactive' for orphaned accounts
 */

import { Database } from "bun:sqlite";
import * as path from "node:path";
import { authenticate } from "ldap-authentication";

// Load database
const dbPath = path.join(import.meta.dir, "..", "data", "indiko.db");
const db = new Database(dbPath);

// Configuration from environment
const LDAP_URL = process.env.LDAP_URL || "ldap://localhost:389";
const LDAP_ADMIN_DN = process.env.LDAP_ADMIN_DN;
const LDAP_ADMIN_PASSWORD = process.env.LDAP_ADMIN_PASSWORD;
const LDAP_USER_SEARCH_BASE =
	process.env.LDAP_USER_SEARCH_BASE || "dc=example,dc=com";
const LDAP_USERNAME_ATTRIBUTE = process.env.LDAP_USERNAME_ATTRIBUTE || "uid";

interface LdapUser {
	username: string;
	id: number;
	status: string;
	created_at: number;
}

interface AuditResult {
	total: number;
	active: number;
	orphaned: number;
	errors: number;
	orphanedUsers: Array<{
		username: string;
		id: number;
		status: string;
		createdDate: string | undefined;
	}>;
}

async function checkLdapUser(username: string): Promise<boolean> {
	try {
		const user = await authenticate({
			ldapOpts: {
				url: LDAP_URL,
			},
			adminDn: LDAP_ADMIN_DN,
			adminPassword: LDAP_ADMIN_PASSWORD,
			userSearchBase: LDAP_USER_SEARCH_BASE,
			usernameAttribute: LDAP_USERNAME_ATTRIBUTE,
			username: username,
			verifyUserExists: true,
		});
		return !!user;
	} catch (error) {
		// User not found or invalid credentials (expected for non-existence check)
		return false;
	}
}

async function auditLdapAccounts(): Promise<AuditResult> {
	console.log("🔍 Starting LDAP orphan account audit...\n");

	// Get all LDAP-provisioned users
	const ldapUsers = db
		.query(
			"SELECT id, username, status, created_at FROM users WHERE provisioned_via_ldap = 1",
		)
		.all() as LdapUser[];

	const result: AuditResult = {
		total: ldapUsers.length,
		active: 0,
		orphaned: 0,
		errors: 0,
		orphanedUsers: [],
	};

	console.log(`Found ${result.total} LDAP-provisioned accounts\n`);

	// Check each user against LDAP
	for (const user of ldapUsers) {
		process.stdout.write(`Checking ${user.username}... `);

		try {
			const existsInLdap = await checkLdapUser(user.username);

			if (existsInLdap) {
				console.log("✅ Found in LDAP");
				result.active++;
			} else {
				console.log("❌ NOT FOUND in LDAP");
				result.orphaned++;
				result.orphanedUsers.push({
					username: user.username,
					id: user.id,
					status: user.status,
					createdDate: new Date(user.created_at * 1000)
						.toISOString()
						.split("T")[0],
				});
			}
		} catch (error) {
			console.log("⚠️ Error checking LDAP");
			result.errors++;
			console.error(
				`   Error: ${error instanceof Error ? error.message : String(error)}`,
			);
		}
	}

	return result;
}

function printReport(result: AuditResult): void {
	console.log(`\n${"=".repeat(60)}`);
	console.log("LDAP ORPHAN ACCOUNT AUDIT REPORT");
	console.log(`${"=".repeat(60)}\n`);

	console.log(`Total LDAP-provisioned accounts: ${result.total}`);
	console.log(`Active in LDAP:                 ${result.active}`);
	console.log(`Orphaned (missing from LDAP):   ${result.orphaned}`);
	console.log(`Check errors:                   ${result.errors}`);

	if (result.orphaned === 0) {
		console.log("\n✅ No orphaned accounts found!");
		return;
	}

	console.log(`\n${"-".repeat(60)}`);
	console.log("ORPHANED ACCOUNTS:");
	console.log(`${"-".repeat(60)}\n`);

	result.orphanedUsers.forEach((user, idx) => {
		console.log(`${idx + 1}. ${user.username}`);
		console.log(
			`   ID: ${user.id} | Status: ${user.status} | Created: ${user.createdDate}`,
		);
	});
}

async function updateOrphanedAccounts(
	result: AuditResult,
	action: "suspend" | "deactivate",
): Promise<void> {
	const newStatus = action === "suspend" ? "suspended" : "inactive";

	console.log(
		`\n📝 Updating ${result.orphaned} orphaned account(s) to status: '${newStatus}'`,
	);

	for (const user of result.orphanedUsers) {
		db.query("UPDATE users SET status = ? WHERE id = ?").run(
			newStatus,
			user.id,
		);
		console.log(`   Updated: ${user.username}`);
	}

	console.log(`\n✅ Updated ${result.orphaned} account(s)`);
}

async function main() {
	// Validate LDAP configuration
	if (!LDAP_ADMIN_DN || !LDAP_ADMIN_PASSWORD) {
		console.error(
			"❌ Error: LDAP_ADMIN_DN and LDAP_ADMIN_PASSWORD environment variables are required",
		);
		process.exit(1);
	}

	const args = process.argv.slice(2);
	const dryRun = args.includes("--dry-run") || args.length === 0;
	const shouldSuspend = args.includes("--suspend");
	const shouldDeactivate = args.includes("--deactivate");

	if (dryRun) {
		console.log("🔄 Running in DRY-RUN mode (no changes will be made)\n");
	}

	try {
		const result = await auditLdapAccounts();
		printReport(result);

		if (!dryRun && result.orphaned > 0) {
			if (shouldSuspend) {
				await updateOrphanedAccounts(result, "suspend");
			} else if (shouldDeactivate) {
				await updateOrphanedAccounts(result, "deactivate");
			} else {
				console.log(
					"\n⚠️ No action specified. Use --suspend or --deactivate to update accounts.",
				);
			}
		}

		process.exit(0);
	} catch (error) {
		console.error(
			"\n❌ Audit failed:",
			error instanceof Error ? error.message : String(error),
		);
		process.exit(1);
	}
}

main();
