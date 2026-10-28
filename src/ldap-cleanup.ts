import { authenticate } from "ldap-authentication";
import { db } from "./db";

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
		createdAt: number;
	}>;
	activeUsers: Array<{
		username: string;
		id: number;
	}>;
}

export type LdapCheckResult = "exists" | "not_found" | "error";

export async function checkLdapUser(
	username: string,
): Promise<LdapCheckResult> {
	try {
		const user = await authenticate({
			ldapOpts: {
				url: process.env.LDAP_URL || "ldap://localhost:389",
			},
			adminDn: process.env.LDAP_ADMIN_DN || "",
			adminPassword: process.env.LDAP_ADMIN_PASSWORD || "",
			userSearchBase: process.env.LDAP_USER_SEARCH_BASE || "dc=example,dc=com",
			usernameAttribute: process.env.LDAP_USERNAME_ATTRIBUTE || "uid",
			username: username,
			verifyUserExists: true,
		});
		return user ? "exists" : "not_found";
	} catch (error) {
		// Distinguish "user not found" from infrastructure errors (network,
		// bind failure, timeout). Only an authoritative not-found should
		// count as orphaned — an LDAP outage must not trigger account
		// suspension/deletion. A bind failure ("Invalid Credentials") means
		// our admin credentials are wrong, not that the user is gone, so it
		// is deliberately classified as an error.
		const message = error instanceof Error ? error.message : String(error);
		if (/invalid credentials/i.test(message)) {
			console.error(
				`[ldap] Bind failed while checking user ${username}:`,
				error,
			);
			return "error";
		}
		if (message.includes("not found") || message.includes("No such object")) {
			return "not_found";
		}
		console.error(`[ldap] Error checking user ${username}:`, error);
		return "error";
	}
}

/**
 * Does the given LDAP group search result refer to `groupDn`?
 * ldap-authentication returns ldapts entries (`dn`) and back-fills
 * `objectName` for ldapjs compatibility; DNs compare case-insensitively.
 */
export function groupEntryMatches(entry: unknown, groupDn: string): boolean {
	if (!entry || typeof entry !== "object") return false;
	const e = entry as { dn?: unknown; objectName?: unknown };
	const want = normalizeDn(groupDn);
	for (const candidate of [e.dn, e.objectName]) {
		if (typeof candidate === "string" && normalizeDn(candidate) === want) {
			return true;
		}
	}
	return false;
}

function normalizeDn(dn: string): string {
	// Lowercase and strip whitespace around RDN separators so
	// "cn=Admins, dc=Example,dc=com" equals "cn=admins,dc=example,dc=com".
	return dn
		.trim()
		.toLowerCase()
		.replace(/\s*,\s*/g, ",")
		.replace(/\s*=\s*/g, "=");
}

/**
 * Pure membership check over an `authenticate()` result. Exported so it can
 * be unit-tested without a directory.
 */
export function userIsInGroup(user: unknown, groupDn: string): boolean {
	if (!user || typeof user !== "object") return false;
	const groups = (user as { groups?: unknown }).groups;
	if (!Array.isArray(groups)) return false;
	return groups.some((g) => groupEntryMatches(g, groupDn));
}

export async function checkLdapGroupMembership(
	username: string,
	_userDn: string,
): Promise<boolean> {
	const groupDn = process.env.LDAP_GROUP_DN;
	if (!groupDn) {
		return true; // No group restriction configured
	}

	const adminDn = process.env.LDAP_ADMIN_DN;
	const adminPassword = process.env.LDAP_ADMIN_PASSWORD;
	if (!adminDn || !adminPassword) {
		console.error(
			"LDAP group membership check requires LDAP_ADMIN_DN and LDAP_ADMIN_PASSWORD",
		);
		return false;
	}

	try {
		const groupClass = process.env.LDAP_GROUP_CLASS || "groupOfUniqueNames";
		const memberAttribute =
			process.env.LDAP_GROUP_MEMBER_ATTRIBUTE || "uniqueMember";

		// verifyUserExists requires admin credentials; the library then runs
		// a group search for the user and attaches `user.groups` (possibly an
		// empty array). Search from the group DN itself so a match can only
		// be that group (or something beneath it); we still compare the DN.
		const user = await authenticate({
			ldapOpts: {
				url: process.env.LDAP_URL || "ldap://localhost:389",
			},
			adminDn,
			adminPassword,
			userSearchBase: process.env.LDAP_USER_SEARCH_BASE || "dc=example,dc=com",
			usernameAttribute: process.env.LDAP_USERNAME_ATTRIBUTE || "uid",
			username: username,
			verifyUserExists: true,
			groupsSearchBase: groupDn,
			groupClass: groupClass,
			groupMemberAttribute: memberAttribute,
		});

		return userIsInGroup(user, groupDn);
	} catch (error) {
		console.error("LDAP group membership check failed:", error);
		return false;
	}
}

export async function getLdapAccounts(): Promise<AuditResult> {
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
		activeUsers: [],
	};

	console.log(`Found ${result.total} LDAP-provisioned accounts\n`);

	// Check each user against LDAP
	for (const user of ldapUsers) {
		process.stdout.write(`Checking ${user.username}... `);

		const checkResult = await checkLdapUser(user.username);

		if (checkResult === "exists") {
			console.log("✅ Found in LDAP");
			result.active++;
			result.activeUsers.push({
				username: user.username,
				id: user.id,
			});
		} else if (checkResult === "not_found") {
			console.log("❌ NOT FOUND in LDAP");
			result.orphaned++;
			result.orphanedUsers.push({
				username: user.username,
				id: user.id,
				status: user.status,
				createdAt: user.created_at,
			});
		} else {
			console.log("⚠️ Error checking LDAP (skipping)");
			result.errors++;
		}
	}

	return result;
}

export async function updateOrphanedAccounts(
	result: AuditResult,
	action: "suspend" | "deactivate" | "remove",
): Promise<void> {
	const newStatus = action === "suspend" ? "suspended" : "inactive";

	console.log(
		`\n📝 Updating ${result.orphaned} orphaned account(s) to status: '${newStatus}'`,
	);

	for (const user of result.orphanedUsers) {
		if (action === "remove") {
			db.query("DELETE FROM users WHERE id = ?").run(user.id);
			console.log(`   Removed: ${user.username}`);
			continue;
		}
		db.query("UPDATE users SET status = ? WHERE id = ?").run(
			newStatus,
			user.id,
		);
		// Revoke sessions and OAuth tokens so suspension takes effect immediately
		db.query("DELETE FROM sessions WHERE user_id = ?").run(user.id);
		db.query("UPDATE tokens SET revoked = 1 WHERE user_id = ?").run(user.id);
		console.log(`   Updated: ${user.username}`);
	}

	console.log(`\n✅ Updated ${result.orphaned} account(s)`);
}
