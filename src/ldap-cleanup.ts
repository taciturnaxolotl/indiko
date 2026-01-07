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
		createdDate: string | undefined;
	}>;
}

export async function checkLdapUser(username: string): Promise<boolean> {
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
		return !!user;
	} catch (error) {
		// User not found or invalid credentials (expected for non-existence check)
		return false;
	}
}

export async function checkLdapGroupMembership(
	username: string,
	userDn: string,
): Promise<boolean> {
	if (!process.env.LDAP_GROUP_DN) {
		return true; // No group restriction configured
	}

	try {
		const groupDn = process.env.LDAP_GROUP_DN;
		const groupClass = process.env.LDAP_GROUP_CLASS || "groupOfUniqueNames";
		const memberAttribute =
			process.env.LDAP_GROUP_MEMBER_ATTRIBUTE || "uniqueMember";

		const user = await authenticate({
			ldapOpts: {
				url: process.env.LDAP_URL || "ldap://localhost:389",
			},
			userDn: userDn,
			userSearchBase: process.env.LDAP_USER_SEARCH_BASE || "dc=example,dc=com",
			usernameAttribute: process.env.LDAP_USERNAME_ATTRIBUTE || "uid",
			username: username,
			verifyUserExists: true,
			groupsSearchBase: groupDn,
			groupClass: groupClass,
			groupMemberAttribute: memberAttribute,
		});

		// If user was found and authenticate returns it, groups are available
		return !!user;
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
		console.log(`   Updated: ${user.username}`);
	}

	console.log(`\n✅ Updated ${result.orphaned} account(s)`);
}
