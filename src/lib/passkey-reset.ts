import type { Database } from "bun:sqlite";
import crypto from "node:crypto";

export interface PasskeyReset {
	username: string;
	passkeys: number;
	sessions: number;
	url: string;
	expiresAt: number;
}

const RESET_LIFETIME = 86400;

/**
 * Wipe a user's passkeys and sessions and mint a one-use link to register a new one.
 * Account, permissions, roles and app grants survive. Shared by the admin API and
 * scripts/reset-passkey.ts so the invite is always bound to the account it resets.
 */
export function resetPasskeys(
	database: Database,
	user: { id: number; username: string },
	adminId: number,
	origin: string,
): PasskeyReset {
	const code = crypto.randomBytes(16).toString("base64url");
	const expiresAt = Math.floor(Date.now() / 1000) + RESET_LIFETIME;

	const reset = database.transaction(() => {
		const passkeys = database
			.query("DELETE FROM credentials WHERE user_id = ?")
			.run(user.id).changes;
		const sessions = database
			.query("DELETE FROM sessions WHERE user_id = ?")
			.run(user.id).changes;
		// Older reset links for this account stop working; only the newest one is live.
		database
			.query("DELETE FROM invites WHERE note = ? AND current_uses < max_uses")
			.run(`PASSKEY_RESET:${user.username}`);
		// The server only accepts a reset invite that names this exact account (ldap_username).
		database
			.query(
				"INSERT INTO invites (code, created_by, max_uses, current_uses, expires_at, note, message, ldap_username) VALUES (?, ?, 1, 0, ?, ?, ?, ?)",
			)
			.run(
				code,
				adminId,
				expiresAt,
				`PASSKEY_RESET:${user.username}`,
				"Your passkey has been reset. Register a new passkey to get back into your account.",
				user.username,
			);
		return { passkeys, sessions };
	})();

	const url = new URL("/login", origin);
	url.searchParams.set("invite", code);
	url.searchParams.set("username", user.username);
	return { username: user.username, ...reset, url: url.toString(), expiresAt };
}
