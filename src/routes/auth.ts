import {
	type AuthenticationResponseJSON,
	generateAuthenticationOptions,
	generateRegistrationOptions,
	type PublicKeyCredentialCreationOptionsJSON,
	type PublicKeyCredentialRequestOptionsJSON,
	type RegistrationResponseJSON,
	type VerifiedAuthenticationResponse,
	type VerifiedRegistrationResponse,
	verifyAuthenticationResponse,
	verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { authenticate } from "ldap-authentication";
import { db } from "../db";
import { checkLdapGroupMembership, checkLdapUser } from "../ldap-cleanup";
import { csrfCookieHeader, generateCsrfToken } from "../lib/session";

const RP_NAME = "Indiko";

// Thrown inside the registration transaction when the invite is exhausted so
// the whole registration rolls back.
class InviteExhaustedError extends Error {
	constructor() {
		super("Invite code fully used");
		this.name = "InviteExhaustedError";
	}
}

export function canRegister(_req: Request): Response {
	const userCount = db.query("SELECT COUNT(*) as count FROM users").get() as {
		count: number;
	};

	return Response.json({
		canRegister: userCount.count === 0,
		bootstrapMode: userCount.count === 0,
	});
}

export async function registerOptions(req: Request): Promise<Response> {
	try {
		const body = await req.json();
		const { username, inviteCode } = body;

		if (!username || typeof username !== "string") {
			return Response.json({ error: "Username required" }, { status: 400 });
		}

		if (
			username.length > 128 ||
			!/^[A-Za-z0-9._@-]+$/.test(username)
		) {
			return Response.json(
				{ error: "Invalid username format" },
				{ status: 400 },
			);
		}

		// Check if username already exists
		const existingUser = db
			.query("SELECT id FROM users WHERE username = ?")
			.get(username) as { id: number } | undefined;

		// Allow re-registration if user exists but has no credentials (passkey reset case)
		let _isPasskeyReset = false;
		if (existingUser) {
			const credCount = db
				.query("SELECT COUNT(*) as count FROM credentials WHERE user_id = ?")
				.get(existingUser.id) as { count: number };

			if (credCount.count > 0) {
				return Response.json(
					{ error: "Username already taken" },
					{ status: 400 },
				);
			}
			// User exists but has no credentials - this is a passkey reset
			_isPasskeyReset = true;
		}

		// Check if this is bootstrap (first user)
		const userCount = db.query("SELECT COUNT(*) as count FROM users").get() as {
			count: number;
		};

		const isBootstrap = userCount.count === 0;
		let inviteMessage: string | null = null;

		// If not bootstrap, require valid invite code
		if (!isBootstrap) {
			if (!inviteCode) {
				return Response.json(
					{ error: "Invite code required" },
					{ status: 403 },
				);
			}

			// Validate invite code
			const invite = db
				.query(
					"SELECT id, max_uses, current_uses, expires_at, message, ldap_username FROM invites WHERE code = ?",
				)
				.get(inviteCode) as
				| {
						id: number;
						max_uses: number;
						current_uses: number;
						expires_at: number | null;
						message: string | null;
						ldap_username: string | null;
				  }
				| undefined;

			if (!invite) {
				return Response.json({ error: "Invalid invite code" }, { status: 403 });
			}

			const now = Math.floor(Date.now() / 1000);
			if (invite.expires_at && invite.expires_at < now) {
				return Response.json({ error: "Invite code expired" }, { status: 403 });
			}

			// Will check usage limit atomically during update

			// If invite is locked to an LDAP username, enforce it
			if (invite.ldap_username && invite.ldap_username !== username) {
				return Response.json(
					{ error: "Username must match LDAP account" },
					{ status: 400 },
				);
			}

			// Store invite message to return with options
			inviteMessage = invite.message;
		}

		// Generate WebAuthn registration options
		const options: PublicKeyCredentialCreationOptionsJSON =
			await generateRegistrationOptions({
				rpName: RP_NAME,
				rpID: process.env.RP_ID || "",
				userName: username,
				userDisplayName: username,
				attestationType: "none",
				authenticatorSelection: {
					residentKey: "required",
					userVerification: "required",
					authenticatorAttachment: "platform",
				},
			});

		// Store challenge
		const expiresAt = Math.floor(Date.now() / 1000) + 300; // 5 minutes
		db.query(
			"INSERT INTO challenges (challenge, username, type, expires_at) VALUES (?, ?, 'registration', ?)",
		).run(options.challenge, username, expiresAt);

		return Response.json({ ...options, inviteMessage });
	} catch (error) {
		console.error("Registration options error:", error);
		return Response.json({ error: "Internal server error" }, { status: 500 });
	}
}

export async function registerVerify(req: Request): Promise<Response> {
	try {
		const body = await req.json();
		const {
			username,
			response,
			challenge: expectedChallenge,
			inviteCode,
		} = body as {
			username: string;
			response: RegistrationResponseJSON;
			challenge?: string;
			inviteCode?: string;
		};

		if (!username || !response) {
			return Response.json(
				{ error: "Username and response required" },
				{ status: 400 },
			);
		}

		if (
			username.length > 128 ||
			!/^[A-Za-z0-9._@-]+$/.test(username)
		) {
			return Response.json(
				{ error: "Invalid username format" },
				{ status: 400 },
			);
		}

		// Check if username already exists
		const existingUser = db
			.query("SELECT id, is_admin FROM users WHERE username = ?")
			.get(username) as { id: number; is_admin: number } | undefined;

		// Allow re-registration if user exists but has no credentials (passkey reset case)
		let isPasskeyReset = false;
		if (existingUser) {
			const credCount = db
				.query("SELECT COUNT(*) as count FROM credentials WHERE user_id = ?")
				.get(existingUser.id) as { count: number };

			if (credCount.count > 0) {
				return Response.json(
					{ error: "Username already taken" },
					{ status: 400 },
				);
			}
			// User exists but has no credentials - this is a passkey reset
			isPasskeyReset = true;
		}

		if (!expectedChallenge) {
			return Response.json({ error: "Invalid challenge" }, { status: 400 });
		}

		// Verify challenge exists and is valid
		const challenge = db
			.query(
				"SELECT challenge, expires_at FROM challenges WHERE challenge = ? AND username = ? AND type = 'registration'",
			)
			.get(expectedChallenge, username) as
			| { challenge: string; expires_at: number }
			| undefined;

		if (!challenge) {
			return Response.json({ error: "Invalid challenge" }, { status: 400 });
		}

		const now = Math.floor(Date.now() / 1000);
		if (challenge.expires_at < now) {
			return Response.json({ error: "Challenge expired" }, { status: 400 });
		}

		// Burn the challenge immediately — it must not be reusable regardless
		// of whether verification succeeds or fails.
		db.query("DELETE FROM challenges WHERE challenge = ?").run(
			challenge.challenge,
		);

		// Check if this is bootstrap (first user)
		const userCount = db.query("SELECT COUNT(*) as count FROM users").get() as {
			count: number;
		};

		const isBootstrap = userCount.count === 0;

		// If not bootstrap, validate invite code
		let inviteId: number | undefined;
		let inviteRoles: Array<{ app_id: number; role: string }> = [];
		if (!isBootstrap) {
			if (!inviteCode) {
				return Response.json(
					{ error: "Invite code required" },
					{ status: 403 },
				);
			}

			const invite = db
				.query(
					"SELECT id, max_uses, current_uses, expires_at, ldap_username FROM invites WHERE code = ?",
				)
				.get(inviteCode) as
				| {
						id: number;
						max_uses: number;
						current_uses: number;
						expires_at: number | null;
						ldap_username: string | null;
				  }
				| undefined;

			if (!invite) {
				return Response.json({ error: "Invalid invite code" }, { status: 403 });
			}

			const now = Math.floor(Date.now() / 1000);
			if (invite.expires_at && invite.expires_at < now) {
				return Response.json({ error: "Invite code expired" }, { status: 403 });
			}

			// If invite is locked to an LDAP username, enforce it
			if (invite.ldap_username && invite.ldap_username !== username) {
				return Response.json(
					{ error: "Username must match LDAP account" },
					{ status: 400 },
				);
			}

			inviteId = invite.id;

			// Get app role assignments for this invite
			inviteRoles = db
				.query("SELECT app_id, role FROM invite_roles WHERE invite_id = ?")
				.all(inviteId) as Array<{ app_id: number; role: string }>;
		}

		// Verify WebAuthn response
		let verification: VerifiedRegistrationResponse;
		try {
			verification = await verifyRegistrationResponse({
				response,
				expectedChallenge: challenge.challenge,
				expectedOrigin: process.env.ORIGIN || "",
				expectedRPID: process.env.RP_ID || "",
			});
		} catch (error) {
			console.error("WebAuthn verification failed:", error);
			return Response.json({ error: "Verification failed" }, { status: 400 });
		}

		if (!verification.verified || !verification.registrationInfo) {
			return Response.json({ error: "Verification failed" }, { status: 400 });
		}

		const { credential } = verification.registrationInfo;

		// Consume the invite and create user/credential/session in one
		// transaction. If the invite is exhausted the whole registration rolls
		// back — no orphaned accounts or sessions.
		const usedAt = Math.floor(Date.now() / 1000);
		let userId = 0;
		let userIsAdmin = false;

		try {
			db.transaction(() => {
				// Atomically consume the invite first — before any user rows exist.
				if (inviteId) {
					const result = db
						.query(
							"UPDATE invites SET current_uses = current_uses + 1 WHERE id = ? AND current_uses < max_uses",
						)
						.run(inviteId);

					if (result.changes === 0) {
						throw new InviteExhaustedError();
					}
				}

				// Check if this user is being provisioned via LDAP
				let isLdapProvisioned = false;
				if (inviteId) {
					const invite = db
						.query("SELECT ldap_username FROM invites WHERE id = ?")
						.get(inviteId) as { ldap_username: string | null } | undefined;
					isLdapProvisioned =
						invite?.ldap_username !== null &&
						invite?.ldap_username !== undefined;
				}

				if (isPasskeyReset && existingUser) {
					// Passkey reset: use existing user, just add credential
					userId = existingUser.id;
					userIsAdmin = existingUser.is_admin === 1;
				} else {
					// Create new user (bootstrap is always admin, invited users are regular users)
					const insertUser = db.query(
						"INSERT INTO users (username, name, is_admin, tier, role, provisioned_via_ldap) VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
					);
					const user = insertUser.get(
						username,
						username,
						isBootstrap ? 1 : 0,
						isBootstrap ? "admin" : "user",
						isBootstrap ? "admin" : "user",
						isLdapProvisioned ? 1 : 0,
					) as { id: number };
					userId = user.id;
					userIsAdmin = isBootstrap;
				}

				// Store credential
				// credential.id is a Uint8Array, convert to Buffer for storage
				db.query(
					"INSERT INTO credentials (user_id, credential_id, public_key, counter, name) VALUES (?, ?, ?, ?, ?)",
				).run(
					userId,
					Buffer.from(credential.id),
					Buffer.from(credential.publicKey),
					credential.counter,
					isPasskeyReset ? "Reset Passkey" : "Primary Passkey",
				);

				if (inviteId) {
					// Record this invite use
					db.query(
						"INSERT INTO invite_uses (invite_id, user_id, used_at) VALUES (?, ?, ?)",
					).run(inviteId, userId, usedAt);

					// Assign app roles to the new user (skip for passkey reset - they already have roles)
					if (inviteRoles.length > 0 && !isPasskeyReset) {
						const insertPermission = db.query(
							"INSERT INTO permissions (user_id, app_id, role) VALUES (?, ?, ?)",
						);
						for (const { app_id, role } of inviteRoles) {
							insertPermission.run(userId, app_id, role);
						}
					}
				}
			})();
		} catch (err) {
			if (err instanceof InviteExhaustedError) {
				return Response.json(
					{ error: "Invite code fully used" },
					{ status: 403 },
				);
			}
			throw err;
		}

		// Create session (outside the transaction — if this fails the account
		// still exists and the user can log in again)
		const token = crypto.randomUUID();
		const expiresAt = Math.floor(Date.now() / 1000) + 86400; // 24 hours
		db.query(
			"INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
		).run(token, userId, expiresAt);

		const isProduction = process.env.NODE_ENV === "production";
		const secureCookie = isProduction ? "; Secure" : "";

		return Response.json(
			{
				token,
				username,
				isAdmin: userIsAdmin,
			},
			{
				headers: [
					[
						"Set-Cookie",
						`indiko_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400${secureCookie}`,
					],
					["Set-Cookie", csrfCookieHeader(generateCsrfToken())],
				],
			},
		);
	} catch (error) {
		console.error("Registration verify error:", error);
		return Response.json({ error: "Internal server error" }, { status: 500 });
	}
}

export async function loginOptions(req: Request): Promise<Response> {
	try {
		const body = await req.json();
		const { username, conditional } = body as {
			username?: string;
			conditional?: boolean;
		};

		// Conditional UI flow: no username needed, browser shows all discoverable creds
		if (conditional) {
			const options: PublicKeyCredentialRequestOptionsJSON =
				await generateAuthenticationOptions({
					rpID: process.env.RP_ID || "",
					userVerification: "required",
				});

			const expiresAt = Math.floor(Date.now() / 1000) + 300;
			db.query(
				"INSERT INTO challenges (challenge, username, type, expires_at) VALUES (?, '', 'authentication', ?)",
			).run(options.challenge, expiresAt);

			return Response.json(options);
		}

		if (!username || typeof username !== "string") {
			return Response.json({ error: "Username required" }, { status: 400 });
		}

		// Check if user exists and is active
		const user = db
			.query(
				"SELECT id, status, provisioned_via_ldap, last_ldap_verified_at FROM users WHERE username = ?",
			)
			.get(username) as
			| {
					id: number;
					status: string;
					provisioned_via_ldap: number;
					last_ldap_verified_at: number | null;
			  }
			| undefined;

		if (!user) {
			return Response.json({ error: "Invalid credentials" }, { status: 401 });
		}

		if (user.status !== "active") {
			return Response.json({ error: "Invalid credentials" }, { status: 401 });
		}

		// Check if LDAP-provisioned user still exists in LDAP (with caching)
		if (user.provisioned_via_ldap === 1) {
			const checkInterval =
				Number.parseInt(process.env.LDAP_CHECK_INTERVAL || "86400", 10) * 1000;
			const now = Date.now();
			const shouldCheck =
				!user.last_ldap_verified_at ||
				now - user.last_ldap_verified_at > checkInterval;

			if (shouldCheck) {
				const ldapResult = await checkLdapUser(username);
				if (ldapResult === "not_found") {
					// User authoritatively no longer exists in LDAP — suspend
					db.query("UPDATE users SET status = 'suspended' WHERE id = ?").run(
						user.id,
					);
					return Response.json(
						{ error: "Invalid credentials" },
						{ status: 401 },
					);
				}
				if (ldapResult === "error") {
					// LDAP infrastructure error — don't suspend, but also don't
					// update the verification timestamp so we retry next login
					console.warn(
						`[auth] LDAP check failed for ${username}, skipping verification`,
					);
				} else {
					// User exists — update last verification timestamp
					db.query(
						"UPDATE users SET last_ldap_verified_at = ? WHERE id = ?",
					).run(Math.floor(now / 1000), user.id);
				}
			}
		}

		// Get user's credentials (just to verify they exist)
		const credentials = db
			.query("SELECT credential_id FROM credentials WHERE user_id = ?")
			.all(user.id) as { credential_id: Buffer }[];

		if (credentials.length === 0) {
			return Response.json({ error: "Invalid credentials" }, { status: 401 });
		}

		// Generate authentication options
		// Use discoverable credentials (no allowCredentials) for better UX
		const options: PublicKeyCredentialRequestOptionsJSON =
			await generateAuthenticationOptions({
				rpID: process.env.RP_ID || "",
				userVerification: "required",
			});

		// Store challenge
		const expiresAt = Math.floor(Date.now() / 1000) + 300; // 5 minutes
		db.query(
			"INSERT INTO challenges (challenge, username, type, expires_at) VALUES (?, ?, 'authentication', ?)",
		).run(options.challenge, username, expiresAt);

		// Local user always uses passkey login, no LDAP verification needed
		return Response.json({
			...options,
			ldapVerificationRequired: false,
		});
	} catch (error) {
		console.error("Login options error:", error);
		return Response.json({ error: "Internal server error" }, { status: 500 });
	}
}

export async function loginVerify(req: Request): Promise<Response> {
	try {
		const body = await req.json();
		const {
			username,
			response,
			conditional,
			challenge: clientChallenge,
		} = body as {
			username?: string;
			response: AuthenticationResponseJSON;
			conditional?: boolean;
			challenge?: string;
		};

		if (!response) {
			return Response.json({ error: "Response required" }, { status: 400 });
		}

		if (!conditional && !username) {
			return Response.json({ error: "Username required" }, { status: 400 });
		}

		if (!clientChallenge) {
			return Response.json({ error: "Challenge required" }, { status: 400 });
		}

		// Look up credential by ID to discover the username
		const credentialIdString = response.id;

		const credentialWithUser = db
			.query(
				"SELECT c.credential_id, c.public_key, c.counter, c.user_id, u.username, u.status FROM credentials c JOIN users u ON c.user_id = u.id WHERE c.credential_id = ?",
			)
			.get(Buffer.from(credentialIdString)) as
			| {
					credential_id: Buffer;
					public_key: Buffer;
					counter: number;
					user_id: number;
					username: string;
					status: string;
			  }
			| undefined;

		if (!credentialWithUser) {
			return Response.json({ error: "Invalid credentials" }, { status: 401 });
		}

		// Check if user account is active
		if (credentialWithUser.status !== "active") {
			return Response.json({ error: "Invalid credentials" }, { status: 401 });
		}

		// Verify the username matches (skip for conditional UI where browser picks the cred)
		if (!conditional && credentialWithUser.username !== username) {
			return Response.json({ error: "Invalid credentials" }, { status: 401 });
		}

		const credential = {
			credential_id: credentialWithUser.credential_id,
			public_key: credentialWithUser.public_key,
			counter: credentialWithUser.counter,
		};
		const user = { id: credentialWithUser.user_id };
		const resolvedUsername = credentialWithUser.username;

		// Verify challenge exists and is valid — look up by the challenge value
		// the client used (returned in the verify body), not "latest row wins".
		// This prevents cross-session challenge confusion and login DoS.
		const challengeUsername = conditional ? "" : resolvedUsername;
		const challenge = db
			.query(
				"SELECT challenge, expires_at FROM challenges WHERE challenge = ? AND username = ? AND type = 'authentication'",
			)
			.get(clientChallenge, challengeUsername) as
			| { challenge: string; expires_at: number }
			| undefined;

		if (!challenge) {
			return Response.json({ error: "Invalid challenge" }, { status: 400 });
		}

		const now = Math.floor(Date.now() / 1000);
		if (challenge.expires_at < now) {
			return Response.json({ error: "Challenge expired" }, { status: 400 });
		}

		// Burn the challenge immediately — it must not be reusable regardless
		// of whether verification succeeds or fails.
		db.query("DELETE FROM challenges WHERE challenge = ?").run(
			challenge.challenge,
		);

		// Verify authentication response
		let verification: VerifiedAuthenticationResponse;
		try {
			verification = await verifyAuthenticationResponse({
				response,
				expectedChallenge: challenge.challenge,
				expectedOrigin: process.env.ORIGIN || "",
				expectedRPID: process.env.RP_ID || "",
				credential: {
					id: credential.credential_id.toString(),
					publicKey: new Uint8Array(credential.public_key),
					counter: credential.counter,
				},
			});
		} catch (error) {
			console.error("WebAuthn verification failed:", error);
			return Response.json({ error: "Verification failed" }, { status: 400 });
		}

		if (!verification.verified) {
			return Response.json({ error: "Verification failed" }, { status: 400 });
		}

		// Reject cloned authenticators: counter must advance. Authenticators
		// that don't support counters always report 0; skip the check then.
		const newCounter = verification.authenticationInfo.newCounter;
		if (credential.counter > 0 && newCounter <= credential.counter) {
			console.warn(
				`[auth] counter regression for credential ${credential.credential_id.toString()} — possible cloned passkey (stored=${credential.counter}, got=${newCounter})`,
			);
			return Response.json({ error: "Verification failed" }, { status: 400 });
		}

		// Update credential counter
		db.query(
			"UPDATE credentials SET counter = ? WHERE user_id = ? AND credential_id = ?",
		).run(
			newCounter,
			user.id,
			credential.credential_id,
		);

		// Create session
		const token = crypto.randomUUID();
		const expiresAt = Math.floor(Date.now() / 1000) + 86400; // 24 hours
		db.query(
			"INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
		).run(token, user.id, expiresAt);

		const isProduction = process.env.NODE_ENV === "production";
		const secureCookie = isProduction ? "; Secure" : "";

		return Response.json(
			{
				token,
				username: resolvedUsername,
			},
			{
				headers: [
					[
						"Set-Cookie",
						`indiko_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400${secureCookie}`,
					],
					["Set-Cookie", csrfCookieHeader(generateCsrfToken())],
				],
			},
		);
	} catch (error) {
		console.error("Login verify error:", error);
		return Response.json({ error: "Internal server error" }, { status: 500 });
	}
}

export async function ldapVerify(req: Request): Promise<Response> {
	try {
		const body = await req.json();
		const { username, password, returnUrl } = body as {
			username: string;
			password: string;
			returnUrl?: string;
		};

		// Check if LDAP is configured
		if (!process.env.LDAP_ADMIN_DN || !process.env.LDAP_ADMIN_PASSWORD) {
			return Response.json(
				{ error: "LDAP is not configured" },
				{ status: 400 },
			);
		}

		if (
			!username ||
			username.length > 128 ||
			!/^[A-Za-z0-9._@-]+$/.test(username)
		) {
			return Response.json(
				{ error: "Invalid username format" },
				{ status: 400 },
			);
		}

		// Verify user doesn't already exist locally (race condition check)
		const existingUser = db
			.query("SELECT id FROM users WHERE username = ?")
			.get(username);

		if (existingUser) {
			return Response.json(
				{ error: "Account already exists. Please use passkey login." },
				{ status: 400 },
			);
		}

		// Attempt LDAP bind WITH password verification
		let ldapUser: unknown;
		let userDn: string | null = null;
		try {
			ldapUser = await authenticate({
				ldapOpts: {
					url: process.env.LDAP_URL || "ldap://localhost:389",
				},
				adminDn: process.env.LDAP_ADMIN_DN || "",
				adminPassword: process.env.LDAP_ADMIN_PASSWORD || "",
				userSearchBase:
					process.env.LDAP_USER_SEARCH_BASE || "dc=example,dc=com",
				usernameAttribute: process.env.LDAP_USERNAME_ATTRIBUTE || "uid",
				username: username,
				userPassword: password,
			});

			// Extract userDn from the returned user object
			if (ldapUser && typeof ldapUser === "object" && "dn" in ldapUser) {
				userDn = (ldapUser as { dn: string }).dn;
			}
		} catch (_ldapError) {
			return Response.json({ error: "Invalid credentials" }, { status: 401 });
		}

		if (!ldapUser) {
			return Response.json({ error: "Invalid credentials" }, { status: 401 });
		}

		// Check group membership if configured.
		// Return the same error as invalid credentials to avoid leaking
		// whether the username exists in LDAP.
		if (userDn) {
			const isInGroup = await checkLdapGroupMembership(username, userDn);
			if (!isInGroup) {
				return Response.json({ error: "Invalid credentials" }, { status: 401 });
			}
		}

		// LDAP auth succeeded - create single-use invite locked to this username
		const inviteCode = crypto.randomUUID();
		const expiresAt = Math.floor(Date.now() / 1000) + 600; // 10 minutes

		// Get an admin user to be the creator (required by NOT NULL constraint)
		const adminUser = db
			.query("SELECT id FROM users WHERE is_admin = 1 LIMIT 1")
			.get() as { id: number } | undefined;

		if (!adminUser) {
			return Response.json(
				{ error: "System not configured for LDAP provisioning" },
				{ status: 500 },
			);
		}

		// Create the LDAP invite (max_uses=1, tied to username)
		db.query(
			"INSERT INTO invites (code, max_uses, current_uses, expires_at, created_by, message, ldap_username) VALUES (?, 1, 0, ?, ?, ?, ?)",
		).run(
			inviteCode,
			expiresAt,
			adminUser.id,
			"LDAP-verified account",
			username,
		);

		const newInviteId = db
			.query("SELECT id FROM invites WHERE code = ?")
			.get(inviteCode) as { id: number };

		// Copy roles from most recent admin-created invite if exists
		const defaultInvite = db
			.query(
				"SELECT id FROM invites WHERE created_by IN (SELECT id FROM users WHERE is_admin = 1) ORDER BY created_at DESC LIMIT 1",
			)
			.get() as { id: number } | undefined;

		if (defaultInvite) {
			const inviteRoles = db
				.query("SELECT app_id, role FROM invite_roles WHERE invite_id = ?")
				.all(defaultInvite.id) as Array<{ app_id: number; role: string }>;

			const insertRole = db.query(
				"INSERT INTO invite_roles (invite_id, app_id, role) VALUES (?, ?, ?)",
			);
			for (const { app_id, role } of inviteRoles) {
				insertRole.run(newInviteId.id, app_id, role);
			}
		}

		return Response.json({
			success: true,
			inviteCode: inviteCode,
			username: username,
			returnUrl: returnUrl || null,
		});
	} catch (error) {
		console.error("LDAP verify error:", error);
		return Response.json({ error: "Internal server error" }, { status: 500 });
	}
}
