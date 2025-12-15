import { db } from "../db";
import {
	generateRegistrationOptions,
	verifyRegistrationResponse,
	generateAuthenticationOptions,
	verifyAuthenticationResponse,
	type VerifiedRegistrationResponse,
	type VerifiedAuthenticationResponse,
	type PublicKeyCredentialCreationOptionsJSON,
	type RegistrationResponseJSON,
	type PublicKeyCredentialRequestOptionsJSON,
	type AuthenticationResponseJSON,
} from "@simplewebauthn/server";

const RP_NAME = "Indiko";

export function canRegister(req: Request): Response {
	const userCount = db
		.query("SELECT COUNT(*) as count FROM users")
		.get() as { count: number };

	return Response.json({
		canRegister: userCount.count === 0,
		bootstrapMode: userCount.count === 0,
	});
}

export async function registerOptions(req: Request): Promise<Response> {
	try {
		const body = await req.json();
		const { username } = body;

		if (!username || typeof username !== "string") {
			return Response.json({ error: "Username required" }, { status: 400 });
		}

		// Check if username already exists
		const existingUser = db
			.query("SELECT id FROM users WHERE username = ?")
			.get(username);

		if (existingUser) {
			return Response.json(
				{ error: "Username already taken" },
				{ status: 400 },
			);
		}

		// Check if this is bootstrap (first user)
		const userCount = db
			.query("SELECT COUNT(*) as count FROM users")
			.get() as { count: number };

		const isBootstrap = userCount.count === 0;

		if (!isBootstrap) {
			return Response.json({ error: "Registration closed" }, { status: 403 });
		}

		// Generate WebAuthn registration options
		const options: PublicKeyCredentialCreationOptionsJSON =
			await generateRegistrationOptions({
				rpName: RP_NAME,
				rpID: process.env.RP_ID!,
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

		return Response.json(options);
	} catch (error) {
		console.error("Registration options error:", error);
		return Response.json({ error: "Internal server error" }, { status: 500 });
	}
}

export async function registerVerify(req: Request): Promise<Response> {
	try {
		const body = await req.json();
		const { username, response, challenge: expectedChallenge } = body as {
			username: string;
			response: RegistrationResponseJSON;
			challenge?: string;
		};

		if (!username || !response) {
			return Response.json(
				{ error: "Username and response required" },
				{ status: 400 },
			);
		}

		// Check if username already exists
		const existingUser = db
			.query("SELECT id FROM users WHERE username = ?")
			.get(username);

		if (existingUser) {
			return Response.json(
				{ error: "Username already taken" },
				{ status: 400 },
			);
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

		// Check if this is bootstrap (first user)
		const userCount = db
			.query("SELECT COUNT(*) as count FROM users")
			.get() as { count: number };

		const isBootstrap = userCount.count === 0;

		if (!isBootstrap) {
			return Response.json({ error: "Registration closed" }, { status: 403 });
		}

		// Verify WebAuthn response
		let verification: VerifiedRegistrationResponse;
		try {
			verification = await verifyRegistrationResponse({
				response,
				expectedChallenge: challenge.challenge,
				expectedOrigin: process.env.ORIGIN!,
				expectedRPID: process.env.RP_ID!,
			});
		} catch (error) {
			console.error("WebAuthn verification failed:", error);
			return Response.json(
				{ error: "Verification failed" },
				{ status: 400 },
			);
		}

		if (!verification.verified || !verification.registrationInfo) {
			return Response.json(
				{ error: "Verification failed" },
				{ status: 400 },
			);
		}

		const { credential } = verification.registrationInfo;

		// Create user (bootstrap is always admin)
		const insertUser = db.query(
			"INSERT INTO users (username, name, is_admin, role) VALUES (?, ?, 1, 'admin') RETURNING id",
		);
		const user = insertUser.get(username, username) as {
			id: number;
		};

		// Store credential
		// credential.id is a Uint8Array, convert to Buffer for storage
		db.query(
			"INSERT INTO credentials (user_id, credential_id, public_key, counter) VALUES (?, ?, ?, ?)",
		).run(
			user.id,
			Buffer.from(credential.id),
			Buffer.from(credential.publicKey),
			credential.counter,
		);

		// Delete challenge
		db.query("DELETE FROM challenges WHERE challenge = ?").run(
			challenge.challenge,
		);

		// Create session
		const token = crypto.randomUUID();
		const expiresAt = Math.floor(Date.now() / 1000) + 86400; // 24 hours
		db.query(
			"INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
		).run(token, user.id, expiresAt);

		return Response.json({
			token,
			username,
			isAdmin: true,
		});
	} catch (error) {
		console.error("Registration verify error:", error);
		return Response.json({ error: "Internal server error" }, { status: 500 });
	}
}

export async function loginOptions(req: Request): Promise<Response> {
	try {
		const body = await req.json();
		const { username } = body;

		if (!username || typeof username !== "string") {
			return Response.json({ error: "Username required" }, { status: 400 });
		}

		// Check if user exists
		const user = db
			.query("SELECT id FROM users WHERE username = ?")
			.get(username) as { id: number } | undefined;

		if (!user) {
			return Response.json({ error: "User not found" }, { status: 404 });
		}

		// Get user's credentials (just to verify they exist)
		const credentials = db
			.query("SELECT credential_id FROM credentials WHERE user_id = ?")
			.all(user.id) as { credential_id: Buffer }[];

		if (credentials.length === 0) {
			return Response.json(
				{ error: "No credentials found" },
				{ status: 404 },
			);
		}

		// Generate authentication options
		// For discoverable credentials, omit allowCredentials to let password managers
		// show all available passkeys for this RP ID
		const options: PublicKeyCredentialRequestOptionsJSON =
			await generateAuthenticationOptions({
				rpID: process.env.RP_ID!,
				userVerification: "required",
			});

		// Store challenge
		const expiresAt = Math.floor(Date.now() / 1000) + 300; // 5 minutes
		db.query(
			"INSERT INTO challenges (challenge, username, type, expires_at) VALUES (?, ?, 'authentication', ?)",
		).run(options.challenge, username, expiresAt);

		return Response.json(options);
	} catch (error) {
		console.error("Login options error:", error);
		return Response.json({ error: "Internal server error" }, { status: 500 });
	}
}

export async function loginVerify(req: Request): Promise<Response> {
	try {
		const body = await req.json();
		const { username, response } = body as {
			username: string;
			response: AuthenticationResponseJSON;
		};

		if (!username || !response) {
			return Response.json(
				{ error: "Username and response required" },
				{ status: 400 },
			);
		}

		// Look up credential by ID
		// Current database has credential_id stored as Buffer containing ASCII text of base64url string
		// So we need to compare the string value, not decode it
		const credentialIdString = response.id; // This is the base64url string like "rHvdOyMkR-6nxGBcDmtV4g"
		
		const credentialWithUser = db
			.query(
				"SELECT c.credential_id, c.public_key, c.counter, c.user_id, u.username FROM credentials c JOIN users u ON c.user_id = u.id WHERE c.credential_id = ?",
			)
			.get(Buffer.from(credentialIdString)) as
			| { credential_id: Buffer; public_key: Buffer; counter: number; user_id: number; username: string }
			| undefined;

		if (!credentialWithUser) {
			return Response.json(
				{ error: "Credential not found" },
				{ status: 404 },
			);
		}

		// Verify the username matches (if provided)
		if (username && credentialWithUser.username !== username) {
			return Response.json(
				{ error: "Credential does not belong to this user" },
				{ status: 403 },
			);
		}

		const credential = {
			credential_id: credentialWithUser.credential_id,
			public_key: credentialWithUser.public_key,
			counter: credentialWithUser.counter,
		};
		const user = { id: credentialWithUser.user_id };

		// Verify challenge exists and is valid
		// Use the discovered username from the credential
		const challenge = db
			.query(
				"SELECT challenge, expires_at FROM challenges WHERE username = ? AND type = 'authentication' ORDER BY created_at DESC LIMIT 1",
			)
			.get(credentialWithUser.username) as
			| { challenge: string; expires_at: number }
			| undefined;

		if (!challenge) {
			return Response.json({ error: "Invalid challenge" }, { status: 400 });
		}

		const now = Math.floor(Date.now() / 1000);
		if (challenge.expires_at < now) {
			return Response.json({ error: "Challenge expired" }, { status: 400 });
		}

		// Verify authentication response
		let verification: VerifiedAuthenticationResponse;
		try {
			verification = await verifyAuthenticationResponse({
				response,
				expectedChallenge: challenge.challenge,
				expectedOrigin: process.env.ORIGIN!,
				expectedRPID: process.env.RP_ID!,
				credential: {
					id: credential.credential_id,
					publicKey: credential.public_key,
					counter: credential.counter,
				},
			});
		} catch (error) {
			console.error("WebAuthn verification failed:", error);
			return Response.json(
				{ error: "Verification failed" },
				{ status: 400 },
			);
		}

		if (!verification.verified) {
			return Response.json(
				{ error: "Verification failed" },
				{ status: 400 },
			);
		}

		// Update credential counter
		db.query("UPDATE credentials SET counter = ? WHERE user_id = ? AND credential_id = ?").run(
			verification.authenticationInfo.newCounter,
			user.id,
			credential.credential_id,
		);

		// Delete challenge
		db.query("DELETE FROM challenges WHERE challenge = ?").run(
			challenge.challenge,
		);

		// Create session
		const token = crypto.randomUUID();
		const expiresAt = Math.floor(Date.now() / 1000) + 86400; // 24 hours
		db.query(
			"INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
		).run(token, user.id, expiresAt);

		return Response.json({
			token,
			username,
		});
	} catch (error) {
		console.error("Login verify error:", error);
		return Response.json({ error: "Internal server error" }, { status: 500 });
	}
}
