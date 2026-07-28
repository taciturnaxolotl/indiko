import {
	generateRegistrationOptions,
	type RegistrationResponseJSON,
	type VerifiedRegistrationResponse,
	verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { db } from "../db";
import { getSessionUserFlexible } from "../lib/session";

const RP_NAME = "Indiko";

// Get all passkeys for current user
export function listPasskeys(req: Request): Response {
	const user = getSessionUserFlexible(req);
	if (user instanceof Response) return user;

	const passkeys = db
		.query(
			"SELECT id, name, created_at FROM credentials WHERE user_id = ? ORDER BY created_at DESC",
		)
		.all(user.userId) as Array<{
		id: number;
		name: string;
		created_at: number;
	}>;

	return Response.json({ passkeys });
}

// Generate options for adding a new passkey
export async function addPasskeyOptions(req: Request): Promise<Response> {
	const user = getSessionUserFlexible(req);
	if (user instanceof Response) return user;

	// Get existing credentials to exclude them
	const existingCredentials = db
		.query("SELECT credential_id FROM credentials WHERE user_id = ?")
		.all(user.userId) as Array<{ credential_id: Buffer }>;

	const excludeCredentials = existingCredentials.map((cred) => ({
		id: Buffer.from(cred.credential_id).toString("base64url"),
		type: "public-key" as const,
	}));

	// Generate WebAuthn registration options
	const options = await generateRegistrationOptions({
		rpName: RP_NAME,
		rpID: process.env.RP_ID ?? "",
		userName: user.username,
		userDisplayName: user.username,
		attestationType: "none",
		excludeCredentials,
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
	).run(options.challenge, user.username, expiresAt);

	return Response.json(options);
}

// Verify and add new passkey
export async function addPasskeyVerify(req: Request): Promise<Response> {
	try {
		const user = getSessionUserFlexible(req);
		if (user instanceof Response) return user;

		const body = await req.json();
		const {
			response,
			challenge: expectedChallenge,
			name,
		} = body as {
			response: RegistrationResponseJSON;
			challenge: string;
			name?: string;
		};

		if (!response) {
			return Response.json({ error: "Response required" }, { status: 400 });
		}

		// Verify challenge exists and is valid
		const challenge = db
			.query(
				"SELECT challenge, expires_at FROM challenges WHERE challenge = ? AND username = ? AND type = 'registration'",
			)
			.get(expectedChallenge, user.username) as
			| { challenge: string; expires_at: number }
			| undefined;

		if (!challenge) {
			return Response.json({ error: "Invalid challenge" }, { status: 400 });
		}

		const now = Math.floor(Date.now() / 1000);
		if (challenge.expires_at < now) {
			return Response.json({ error: "Challenge expired" }, { status: 400 });
		}

		// Burn the challenge immediately — single use regardless of outcome
		db.query("DELETE FROM challenges WHERE challenge = ?").run(
			challenge.challenge,
		);

		// Verify WebAuthn response
		let verification: VerifiedRegistrationResponse;
		try {
			verification = await verifyRegistrationResponse({
				response,
				expectedChallenge: challenge.challenge,
				expectedOrigin: process.env.ORIGIN ?? "",
				expectedRPID: process.env.RP_ID ?? "",
			});
		} catch (error) {
			console.error("WebAuthn verification failed:", error);
			return Response.json({ error: "Verification failed" }, { status: 400 });
		}

		if (!verification.verified || !verification.registrationInfo) {
			return Response.json({ error: "Verification failed" }, { status: 400 });
		}

		const { credential } = verification.registrationInfo;

		// Generate default name if not provided
		const passkeyCount = db
			.query("SELECT COUNT(*) as count FROM credentials WHERE user_id = ?")
			.get(user.userId) as { count: number };

		const passkeyName = name || `Passkey ${passkeyCount.count + 1}`;

		// Store credential
		const result = db
			.query(
				"INSERT INTO credentials (user_id, credential_id, public_key, counter, name) VALUES (?, ?, ?, ?, ?) RETURNING id",
			)
			.get(
				user.userId,
				Buffer.from(credential.id),
				Buffer.from(credential.publicKey),
				credential.counter,
				passkeyName,
			) as { id: number };

		return Response.json({
			success: true,
			passkey: {
				id: result.id,
				name: passkeyName,
				created_at: Math.floor(Date.now() / 1000),
			},
		});
	} catch (error) {
		console.error("Add passkey verify error:", error);
		return Response.json({ error: "Internal server error" }, { status: 500 });
	}
}

// Delete a passkey
export function deletePasskey(req: Request): Response {
	const user = getSessionUserFlexible(req);
	if (user instanceof Response) return user;

	const url = new URL(req.url);
	const passkeyId = url.pathname.split("/").pop();

	if (!passkeyId) {
		return Response.json({ error: "Passkey ID required" }, { status: 400 });
	}

	// Check if this is the user's passkey
	const passkey = db
		.query("SELECT user_id FROM credentials WHERE id = ?")
		.get(Number(passkeyId)) as { user_id: number } | undefined;

	if (!passkey || passkey.user_id !== user.userId) {
		return Response.json({ error: "Passkey not found" }, { status: 404 });
	}

	// Check if this is the last passkey
	const passkeyCount = db
		.query("SELECT COUNT(*) as count FROM credentials WHERE user_id = ?")
		.get(user.userId) as { count: number };

	if (passkeyCount.count <= 1) {
		return Response.json(
			{ error: "Cannot delete last passkey" },
			{ status: 400 },
		);
	}

	// Delete the passkey
	db.query("DELETE FROM credentials WHERE id = ?").run(Number(passkeyId));

	return Response.json({ success: true });
}

// Rename a passkey
export async function renamePasskey(req: Request): Promise<Response> {
	const user = getSessionUserFlexible(req);
	if (user instanceof Response) return user;

	const url = new URL(req.url);
	const passkeyId = url.pathname.split("/").pop();

	if (!passkeyId) {
		return Response.json({ error: "Passkey ID required" }, { status: 400 });
	}

	const body = await req.json();
	const { name } = body as { name?: string };

	if (!name || typeof name !== "string" || name.trim().length === 0) {
		return Response.json({ error: "Name required" }, { status: 400 });
	}

	// Check if this is the user's passkey
	const passkey = db
		.query("SELECT user_id FROM credentials WHERE id = ?")
		.get(Number(passkeyId)) as { user_id: number } | undefined;

	if (!passkey || passkey.user_id !== user.userId) {
		return Response.json({ error: "Passkey not found" }, { status: 404 });
	}

	// Update the name
	db.query("UPDATE credentials SET name = ? WHERE id = ?").run(
		name.trim(),
		Number(passkeyId),
	);

	return Response.json({ success: true, name: name.trim() });
}
