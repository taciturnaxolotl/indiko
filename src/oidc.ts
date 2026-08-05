import { exportJWK, generateKeyPair, importPKCS8, SignJWT } from "jose";
import { db } from "./db";

interface OIDCKey {
	id: number;
	kid: string;
	private_key: string;
	public_key: string;
	is_active: number;
	created_at: number;
}

interface JWK {
	kty: string;
	use: string;
	alg: string;
	kid: string;
	n: string;
	e: string;
}

async function generateAndStoreKey(): Promise<OIDCKey> {
	const { privateKey, publicKey } = await generateKeyPair("RS256", {
		modulusLength: 2048,
		extractable: true,
	});

	const privateKeyPem = await exportKeyToPem(privateKey);
	const publicKeyPem = await exportKeyToPem(publicKey);

	const kid = `indiko-oidc-key-${crypto.randomUUID()}`;

	db.query(
		"INSERT INTO oidc_keys (kid, private_key, public_key, is_active) VALUES (?, ?, ?, 1)",
	).run(kid, privateKeyPem, publicKeyPem);

	const key = db
		.query("SELECT * FROM oidc_keys WHERE kid = ?")
		.get(kid) as OIDCKey;

	return key;
}

async function exportKeyToPem(key: CryptoKey): Promise<string> {
	const format = key.type === "private" ? "pkcs8" : "spki";
	const exported = await crypto.subtle.exportKey(format, key);
	const base64 = Buffer.from(exported).toString("base64");
	const type = key.type === "private" ? "PRIVATE KEY" : "PUBLIC KEY";

	const lines = base64.match(/.{1,64}/g) || [];
	return `-----BEGIN ${type}-----\n${lines.join("\n")}\n-----END ${type}-----`;
}

export async function getActiveKey(): Promise<OIDCKey> {
	let key = db
		.query(
			"SELECT * FROM oidc_keys WHERE is_active = 1 ORDER BY id DESC LIMIT 1",
		)
		.get() as OIDCKey | undefined;

	if (!key) {
		key = await generateAndStoreKey();
	}

	return key;
}

export async function getJWKS(): Promise<{ keys: JWK[] }> {
	const keys = db
		.query("SELECT * FROM oidc_keys WHERE is_active = 1")
		.all() as OIDCKey[];

	const jwks: JWK[] = [];

	for (const key of keys) {
		const publicKey = await importPublicKey(key.public_key);
		const jwk = await exportJWK(publicKey);

		jwks.push({
			kty: jwk.kty as string,
			use: "sig",
			alg: "RS256",
			kid: key.kid,
			n: jwk.n as string,
			e: jwk.e as string,
		});
	}

	return { keys: jwks };
}

async function importPublicKey(pem: string): Promise<CryptoKey> {
	const pemContents = pem
		.replace("-----BEGIN PUBLIC KEY-----", "")
		.replace("-----END PUBLIC KEY-----", "")
		.replace(/\n/g, "");

	const binaryDer = Buffer.from(pemContents, "base64");

	return await crypto.subtle.importKey(
		"spki",
		binaryDer,
		{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
		true,
		["verify"],
	);
}

interface IDTokenClaims {
	sub: string;
	aud: string;
	nonce?: string;
	auth_time?: number;
	at_hash?: string;
	name?: string;
	email?: string;
	picture?: string;
	website?: string;
}

// OIDC Core §3.1.3.6: at_hash is the base64url of the left half of the
// SHA-256 hash of the access token.
async function computeAtHash(accessToken: string): Promise<string> {
	const hash = await crypto.subtle.digest(
		"SHA-256",
		new TextEncoder().encode(accessToken),
	);
	const half = new Uint8Array(hash).slice(0, 16);
	return Buffer.from(half).toString("base64url");
}

export async function signIDToken(
	issuer: string,
	claims: IDTokenClaims,
	accessToken?: string,
): Promise<string> {
	const key = await getActiveKey();
	const privateKey = await importPKCS8(key.private_key, "RS256");

	const now = Math.floor(Date.now() / 1000);
	const expiresIn = 3600; // 1 hour

	const allClaims = { ...claims };
	if (accessToken) {
		allClaims.at_hash = await computeAtHash(accessToken);
	}

	const builder = new SignJWT({
		...allClaims,
		iss: issuer,
		iat: now,
		exp: now + expiresIn,
	}).setProtectedHeader({ alg: "RS256", typ: "JWT", kid: key.kid });

	return await builder.sign(privateKey);
}

export function getDiscoveryDocument(origin: string) {
	return {
		issuer: origin,
		authorization_endpoint: `${origin}/auth/authorize`,
		token_endpoint: `${origin}/auth/token`,
		revocation_endpoint: `${origin}/auth/token/revoke`,
		userinfo_endpoint: `${origin}/userinfo`,
		jwks_uri: `${origin}/jwks`,
		scopes_supported: ["openid", "profile", "email", "offline_access"],
		response_types_supported: ["code"],
		grant_types_supported: [
			"authorization_code",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code",
		],
		subject_types_supported: ["public"],
		id_token_signing_alg_values_supported: ["RS256"],
		token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
		claims_supported: [
			"sub",
			"iss",
			"aud",
			"exp",
			"iat",
			"auth_time",
			"nonce",
			"name",
			"email",
			"picture",
			"website",
		],
		code_challenge_methods_supported: ["S256"],
		authorization_response_iss_parameter_supported: true,
	};
}
