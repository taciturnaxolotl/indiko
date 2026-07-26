// Point the app's db module at a throwaway database before importing it.
process.env.DATABASE_URL = ":memory:";

const { db } = await import("../../src/db");

export { db };

let userSeq = 0;

export function createUser(overrides: {
	username?: string;
	tier?: string;
	status?: string;
	isAdmin?: number;
}): number {
	userSeq += 1;
	const username = overrides.username ?? `user${userSeq}`;
	const tier = overrides.tier ?? "user";
	const status = overrides.status ?? "active";
	const isAdmin = overrides.isAdmin ?? (tier === "admin" ? 1 : 0);

	const result = db
		.query(
			"INSERT INTO users (username, name, tier, status, is_admin) VALUES (?, ?, ?, ?, ?)",
		)
		.run(username, `User ${userSeq}`, tier, status, isAdmin);

	return Number(result.lastInsertRowid);
}

export function createSession(
	userId: number,
	overrides: { token?: string; expiresAt?: number } = {},
): string {
	const token = overrides.token ?? `test-token-${crypto.randomUUID()}`;
	const expiresAt = overrides.expiresAt ?? Math.floor(Date.now() / 1000) + 3600;

	db.query(
		"INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
	).run(token, userId, expiresAt);

	return token;
}

export function bearerReq(token: string | null): Request {
	const headers = new Headers();
	if (token) headers.set("Authorization", `Bearer ${token}`);
	return new Request("http://localhost/api/test", { headers });
}

export function cookieReq(token: string | null): Request {
	const headers = new Headers();
	if (token) headers.set("Cookie", `indiko_session=${token}`);
	return new Request("http://localhost/", { headers });
}
