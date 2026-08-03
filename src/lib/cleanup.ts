import { db } from "../db";

// sweepExpiredRecords purges rows whose lifetime is genuinely over.
//
// Tokens are keyed off refresh_expires_at, not expires_at: expires_at is the
// access-token lifetime (one hour), but the row also carries the 30-day
// refresh token. Deleting it on access expiry kills the session for any client
// that goes quiet for more than an hour, and erases rotated rows that RFC
// 9700 reuse detection still needs. A row is garbage only when its refresh
// token has lapsed (or, for rows without one, its access token), or when it
// was revoked.
export function sweepExpiredRecords(now: number): {
	sessions: number;
	challenges: number;
	authcodes: number;
	tokens: number;
	deviceCodes: number;
} {
	const sessions = db
		.query("DELETE FROM sessions WHERE expires_at < ?")
		.run(now).changes;
	const challenges = db
		.query("DELETE FROM challenges WHERE expires_at < ?")
		.run(now).changes;
	const authcodes = db
		.query("DELETE FROM authcodes WHERE expires_at < ?")
		.run(now).changes;
	const tokens = db
		.query(
			`DELETE FROM tokens WHERE revoked = 1
				OR (refresh_expires_at IS NOT NULL AND refresh_expires_at < ?)
				OR (refresh_expires_at IS NULL AND expires_at < ?)`,
		)
		.run(now, now).changes;
	const deviceCodes = db
		.query("DELETE FROM device_codes WHERE expires_at < ?")
		.run(now).changes;

	return {
		sessions: Number(sessions),
		challenges: Number(challenges),
		authcodes: Number(authcodes),
		tokens: Number(tokens),
		deviceCodes: Number(deviceCodes),
	};
}
