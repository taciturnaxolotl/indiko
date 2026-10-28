import crypto from "node:crypto";
import { db } from "../../db";
import { getSessionUserFlexible, validateCsrf } from "../../lib/session";

function requireAdmin(req: Request): { userId: number } | Response {
	const user = getSessionUserFlexible(req);
	if (user instanceof Response) {
		return user;
	}

	if (!user.isAdmin) {
		return Response.json({ error: "Admin access required" }, { status: 403 });
	}

	return user;
}

function parseInviteId(req: Request): string | null {
	const url = new URL(req.url);
	const parts = url.pathname.split("/");
	const inviteId = parts[parts.length - 1];

	if (!inviteId || Number.isNaN(Number(inviteId))) {
		return null;
	}
	return inviteId;
}

// Input caps for the free-text fields on an invite.
const MAX_NOTE_LENGTH = 1024;
const MAX_MESSAGE_LENGTH = 4096;
const MAX_USES_LIMIT = 1_000_000;

type Check<T> = { ok: true; value: T } | { ok: false; error: string };

/** Positive integer. */
function checkMaxUses(value: unknown): Check<number> {
	if (
		typeof value !== "number" ||
		!Number.isInteger(value) ||
		value < 1 ||
		value > MAX_USES_LIMIT
	) {
		return { ok: false, error: "maxUses must be a positive integer" };
	}
	return { ok: true, value };
}

/** Unix timestamp in seconds (the form the admin UI sends), or null for "never". */
function checkExpiresAt(value: unknown): Check<number | null> {
	if (value === null) return { ok: true, value: null };
	if (
		typeof value !== "number" ||
		!Number.isInteger(value) ||
		value < 0 ||
		value > 4_102_444_800 // year 2100 — catches millisecond timestamps
	) {
		return {
			ok: false,
			error: "expiresAt must be a Unix timestamp in seconds or null",
		};
	}
	return { ok: true, value };
}

/** Optional bounded string; null/"" clear it. */
function checkText(
	value: unknown,
	label: string,
	max: number,
): Check<string | null> {
	if (value === null || value === "") return { ok: true, value: null };
	if (typeof value !== "string") {
		return { ok: false, error: `${label} must be a string` };
	}
	if (value.length > max) {
		return { ok: false, error: `${label} must be at most ${max} characters` };
	}
	return { ok: true, value };
}

async function readJsonObject(
	req: Request,
): Promise<Record<string, unknown> | Response> {
	let body: unknown;
	try {
		body = await req.json();
	} catch {
		return Response.json({ error: "Body must be JSON" }, { status: 400 });
	}
	if (!body || typeof body !== "object" || Array.isArray(body)) {
		return Response.json(
			{ error: "Body must be a JSON object" },
			{ status: 400 },
		);
	}
	return body as Record<string, unknown>;
}

// POST /api/invites/create - Create invite link (admin only)
export async function createInvite(req: Request): Promise<Response> {
	const user = requireAdmin(req);
	if (user instanceof Response) {
		return user;
	}

	const csrfError = validateCsrf(req);
	if (csrfError) return csrfError;

	const body = await readJsonObject(req);
	if (body instanceof Response) return body;

	const maxUsesCheck = checkMaxUses(
		body.maxUses === undefined ? 1 : body.maxUses,
	);
	if (!maxUsesCheck.ok) {
		return Response.json({ error: maxUsesCheck.error }, { status: 400 });
	}
	const expiresAtCheck = checkExpiresAt(
		body.expiresAt === undefined ? null : body.expiresAt,
	);
	if (!expiresAtCheck.ok) {
		return Response.json({ error: expiresAtCheck.error }, { status: 400 });
	}
	const noteCheck = checkText(body.note ?? null, "note", MAX_NOTE_LENGTH);
	if (!noteCheck.ok) {
		return Response.json({ error: noteCheck.error }, { status: 400 });
	}
	const messageCheck = checkText(
		body.message ?? null,
		"message",
		MAX_MESSAGE_LENGTH,
	);
	if (!messageCheck.ok) {
		return Response.json({ error: messageCheck.error }, { status: 400 });
	}

	// Validate appRoles up front so a bad entry can't leave an orphan invite
	// behind after the first INSERT.
	const appRoles: Array<{ appId: number; role: string }> = [];
	if (body.appRoles !== undefined && body.appRoles !== null) {
		if (!Array.isArray(body.appRoles)) {
			return Response.json(
				{ error: "appRoles must be an array" },
				{ status: 400 },
			);
		}
		for (const entry of body.appRoles as unknown[]) {
			if (
				!entry ||
				typeof entry !== "object" ||
				typeof (entry as { appId?: unknown }).appId !== "number" ||
				!Number.isInteger((entry as { appId: number }).appId) ||
				typeof (entry as { role?: unknown }).role !== "string" ||
				!(entry as { role: string }).role.trim() ||
				(entry as { role: string }).role.length > 256
			) {
				return Response.json(
					{
						error: "appRoles entries must be { appId: integer, role: string }",
					},
					{ status: 400 },
				);
			}
			const { appId, role } = entry as { appId: number; role: string };
			const app = db.query("SELECT id FROM apps WHERE id = ?").get(appId);
			if (!app) {
				return Response.json(
					{ error: `Unknown appId: ${appId}` },
					{ status: 400 },
				);
			}
			appRoles.push({ appId, role });
		}
	}

	const inviteCode = crypto.randomBytes(16).toString("base64url");
	const maxUses = maxUsesCheck.value;
	const expiresAt = expiresAtCheck.value;
	const note = noteCheck.value;
	const message = messageCheck.value;

	const insertInvite = db.query(
		"INSERT INTO invites (code, created_by, max_uses, expires_at, note, message) VALUES (?, ?, ?, ?, ?, ?)",
	);
	const insertRole = db.prepare(
		"INSERT INTO invite_roles (invite_id, app_id, role) VALUES (?, ?, ?)",
	);

	const create = db.transaction(() => {
		const result = insertInvite.run(
			inviteCode,
			user.userId,
			maxUses,
			expiresAt,
			note,
			message,
		);
		const inviteId = Number(result.lastInsertRowid);
		for (const appRole of appRoles) {
			insertRole.run(inviteId, appRole.appId, appRole.role);
		}
	});
	create();

	return Response.json({
		inviteCode,
		inviteUrl: `${process.env.ORIGIN}/login?invite=${inviteCode}`,
	});
}

// GET /api/invites - List all invites (admin only)
export function listInvites(req: Request): Response {
	const user = requireAdmin(req);
	if (user instanceof Response) {
		return user;
	}

	const invites = db
		.query(`
		SELECT i.id, i.code, i.max_uses, i.current_uses, i.expires_at, i.note, i.message, i.created_at,
			creator.username as created_by_username
		FROM invites i
		LEFT JOIN users creator ON i.created_by = creator.id
		ORDER BY i.created_at DESC
	`)
		.all() as Array<{
		id: number;
		code: string;
		max_uses: number;
		current_uses: number;
		expires_at: number | null;
		note: string | null;
		message: string | null;
		created_at: number;
		created_by_username: string;
	}>;

	const inviteRoles = db
		.query(`
		SELECT ir.invite_id, ir.app_id, ir.role, a.client_id, a.name
		FROM invite_roles ir
		JOIN apps a ON ir.app_id = a.id
	`)
		.all() as Array<{
		invite_id: number;
		app_id: number;
		role: string;
		client_id: string;
		name: string | null;
	}>;

	const inviteUses = db
		.query(`
		SELECT iu.invite_id, iu.used_at, u.username
		FROM invite_uses iu
		JOIN users u ON iu.user_id = u.id
		ORDER BY iu.used_at DESC
	`)
		.all() as Array<{
		invite_id: number;
		used_at: number;
		username: string;
	}>;

	const now = Math.floor(Date.now() / 1000);

	return Response.json({
		invites: invites.map((inv) => ({
			id: inv.id,
			code: inv.code,
			maxUses: inv.max_uses,
			currentUses: inv.current_uses,
			isExpired: inv.expires_at ? inv.expires_at < now : false,
			isFullyUsed: inv.current_uses >= inv.max_uses,
			expiresAt: inv.expires_at,
			note: inv.note,
			message: inv.message,
			createdAt: inv.created_at,
			createdBy: inv.created_by_username,
			inviteUrl: `${process.env.ORIGIN}/login?invite=${inv.code}`,
			appRoles: inviteRoles
				.filter((r) => r.invite_id === inv.id)
				.map((r) => ({
					appId: r.app_id,
					clientId: r.client_id,
					name: r.name,
					role: r.role,
				})),
			usedBy: inviteUses
				.filter((u) => u.invite_id === inv.id)
				.map((u) => ({
					username: u.username,
					usedAt: u.used_at,
				})),
		})),
	});
}

// PATCH /api/invites/:id - Update invite (admin only)
export async function updateInvite(req: Request): Promise<Response> {
	const user = requireAdmin(req);
	if (user instanceof Response) {
		return user;
	}

	const csrfError = validateCsrf(req);
	if (csrfError) return csrfError;

	const inviteId = parseInviteId(req);
	if (!inviteId) {
		return Response.json({ error: "Invalid invite ID" }, { status: 400 });
	}

	const body = await readJsonObject(req);
	if (body instanceof Response) return body;

	const updates: string[] = [];
	const values: (number | string | null)[] = [];

	if (body.maxUses !== undefined) {
		const check = checkMaxUses(body.maxUses);
		if (!check.ok) {
			return Response.json({ error: check.error }, { status: 400 });
		}
		updates.push("max_uses = ?");
		values.push(check.value);
	}
	if (body.expiresAt !== undefined) {
		const check = checkExpiresAt(body.expiresAt);
		if (!check.ok) {
			return Response.json({ error: check.error }, { status: 400 });
		}
		updates.push("expires_at = ?");
		values.push(check.value);
	}
	if (body.note !== undefined) {
		const check = checkText(body.note, "note", MAX_NOTE_LENGTH);
		if (!check.ok) {
			return Response.json({ error: check.error }, { status: 400 });
		}
		updates.push("note = ?");
		values.push(check.value);
	}
	if (body.message !== undefined) {
		const check = checkText(body.message, "message", MAX_MESSAGE_LENGTH);
		if (!check.ok) {
			return Response.json({ error: check.error }, { status: 400 });
		}
		updates.push("message = ?");
		values.push(check.value);
	}

	if (updates.length === 0) {
		return Response.json({ error: "No fields to update" }, { status: 400 });
	}

	values.push(inviteId);

	db.query(`UPDATE invites SET ${updates.join(", ")} WHERE id = ?`).run(
		...values,
	);

	return Response.json({ success: true });
}

// DELETE /api/invites/:id - Delete an invite (admin only)
export function deleteInvite(req: Request): Response {
	const user = requireAdmin(req);
	if (user instanceof Response) {
		return user;
	}

	const csrfError = validateCsrf(req);
	if (csrfError) return csrfError;

	const inviteId = parseInviteId(req);
	if (!inviteId) {
		return Response.json({ error: "Invalid invite ID" }, { status: 400 });
	}

	db.query("DELETE FROM invites WHERE id = ?").run(inviteId);

	return Response.json({ success: true });
}
