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

// POST /api/invites/create - Create invite link (admin only)
export async function createInvite(req: Request): Promise<Response> {
	const user = requireAdmin(req);
	if (user instanceof Response) {
		return user;
	}

	const csrfError = validateCsrf(req);
	if (csrfError) return csrfError;

	const body = (await req.json()) as {
		maxUses?: number;
		expiresAt?: number | null;
		note?: string | null;
		message?: string | null;
		appRoles?: Array<{ appId: number; role: string }>;
	};

	const inviteCode = crypto.randomBytes(16).toString("base64url");
	const maxUses = body.maxUses || 1;
	const expiresAt = body.expiresAt || null;
	const note = body.note || null;
	const message = body.message || null;

	const result = db
		.query(
			"INSERT INTO invites (code, created_by, max_uses, expires_at, note, message) VALUES (?, ?, ?, ?, ?, ?)",
		)
		.run(inviteCode, user.userId, maxUses, expiresAt, note, message);

	const inviteId = Number(result.lastInsertRowid);

	if (body.appRoles && body.appRoles.length > 0) {
		const stmt = db.prepare(
			"INSERT INTO invite_roles (invite_id, app_id, role) VALUES (?, ?, ?)",
		);
		for (const appRole of body.appRoles) {
			stmt.run(inviteId, appRole.appId, appRole.role);
		}
	}

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

	const body = (await req.json()) as {
		maxUses?: number | null;
		expiresAt?: number | null;
		note?: string | null;
		message?: string | null;
	};

	const updates: string[] = [];
	const values: (number | string | null)[] = [];

	if (body.maxUses !== undefined) {
		updates.push("max_uses = ?");
		values.push(body.maxUses);
	}
	if (body.expiresAt !== undefined) {
		updates.push("expires_at = ?");
		values.push(body.expiresAt);
	}
	if (body.note !== undefined) {
		updates.push("note = ?");
		values.push(body.note);
	}
	if (body.message !== undefined) {
		updates.push("message = ?");
		values.push(body.message);
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
