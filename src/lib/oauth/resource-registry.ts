import { db } from "../../db";

// Live policy for registered resource servers; unregistered audiences pass everything.

export interface RegisteredResource {
	id: number;
	identifier: string;
	name: string;
	description: string | null;
	logoUrl: string | null;
	availableRoles: string[] | null;
	defaultRole: string | null;
	restrictClients: boolean;
	assignmentRequired: boolean;
}

export interface ResourceRow {
	id: number;
	identifier: string;
	name: string;
	description: string | null;
	logo_url: string | null;
	available_roles: string | null;
	default_role: string | null;
	restrict_clients: number;
	assignment_required: number;
}

export interface AccessDenial {
	error: "invalid_target" | "access_denied";
	description: string;
}

export type Access =
	| { ok: true; roles: Record<string, string> }
	| { ok: false; denial: AccessDenial };

export function parseRoleList(stored: string | null): string[] | null {
	if (!stored) return null;
	try {
		const parsed = JSON.parse(stored);
		return Array.isArray(parsed)
			? parsed.filter((r): r is string => typeof r === "string")
			: null;
	} catch {
		return null;
	}
}

export function rowToResource(row: ResourceRow): RegisteredResource {
	return {
		id: row.id,
		identifier: row.identifier,
		name: row.name,
		description: row.description,
		logoUrl: row.logo_url,
		availableRoles: parseRoleList(row.available_roles),
		defaultRole: row.default_role,
		restrictClients: row.restrict_clients === 1,
		assignmentRequired: row.assignment_required === 1,
	};
}

export function findResource(identifier: string): RegisteredResource | null {
	const row = db
		.query("SELECT * FROM resources WHERE identifier = ?")
		.get(identifier) as ResourceRow | undefined;
	return row ? rowToResource(row) : null;
}

/** A registered audience as seen through one client: listed or not, and its role ceiling. */
interface Binding {
	resource: RegisteredResource;
	listed: boolean;
	ceiling: string[] | null;
}

function bindings(clientId: string, identifiers: string[]): Binding[] {
	return identifiers.flatMap((identifier) => {
		const resource = findResource(identifier);
		if (!resource) return [];
		const entry = db
			.query(
				"SELECT allowed_roles FROM resource_clients WHERE resource_id = ? AND client_id = ?",
			)
			.get(resource.id, clientId) as { allowed_roles: string | null } | null;
		return [
			{
				resource,
				listed: entry !== null,
				ceiling: parseRoleList(entry?.allowed_roles ?? null),
			},
		];
	});
}

function clientDenial({ resource, listed }: Binding): AccessDenial | null {
	if (!resource.restrictClients || listed) return null;
	return {
		error: "invalid_target",
		description: `This client is not allowed to request tokens for ${resource.identifier}`,
	};
}

/** Roles are not ranked: a role outside the client's ceiling is withheld, not demoted. */
function roleFor(
	{ resource, ceiling }: Binding,
	userId: number,
): string | null {
	const assigned = db
		.query(
			"SELECT role FROM resource_roles WHERE resource_id = ? AND user_id = ?",
		)
		.get(resource.id, userId) as { role: string } | undefined;
	const role = assigned?.role ?? resource.defaultRole;
	return role && (!ceiling || ceiling.includes(role)) ? role : null;
}

/** Before sign-in, when only the client is known. */
export function checkClientAccess(
	clientId: string,
	identifiers: string[],
): AccessDenial | null {
	for (const binding of bindings(clientId, identifiers)) {
		const denial = clientDenial(binding);
		if (denial) return denial;
	}
	return null;
}

export function evaluateAccess(
	clientId: string,
	userId: number,
	identifiers: string[],
): Access {
	const roles: Record<string, string> = {};
	for (const binding of bindings(clientId, identifiers)) {
		const denial = clientDenial(binding);
		if (denial) return { ok: false, denial };
		const role = roleFor(binding, userId);
		if (role) roles[binding.resource.identifier] = role;
		else if (binding.resource.assignmentRequired) {
			return {
				ok: false,
				denial: {
					error: "access_denied",
					description: `You do not have access to ${binding.resource.name}`,
				},
			};
		}
	}
	return { ok: true, roles };
}

/** Introspection claims: one audience gives `aud` + `role`, several give arrays/maps. */
export function audienceClaims(
	identifiers: string[],
	roles: Record<string, string>,
): Record<string, unknown> {
	if (identifiers.length === 0) return {};
	if (identifiers.length === 1) {
		const [aud] = identifiers as [string];
		return roles[aud] ? { aud, role: roles[aud] } : { aud };
	}
	return Object.keys(roles).length > 0
		? { aud: identifiers, roles }
		: { aud: identifiers };
}
