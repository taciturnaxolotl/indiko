import { env } from "bun";
import { db } from "./db";
import adminHTML from "./html/admin.html";
import adminClientsHTML from "./html/admin-clients.html";
import adminInvitesHTML from "./html/admin-invites.html";
import appsHTML from "./html/apps.html";
import indexHTML from "./html/index.html";
import loginHTML from "./html/login.html";
import { getLdapAccounts, updateOrphanedAccounts } from "./ldap-cleanup";
import { getDiscoveryDocument, getJWKS } from "./oidc";
import {
	deleteSelfAccount,
	deleteUser,
	disableUser,
	enableUser,
	getAppDetails,
	getAuthorizedApps,
	getProfile,
	hello,
	listAllApps,
	listUsers,
	revokeApp,
	revokeAppForUser,
	updateProfile,
	updateUserTier,
} from "./routes/api";
import {
	canRegister,
	ldapVerify,
	loginOptions,
	loginVerify,
	registerOptions,
	registerVerify,
} from "./routes/auth";
import {
	createClient,
	deleteClient,
	getClient,
	listClients,
	regenerateClientSecret,
	setUserRole,
	updateClient,
} from "./routes/clients";
import { docsJs, docsMarkdown, docsPage } from "./routes/docs";
import { authorizeGet, authorizePost } from "./routes/oauth/authorize";
import { deviceAuthorization } from "./routes/oauth/device";
import { deviceGet, devicePost } from "./routes/oauth/device-verify";
import { clientMetadata, indieauthMetadata } from "./routes/oauth/discovery";
import {
	createInvite,
	deleteInvite,
	listInvites,
	updateInvite,
} from "./routes/oauth/invites";
import { userProfile } from "./routes/oauth/profile";
import { registerClient } from "./routes/oauth/register";
import { token, tokenIntrospect, tokenRevoke } from "./routes/oauth/token";
import { logout, userinfo } from "./routes/oauth/userinfo";
import {
	addPasskeyOptions,
	addPasskeyVerify,
	deletePasskey,
	listPasskeys,
	renamePasskey,
} from "./routes/passkeys";

(() => {
	const required = ["ORIGIN", "RP_ID"];

	const missing = required.filter((key) => !process.env[key]);

	if (missing.length > 0) {
		console.warn(
			`[Startup] Missing required environment variables: ${missing.join(", ")}`,
		);
		process.exit(1);
	}

	// Validate ORIGIN is HTTPS in production
	const origin = process.env.ORIGIN as string;
	const rpId = process.env.RP_ID as string;
	const nodeEnv = process.env.NODE_ENV || "development";

	if (nodeEnv === "production" && !origin.startsWith("https://")) {
		console.error(
			`[Startup] ORIGIN must use HTTPS in production (got: ${origin})`,
		);
		process.exit(1);
	}

	// Validate RP_ID matches ORIGIN domain
	try {
		const originUrl = new URL(origin);
		if (originUrl.hostname !== rpId) {
			console.error(
				`[Startup] RP_ID must match ORIGIN domain (ORIGIN: ${originUrl.hostname}, RP_ID: ${rpId})`,
			);
			process.exit(1);
		}
	} catch {
		console.error(`[Startup] Invalid ORIGIN URL format: ${origin}`);
		process.exit(1);
	}

	console.log(`[Startup] Environment validated (${nodeEnv} mode)`);
})();

import { SECURITY_HEADERS } from "./lib/security-headers";

// Wrap HTML imports to add security headers. Bun's HTML imports become
// static handlers in the routes object — wrapping them in functions lets
// us attach headers.
function withHeaders(html: unknown): () => Response {
	return () => {
		// Bun HTML imports are Response-like objects; clone and add headers
		const res = html as Response;
		const newRes = new Response(res.body, {
			status: res.status,
			headers: { ...Object.fromEntries(res.headers.entries()), ...SECURITY_HEADERS },
		});
		return newRes;
	};
}

const server = Bun.serve({
	port: env.PORT ? Number.parseInt(env.PORT, 10) : 3000,
	routes: {
		"/favicon.svg": Bun.file("./public/favicon.svg"),
		"/logo.svg": Bun.file("./public/logo.svg"),
		"/": withHeaders(indexHTML),
		"/health": () => {
			try {
				// Verify database is accessible
				db.query("SELECT 1").get();
				return Response.json({
					status: "ok",
					timestamp: new Date().toISOString(),
				});
			} catch {
				return Response.json(
					{ status: "error", error: "Database unavailable" },
					{ status: 503 },
				);
			}
		},
		"/admin": withHeaders(adminHTML),
		"/admin/invites": withHeaders(adminInvitesHTML),
		"/admin/apps": () => Response.redirect("/admin/clients", 302),
		"/admin/clients": withHeaders(adminClientsHTML),
		"/login": withHeaders(loginHTML),
		"/docs": docsPage,
		"/docs.md": docsMarkdown,
		"/docs.css": Bun.file("./public/docs.css"),
		"/docs.js": docsJs,
		"/styles.css": Bun.file("./src/styles.css"),
		"/ds/tokens.css": Bun.file("./src/client/ds/tokens.css"),
		"/ds/components.css": Bun.file("./src/client/ds/components.css"),
		"/apps": withHeaders(appsHTML),
		// Well-known endpoints
		"/.well-known/security.txt": () => {
			const expiryDate = new Date();
			expiryDate.setMonth(expiryDate.getMonth() + 3);
			expiryDate.setSeconds(0, 0);
			const expires = expiryDate.toISOString();
			return new Response(
				`# Security Contact Information for Indiko
# See: https://securitytxt.org/
Contact: mailto:security@dunkirk.sh
Expires: ${expires}
Preferred-Languages: en
Canonical: ${env.ORIGIN}/.well-known/security.txt
Policy: https://tangled.org/dunkirk.sh/indiko/blob/main/SECURITY.md
`,
				{
					headers: {
						"Content-Type": "text/plain; charset=utf-8",
					},
				},
			);
		},
		"/.well-known/oauth-authorization-server": indieauthMetadata,
		"/.well-known/oauth-client": (req: Request) => {
			if (req.method === "GET") return clientMetadata(req);
			if (req.method === "OPTIONS")
				return new Response(null, {
					status: 204,
					headers: {
						"Access-Control-Allow-Origin": "*",
						"Access-Control-Allow-Methods": "GET, OPTIONS",
					},
				});
			return new Response("Method not allowed", { status: 405 });
		},
		"/.well-known/openid-configuration": () => {
			const origin = process.env.ORIGIN as string;
			return Response.json(getDiscoveryDocument(origin));
		},
		"/jwks": async () => {
			const jwks = await getJWKS();
			return Response.json(jwks);
		},
		// OAuth/IndieAuth endpoints
		"/userinfo": (req: Request) => {
			if (req.method === "GET") return userinfo(req);
			return new Response("Method not allowed", { status: 405 });
		},
		// API endpoints
		"/api/hello": hello,
		"/api/users": listUsers,
		"/api/profile": (req: Request) => {
			if (req.method === "GET") return getProfile(req);
			if (req.method === "PUT") return updateProfile(req);
			if (req.method === "DELETE") return deleteSelfAccount(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/apps": (req: Request) => {
			if (req.method === "GET") return getAuthorizedApps(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/apps": (req: Request) => {
			if (req.method === "GET") return listAllApps(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/clients": (req: Request) => {
			if (req.method === "GET") return listClients(req);
			if (req.method === "POST") return createClient(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/invites/create": (req: Request) => {
			if (req.method === "POST") return createInvite(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/invites": (req: Request) => {
			if (req.method === "GET") return listInvites(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/invites/:id": (req: Request) => {
			if (req.method === "PATCH") return updateInvite(req);
			if (req.method === "DELETE") return deleteInvite(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/users/:id/disable": (req) => {
			if (req.method === "POST") {
				return disableUser(req, req.params.id);
			}
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/users/:id/enable": (req) => {
			if (req.method === "POST") {
				return enableUser(req, req.params.id);
			}
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/users/:id/tier": (req) => {
			if (req.method === "PUT") {
				return updateUserTier(req, req.params.id);
			}
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/users/:id/delete": (req) => {
			if (req.method === "DELETE") {
				return deleteUser(req, req.params.id);
			}
			return new Response("Method not allowed", { status: 405 });
		},
		// IndieAuth/OAuth 2.0 endpoints
		"/auth/authorize": async (req: Request) => {
			if (req.method === "GET") return authorizeGet(req);
			if (req.method === "POST") return await authorizePost(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/oauth/register": async (req: Request) => {
			if (req.method === "POST") return await registerClient(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/auth/device": async (req: Request) => {
			if (req.method === "POST") return await deviceAuthorization(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/device": async (req: Request) => {
			if (req.method === "GET") return deviceGet(req);
			if (req.method === "POST") return await devicePost(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/auth/token": async (req: Request) => {
			if (req.method === "POST") return await token(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/auth/token/introspect": async (req: Request) => {
			if (req.method === "POST") return await tokenIntrospect(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/auth/token/revoke": async (req: Request) => {
			if (req.method === "POST") return await tokenRevoke(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/auth/logout": (req: Request) => {
			if (req.method === "POST") return logout(req);
			return new Response("Method not allowed", { status: 405 });
		},
		// Passkey auth endpoints
		"/auth/can-register": canRegister,
		"/auth/register/options": registerOptions,
		"/auth/register/verify": registerVerify,
		"/auth/login/options": loginOptions,
		"/auth/login/verify": loginVerify,
		// LDAP verification endpoint
		"/api/ldap-verify": (req: Request) => {
			if (req.method === "POST") return ldapVerify(req);
			return new Response("Method not allowed", { status: 405 });
		},
		// Passkey management endpoints
		"/api/passkeys": (req: Request) => {
			if (req.method === "GET") return listPasskeys(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/passkeys/add/options": (req: Request) => {
			if (req.method === "POST") return addPasskeyOptions(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/passkeys/add/verify": (req: Request) => {
			if (req.method === "POST") return addPasskeyVerify(req);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/passkeys/:id": (req: Request) => {
			if (req.method === "DELETE") return deletePasskey(req);
			if (req.method === "PATCH") return renamePasskey(req);
			return new Response("Method not allowed", { status: 405 });
		},
		// Dynamic routes with Bun's :param syntax
		"/u/:username": userProfile,
		"/api/apps/:clientId": (req) => {
			if (req.method === "DELETE") return revokeApp(req, req.params.clientId);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/apps/:clientId": (req) => {
			if (req.method === "GET") return getAppDetails(req, req.params.clientId);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/apps/:clientId/users/:username": (req) => {
			if (req.method === "DELETE")
				return revokeAppForUser(req, req.params.clientId, req.params.username);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/clients/:clientId": (req) => {
			if (req.method === "GET") return getClient(req, req.params.clientId);
			if (req.method === "PUT") return updateClient(req, req.params.clientId);
			if (req.method === "DELETE")
				return deleteClient(req, req.params.clientId);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/clients/:clientId/users/:username/role": (req) => {
			if (req.method === "POST")
				return setUserRole(req, req.params.clientId, req.params.username);
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/clients/:clientId/secret": (req) => {
			if (req.method === "POST")
				return regenerateClientSecret(req, req.params.clientId);
			return new Response("Method not allowed", { status: 405 });
		},
	},
	development: process.env.NODE_ENV === "dev",
});

console.log("[Indiko] running on", env.ORIGIN);

// Cleanup job: runs every hour to remove expired data
const cleanupJob = setInterval(() => {
	const now = Math.floor(Date.now() / 1000);

	const sessionsDeleted = db
		.query("DELETE FROM sessions WHERE expires_at < ?")
		.run(now);
	const challengesDeleted = db
		.query("DELETE FROM challenges WHERE expires_at < ?")
		.run(now);
	const authcodesDeleted = db
		.query("DELETE FROM authcodes WHERE expires_at < ?")
		.run(now);
	const tokensDeleted = db
		.query("DELETE FROM tokens WHERE expires_at < ? OR revoked = 1")
		.run(now);
	const deviceCodesDeleted = db
		.query("DELETE FROM device_codes WHERE expires_at < ?")
		.run(now);

	const total =
		sessionsDeleted.changes +
		challengesDeleted.changes +
		authcodesDeleted.changes +
		tokensDeleted.changes +
		deviceCodesDeleted.changes;

	if (total > 0) {
		console.log(
			`[Cleanup] Removed ${total} expired records (sessions: ${sessionsDeleted.changes}, challenges: ${challengesDeleted.changes}, authcodes: ${authcodesDeleted.changes}, tokens: ${tokensDeleted.changes}, device_codes: ${deviceCodesDeleted.changes})`,
		);
	}
}, 3600000); // 1 hour in milliseconds

const ldapCleanupJob =
	process.env.LDAP_ADMIN_DN && process.env.LDAP_ADMIN_PASSWORD
		? setInterval(async () => {
				const result = await getLdapAccounts();
				const action = process.env.LDAP_ORPHAN_ACTION || "deactivate";
				const gracePeriod = Number.parseInt(
					process.env.LDAP_ORPHAN_GRACE_PERIOD || "604800",
					10,
				); // 7 days default
				const now = Math.floor(Date.now() / 1000);

				// Don't take any destructive action if there were LDAP errors —
				// an infrastructure failure must not trigger account deletion.
				if (result.errors > 0) {
					console.warn(
						`[LDAP Cleanup] ${result.errors} LDAP errors encountered — skipping orphan actions this run`,
					);
					return;
				}

				// Mark newly orphaned users (set orphaned_since on first detection)
				for (const orphan of result.orphanedUsers) {
					db.query(
						"UPDATE users SET orphaned_since = ? WHERE id = ? AND orphaned_since IS NULL",
					).run(now, orphan.id);
				}

				// Clear orphaned_since for users found back in LDAP
				for (const activeUser of result.activeUsers) {
					db.query(
						"UPDATE users SET orphaned_since = NULL WHERE id = ? AND orphaned_since IS NOT NULL",
					).run(activeUser.id);
				}

				// Only take action on accounts orphaned longer than grace period
				// (measured from first orphan detection, not account creation)
				if (result.orphaned > 0) {
					const expiredOrphans = db
						.query(
							"SELECT id, username FROM users WHERE provisioned_via_ldap = 1 AND orphaned_since IS NOT NULL AND (? - orphaned_since) > ?",
						)
						.all(now, gracePeriod) as Array<{
						id: number;
						username: string;
					}>;

					if (expiredOrphans.length > 0) {
						const expiredResult = {
							...result,
							orphanedUsers: expiredOrphans.map((u) => ({
								username: u.username,
								id: u.id,
								status: "unknown",
								createdAt: 0,
							})),
						};
						if (action === "suspend") {
							await updateOrphanedAccounts(expiredResult, "suspend");
						} else if (action === "deactivate") {
							await updateOrphanedAccounts(expiredResult, "deactivate");
						} else if (action === "remove") {
							await updateOrphanedAccounts(expiredResult, "remove");
						}
						console.log(
							`[LDAP Cleanup] ${action === "remove" ? "Removed" : action === "suspend" ? "Suspended" : "Deactivated"} ${expiredOrphans.length} LDAP orphan accounts (grace period: ${gracePeriod}s)`,
						);
					}
				}

				console.log(
					`[LDAP Cleanup] Check completed: ${result.total} total, ${result.active} active, ${result.orphaned} orphaned, ${result.errors} errors.`,
				);
			}, 3600000)
		: null; // 1 hour in milliseconds

let is_shutting_down = false;
function shutdown(sig: string) {
	if (is_shutting_down) return;
	is_shutting_down = true;

	console.log(`[Shutdown] triggering shutdown due to ${sig}`);

	clearInterval(cleanupJob);
	if (ldapCleanupJob) clearInterval(ldapCleanupJob);
	console.log("[Shutdown] stopped cleanup job");

	server.stop();
	console.log("[Shutdown] stopped server");

	db.close();
	console.log("[Shutdown] closed db");

	process.exit(0);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
