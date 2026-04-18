import { env } from "bun";
import { db } from "./db";
import adminHTML from "./html/admin.html";
import adminClientsHTML from "./html/admin-clients.html";
import adminInvitesHTML from "./html/admin-invites.html";
import appsHTML from "./html/apps.html";
import docsHTML from "./html/docs.html";
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
import {
	authorizeGet,
	authorizePost,
	clientMetadata,
	createInvite,
	deleteInvite,
	indieauthMetadata,
	listInvites,
	logout,
	token,
	tokenIntrospect,
	tokenRevoke,
	updateInvite,
	userinfo,
	userProfile,
} from "./routes/indieauth";
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

const server = Bun.serve({
	port: env.PORT ? Number.parseInt(env.PORT, 10) : 3000,
	routes: {
		"/favicon.svg": Bun.file("./public/favicon.svg"),
		"/": indexHTML,
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
		"/admin": adminHTML,
		"/admin/invites": adminInvitesHTML,
		"/admin/apps": () => Response.redirect("/admin/clients", 302),
		"/admin/clients": adminClientsHTML,
		"/login": loginHTML,
		"/docs": docsHTML,
		"/apps": appsHTML,
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
		"/api/admin/users/:id/disable": (req: Request) => {
			if (req.method === "POST") {
				const url = new URL(req.url);
				const userId = url.pathname.split("/")[4];
				return disableUser(req, userId);
			}
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/users/:id/enable": (req: Request) => {
			if (req.method === "POST") {
				const url = new URL(req.url);
				const userId = url.pathname.split("/")[4];
				return enableUser(req, userId);
			}
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/users/:id/tier": (req: Request) => {
			if (req.method === "PUT") {
				const url = new URL(req.url);
				const userId = url.pathname.split("/")[4];
				return updateUserTier(req, userId);
			}
			return new Response("Method not allowed", { status: 405 });
		},
		"/api/admin/users/:id/delete": (req: Request) => {
			if (req.method === "DELETE") {
				const url = new URL(req.url);
				const userId = url.pathname.split("/")[4];
				return deleteUser(req, userId);
			}
			return new Response("Method not allowed", { status: 405 });
		},
		// IndieAuth/OAuth 2.0 endpoints
		"/auth/authorize": async (req: Request) => {
			if (req.method === "GET") return authorizeGet(req);
			if (req.method === "POST") return await authorizePost(req);
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

	const total =
		sessionsDeleted.changes +
		challengesDeleted.changes +
		authcodesDeleted.changes +
		tokensDeleted.changes;

	if (total > 0) {
		console.log(
			`[Cleanup] Removed ${total} expired records (sessions: ${sessionsDeleted.changes}, challenges: ${challengesDeleted.changes}, authcodes: ${authcodesDeleted.changes}, tokens: ${tokensDeleted.changes})`,
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

				// Only take action on accounts orphaned longer than grace period
				if (result.orphaned > 0) {
					const expiredOrphans = result.orphanedUsers.filter(
						(user) => now - user.createdAt > gracePeriod,
					);

					if (expiredOrphans.length > 0) {
						if (action === "suspend") {
							await updateOrphanedAccounts(
								{ ...result, orphanedUsers: expiredOrphans },
								"suspend",
							);
						} else if (action === "deactivate") {
							await updateOrphanedAccounts(
								{ ...result, orphanedUsers: expiredOrphans },
								"deactivate",
							);
						} else if (action === "remove") {
							await updateOrphanedAccounts(
								{ ...result, orphanedUsers: expiredOrphans },
								"remove",
							);
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
