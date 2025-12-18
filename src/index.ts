import { env } from "bun";
import { db } from "./db";
import indexHTML from "./html/index.html";
import adminHTML from "./html/admin.html";
import adminInvitesHTML from "./html/admin-invites.html";
import adminClientsHTML from "./html/admin-clients.html";
import loginHTML from "./html/login.html";
import profileHTML from "./html/profile.html";
import docsHTML from "./html/docs.html";
import appsHTML from "./html/apps.html";
import {
	canRegister,
	registerOptions,
	registerVerify,
	loginOptions,
	loginVerify,
} from "./routes/auth";
import {
	hello,
	listUsers,
	getProfile,
	updateProfile,
	getAuthorizedApps,
	revokeApp,
	listAllApps,
	getAppDetails,
	revokeAppForUser,
	disableUser,
	enableUser,
	deleteUser,
} from "./routes/api";
import {
	authorizeGet,
	authorizePost,
	token,
	logout,
	userProfile,
	createInvite,
	listInvites,
	updateInvite,
	deleteInvite,
} from "./routes/indieauth";
import {
	listClients,
	createClient,
	getClient,
	updateClient,
	deleteClient,
	setUserRole,
	regenerateClientSecret,
} from "./routes/clients";

(() => {
	const required = ["ORIGIN", "RP_ID"];

	const missing = required.filter((key) => !process.env[key]);

	if (missing.length > 0) {
		console.warn(
			`[Startup] Missing required envivonment variables: ${missing.join(", ")}`,
		);
		process.exit(1);
	}
})();

const server = Bun.serve({
	port: env.PORT ? Number.parseInt(env.PORT, 10) : 3000,
	routes: {
		"/": indexHTML,
		"/admin": adminHTML,
		"/admin/invites": adminInvitesHTML,
		"/admin/apps": () => Response.redirect("/admin/clients", 302),
		"/admin/clients": adminClientsHTML,
		"/login": loginHTML,
		"/profile": profileHTML,
		"/docs": docsHTML,
		"/apps": appsHTML,
		// API endpoints
		"/api/hello": hello,
		"/api/users": listUsers,
		"/api/profile": (req: Request) => {
			if (req.method === "GET") return getProfile(req);
			if (req.method === "PUT") return updateProfile(req);
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
		// Dynamic routes with Bun's :param syntax
		"/u/:username": (req) => userProfile(req, req.params.username),
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
			if (req.method === "DELETE") return deleteClient(req, req.params.clientId);
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

let is_shutting_down = false;
function shutdown(sig: string) {
	if (is_shutting_down) return;
	is_shutting_down = true;

	console.log(`[Shutdown] triggering shutdown due to ${sig}`);

	server.stop();
	console.log("[Shutdown] stopped server");

	db.close();
	console.log("[Shutdown] closed db");

	process.exit(0);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
