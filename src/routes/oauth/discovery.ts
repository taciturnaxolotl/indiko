import { db } from "../../db";

// GET /.well-known/oauth-client - Client metadata lookup
export function clientMetadata(req: Request): Response {
	const url = new URL(req.url);
	const clientId = url.searchParams.get("client_id");

	if (!clientId) {
		return Response.json(
			{
				error: "invalid_request",
				error_description: "client_id parameter is required",
			},
			{ status: 400 },
		);
	}

	const client = db
		.query(
			`SELECT
				client_id,
				name,
				logo_url,
				description,
				redirect_uris,
				is_preregistered,
				available_roles,
				default_role,
				first_seen,
				last_used
			FROM apps
			WHERE client_id = ?`,
		)
		.get(clientId) as
		| {
				client_id: string;
				name: string | null;
				logo_url: string | null;
				description: string | null;
				redirect_uris: string;
				is_preregistered: number;
				available_roles: string | null;
				default_role: string | null;
				first_seen: number;
				last_used: number;
		  }
		| undefined;

	if (!client) {
		return Response.json(
			{ error: "not_found", error_description: "Client not found" },
			{ status: 404 },
		);
	}

	const redirectUris = JSON.parse(client.redirect_uris) as string[];
	const availableRoles = client.available_roles
		? (JSON.parse(client.available_roles) as string[])
		: undefined;

	// Derive client_uri from the client_id when it's a URL (auto-registered apps)
	let clientUri: string | undefined;
	try {
		new URL(client.client_id);
		clientUri = client.client_id;
	} catch {
		// Pre-registered clients use opaque IDs, not URLs
	}

	const metadata: Record<string, unknown> = {
		client_id: client.client_id,
		client_name:
			client.name ||
			(clientUri ? new URL(clientUri).hostname : client.client_id),
		redirect_uris: redirectUris,
		grant_types: ["authorization_code"],
		response_types: ["code"],
		token_endpoint_auth_method: client.is_preregistered
			? "client_secret_post"
			: "none",
	};

	if (clientUri) metadata.client_uri = clientUri;
	if (client.logo_url) metadata.logo_uri = client.logo_url;
	if (client.description) metadata.client_description = client.description;
	if (availableRoles) metadata.roles = availableRoles;
	if (client.default_role) metadata.default_role = client.default_role;

	return Response.json(metadata, {
		headers: {
			"Content-Type": "application/json",
			"Access-Control-Allow-Origin": "*",
		},
	});
}

// GET /.well-known/oauth-authorization-server - IndieAuth metadata endpoint
export function indieauthMetadata(): Response {
	const origin = process.env.ORIGIN || "http://localhost:3000";

	const metadata = {
		issuer: origin,
		authorization_endpoint: `${origin}/auth/authorize`,
		token_endpoint: `${origin}/auth/token`,
		introspection_endpoint: `${origin}/auth/token/introspect`,
		introspection_endpoint_auth_methods_supported: ["none"],
		revocation_endpoint: `${origin}/auth/token/revoke`,
		revocation_endpoint_auth_methods_supported: ["none"],
		userinfo_endpoint: `${origin}/userinfo`,
		jwks_uri: `${origin}/jwks`,
		code_challenge_methods_supported: ["S256"],
		scopes_supported: ["profile", "email"],
		response_types_supported: ["code"],
		grant_types_supported: [
			"authorization_code",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code",
		],
		token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
		service_documentation: `${origin}/docs`,
		client_id_metadata_document_supported: true,
		authorization_response_iss_parameter_supported: true,
		device_authorization_endpoint: `${origin}/auth/device`,
	};

	return Response.json(metadata, {
		headers: {
			"Content-Type": "application/json",
			"Access-Control-Allow-Origin": "*",
		},
	});
}
