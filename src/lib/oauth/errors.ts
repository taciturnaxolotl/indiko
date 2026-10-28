// RFC 6749 §5.2 style error with WWW-Authenticate header
export function unauthorizedResponse(
	error: string,
	description: string,
): Response {
	return Response.json(
		{ error, error_description: description },
		{
			status: 401,
			headers: {
				"WWW-Authenticate": `Bearer realm="indiko", error="${error}", error_description="${description}"`,
			},
		},
	);
}

export function oauthError(
	status: number,
	error: string,
	description: string,
): Response {
	return Response.json({ error, error_description: description }, { status });
}

// Parse a request body as JSON or form-encoded; returns null for anything else
export async function parseBody(
	req: Request,
): Promise<Record<string, string> | null> {
	const contentType = req.headers.get("Content-Type");

	if (contentType?.includes("application/json")) {
		return (await req.json()) as Record<string, string>;
	}
	if (contentType?.includes("application/x-www-form-urlencoded")) {
		const formData = await req.formData();
		return Object.fromEntries(formData.entries()) as Record<string, string>;
	}
	return null;
}

export const NO_STORE_HEADERS = {
	"Content-Type": "application/json",
	"Cache-Control": "no-store",
	Pragma: "no-cache",
};

// CORS for the endpoints browser-based clients call directly (IndieAuth §5.3).
// A bare wildcard origin is safe only because none of these endpoints read
// cookies; it must never be paired with Access-Control-Allow-Credentials.
export const CORS_HEADERS = {
	"Access-Control-Allow-Origin": "*",
	"Access-Control-Allow-Methods": "POST, OPTIONS",
	"Access-Control-Allow-Headers": "Content-Type, Authorization",
	"Access-Control-Max-Age": "86400",
};

export function corsPreflight(methods = "POST, OPTIONS"): Response {
	return new Response(null, {
		status: 204,
		headers: { ...CORS_HEADERS, "Access-Control-Allow-Methods": methods },
	});
}

export function withCors(response: Response): Response {
	response.headers.set("Access-Control-Allow-Origin", "*");
	return response;
}

// RFC 6749 §3.2: token endpoints take POST only. Say so in the same JSON shape
// as every other token error so clients never have to parse a text body.
export function methodNotAllowed(allow: string): Response {
	return Response.json(
		{
			error: "invalid_request",
			error_description: `Method not allowed. Use ${allow}.`,
		},
		{ status: 405, headers: { Allow: allow, ...CORS_HEADERS } },
	);
}
