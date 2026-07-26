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
