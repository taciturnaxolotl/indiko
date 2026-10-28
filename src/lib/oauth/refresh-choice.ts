/**
 * IndieAuth clients have no scope that means "keep me signed in": the spec
 * leaves refresh tokens to the server's discretion (§5.5) and never mentions
 * offline_access, which is an OpenID Connect idea. So for a request that is
 * plainly IndieAuth (scoped, no openid, no offline_access) the consent screen
 * offers the choice to the person instead, and their answer travels on the
 * authorization code rather than in the scope string the client sees.
 */
export function offersStaySignedIn(scopes: readonly string[]): boolean {
	return (
		scopes.length > 0 &&
		!scopes.includes("openid") &&
		!scopes.includes("offline_access")
	);
}

export const STAY_SIGNED_IN_FIELD = "stay_signed_in";
