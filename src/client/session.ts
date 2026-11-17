// One /api/hello per page, remembered across navigations so the chrome can draw signed-in state at once.

export interface Session {
	id: number;
	username: string;
	isAdmin: boolean;
	tier: string;
}

const KEY = "indiko.session";
let live: Promise<Session | null> | undefined;

/** Last known session, for painting before the network answers. Never trust it for access. */
export function cachedSession(): Session | null {
	try {
		const raw = sessionStorage.getItem(KEY);
		return raw ? (JSON.parse(raw) as Session) : null;
	} catch {
		return null;
	}
}

export function forgetSession(): void {
	live = undefined;
	sessionStorage.removeItem(KEY);
}

/** The verified session, fetched once per page; null when signed out. */
export function session(): Promise<Session | null> {
	live ??= fetch("/api/hello").then(async (res) => {
		if (!res.ok) {
			forgetSession();
			return null;
		}
		const { id, username, isAdmin, tier } = (await res.json()) as Session;
		const current = { id, username, isAdmin: !!isAdmin, tier };
		sessionStorage.setItem(KEY, JSON.stringify(current));
		return current;
	});
	return live;
}

/** Resolves only for a permitted visitor; everyone else is sent away and it never resolves. */
export async function requirePage(
	opts: { admin?: boolean } = {},
): Promise<Session> {
	const current = await session();
	const target = !current
		? "/login"
		: opts.admin && !current.isAdmin
			? "/"
			: null;
	if (target) {
		window.location.replace(target);
		return new Promise<never>(() => {});
	}
	return current as Session;
}
