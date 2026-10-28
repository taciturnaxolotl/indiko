import { describe, expect, test } from "bun:test";
import { getClientIp, setServer } from "../src/lib/client-ip";

function req(headers: Record<string, string> = {}): Request {
	return new Request("http://localhost/x", { headers });
}

function withEnv<T>(value: string | undefined, fn: () => T): T {
	const prev = process.env.TRUSTED_PROXY;
	if (value === undefined) delete process.env.TRUSTED_PROXY;
	else process.env.TRUSTED_PROXY = value;
	try {
		return fn();
	} finally {
		if (prev === undefined) delete process.env.TRUSTED_PROXY;
		else process.env.TRUSTED_PROXY = prev;
	}
}

const fakeServer = (address: string | null) => ({
	requestIP: () => (address ? { address } : null),
});

describe("getClientIp", () => {
	test("uses the socket IP when no proxy is trusted", () => {
		setServer(fakeServer("203.0.113.9"));
		try {
			withEnv(undefined, () => {
				expect(
					getClientIp(
						req({
							"x-forwarded-for": "1.2.3.4",
							"cf-ray": "abc",
							"cf-connecting-ip": "5.6.7.8",
						}),
					),
				).toBe("203.0.113.9");
			});
		} finally {
			setServer(null);
		}
	});

	test("falls back to 'direct' when no server is registered", () => {
		setServer(null);
		withEnv(undefined, () => {
			expect(getClientIp(req())).toBe("direct");
		});
	});

	test("falls back to 'direct' when requestIP returns null", () => {
		setServer(fakeServer(null));
		try {
			withEnv(undefined, () => {
				expect(getClientIp(req())).toBe("direct");
			});
		} finally {
			setServer(null);
		}
	});

	test("cloudflare mode honours CF-Connecting-IP only with CF-Ray", () => {
		setServer(fakeServer("203.0.113.9"));
		try {
			withEnv("cloudflare", () => {
				expect(
					getClientIp(req({ "cf-ray": "abc", "cf-connecting-ip": "5.6.7.8" })),
				).toBe("5.6.7.8");
				// Missing CF-Ray, no XFF: fall back to socket IP
				expect(getClientIp(req({ "cf-connecting-ip": "5.6.7.8" }))).toBe(
					"203.0.113.9",
				);
			});
		} finally {
			setServer(null);
		}
	});

	test("xff mode takes the rightmost entry and falls back to socket IP", () => {
		setServer(fakeServer("203.0.113.9"));
		try {
			withEnv("xff", () => {
				expect(
					getClientIp(req({ "x-forwarded-for": "1.1.1.1, 2.2.2.2" })),
				).toBe("2.2.2.2");
				expect(getClientIp(req())).toBe("203.0.113.9");
			});
		} finally {
			setServer(null);
		}
	});
});
