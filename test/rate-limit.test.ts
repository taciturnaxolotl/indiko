import { describe, expect, test } from "bun:test";
import { RateLimiter, rateLimitedResponse } from "../src/lib/rate-limit";

// The limiter is a no-op under NODE_ENV=test unless `force` is set, so
// every limiter here opts in explicitly.
function limiter(
	opts: Partial<ConstructorParameters<typeof RateLimiter>[0]> = {},
) {
	let now = 1_000_000;
	const rl = new RateLimiter({
		max: 3,
		windowMs: 1000,
		force: true,
		now: () => now,
		...opts,
	});
	return { rl, tick: (ms: number) => (now += ms) };
}

describe("RateLimiter", () => {
	test("allows up to max hits then limits", () => {
		const { rl } = limiter();
		expect(rl.hit("a").limited).toBe(false);
		expect(rl.hit("a").limited).toBe(false);
		const third = rl.hit("a");
		expect(third.limited).toBe(false);
		expect(third.remaining).toBe(0);
		const fourth = rl.hit("a");
		expect(fourth.limited).toBe(true);
		expect(fourth.retryAfterSeconds).toBeGreaterThanOrEqual(1);
	});

	test("keys are independent", () => {
		const { rl } = limiter({ max: 1 });
		expect(rl.hit("a").limited).toBe(false);
		expect(rl.hit("a").limited).toBe(true);
		expect(rl.hit("b").limited).toBe(false);
	});

	test("window resets after windowMs", () => {
		const { rl, tick } = limiter({ max: 1, windowMs: 1000 });
		expect(rl.hit("a").limited).toBe(false);
		expect(rl.hit("a").limited).toBe(true);
		tick(999);
		expect(rl.hit("a").limited).toBe(true);
		tick(1);
		expect(rl.hit("a").limited).toBe(false);
	});

	test("isLimited does not consume a hit", () => {
		const { rl } = limiter({ max: 2 });
		rl.hit("a");
		expect(rl.isLimited("a")).toBe(false);
		expect(rl.isLimited("a")).toBe(false);
		rl.hit("a");
		expect(rl.isLimited("a")).toBe(true);
		expect(rl.isLimited("unknown")).toBe(false);
	});

	test("reset forgets a key", () => {
		const { rl } = limiter({ max: 1 });
		rl.hit("a");
		expect(rl.hit("a").limited).toBe(true);
		rl.reset("a");
		expect(rl.hit("a").limited).toBe(false);
	});

	test("prunes expired entries periodically", () => {
		const { rl, tick } = limiter({ max: 5, windowMs: 100, pruneEvery: 10 });
		for (let i = 0; i < 9; i++) rl.hit(`k${i}`);
		expect(rl.size).toBe(9);
		tick(200); // everything expired
		rl.hit("fresh"); // 10th hit triggers prune
		expect(rl.size).toBe(1);
	});

	test("explicit prune drops only expired buckets", () => {
		const { rl, tick } = limiter({ max: 5, windowMs: 100 });
		rl.hit("old");
		tick(150);
		rl.hit("new");
		rl.prune();
		expect(rl.size).toBe(1);
		expect(rl.isLimited("new")).toBe(false);
	});

	test("is disabled under NODE_ENV=test unless forced", () => {
		expect(process.env.NODE_ENV).toBe("test");
		const rl = new RateLimiter({ max: 1, windowMs: 1000 });
		for (let i = 0; i < 10; i++) expect(rl.hit("a").limited).toBe(false);
		expect(rl.isLimited("a")).toBe(false);
	});

	test("rateLimitedResponse is a 429 with Retry-After", async () => {
		const res = rateLimitedResponse({
			limited: true,
			remaining: 0,
			retryAfterSeconds: 42,
		});
		expect(res.status).toBe(429);
		expect(res.headers.get("Retry-After")).toBe("42");
		const body = (await res.json()) as { error: string };
		expect(body.error).toContain("Too many requests");
	});
});
