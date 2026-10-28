/**
 * Small in-memory fixed-window rate limiter.
 *
 * Each limiter is keyed by an arbitrary string (IP, username, ...). The
 * first hit on a key opens a window of `windowMs`; up to `max` hits are
 * allowed inside it, after which `hit()` reports the key as limited until
 * the window expires. Expired entries are pruned lazily on every Nth hit
 * so the map cannot grow unbounded under a key-spraying attack.
 *
 * Like the token endpoint limiter, it is a no-op under NODE_ENV=test so
 * the test suite can hammer handlers without tripping it. Pass
 * `{ force: true }` to opt back in (used by the limiter's own tests).
 */

export interface RateLimiterOptions {
	/** Maximum number of hits allowed per window. */
	max: number;
	/** Window length in milliseconds. */
	windowMs: number;
	/** Prune expired entries every this many hits (default 256). */
	pruneEvery?: number;
	/** Bypass the NODE_ENV=test short-circuit. */
	force?: boolean;
	/** Clock override for tests. */
	now?: () => number;
}

export interface RateLimitResult {
	limited: boolean;
	/** Hits remaining in the current window (0 when limited). */
	remaining: number;
	/** Seconds until the window resets (rounded up, >= 1). */
	retryAfterSeconds: number;
}

interface Bucket {
	count: number;
	resetAt: number;
}

export class RateLimiter {
	private readonly buckets = new Map<string, Bucket>();
	private readonly max: number;
	private readonly windowMs: number;
	private readonly pruneEvery: number;
	private readonly force: boolean;
	private readonly now: () => number;
	private hitsSincePrune = 0;

	constructor(options: RateLimiterOptions) {
		this.max = options.max;
		this.windowMs = options.windowMs;
		this.pruneEvery = options.pruneEvery ?? 256;
		this.force = options.force ?? false;
		this.now = options.now ?? Date.now;
	}

	private get disabled(): boolean {
		return !this.force && process.env.NODE_ENV === "test";
	}

	/** Record a hit for `key` and report whether it is over the limit. */
	hit(key: string): RateLimitResult {
		if (this.disabled) {
			return { limited: false, remaining: this.max, retryAfterSeconds: 0 };
		}

		const now = this.now();
		this.hitsSincePrune += 1;
		if (this.hitsSincePrune >= this.pruneEvery) {
			this.prune(now);
		}

		let bucket = this.buckets.get(key);
		if (!bucket || bucket.resetAt <= now) {
			bucket = { count: 0, resetAt: now + this.windowMs };
			this.buckets.set(key, bucket);
		}

		bucket.count += 1;
		const retryAfterSeconds = Math.max(
			1,
			Math.ceil((bucket.resetAt - now) / 1000),
		);

		if (bucket.count > this.max) {
			return { limited: true, remaining: 0, retryAfterSeconds };
		}
		return {
			limited: false,
			remaining: this.max - bucket.count,
			retryAfterSeconds,
		};
	}

	/** Check without recording a hit. */
	isLimited(key: string): boolean {
		if (this.disabled) return false;
		const bucket = this.buckets.get(key);
		if (!bucket || bucket.resetAt <= this.now()) return false;
		return bucket.count >= this.max;
	}

	/** Forget a key (e.g. after a successful login). */
	reset(key: string): void {
		this.buckets.delete(key);
	}

	/** Drop all expired buckets. */
	prune(now: number = this.now()): void {
		this.hitsSincePrune = 0;
		for (const [key, bucket] of this.buckets) {
			if (bucket.resetAt <= now) this.buckets.delete(key);
		}
	}

	/** Number of live buckets (for tests/metrics). */
	get size(): number {
		return this.buckets.size;
	}
}

/** Standard 429 JSON response carrying a Retry-After header. */
export function rateLimitedResponse(result: RateLimitResult): Response {
	return Response.json(
		{ error: "Too many requests. Please try again later." },
		{
			status: 429,
			headers: { "Retry-After": String(result.retryAfterSeconds) },
		},
	);
}
