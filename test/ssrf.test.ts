// SSRF guard rails: the CGNAT range must be blocked like any other internal
// range, and response bodies must be bounded so a remote cannot stream forever.

import { describe, expect, test } from "bun:test";
import {
	readBodyCapped,
	validateExternalURL,
} from "../src/lib/ssrf-safe-fetch";

describe("validateExternalURL: 100.64.0.0/10 (CGNAT / Tailscale)", () => {
	const blocked = [
		"100.64.0.0",
		"100.64.0.1",
		"100.69.255.255",
		"100.70.1.1",
		"100.99.1.1",
		"100.100.100.200", // Alibaba Cloud metadata
		"100.119.0.1",
		"100.120.0.1",
		"100.127.255.255",
	];
	for (const ip of blocked) {
		test(`blocks ${ip}`, () => {
			const result = validateExternalURL(`http://${ip}/metadata`);
			expect(result.safe).toBe(false);
			expect(result.error).toContain("private/reserved");
		});
	}

	const allowed = [
		"100.63.255.255",
		"100.128.0.0",
		"100.0.0.1",
		"100.200.1.1",
		"101.64.0.1",
		"1.1.1.1",
	];
	for (const ip of allowed) {
		test(`allows ${ip}`, () => {
			expect(validateExternalURL(`https://${ip}/`).safe).toBe(true);
		});
	}

	test("the mapped-IPv6 and NAT64 forms of a CGNAT address are blocked too", () => {
		// ::ffff:100.64.0.1
		expect(validateExternalURL("http://[::ffff:100.64.0.1]/").safe).toBe(false);
		// ::ffff:6440:0001 == 100.64.0.1
		expect(validateExternalURL("http://[::ffff:6440:1]/").safe).toBe(false);
		// 64:ff9b::6440:1 == 100.64.0.1 via NAT64
		expect(validateExternalURL("http://[64:ff9b::6440:1]/").safe).toBe(false);
	});

	test("the pre-existing ranges are still blocked", () => {
		for (const ip of [
			"127.0.0.1",
			"10.0.0.1",
			"169.254.169.254",
			"192.168.1.1",
			"172.16.0.1",
		]) {
			expect(validateExternalURL(`http://${ip}/`).safe).toBe(false);
		}
	});
});

function streamOf(chunks: Uint8Array[], opts: { hang?: boolean } = {}) {
	let cancelled = false;
	const stream = new ReadableStream<Uint8Array>({
		async pull(controller) {
			if (chunks.length > 0) {
				controller.enqueue(chunks.shift() as Uint8Array);
				return;
			}
			if (opts.hang) {
				// Never close: simulate a remote that keeps the connection open.
				await new Promise(() => {});
				return;
			}
			controller.close();
		},
		cancel() {
			cancelled = true;
		},
	});
	return { stream, wasCancelled: () => cancelled };
}

const enc = new TextEncoder();

describe("readBodyCapped", () => {
	test("returns the whole body when under the cap", async () => {
		const { stream } = streamOf([enc.encode("hello "), enc.encode("world")]);
		const result = await readBodyCapped(new Response(stream), 1024);
		expect(result).toEqual({ text: "hello world", truncated: false });
	});

	test("a body exactly at the cap is not reported as truncated", async () => {
		const { stream } = streamOf([enc.encode("abcd"), enc.encode("efgh")]);
		const result = await readBodyCapped(new Response(stream), 8);
		expect(result).toEqual({ text: "abcdefgh", truncated: false });
	});

	test("truncates at the cap, cancels the stream, and says so", async () => {
		const chunks: Uint8Array[] = [];
		for (let i = 0; i < 100; i++) chunks.push(enc.encode("x".repeat(100)));
		const { stream, wasCancelled } = streamOf(chunks);

		const result = await readBodyCapped(new Response(stream), 250);
		expect(result).not.toBeNull();
		expect(result?.truncated).toBe(true);
		expect(result?.text.length).toBe(250);
		expect(result?.text).toBe("x".repeat(250));
		expect(wasCancelled()).toBe(true);
	});

	test("stops an endless body at the cap instead of hanging", async () => {
		let pulls = 0;
		const endless = new ReadableStream<Uint8Array>({
			pull(controller) {
				pulls += 1;
				controller.enqueue(enc.encode("y".repeat(1000)));
			},
		});
		const result = await readBodyCapped(new Response(endless), 16 * 1024);
		expect(result?.truncated).toBe(true);
		expect(result?.text.length).toBe(16 * 1024);
		// A little read-ahead is fine; megabytes would mean the cap is not working.
		expect(pulls).toBeLessThan(64);
	});

	test("returns null when the body does not finish within the read timeout", async () => {
		const { stream, wasCancelled } = streamOf([enc.encode("partial")], {
			hang: true,
		});
		const started = Date.now();
		const result = await readBodyCapped(new Response(stream), 1024, {
			timeout: 50,
		});
		expect(result).toBeNull();
		expect(wasCancelled()).toBe(true);
		expect(Date.now() - started).toBeLessThan(2000);
	});

	test("an empty body reads as empty text", async () => {
		const result = await readBodyCapped(new Response(null), 1024);
		expect(result).toEqual({ text: "", truncated: false });
	});

	test("works with a plain string Response too", async () => {
		const result = await readBodyCapped(new Response('{"a":1}'), 1024);
		expect(result).toEqual({ text: '{"a":1}', truncated: false });
	});
});
