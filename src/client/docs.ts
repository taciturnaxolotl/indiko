import hljs from "highlight.js/lib/core";
import css from "highlight.js/lib/languages/css";
import json from "highlight.js/lib/languages/json";
import xml from "highlight.js/lib/languages/xml";
import "./ds";

hljs.registerLanguage("json", json);
hljs.registerLanguage("css", css);
hljs.registerLanguage("xml", xml);
hljs.registerLanguage("html", xml);

// The button snippet is code that documents code, so it lives client-side
// and gets highlighted + made copyable here.
const buttonCodeRaw = `<!-- Add Google Fonts to your <head> -->
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300..700&display=swap" rel="stylesheet">

<!-- Button HTML -->
<a href="YOUR_OAUTH_URL_HERE" class="indiko-button">
  Sign in with Indiko
</a>

<style>
  .indiko-button {
    position: relative;
    display: inline-block;
    padding: 1rem 2rem;
    background: #ab4967;
    color: #d9d0de;
    border: 4px solid #26242b;
    font-size: 1rem;
    font-weight: 700;
    text-decoration: none;
    font-family: 'Space Grotesk', sans-serif;
    text-transform: uppercase;
    letter-spacing: 0.1rem;
    box-shadow: 6px 6px 0 #26242b;
    transition: all 0.15s ease;
  }

  .indiko-button::before {
    content: '';
    position: absolute;
    top: -4px;
    left: -4px;
    right: -4px;
    bottom: -4px;
    background: transparent;
    border: 4px solid #a04668;
    pointer-events: none;
    transition: all 0.15s ease;
  }

  .indiko-button:hover {
    transform: translate(3px, 3px);
    box-shadow: 3px 3px 0 #26242b;
  }

  .indiko-button:hover::before {
    top: -7px;
    left: -7px;
    right: -7px;
    bottom: -7px;
  }

  .indiko-button:active {
    transform: translate(6px, 6px);
    box-shadow: 0 0 0 #26242b;
  }
</style>`;

// PKCE helpers
function generateRandomString(length: number): string {
	const array = new Uint8Array(length);
	crypto.getRandomValues(array);
	return btoa(String.fromCharCode(...array))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=/g, "");
}

async function sha256(plain: string): Promise<string> {
	const encoder = new TextEncoder();
	const data = encoder.encode(plain);
	const hash = await crypto.subtle.digest("SHA-256", data);
	const hashArray = Array.from(new Uint8Array(hash));
	return btoa(String.fromCharCode(...hashArray))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=/g, "");
}

function $(id: string): HTMLElement | null {
	return document.getElementById(id);
}

function initButtonSnippet() {
	const codeEl = $("buttonCode") as HTMLElement | null;
	if (codeEl) {
		codeEl.innerHTML = hljs.highlight(buttonCodeRaw, {
			language: "xml",
		}).value;
		codeEl.classList.add("hljs");
	}

	const copyBtn = $("copyButtonCode") as HTMLButtonElement | null;
	copyBtn?.addEventListener("click", async () => {
		try {
			await navigator.clipboard.writeText(buttonCodeRaw);
			copyBtn.textContent = "copied! ✓";
			setTimeout(() => {
				copyBtn.textContent = "copy button code";
			}, 2000);
		} catch {
			// Clipboard unavailable
		}
	});

	$("demoButton")?.addEventListener("click", (e) => e.preventDefault());
}

function initTester() {
	const clientIdInput = $("clientId") as HTMLInputElement | null;
	const redirectUriInput = $("redirectUri") as HTMLInputElement | null;
	const startBtn = $("startBtn") as HTMLButtonElement | null;
	const callbackSection = $("callbackSection");
	const callbackInfo = $("callbackInfo");
	const exchangeBtn = $("exchangeBtn") as HTMLButtonElement | null;
	const resultSection = $("resultSection");
	const resultDiv = $("result");

	if (!clientIdInput || !redirectUriInput || !startBtn || !exchangeBtn) return;

	redirectUriInput.value = window.location.origin + window.location.pathname;
	clientIdInput.value = window.location.origin;

	const urlParams = new URLSearchParams(window.location.search);
	const code = urlParams.get("code");
	const state = urlParams.get("state");
	const error = urlParams.get("error");

	function showResult(text: string, type: "success" | "error") {
		if (!resultDiv) return;
		if (type === "success" && text.includes("{")) {
			const jsonStart = text.indexOf("{");
			const jsonStr = text.substring(jsonStart);
			const prefix = text.substring(0, jsonStart).trim();
			try {
				const data = JSON.parse(jsonStr);
				const formatted = JSON.stringify(data, null, 2);
				const highlighted = hljs.highlight(formatted, {
					language: "json",
				}).value;
				resultDiv.innerHTML = `<strong style="color: var(--accent); font-size: 1.125rem; display: block; margin-bottom: 1rem;">${prefix}</strong><pre style="margin: 0;"><code class="hljs">${highlighted}</code></pre>`;
			} catch {
				resultDiv.textContent = text;
			}
		} else {
			resultDiv.textContent = text;
		}
		resultDiv.className = `result show ${type}`;
	}

	function handleCallback(authCode: string, returnedState: string) {
		const storedState = localStorage.getItem("oauth_state");
		if (returnedState !== storedState) {
			showResult("Error: State mismatch (CSRF attack?)", "error");
			if (resultSection) resultSection.style.display = "block";
			return;
		}

		if (callbackSection) callbackSection.style.display = "block";
		if (callbackInfo) {
			callbackInfo.innerHTML = `
				<p style="margin-bottom: 1rem;"><strong>Authorization Code:</strong><br><code style="word-break: break-all;">${authCode}</code></p>
				<p><strong>State:</strong> <code>${returnedState}</code> ✓ (verified)</p>
			`;
		}
		callbackSection?.scrollIntoView({ behavior: "smooth" });
	}

	if (error) {
		showResult(
			`Error: ${error}\n${urlParams.get("error_description") || ""}`,
			"error",
		);
		if (resultSection) resultSection.style.display = "block";
	} else if (code && state) {
		handleCallback(code, state);
	}

	startBtn.addEventListener("click", async () => {
		const clientId = clientIdInput.value.trim();
		const redirectUri = redirectUriInput.value.trim();

		if (!clientId || !redirectUri) {
			return;
		}

		const scopeCheckboxes = document.querySelectorAll(
			'input[name="scope"]:checked',
		);
		const scopes = Array.from(scopeCheckboxes).map(
			(cb) => (cb as HTMLInputElement).value,
		);

		if (scopes.length === 0) return;

		const codeVerifier = generateRandomString(64);
		const codeChallenge = await sha256(codeVerifier);
		const state = generateRandomString(32);

		localStorage.setItem("oauth_code_verifier", codeVerifier);
		localStorage.setItem("oauth_state", state);
		localStorage.setItem("oauth_client_id", clientId);
		localStorage.setItem("oauth_redirect_uri", redirectUri);

		const authUrl = new URL("/auth/authorize", window.location.origin);
		authUrl.searchParams.set("response_type", "code");
		authUrl.searchParams.set("client_id", clientId);
		authUrl.searchParams.set("redirect_uri", redirectUri);
		authUrl.searchParams.set("state", state);
		authUrl.searchParams.set("code_challenge", codeChallenge);
		authUrl.searchParams.set("code_challenge_method", "S256");
		authUrl.searchParams.set("scope", scopes.join(" "));

		window.location.href = authUrl.toString();
	});

	exchangeBtn.addEventListener("click", async () => {
		const code = urlParams.get("code");
		const codeVerifier = localStorage.getItem("oauth_code_verifier");
		const clientId = localStorage.getItem("oauth_client_id");
		const redirectUri = localStorage.getItem("oauth_redirect_uri");

		if (!code || !codeVerifier || !clientId || !redirectUri) {
			showResult("Error: Missing OAuth parameters", "error");
			if (resultSection) resultSection.style.display = "block";
			return;
		}

		exchangeBtn.disabled = true;
		exchangeBtn.textContent = "exchanging...";

		try {
			const response = await fetch("/auth/token", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					grant_type: "authorization_code",
					code,
					client_id: clientId,
					redirect_uri: redirectUri,
					code_verifier: codeVerifier,
				}),
			});

			const data = await response.json();

			if (!response.ok) {
				showResult(
					`Error: ${data.error}\n${data.error_description || ""}`,
					"error",
				);
			} else {
				showResult(
					`Success! User authenticated:\n\n${JSON.stringify(data, null, 2)}`,
					"success",
				);
				localStorage.removeItem("oauth_code_verifier");
				localStorage.removeItem("oauth_state");
				localStorage.removeItem("oauth_client_id");
				localStorage.removeItem("oauth_redirect_uri");
			}
		} catch (err) {
			showResult(`Error: ${(err as Error).message}`, "error");
		} finally {
			exchangeBtn.disabled = false;
			exchangeBtn.textContent = "exchange code for profile";
			if (resultSection) {
				resultSection.style.display = "block";
				resultSection.scrollIntoView({ behavior: "smooth" });
			}
		}
	});
}

function initCopyMd() {
	const btn = $("copyMdBtn") as HTMLButtonElement | null;
	btn?.addEventListener("click", async () => {
		try {
			const res = await fetch("/docs.md");
			const md = await res.text();
			await navigator.clipboard.writeText(md);
			btn.textContent = "copied! ✓";
			setTimeout(() => {
				btn.textContent = "copy as markdown";
			}, 2000);
		} catch {
			// Clipboard unavailable
		}
	});
}

function init() {
	initCopyMd();
	initButtonSnippet();
	initTester();
}

if (document.readyState === "complete") {
	init();
} else {
	document.addEventListener("DOMContentLoaded", init);
}
