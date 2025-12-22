// PKCE helper functions
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

// Elements
const clientIdInput = document.getElementById("clientId") as HTMLInputElement;
const redirectUriInput = document.getElementById(
	"redirectUri",
) as HTMLInputElement;
const startBtn = document.getElementById("startBtn") as HTMLButtonElement;
const callbackSection = document.getElementById(
	"callbackSection",
) as HTMLElement;
const callbackInfo = document.getElementById("callbackInfo") as HTMLElement;
const exchangeBtn = document.getElementById("exchangeBtn") as HTMLButtonElement;
const resultSection = document.getElementById("resultSection") as HTMLElement;
const resultDiv = document.getElementById("result") as HTMLElement;

// Auto-fill redirect URI with current page URL
const currentUrl = window.location.origin + window.location.pathname;
redirectUriInput.value = currentUrl;

// Auto-fill client ID with a test URL
clientIdInput.value = window.location.origin;

// Check if we're handling a callback
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get("code");
const state = urlParams.get("state");
const error = urlParams.get("error");

if (error) {
	// OAuth error response
	showResult(
		`Error: ${error}\n${urlParams.get("error_description") || ""}`,
		"error",
	);
	resultSection.style.display = "block";
} else if (code && state) {
	// We have a callback with authorization code
	handleCallback(code, state);
}

// Start OAuth flow
startBtn.addEventListener("click", async () => {
	const clientId = clientIdInput.value.trim();
	const redirectUri = redirectUriInput.value.trim();

	if (!clientId || !redirectUri) {
		alert("Please fill in client ID and redirect URI");
		return;
	}

	// Get selected scopes
	const scopeCheckboxes = document.querySelectorAll(
		'input[name="scope"]:checked',
	);
	const scopes = Array.from(scopeCheckboxes).map(
		(cb) => (cb as HTMLInputElement).value,
	);

	if (scopes.length === 0) {
		alert("Please select at least one scope");
		return;
	}

	// Generate PKCE parameters
	const codeVerifier = generateRandomString(64);
	const codeChallenge = await sha256(codeVerifier);
	const state = generateRandomString(32);

	// Store PKCE values in localStorage for callback
	localStorage.setItem("oauth_code_verifier", codeVerifier);
	localStorage.setItem("oauth_state", state);
	localStorage.setItem("oauth_client_id", clientId);
	localStorage.setItem("oauth_redirect_uri", redirectUri);

	// Build authorization URL
	const authUrl = new URL("/auth/authorize", window.location.origin);
	authUrl.searchParams.set("response_type", "code");
	authUrl.searchParams.set("client_id", clientId);
	authUrl.searchParams.set("redirect_uri", redirectUri);
	authUrl.searchParams.set("state", state);
	authUrl.searchParams.set("code_challenge", codeChallenge);
	authUrl.searchParams.set("code_challenge_method", "S256");
	authUrl.searchParams.set("scope", scopes.join(" "));

	// Redirect to authorization endpoint
	window.location.href = authUrl.toString();
});

// Handle OAuth callback
function handleCallback(code: string, state: string) {
	const storedState = localStorage.getItem("oauth_state");

	if (state !== storedState) {
		showResult("Error: State mismatch (CSRF attack?)", "error");
		resultSection.style.display = "block";
		return;
	}

	callbackSection.style.display = "block";
	callbackInfo.innerHTML = `
		<p style="margin-bottom: 1rem;"><strong>Authorization Code:</strong><br><code style="word-break: break-all;">${code}</code></p>
		<p><strong>State:</strong> <code>${state}</code> ✓ (verified)</p>
	`;

	// Scroll to callback section
	callbackSection.scrollIntoView({ behavior: "smooth" });
}

// Exchange authorization code for user profile
exchangeBtn.addEventListener("click", async () => {
	const code = urlParams.get("code");
	const codeVerifier = localStorage.getItem("oauth_code_verifier");
	const clientId = localStorage.getItem("oauth_client_id");
	const redirectUri = localStorage.getItem("oauth_redirect_uri");

	if (!code || !codeVerifier || !clientId || !redirectUri) {
		showResult("Error: Missing OAuth parameters", "error");
		resultSection.style.display = "block";
		return;
	}

	exchangeBtn.disabled = true;
	exchangeBtn.textContent = "exchanging...";

	try {
		const response = await fetch("/auth/token", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
			},
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

			// Clean up localStorage
			localStorage.removeItem("oauth_code_verifier");
			localStorage.removeItem("oauth_state");
			localStorage.removeItem("oauth_client_id");
			localStorage.removeItem("oauth_redirect_uri");
		}
	} catch (error) {
		showResult(`Error: ${(error as Error).message}`, "error");
	} finally {
		exchangeBtn.disabled = false;
		exchangeBtn.textContent = "exchange code for profile";
		resultSection.style.display = "block";
		resultSection.scrollIntoView({ behavior: "smooth" });
	}
});

function showResult(text: string, type: "success" | "error") {
	if (type === "success" && text.includes("{")) {
		// Extract and parse JSON from success message
		const jsonStart = text.indexOf("{");
		const jsonStr = text.substring(jsonStart);
		const prefix = text.substring(0, jsonStart);

		try {
			const data = JSON.parse(jsonStr);
			resultDiv.innerHTML = `${prefix}<pre style="margin: 0; font-family: 'Space Grotesk', monospace;">${syntaxHighlightJSON(data)}</pre>`;
		} catch {
			resultDiv.textContent = text;
		}
	} else {
		resultDiv.textContent = text;
	}
	resultDiv.className = `result show ${type}`;
}

function syntaxHighlightJSON(obj: any): string {
	const json = JSON.stringify(obj, null, 2);
	return json.replace(
		/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,
		(match) => {
			let cls = "json-number";
			if (/^"/.test(match)) {
				if (/:$/.test(match)) {
					cls = "json-key";
				} else {
					cls = "json-string";
				}
			} else if (/true|false/.test(match)) {
				cls = "json-boolean";
			} else if (/null/.test(match)) {
				cls = "json-null";
			}
			return `<span class="${cls}">${match}</span>`;
		},
	);
}
