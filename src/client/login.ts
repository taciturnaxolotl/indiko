import {
	startAuthentication,
	startRegistration,
} from "@simplewebauthn/browser";

const loginForm = document.getElementById("loginForm") as HTMLFormElement;
const registerForm = document.getElementById("registerForm") as HTMLFormElement;
const ldapForm = document.getElementById("ldapForm") as HTMLFormElement;
const message = document.getElementById("message") as HTMLDivElement;

let pendingLdapUsername: string | null = null;

// Check if registration is allowed on page load
async function checkRegistrationAllowed() {
	try {
		// Check for invite code in URL
		const urlParams = new URLSearchParams(window.location.search);
		const inviteCode = urlParams.get("invite");

		if (inviteCode) {
			// Check if username is locked (from LDAP flow)
			const lockedUsername = urlParams.get("username");
			const registerUsernameInput = document.getElementById(
				"registerUsername",
			) as HTMLInputElement;

			// Fetch invite details to show message
			try {
				const testUsername = lockedUsername || "temp";
				const response = await fetch("/auth/register/options", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ username: testUsername, inviteCode }),
				});

				if (response.ok) {
					const data = await response.json();
					if (data.inviteMessage) {
						showMessage(data.inviteMessage, "success", true);
					}
				}
			} catch {
				// Ignore errors, just won't show message
			}

			// Show registration form with invite
			const subtitleElement = document.querySelector(".subtitle");
			if (subtitleElement) {
				subtitleElement.textContent = "create your account";
			}

			// If username is locked from LDAP, pre-fill and disable
			if (lockedUsername) {
				registerUsernameInput.value = lockedUsername;
				registerUsernameInput.readOnly = true;
				registerUsernameInput.style.opacity = "0.7";
				registerUsernameInput.style.cursor = "not-allowed";
			} else {
				registerUsernameInput.placeholder = "choose username";
			}

			(
				document
					.getElementById("registerBtn")
					?.querySelector("button") as HTMLButtonElement
			).textContent = "create account";
			loginForm.style.display = "none";
			registerForm.style.display = "block";
			return;
		}

		const response = await fetch("/auth/can-register");
		const { canRegister } = await response.json();

		if (canRegister) {
			// First user - show as admin registration
			const subtitleElement = document.querySelector(".subtitle");
			if (subtitleElement) {
				subtitleElement.textContent = "create admin account";
			}
			(
				document.getElementById("registerUsername") as HTMLInputElement
			).placeholder = "admin username";
			(
				document
					.getElementById("registerBtn")
					?.querySelector("button") as HTMLButtonElement
			).textContent = "create admin account";
			// Hide login form for first setup
			loginForm.style.display = "none";
			registerForm.style.display = "block";
		}
	} catch (error) {
		console.error("Failed to check registration status:", error);
	}
}

checkRegistrationAllowed();

// Conditional UI: show passkeys in the browser's autofill dropdown
async function initConditionalUI() {
	try {
		const optionsRes = await fetch("/auth/login/options", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ conditional: true }),
		});

		if (!optionsRes.ok) return;

		const options = await optionsRes.json();

		// This call blocks until the user picks a passkey from the autofill menu
		const authResponse = await startAuthentication({
			optionsJSON: options,
			useBrowserAutofill: true,
		});

		const verifyRes = await fetch("/auth/login/verify", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ response: authResponse, conditional: true }),
		});

		if (!verifyRes.ok) {
			const error = await verifyRes.json();
			showMessage(error.error || "Authentication failed");
			return;
		}

		const { token } = await verifyRes.json();
		localStorage.setItem("indiko_session", token);
		showMessage("Login successful!", "success");
		setTimeout(() => {
			window.location.href = "/";
		}, 1000);
	} catch {
		// User cancelled or browser doesn't support conditional UI — fall back to manual flow
	}
}

initConditionalUI();

function showMessage(
	text: string,
	type: "error" | "success" = "error",
	persist = false,
) {
	message.textContent = text;
	message.className = `message show ${type}`;
	if (!persist) {
		setTimeout(() => message.classList.remove("show"), 5000);
	}
}

// Login flow
loginForm.addEventListener("submit", async (e) => {
	e.preventDefault();
	const username = (document.getElementById("username") as HTMLInputElement)
		.value;
	const loginBtn = document
		.getElementById("loginBtn")
		?.querySelector("button") as HTMLButtonElement;

	try {
		loginBtn.disabled = true;
		loginBtn.textContent = "preparing...";

		// Get authentication options
		const optionsRes = await fetch("/auth/login/options", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ username }),
		});

		if (!optionsRes.ok) {
			const error = await optionsRes.json();
			throw new Error(error.error || "Failed to get auth options");
		}

		const options = await optionsRes.json();

		// Check if LDAP verification is required (user exists in LDAP but not locally)
		if (options.ldapVerificationRequired) {
			showLdapPasswordPrompt(options.username);
			loginBtn.disabled = false;
			loginBtn.textContent = "sign in";
			return;
		}

		loginBtn.textContent = "use your passkey...";

		// Start authentication
		const authResponse = await startAuthentication(options);

		loginBtn.textContent = "verifying...";

		// Verify authentication
		const verifyRes = await fetch("/auth/login/verify", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ username, response: authResponse }),
		});

		if (!verifyRes.ok) {
			const error = await verifyRes.json();
			throw new Error(error.error || "Authentication failed");
		}

		const { token } = await verifyRes.json();
		localStorage.setItem("indiko_session", token);

		showMessage("Login successful!", "success");

		// Check for return URL parameter
		const urlParams = new URLSearchParams(window.location.search);
		const returnUrl = urlParams.get("return") || "/";

		const redirectTimer = setTimeout(() => {
			window.location.href = returnUrl;
		}, 1000);
		redirectTimer as unknown as number;
	} catch (error) {
		showMessage((error as Error).message || "Authentication failed");
		loginBtn.disabled = false;
		loginBtn.textContent = "sign in";
	}
});

// Registration flow
registerForm.addEventListener("submit", async (e) => {
	e.preventDefault();
	const username = (
		document.getElementById("registerUsername") as HTMLInputElement
	).value;
	const registerBtn = document
		.getElementById("registerBtn")
		?.querySelector("button") as HTMLButtonElement;

	try {
		registerBtn.disabled = true;
		registerBtn.textContent = "preparing...";

		// Get invite code from URL if present
		const urlParams = new URLSearchParams(window.location.search);
		const inviteCode = urlParams.get("invite");

		// Get registration options
		const optionsRes = await fetch("/auth/register/options", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ username, inviteCode }),
		});

		if (!optionsRes.ok) {
			const error = await optionsRes.json();
			throw new Error(error.error || "Failed to get registration options");
		}

		const options = await optionsRes.json();

		registerBtn.textContent = "create your passkey...";

		// Start registration
		const regResponse = await startRegistration(options);

		registerBtn.textContent = "verifying...";

		// Verify registration
		const verifyRes = await fetch("/auth/register/verify", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				username,
				response: regResponse,
				challenge: options.challenge,
				inviteCode,
			}),
		});

		if (!verifyRes.ok) {
			const error = await verifyRes.json();
			throw new Error(error.error || "Registration failed");
		}

		const { token } = await verifyRes.json();
		localStorage.setItem("indiko_session", token);

		showMessage("Registration successful!", "success");

		// Check for return URL: first sessionStorage (from LDAP flow), then URL param, fallback to /
		const storedRedirect = sessionStorage.getItem("postRegistrationRedirect");
		const returnUrl = storedRedirect || urlParams.get("return") || "/";

		// Clear the stored redirect after use
		if (storedRedirect) {
			sessionStorage.removeItem("postRegistrationRedirect");
		}

		const redirectTimer = setTimeout(() => {
			window.location.href = returnUrl;
		}, 1000);
		redirectTimer as unknown as number;
	} catch (error) {
		showMessage((error as Error).message || "Registration failed");
		registerBtn.disabled = false;
		registerBtn.textContent = "register passkey";
	}
});

// LDAP verification flow
function showLdapPasswordPrompt(username: string) {
	pendingLdapUsername = username;

	// Update UI to show LDAP form
	const subtitleElement = document.querySelector(".subtitle");
	if (subtitleElement) {
		subtitleElement.textContent = "verify your LDAP password";
	}

	// Update LDAP form username display
	const ldapUsernameSpan = document.getElementById("ldapUsername");
	if (ldapUsernameSpan) {
		ldapUsernameSpan.textContent = username;
	}

	// Show LDAP form, hide others
	loginForm.style.display = "none";
	registerForm.style.display = "none";
	ldapForm.style.display = "block";

	showMessage(
		"This username exists in the linked LDAP directory. Enter your LDAP password to create your account.",
		"success",
		true,
	);
}

ldapForm.addEventListener("submit", async (e) => {
	e.preventDefault();

	if (!pendingLdapUsername) {
		showMessage("No username pending for LDAP verification");
		return;
	}

	const password = (document.getElementById("ldapPassword") as HTMLInputElement)
		.value;
	const ldapBtn = document
		.getElementById("ldapBtn")
		?.querySelector("button") as HTMLButtonElement;

	try {
		ldapBtn.disabled = true;
		ldapBtn.textContent = "verifying...";

		// Get return URL for after registration
		const urlParams = new URLSearchParams(window.location.search);
		const returnUrl = urlParams.get("return") || "/";

		// Verify LDAP credentials
		const verifyRes = await fetch("/api/ldap-verify", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				username: pendingLdapUsername,
				password: password,
				returnUrl: returnUrl,
			}),
		});

		if (!verifyRes.ok) {
			const error = await verifyRes.json();
			throw new Error(error.error || "LDAP verification failed");
		}

		const result = await verifyRes.json();

		if (result.success) {
			showMessage(
				"LDAP verification successful! Redirecting to setup...",
				"success",
			);

			// Store return URL for after registration completes
			if (result.returnUrl) {
				sessionStorage.setItem("postRegistrationRedirect", result.returnUrl);
			}

			// Redirect to registration with the invite code and locked username
			const registerUrl = `/login?invite=${encodeURIComponent(result.inviteCode)}&username=${encodeURIComponent(result.username)}`;

			setTimeout(() => {
				window.location.href = registerUrl;
			}, 1000);
		}
	} catch (error) {
		showMessage((error as Error).message || "LDAP verification failed");
		ldapBtn.disabled = false;
		ldapBtn.textContent = "verify & continue";
	}
});
