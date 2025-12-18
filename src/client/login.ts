import { startAuthentication, startRegistration } from '@simplewebauthn/browser';

const loginForm = document.getElementById('loginForm') as HTMLFormElement;
const registerForm = document.getElementById('registerForm') as HTMLFormElement;
const message = document.getElementById('message') as HTMLDivElement;

// Check if registration is allowed on page load
async function checkRegistrationAllowed() {
	try {
		// Check for invite code in URL
		const urlParams = new URLSearchParams(window.location.search);
		const inviteCode = urlParams.get('invite');

		if (inviteCode) {
			// Fetch invite details to show message
			try {
				const response = await fetch('/auth/register/options', {
					method: 'POST',
					headers: {'Content-Type': 'application/json'},
					body: JSON.stringify({username: 'temp', inviteCode})
				});

				if (response.ok) {
					const data = await response.json();
					if (data.inviteMessage) {
						showMessage(data.inviteMessage, 'success', true);
					}
				}
			} catch {
				// Ignore errors, just won't show message
			}

			// Show registration form with invite
			const subtitleElement = document.querySelector('.subtitle');
			if (subtitleElement) {
				subtitleElement.textContent = 'create your account';
			}
			(document.getElementById('registerUsername') as HTMLInputElement).placeholder = 'choose username';
			(document.getElementById('registerBtn') as HTMLButtonElement).textContent = 'create account';
			loginForm.style.display = 'none';
			registerForm.style.display = 'block';
			return;
		}

		const response = await fetch('/auth/can-register');
		const {canRegister} = await response.json();

		if (canRegister) {
			// First user - show as admin registration
			const subtitleElement = document.querySelector('.subtitle');
			if (subtitleElement) {
				subtitleElement.textContent = 'create admin account';
			}
			(document.getElementById('registerUsername') as HTMLInputElement).placeholder = 'admin username';
			(document.getElementById('registerBtn') as HTMLButtonElement).textContent = 'create admin account';
			// Hide login form for first setup
			loginForm.style.display = 'none';
			registerForm.style.display = 'block';
		}
	} catch (error) {
		console.error('Failed to check registration status:', error);
	}
}

checkRegistrationAllowed();

function showMessage(text: string, type: 'error' | 'success' = 'error', persist = false) {
	message.textContent = text;
	message.className = `message show ${type}`;
	if (!persist) {
		setTimeout(() => message.classList.remove('show'), 5000);
	}
}

// Login flow
loginForm.addEventListener('submit', async (e) => {
	e.preventDefault();
	const username = (document.getElementById('username') as HTMLInputElement).value;
	const loginBtn = document.getElementById('loginBtn') as HTMLButtonElement;

	try {
		loginBtn.disabled = true;
		loginBtn.textContent = 'preparing...';

		// Get authentication options
		const optionsRes = await fetch('/auth/login/options', {
			method: 'POST',
			headers: {'Content-Type': 'application/json'},
			body: JSON.stringify({username})
		});

		if (!optionsRes.ok) {
			const error = await optionsRes.json();
			throw new Error(error.error || 'Failed to get auth options');
		}

		const options = await optionsRes.json();

		loginBtn.textContent = 'use your passkey...';

		// Start authentication
		const authResponse = await startAuthentication(options);

		loginBtn.textContent = 'verifying...';

		// Verify authentication
		const verifyRes = await fetch('/auth/login/verify', {
			method: 'POST',
			headers: {'Content-Type': 'application/json'},
			body: JSON.stringify({username, response: authResponse})
		});

		if (!verifyRes.ok) {
			const error = await verifyRes.json();
			throw new Error(error.error || 'Authentication failed');
		}

		const {token} = await verifyRes.json();
		localStorage.setItem('indiko_session', token);

		showMessage('Login successful!', 'success');
		
		// Check for return URL parameter
		const urlParams = new URLSearchParams(window.location.search);
		const returnUrl = urlParams.get('return') || '/';
		
		const redirectTimer = setTimeout(() => {
			window.location.href = returnUrl;
		}, 1000);
		(redirectTimer as unknown as number);

	} catch (error) {
		showMessage((error as Error).message || 'Authentication failed');
		loginBtn.disabled = false;
		loginBtn.textContent = 'sign in';
	}
});

// Registration flow
registerForm.addEventListener('submit', async (e) => {
	e.preventDefault();
	const username = (document.getElementById('registerUsername') as HTMLInputElement).value;
	const registerBtn = document.getElementById('registerBtn') as HTMLButtonElement;

	try {
		registerBtn.disabled = true;
		registerBtn.textContent = 'preparing...';

		// Get invite code from URL if present
		const urlParams = new URLSearchParams(window.location.search);
		const inviteCode = urlParams.get('invite');

		// Get registration options
		const optionsRes = await fetch('/auth/register/options', {
			method: 'POST',
			headers: {'Content-Type': 'application/json'},
			body: JSON.stringify({username, inviteCode})
		});

		if (!optionsRes.ok) {
			const error = await optionsRes.json();
			throw new Error(error.error || 'Failed to get registration options');
		}

		const options = await optionsRes.json();

		registerBtn.textContent = 'create your passkey...';

		// Start registration
		const regResponse = await startRegistration(options);

		registerBtn.textContent = 'verifying...';

		// Verify registration
		const verifyRes = await fetch('/auth/register/verify', {
			method: 'POST',
			headers: {'Content-Type': 'application/json'},
			body: JSON.stringify({username, response: regResponse, challenge: options.challenge, inviteCode})
		});

		if (!verifyRes.ok) {
			const error = await verifyRes.json();
			throw new Error(error.error || 'Registration failed');
		}

		const {token} = await verifyRes.json();
		localStorage.setItem('indiko_session', token);

		showMessage('Registration successful!', 'success');
		
		// Check for return URL parameter
		const returnUrl = urlParams.get('return') || '/';
		
		const redirectTimer = setTimeout(() => {
			window.location.href = returnUrl;
		}, 1000);
		(redirectTimer as unknown as number);

	} catch (error) {
		showMessage((error as Error).message || 'Registration failed');
		registerBtn.disabled = false;
		registerBtn.textContent = 'register passkey';
	}
});
