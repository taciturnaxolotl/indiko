// JSON syntax highlighter
function highlightJSON(json: string): string {
	return json
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"([^"]+)":/g, '<span class="json-key">"$1"</span>:')
		.replace(/: "([^"]*)"/g, ': <span class="json-string">"$1"</span>')
		.replace(/: (\d+\.?\d*)/g, ': <span class="json-number">$1</span>')
		.replace(/: (true|false|null)/g, ': <span class="json-boolean">$1</span>');
}

// PKCE helper functions
function generateRandomString(length: number): string {
	const array = new Uint8Array(length);
	crypto.getRandomValues(array);
	return btoa(String.fromCharCode(...array))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=/g, '');
}

async function sha256(plain: string): Promise<string> {
	const encoder = new TextEncoder();
	const data = encoder.encode(plain);
	const hash = await crypto.subtle.digest('SHA-256', data);
	const hashArray = Array.from(new Uint8Array(hash));
	return btoa(String.fromCharCode(...hashArray))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=/g, '');
}

// Elements
const clientIdInput = document.getElementById('clientId') as HTMLInputElement;
const redirectUriInput = document.getElementById('redirectUri') as HTMLInputElement;
const startBtn = document.getElementById('startBtn') as HTMLButtonElement;
const callbackSection = document.getElementById('callbackSection') as HTMLElement;
const callbackInfo = document.getElementById('callbackInfo') as HTMLElement;
const exchangeBtn = document.getElementById('exchangeBtn') as HTMLButtonElement;
const resultSection = document.getElementById('resultSection') as HTMLElement;
const resultDiv = document.getElementById('result') as HTMLElement;
const copyMarkdownBtn = document.getElementById('copyMarkdownBtn') as HTMLButtonElement;

// Auto-fill redirect URI with current page URL
const currentUrl = window.location.origin + window.location.pathname;
redirectUriInput.value = currentUrl;

// Auto-fill client ID with a test URL
clientIdInput.value = window.location.origin;

// Update documentation examples with current origin
const origin = window.location.origin;
const authUrlEl = document.getElementById('authUrl');
const tokenUrlEl = document.getElementById('tokenUrl');
const profileMeUrlEl = document.getElementById('profileMeUrl');

if (authUrlEl) authUrlEl.textContent = `${origin}/auth/authorize`;
if (tokenUrlEl) tokenUrlEl.textContent = `${origin}/auth/token`;
if (profileMeUrlEl) profileMeUrlEl.textContent = `"${origin}/u/username"`;

// Check if we're handling a callback
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');
const state = urlParams.get('state');
const error = urlParams.get('error');

if (error) {
	// OAuth error response
	showResult(`Error: ${error}\n${urlParams.get('error_description') || ''}`, 'error');
	resultSection.style.display = 'block';
} else if (code && state) {
	// We have a callback with authorization code
	handleCallback(code, state);
}

// Start OAuth flow
startBtn.addEventListener('click', async () => {
	const clientId = clientIdInput.value.trim();
	const redirectUri = redirectUriInput.value.trim();

	if (!clientId || !redirectUri) {
		alert('Please fill in client ID and redirect URI');
		return;
	}

	// Get selected scopes
	const scopeCheckboxes = document.querySelectorAll('input[name="scope"]:checked');
	const scopes = Array.from(scopeCheckboxes).map((cb) => (cb as HTMLInputElement).value);

	if (scopes.length === 0) {
		alert('Please select at least one scope');
		return;
	}

	// Generate PKCE parameters
	const codeVerifier = generateRandomString(64);
	const codeChallenge = await sha256(codeVerifier);
	const state = generateRandomString(32);

	// Store PKCE values in localStorage for callback
	localStorage.setItem('oauth_code_verifier', codeVerifier);
	localStorage.setItem('oauth_state', state);
	localStorage.setItem('oauth_client_id', clientId);
	localStorage.setItem('oauth_redirect_uri', redirectUri);

	// Build authorization URL
	const authUrl = new URL('/auth/authorize', window.location.origin);
	authUrl.searchParams.set('response_type', 'code');
	authUrl.searchParams.set('client_id', clientId);
	authUrl.searchParams.set('redirect_uri', redirectUri);
	authUrl.searchParams.set('state', state);
	authUrl.searchParams.set('code_challenge', codeChallenge);
	authUrl.searchParams.set('code_challenge_method', 'S256');
	authUrl.searchParams.set('scope', scopes.join(' '));

	// Redirect to authorization endpoint
	window.location.href = authUrl.toString();
});

// Handle OAuth callback
function handleCallback(code: string, state: string) {
	const storedState = localStorage.getItem('oauth_state');

	if (state !== storedState) {
		showResult('Error: State mismatch (CSRF attack?)', 'error');
		resultSection.style.display = 'block';
		return;
	}

	callbackSection.style.display = 'block';
	callbackInfo.innerHTML = `
		<p style="margin-bottom: 1rem;"><strong>Authorization Code:</strong><br><code style="word-break: break-all;">${code}</code></p>
		<p><strong>State:</strong> <code>${state}</code> ✓ (verified)</p>
	`;

	// Scroll to callback section
	callbackSection.scrollIntoView({ behavior: 'smooth' });
}

// Exchange authorization code for user profile
exchangeBtn.addEventListener('click', async () => {
	const code = urlParams.get('code');
	const codeVerifier = localStorage.getItem('oauth_code_verifier');
	const clientId = localStorage.getItem('oauth_client_id');
	const redirectUri = localStorage.getItem('oauth_redirect_uri');

	if (!code || !codeVerifier || !clientId || !redirectUri) {
		showResult('Error: Missing OAuth parameters', 'error');
		resultSection.style.display = 'block';
		return;
	}

	exchangeBtn.disabled = true;
	exchangeBtn.textContent = 'exchanging...';

	try {
		const response = await fetch('/auth/token', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({
				grant_type: 'authorization_code',
				code,
				client_id: clientId,
				redirect_uri: redirectUri,
				code_verifier: codeVerifier,
			}),
		});

		const data = await response.json();

		if (!response.ok) {
			showResult(
				`Error: ${data.error}\n${data.error_description || ''}`,
				'error'
			);
		} else {
			showResult(
				`Success! User authenticated:\n\n${JSON.stringify(data, null, 2)}`,
				'success'
			);

			// Clean up localStorage
			localStorage.removeItem('oauth_code_verifier');
			localStorage.removeItem('oauth_state');
			localStorage.removeItem('oauth_client_id');
			localStorage.removeItem('oauth_redirect_uri');
		}
	} catch (error) {
		showResult(`Error: ${(error as Error).message}`, 'error');
	} finally {
		exchangeBtn.disabled = false;
		exchangeBtn.textContent = 'exchange code for profile';
		resultSection.style.display = 'block';
		resultSection.scrollIntoView({ behavior: 'smooth' });
	}
});

function showResult(text: string, type: 'success' | 'error') {
	if (type === 'success' && text.includes('{')) {
		// Extract and parse JSON from success message
		const jsonStart = text.indexOf('{');
		const jsonStr = text.substring(jsonStart);
		const prefix = text.substring(0, jsonStart).trim();
		
		try {
			const data = JSON.parse(jsonStr);
			const formattedJson = JSON.stringify(data, null, 2);
			
			// Apply custom JSON syntax highlighting
			const highlightedJson = highlightJSON(formattedJson);
			
			resultDiv.innerHTML = `<strong style="color: var(--berry-crush); font-size: 1.125rem; display: block; margin-bottom: 1rem;">${prefix}</strong><pre style="margin: 0;"><code>${highlightedJson}</code></pre>`;
		} catch {
			resultDiv.textContent = text;
		}
	} else {
		resultDiv.textContent = text;
	}
	resultDiv.className = `result show ${type}`;
}

// Convert HTML documentation to Markdown by parsing the DOM
function extractMarkdown(): string {
	const lines: string[] = [];
	
	// Get title and subtitle from header
	const h1 = document.querySelector('header h1');
	const subtitle = document.querySelector('header .subtitle');
	
	if (h1) {
		lines.push(`# ${h1.textContent}`);
		lines.push('');
	}
	
	if (subtitle) {
		lines.push(subtitle.textContent || '');
		lines.push('');
	}
	
	// Process each section (skip TOC and OAuth tester)
	const sections = document.querySelectorAll('.section');
	
	sections.forEach((section) => {
		// Skip the OAuth tester section
		if (section.id === 'tester') return;
		
		processElement(section, lines);
		lines.push('');
	});
	
	return lines.join('\n');
}

function processElement(el: Element, lines: string[], indent = 0): void {
	const tag = el.tagName.toLowerCase();
	
	// Headers
	if (tag === 'h2') {
		lines.push(`## ${el.textContent}`);
		lines.push('');
	} else if (tag === 'h3') {
		lines.push(`### ${el.textContent}`);
		lines.push('');
	}
	// Paragraphs
	else if (tag === 'p') {
		lines.push(el.textContent || '');
		lines.push('');
	}
	// Lists
	else if (tag === 'ul' || tag === 'ol') {
		const items = el.querySelectorAll(':scope > li');
		items.forEach((li, i) => {
			const prefix = tag === 'ol' ? `${i + 1}. ` : '- ';
			const text = getTextContent(li);
			lines.push(`${prefix}${text}`);
		});
		lines.push('');
	}
	// Tables
	else if (tag === 'table') {
		const headers: string[] = [];
		const rows: string[][] = [];
		
		// Get headers
		el.querySelectorAll('thead th').forEach((th) => {
			headers.push(th.textContent?.trim() || '');
		});
		
		// Get rows
		el.querySelectorAll('tbody tr').forEach((tr) => {
			const row: string[] = [];
			tr.querySelectorAll('td').forEach((td) => {
				row.push(td.textContent?.trim() || '');
			});
			rows.push(row);
		});
		
		// Format as markdown table
		if (headers.length > 0) {
			lines.push(`| ${headers.join(' | ')} |`);
			lines.push(`|${headers.map(() => '-------').join('|')}|`);
			rows.forEach((row) => {
				lines.push(`| ${row.join(' | ')} |`);
			});
			lines.push('');
		}
	}
	// Code blocks
	else if (tag === 'pre') {
		const code = el.querySelector('code');
		if (code) {
			// Detect language from class or content
			let lang = '';
			const text = code.textContent || '';
			
			if (text.includes('GET ') || text.includes('POST ')) {
				lang = 'http';
			} else if (text.includes('{') && text.includes('"')) {
				lang = 'json';
			}
			
			lines.push(`\`\`\`${lang}`);
			lines.push(text.trim());
			lines.push('```');
			lines.push('');
		}
	}
	// Info boxes
	else if (el.classList.contains('info-box')) {
		const strong = el.querySelector('strong');
		const text = el.textContent?.trim() || '';
		
		if (strong) {
			// Extract content after the strong tag
			const afterStrong = text.substring(strong.textContent?.length || 0).trim();
			lines.push(`> **${strong.textContent}** ${afterStrong}`);
		} else {
			lines.push(`> ${text}`);
		}
		lines.push('');
	}
	// Process children for sections and divs
	else if (tag === 'section' || tag === 'div') {
		Array.from(el.children).forEach((child) => {
			processElement(child, lines, indent);
		});
	}
}

// Get text content, preserving inline code formatting
function getTextContent(el: Element): string {
	let text = '';
	
	el.childNodes.forEach((node) => {
		if (node.nodeType === Node.TEXT_NODE) {
			text += node.textContent;
		} else if (node.nodeType === Node.ELEMENT_NODE) {
			const elem = node as Element;
			if (elem.tagName.toLowerCase() === 'code') {
				text += `\`${elem.textContent}\``;
			} else if (elem.tagName.toLowerCase() === 'strong') {
				text += `**${elem.textContent}**`;
			} else {
				text += elem.textContent;
			}
		}
	});
	
	return text.trim();
}

// Copy markdown to clipboard
copyMarkdownBtn.addEventListener('click', async () => {
	const markdown = extractMarkdown();
	
	try {
		await navigator.clipboard.writeText(markdown);
		copyMarkdownBtn.textContent = 'copied! ✓';
		setTimeout(() => {
			copyMarkdownBtn.textContent = 'copy as markdown';
		}, 2000);
	} catch (error) {
		console.error('Failed to copy:', error);
		alert('Failed to copy to clipboard');
	}
});
