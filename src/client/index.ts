const token = localStorage.getItem('indiko_session');
const footer = document.getElementById('footer') as HTMLElement;
const welcome = document.getElementById('welcome') as HTMLElement;
const subtitle = document.getElementById('subtitle') as HTMLElement;
const recentApps = document.getElementById('recentApps') as HTMLElement;
const profileForm = document.getElementById('profileForm') as HTMLFormElement;
const saveBtn = document.getElementById('saveBtn') as HTMLButtonElement;
const message = document.getElementById('message') as HTMLDivElement;
const profileName = document.getElementById('profileName') as HTMLElement;
const profileUsername = document.getElementById('profileUsername') as HTMLElement;
const profileAvatar = document.getElementById('profileAvatar') as HTMLElement;
const avatarInitials = document.getElementById('avatarInitials') as HTMLElement;
const publicProfileLink = document.getElementById('publicProfileLink') as HTMLAnchorElement;
const profileLinks = document.getElementById('profileLinks') as HTMLElement;

const nameInput = document.getElementById('name') as HTMLInputElement;
const emailInput = document.getElementById('email') as HTMLInputElement;
const photoInput = document.getElementById('photo') as HTMLInputElement;
const urlInput = document.getElementById('url') as HTMLInputElement;

let currentUsername = '';

if (!token) {
	window.location.href = '/login';
}

interface App {
	clientId: string;
	name: string;
	scopes: string[];
	grantedAt: number;
	lastUsed: number;
}

interface Profile {
	username: string;
	name: string;
	email: string | null;
	photo: string | null;
	url: string | null;
}



function showMessage(text: string, type: 'success' | 'error') {
	message.textContent = text;
	message.className = `message show ${type}`;
	setTimeout(() => message.classList.remove('show'), 5000);
}

// Check auth and display user
async function checkAuth() {
	if (!token) {
		window.location.href = '/login';
		return;
	}

	try {
		const response = await fetch('/api/hello', {
			headers: {
				'Authorization': `Bearer ${token}`,
			},
		});

		if (response.status === 401) {
			localStorage.removeItem('indiko_session');
			window.location.href = '/login';
			return;
		}

		const data = await response.json();
		
		// Update welcome message
		welcome.textContent = `welcome, ${data.username}`;
		subtitle.textContent = 'your identity dashboard';

		// Build footer with conditional admin link
		const adminLink = data.isAdmin ? ' • <a href="/admin">admin</a>' : '';
		footer.innerHTML = `signed in as <strong><a href="/u/${data.username}">${data.username}</a></strong> • <a href="/apps">apps</a> • <a href="/docs">docs</a>${adminLink} • <a href="/login" id="logoutLink">sign out</a>`;

		// Handle logout
		document.getElementById('logoutLink')?.addEventListener('click', async (e) => {
			e.preventDefault();
			try {
				await fetch('/auth/logout', {
					method: 'POST',
					headers: {
						'Authorization': `Bearer ${token}`,
					},
				});
			} catch {
				// Ignore logout errors
			}
			localStorage.removeItem('indiko_session');
			window.location.href = '/login';
		});

		// Load profile and apps
		loadProfile();
		loadRecentApps();
	} catch (error) {
		console.error('Auth check failed:', error);
		footer.textContent = 'error loading user info';
	}
}

async function loadProfile() {
	try {
		const response = await fetch('/api/profile', {
			headers: {
				'Authorization': `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error('Failed to load profile');
		}

		const profile = await response.json() as Profile;
		currentUsername = profile.username;

		// Populate form
		nameInput.value = profile.name;
		emailInput.value = profile.email || '';
		photoInput.value = profile.photo || '';
		urlInput.value = profile.url || '';

		// Initial preview update
		updatePreview();
	} catch (error) {
		console.error('Failed to load profile:', error);
		showMessage('Failed to load profile', 'error');
	}
}

// Handle profile form submission
profileForm.addEventListener('submit', async (e) => {
	e.preventDefault();

	const name = nameInput.value.trim();
	const email = emailInput.value.trim();
	const photo = photoInput.value.trim();
	const url = urlInput.value.trim();

	if (!name) {
		showMessage('Name is required', 'error');
		return;
	}

	saveBtn.disabled = true;
	saveBtn.textContent = 'saving...';

	try {
		const response = await fetch('/api/profile', {
			method: 'PUT',
			headers: {
				'Authorization': `Bearer ${token}`,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({
				name,
				email: email || null,
				photo: photo || null,
				url: url || null,
			}),
		});

		if (!response.ok) {
			throw new Error('Failed to update profile');
		}

		showMessage('Profile updated successfully!', 'success');
	} catch (error) {
		console.error('Failed to update profile:', error);
		showMessage('Failed to update profile', 'error');
	} finally {
		saveBtn.disabled = false;
		saveBtn.textContent = 'save profile';
	}
});

function updatePreview() {
	const name = nameInput.value.trim() || 'Your Name';
	const photo = photoInput.value.trim();
	const email = emailInput.value.trim();
	const url = urlInput.value.trim();

	// Update name
	profileName.textContent = name;
	profileUsername.textContent = `@${currentUsername}`;
	avatarInitials.textContent = currentUsername.slice(0, 2).toUpperCase();
	publicProfileLink.href = `/u/${currentUsername}`;

	// Update photo
	const existingImg = profileAvatar.querySelector('img');
	if (photo) {
		if (existingImg) {
			existingImg.src = photo;
			existingImg.alt = name;
		} else {
			const img = document.createElement('img');
			img.src = photo;
			img.alt = name;
			profileAvatar.insertBefore(img, avatarInitials);
		}
		avatarInitials.style.display = 'none';
	} else {
		if (existingImg) {
			existingImg.remove();
		}
		avatarInitials.style.display = '';
	}

	// Update links
	let links = `<a href="/u/${currentUsername}" id="publicProfileLink">view public profile</a>`;
	if (email) {
		links += ` • <a href="mailto:${email}">email</a>`;
	}
	if (url) {
		links += ` • <a href="${url}" target="_blank" rel="noopener noreferrer">website</a>`;
	}
	profileLinks.innerHTML = links;
}

// Live update listeners
nameInput.addEventListener('input', updatePreview);
emailInput.addEventListener('input', updatePreview);
photoInput.addEventListener('input', updatePreview);
urlInput.addEventListener('input', updatePreview);

async function loadRecentApps() {
	try {
		const response = await fetch('/api/apps', {
			headers: {
				'Authorization': `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error('Failed to load apps');
		}

		const data = await response.json();
		const apps = data.apps as App[];
		
		if (apps.length === 0) {
			recentApps.innerHTML = '<div class="empty">No authorized apps yet</div>';
			return;
		}

		// Show top 7 most recent
		const recent = apps.slice(0, 7);
		
		recentApps.innerHTML = recent.map((app) => {
			const lastUsedDate = new Date(app.lastUsed * 1000).toLocaleDateString();
			
			return `
				<div class="app-item">
					<div class="app-name">${app.name}</div>
					<div class="app-date">${lastUsedDate}</div>
				</div>
			`;
		}).join('');

		if (apps.length > 7) {
			recentApps.innerHTML += '<a href="/apps" class="view-all">view all apps →</a>';
		}
	} catch (error) {
		console.error('Failed to load apps:', error);
		recentApps.innerHTML = '<div class="empty">Failed to load apps</div>';
	}
}

checkAuth();
