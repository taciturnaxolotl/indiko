const token = localStorage.getItem('indiko_session');
const profileForm = document.getElementById('profileForm') as HTMLFormElement;
const avatarPreview = document.getElementById('avatarPreview') as HTMLElement;
const message = document.getElementById('message') as HTMLElement;

const usernameInput = document.getElementById('username') as HTMLInputElement;
const nameInput = document.getElementById('name') as HTMLInputElement;
const emailInput = document.getElementById('email') as HTMLInputElement;
const photoInput = document.getElementById('photo') as HTMLInputElement;
const urlInput = document.getElementById('url') as HTMLInputElement;

function showMessage(text: string, type: 'error' | 'success' = 'error') {
	message.textContent = text;
	message.className = `message show ${type}`;
	setTimeout(() => message.classList.remove('show'), 5000);
}

function updateAvatarPreview(photo: string | null, username: string) {
	if (photo) {
		avatarPreview.innerHTML = `<img src="${photo}" alt="${username}" />`;
	} else {
		const initials = username.substring(0, 2).toUpperCase();
		avatarPreview.textContent = initials;
	}
}

async function loadProfile() {
	if (!token) {
		window.location.href = '/login';
		return;
	}

	try {
		const response = await fetch('/api/profile', {
			headers: {
				'Authorization': `Bearer ${token}`,
			},
		});

		if (response.status === 401 || response.status === 403) {
			localStorage.removeItem('indiko_session');
			window.location.href = '/login';
			return;
		}

		if (!response.ok) {
			throw new Error('Failed to load profile');
		}

		const profile = await response.json();

		usernameInput.value = profile.username;
		nameInput.value = profile.name || '';
		emailInput.value = profile.email || '';
		photoInput.value = profile.photo || '';
		urlInput.value = profile.url || '';

		updateAvatarPreview(profile.photo, profile.username);

		// Update avatar preview when photo URL changes
		photoInput.addEventListener('input', () => {
			updateAvatarPreview(photoInput.value || null, profile.username);
		});
	} catch (error) {
		console.error('Failed to load profile:', error);
		showMessage('Failed to load profile');
	}
}

profileForm.addEventListener('submit', async (e) => {
	e.preventDefault();

	const saveBtn = document.getElementById('saveBtn') as HTMLButtonElement;
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
				name: nameInput.value,
				email: emailInput.value || null,
				photo: photoInput.value || null,
				url: urlInput.value || null,
			}),
		});

		if (!response.ok) {
			const error = await response.json();
			throw new Error(error.error || 'Failed to update profile');
		}

		showMessage('Profile updated successfully!', 'success');
		const redirectTimer = setTimeout(() => {
			window.location.href = '/';
		}, 1500);
		(redirectTimer as unknown as number);
	} catch (error) {
		showMessage((error as Error).message || 'Failed to update profile');
		saveBtn.disabled = false;
		saveBtn.textContent = 'save changes';
	}
});

loadProfile();
