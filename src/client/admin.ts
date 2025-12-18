const token = localStorage.getItem('indiko_session');
const footer = document.getElementById('footer') as HTMLElement;
const usersList = document.getElementById('usersList') as HTMLElement;

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

		footer.innerHTML = `admin • signed in as <strong><a href="/u/${data.username}">${data.username}</a></strong> • <a href="/login" id="logoutLink">sign out</a>
		<div class="back-link"><a href="/">← back to dashboard</a></div>`;

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

		// Check if admin
		if (!data.isAdmin) {
			window.location.href = '/';
			return;
		}

		// Load users if admin
		loadUsers();
	} catch (error) {
		console.error('Auth check failed:', error);
		footer.textContent = 'error loading user info';
		usersList.innerHTML = '<div class="error">Failed to load users</div>';
	}
}

async function loadUsers() {
	try {
		const response = await fetch('/api/users', {
			headers: {
				'Authorization': `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			throw new Error('Failed to load users');
		}

		const data = await response.json();
		
		if (data.users.length === 0) {
			usersList.innerHTML = '<div class="loading">No users found</div>';
			return;
		}

		usersList.innerHTML = data.users.map((user: {
			id: number;
			username: string;
			name: string;
			email: string | null;
			photo: string | null;
			status: string;
			role: string;
			isAdmin: boolean;
			createdAt: number;
			credentialCount: number;
		}) => {
			const createdDate = new Date(user.createdAt * 1000).toLocaleDateString();
			const initials = user.username.substring(0, 2).toUpperCase();
			const avatarContent = user.photo 
				? `<img src="${user.photo}" alt="${user.username}" />`
				: initials;
			
			return `
				<div class="user-card" data-user-id="${user.id}">
					<div class="user-avatar">${avatarContent}</div>
					<div class="user-info">
						<div class="user-name">${user.username}</div>
						<div class="user-meta">
							<span class="user-meta-item">${user.credentialCount} passkey${user.credentialCount !== 1 ? 's' : ''}</span>
							<span class="user-meta-item">joined ${createdDate}</span>
							${user.email ? `<span class="user-meta-item">${user.email}</span>` : ''}
						</div>
					</div>
					<div class="user-badges">
						<span class="user-badge badge-status ${user.status}">${user.status}</span>
						<span class="user-badge badge-role">${user.role}</span>
					</div>
					<div class="user-actions">
						${user.status !== 'suspended' ? `<button class="btn btn-disable" data-action="disable" data-user-id="${user.id}">disable</button>` : ''}
						<button class="btn btn-delete" data-action="delete" data-user-id="${user.id}">delete</button>
					</div>
				</div>
			`;
		}).join('');

		// Add event listeners for action buttons
		document.querySelectorAll('.btn[data-action]').forEach(btn => {
			btn.addEventListener('click', handleUserAction);
		});
	} catch (error) {
		console.error('Failed to load users:', error);
		usersList.innerHTML = '<div class="error">Failed to load users</div>';
	}
}

async function handleUserAction(e: Event) {
	const btn = e.target as HTMLButtonElement;
	const action = btn.dataset.action;
	const userId = btn.dataset.userId;
	
	if (!userId || !action) return;

	const confirmMessage = action === 'delete' 
		? 'Are you sure you want to delete this user? This cannot be undone.'
		: 'Are you sure you want to disable this user? They will be logged out and unable to sign in.';

	if (!confirm(confirmMessage)) return;

	try {
		const endpoint = action === 'delete' 
			? `/api/admin/users/${userId}/delete`
			: `/api/admin/users/${userId}/disable`;
		
		const method = action === 'delete' ? 'DELETE' : 'POST';

		const response = await fetch(endpoint, {
			method,
			headers: {
				'Authorization': `Bearer ${token}`,
			},
		});

		if (!response.ok) {
			const error = await response.json();
			throw new Error(error.error || 'Failed to perform action');
		}

		// Reload users list
		loadUsers();
	} catch (error) {
		console.error(`Failed to ${action} user:`, error);
		alert(`Failed to ${action} user: ${error instanceof Error ? error.message : 'Unknown error'}`);
	}
}

checkAuth();
