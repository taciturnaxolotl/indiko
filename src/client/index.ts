const token = localStorage.getItem('indiko_session');
const footer = document.getElementById('footer') as HTMLElement;

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

		footer.innerHTML = `signed in as <strong>${data.username}</strong> • <a href="/login" id="logoutLink">sign out</a>`;

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
			} catch (e) { }
			localStorage.removeItem('indiko_session');
			window.location.href = '/login';
		});
	} catch (error) {
		console.error('Auth check failed:', error);
		footer.textContent = 'error loading user info';
	}
}

checkAuth();
