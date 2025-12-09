// User Portal JavaScript
const API_BASE = '';

// Store branding info and settings globally
let organizationName = 'CaddyMAN'; // Default fallback
let enhancedSecurityEnabled = false; // Enhanced Security Mode status

// Security helper functions
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return '';
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Secure way to set HTML content - sanitizes by default
function setContent(element, content, allowHtml = false) {
    if (!element) return;
    if (allowHtml) {
        // For trusted HTML content only (from our own template strings, not user input)
        element.innerHTML = content;
    } else {
        // Default: treat as plain text to prevent XSS
        element.textContent = content;
    }
}

// Helper function for API calls
async function apiCall(endpoint, options = {}) {
    const response = await fetch(API_BASE + endpoint, {
        ...options,
        credentials: 'same-origin',
        headers: {
            ...options.headers
        }
    });

    if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: 'Request failed' }));
        throw new Error(error.detail || 'Request failed');
    }

    return response.json();
}

// Load branding and settings configuration
async function loadBranding() {
    try {
        // Fetch public settings info without authentication
        const response = await fetch('/api/user-portal/settings');
        if (response.ok) {
            const settings = await response.json();
            organizationName = settings.organization_name || 'CaddyMAN';
            enhancedSecurityEnabled = settings.enhanced_security || false;

            // Update page elements
            const orgNameEl = document.getElementById('org-name');
            if (orgNameEl) orgNameEl.textContent = organizationName;

            const pageTitleEl = document.getElementById('page-title');
            if (pageTitleEl) pageTitleEl.textContent = `${organizationName} User Portal`;

            // Update password field hints and minlength based on Enhanced Security Mode
            updatePasswordFieldRequirements();
        }
    } catch (err) {
        console.error('Failed to load branding:', err);
        // Use defaults if fetch fails
        const orgNameEl = document.getElementById('org-name');
        if (orgNameEl) orgNameEl.textContent = 'CaddyMAN';
        updatePasswordFieldRequirements();
    }
}

// Update password field requirements based on Enhanced Security Mode
function updatePasswordFieldRequirements() {
    const passwordFields = [
        { id: 'setup-password', hintSelector: '#setup-password + .hint' },
        { id: 'setup-password-confirm', hintSelector: null },
        { id: 'new-password', hintSelector: '#new-password + .hint' },
        { id: 'new-password-confirm', hintSelector: null },
        { id: 'reset-new-password', hintSelector: '#reset-new-password + .hint' },
        { id: 'reset-new-password-confirm', hintSelector: null }
    ];

    const minLength = enhancedSecurityEnabled ? 8 : 4;
    const hintText = enhancedSecurityEnabled
        ? 'Min 8 chars (all 4 types: A-Z, a-z, 0-9, symbols) OR 10 (any 3) OR 14 (any 2) OR 20 (one type)'
        : 'Minimum 4 characters';

    passwordFields.forEach(field => {
        const input = document.getElementById(field.id);
        if (input) {
            input.setAttribute('minlength', minLength);
        }
        if (field.hintSelector) {
            const hint = document.querySelector(field.hintSelector);
            if (hint) {
                hint.textContent = hintText;
            }
        }
    });
}

// Alert system
function showAlert(message, type = 'info') {
    const container = document.getElementById('alert-container');
    const alert = document.createElement('div');
    alert.className = `alert ${type}`;
    alert.textContent = message;
    container.appendChild(alert);

    setTimeout(() => {
        alert.remove();
    }, 5000);
}

// Page navigation
function showPage(pageId) {
    document.querySelectorAll('.page').forEach(page => {
        page.classList.add('hidden');
    });
    document.getElementById(pageId).classList.remove('hidden');
}

// Check authentication status on load
async function checkAuth() {
    try {
        const user = await apiCall('/api/user');
        if (user && user.username) {
            // User is logged in, show profile page
            loadProfile(user);
            showPage('profile-page');
        } else {
            // Not logged in, show login page
            showPage('login-page');
        }
    } catch (err) {
        // Check if we have an invite token or reset token in URL
        const params = new URLSearchParams(window.location.search);
        const inviteToken = params.get('token');
        const resetToken = params.get('reset_token');

        if (inviteToken) {
            // Show setup page with invite token
            loadSetupPage(inviteToken);
        } else if (resetToken) {
            // Show password reset page with reset token
            loadResetPasswordPage(resetToken);
        } else {
            // Show login page
            showPage('login-page');
        }
    }
}

// Load setup page for invite links
async function loadSetupPage(token) {
    try {
        const invite = await apiCall(`/api/user-portal/invite/${token}`);

        document.getElementById('setup-username').textContent = invite.username;
        document.getElementById('setup-email').textContent = invite.email;

        // Store token for form submission
        document.getElementById('setup-form').dataset.token = token;

        showPage('setup-page');
    } catch (err) {
        showAlert('Invalid or expired invite link', 'error');
        setTimeout(() => {
            showPage('login-page');
        }, 2000);
    }
}

// Handle setup form submission
document.getElementById('setup-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const password = document.getElementById('setup-password').value;
    const confirmPassword = document.getElementById('setup-password-confirm').value;
    const token = e.target.dataset.token;

    if (password !== confirmPassword) {
        showAlert('Passwords do not match', 'error');
        return;
    }

    const minLength = enhancedSecurityEnabled ? 8 : 4;
    if (password.length < minLength) {
        showAlert(`Password must be at least ${minLength} characters`, 'error');
        return;
    }

    try {
        const result = await apiCall('/api/user-portal/setup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token, password })
        });

        if (result.requires_2fa) {
            showAlert('Account activated! Your group requires 2FA. Please log in and enable 2FA immediately.', 'warning');
        } else {
            showAlert('Account activated successfully! Please log in.', 'success');
        }

        setTimeout(() => {
            window.location.href = '/user-portal';
        }, 3000);
    } catch (err) {
        showAlert(err.message, 'error');
    }
});

// Load profile page
async function loadProfile(user) {
    document.getElementById('profile-username').textContent = user.username;
    document.getElementById('profile-email').textContent = user.email || 'Not set';
    document.getElementById('profile-groups').textContent = user.groups.join(', ') || 'None';

    // Set current email in update form
    document.getElementById('new-email').value = user.email || '';

    // Load WiFi password status
    await loadWifiPasswordStatus();

    // Load 2FA status
    load2FAStatus(user);
}

// Load 2FA status
function load2FAStatus(user) {
    const enabledText = document.getElementById('2fa-enabled-text');
    const enableSection = document.getElementById('2fa-enable-section');
    const qrSection = document.getElementById('2fa-qr-section');
    const disableSection = document.getElementById('2fa-disable-section');

    if (user.totp_enabled) {
        enabledText.textContent = 'Enabled ✓';
        enabledText.style.color = 'var(--success)';
        enableSection.classList.add('hidden');
        qrSection.classList.add('hidden');
        disableSection.classList.remove('hidden');
    } else {
        enabledText.textContent = 'Disabled';
        enabledText.style.color = 'var(--danger)';
        enableSection.classList.remove('hidden');
        qrSection.classList.add('hidden');
        disableSection.classList.add('hidden');
    }
}

// Handle login
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    const twoFactorToken = document.getElementById('login-2fa-token').value;

    try {
        const result = await apiCall('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                password,
                two_factor_token: twoFactorToken || undefined
            })
        });

        if (result.requires_2fa) {
            document.getElementById('login-2fa-group').style.display = 'block';
            showAlert('Please enter your 2FA code', 'info');
        } else {
            showAlert('Login successful!', 'success');

            // Check for return_to parameter (for OIDC/OAuth flow)
            const urlParams = new URLSearchParams(window.location.search);
            const returnTo = urlParams.get('return_to');

            setTimeout(() => {
                if (returnTo) {
                    // Redirect to OAuth/OIDC flow
                    window.location.href = returnTo;
                } else {
                    // Normal login - reload to show profile
                    window.location.reload();
                }
            }, 1000);
        }
    } catch (err) {
        showAlert(err.message, 'error');
    }
});

// Handle logout
document.getElementById('logout-btn').addEventListener('click', async () => {
    try {
        await apiCall('/api/auth/logout', { method: 'POST' });
        showAlert('Logged out successfully', 'success');
        setTimeout(() => {
            window.location.href = '/user-portal';
        }, 1000);
    } catch (err) {
        showAlert(err.message, 'error');
    }
});

// Handle change password
document.getElementById('change-password-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('new-password-confirm').value;

    if (newPassword !== confirmPassword) {
        showAlert('New passwords do not match', 'error');
        return;
    }

    if (newPassword.length < 4) {
        showAlert('Password must be at least 4 characters', 'error');
        return;
    }

    try {
        await apiCall('/api/user-portal/change-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ current_password: currentPassword, new_password: newPassword })
        });

        showAlert('Password changed successfully!', 'success');
        e.target.reset();
    } catch (err) {
        showAlert(err.message, 'error');
    }
});

// Handle update email
document.getElementById('update-email-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const newEmail = document.getElementById('new-email').value;

    try {
        await apiCall('/api/user-portal/update-email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: newEmail })
        });

        showAlert('Email updated successfully!', 'success');
        document.getElementById('profile-email').textContent = newEmail;
    } catch (err) {
        showAlert(err.message, 'error');
    }
});

// Load and manage WiFi password status
async function loadWifiPasswordStatus() {
    try {
        const status = await apiCall('/api/user-portal/wifi-password-status');

        const wifiSection = document.getElementById('wifi-password-section');
        const wifiStatusText = document.getElementById('wifi-status-text');
        const deleteBtn = document.getElementById('delete-wifi-password-btn');
        const setBtn = document.getElementById('set-wifi-password-btn');

        // Show section only if user is eligible (PEAP enabled AND in RADIUS group)
        if (status.is_eligible) {
            wifiSection.style.display = 'block';

            // Update status text
            if (status.has_wifi_password) {
                setContent(wifiStatusText, '<strong style="color: var(--success);">Status:</strong> WiFi password is configured ✓', true);
                deleteBtn.style.display = 'inline-block';
                setBtn.textContent = 'Update WiFi Password';
            } else {
                setContent(wifiStatusText, '<strong style="color: var(--warning);">Status:</strong> No WiFi password set', true);
                deleteBtn.style.display = 'none';
                setBtn.textContent = 'Set WiFi Password';
            }
        } else {
            wifiSection.style.display = 'none';

            // Show reason if not eligible
            if (!status.peap_enabled) {
                console.log('WiFi password not available: PEAP is not enabled');
            } else if (!status.in_radius_group) {
                console.log('WiFi password not available: User is not in a RADIUS-allowed group');
            }
        }
    } catch (err) {
        console.error('Failed to load WiFi password status:', err);
        document.getElementById('wifi-password-section').style.display = 'none';
    }
}

// Handle WiFi password form submission
document.getElementById('wifi-password-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const accountPassword = document.getElementById('account-password-wifi').value;
    const wifiPassword = document.getElementById('wifi-password').value;
    const wifiPasswordConfirm = document.getElementById('wifi-password-confirm').value;

    // Validate passwords match
    if (wifiPassword !== wifiPasswordConfirm) {
        showAlert('WiFi passwords do not match', 'error');
        return;
    }

    // Validate minimum length
    if (wifiPassword.length < 8) {
        showAlert('WiFi password must be at least 8 characters', 'error');
        return;
    }

    // Validate not same as account password
    if (wifiPassword === accountPassword) {
        showAlert('WiFi password must be different from your account password', 'error');
        return;
    }

    try {
        await apiCall('/api/user-portal/set-wifi-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                account_password: accountPassword,
                wifi_password: wifiPassword
            })
        });

        showAlert('WiFi password set successfully!', 'success');

        // Clear form
        e.target.reset();

        // Reload status
        await loadWifiPasswordStatus();
    } catch (err) {
        showAlert(err.message, 'error');
    }
});

// Handle delete WiFi password
document.getElementById('delete-wifi-password-btn').addEventListener('click', async () => {
    if (!confirm('Are you sure you want to delete your WiFi password? You will no longer be able to authenticate to WiFi networks until you set a new one.')) {
        return;
    }

    try {
        await apiCall('/api/user-portal/delete-wifi-password', {
            method: 'DELETE'
        });

        showAlert('WiFi password deleted successfully', 'success');

        // Clear form
        document.getElementById('wifi-password-form').reset();

        // Reload status
        await loadWifiPasswordStatus();
    } catch (err) {
        showAlert(err.message, 'error');
    }
});

// Enable 2FA
document.getElementById('enable-2fa-btn').addEventListener('click', async () => {
    try {
        const result = await apiCall('/api/user-portal/enable-2fa', {
            method: 'POST'
        });

        // Show QR code
        document.getElementById('2fa-qr-code').src = result.qr_code;
        document.getElementById('2fa-enable-section').classList.add('hidden');
        document.getElementById('2fa-qr-section').classList.remove('hidden');
    } catch (err) {
        showAlert(err.message, 'error');
    }
});

// Verify and enable 2FA
document.getElementById('verify-2fa-btn').addEventListener('click', async () => {
    const token = document.getElementById('2fa-verify-token').value;

    if (!token || token.length !== 6) {
        showAlert('Please enter a valid 6-digit code', 'error');
        return;
    }

    try {
        await apiCall('/api/user-portal/verify-2fa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token })
        });

        showAlert('2FA enabled successfully!', 'success');

        // Reload to update status
        setTimeout(() => {
            window.location.reload();
        }, 1500);
    } catch (err) {
        showAlert(err.message, 'error');
    }
});

// Cancel 2FA setup
document.getElementById('cancel-2fa-btn').addEventListener('click', () => {
    document.getElementById('2fa-qr-section').classList.add('hidden');
    document.getElementById('2fa-enable-section').classList.remove('hidden');
    document.getElementById('2fa-verify-token').value = '';
});

// Disable 2FA
document.getElementById('disable-2fa-btn').addEventListener('click', async () => {
    if (!confirm('Are you sure you want to disable 2FA? This will make your account less secure.')) {
        return;
    }

    try {
        await apiCall('/api/user-portal/disable-2fa', {
            method: 'POST'
        });

        showAlert('2FA disabled', 'success');

        // Reload to update status
        setTimeout(() => {
            window.location.reload();
        }, 1500);
    } catch (err) {
        showAlert(err.message, 'error');
    }
});

// Password Reset Functions

// Forgot password link handler
document.getElementById('forgot-password-link').addEventListener('click', (e) => {
    e.preventDefault();
    showPage('forgot-password-page');
});

// Handle forgot password form submission
document.getElementById('forgot-password-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const email = document.getElementById('reset-email').value;

    try {
        await apiCall('/api/user-portal/request-password-reset', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });

        showAlert('If an account exists with this email, a password reset link has been sent.', 'success');

        // Show login page after short delay
        setTimeout(() => {
            showPage('login-page');
        }, 3000);
    } catch (err) {
        showAlert(err.message, 'error');
    }
});

// Load password reset page
async function loadResetPasswordPage(token) {
    try {
        const reset = await apiCall(`/api/user-portal/verify-reset-token/${token}`);

        document.getElementById('reset-username').textContent = reset.username;
        document.getElementById('reset-email-display').textContent = reset.email;

        // Store token for form submission
        document.getElementById('reset-password-form').dataset.token = token;

        // Show 2FA field if account has 2FA enabled
        if (reset.requires_2fa) {
            document.getElementById('reset-2fa-group').style.display = 'block';
            document.getElementById('reset-2fa-token').required = true;
        } else {
            document.getElementById('reset-2fa-group').style.display = 'none';
            document.getElementById('reset-2fa-token').required = false;
        }

        showPage('reset-password-page');
    } catch (err) {
        showAlert('Invalid or expired password reset link', 'error');
        setTimeout(() => {
            showPage('login-page');
        }, 2000);
    }
}

// Handle password reset form submission
document.getElementById('reset-password-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const newPassword = document.getElementById('reset-new-password').value;
    const confirmPassword = document.getElementById('reset-new-password-confirm').value;
    const token = e.target.dataset.token;
    const twoFactorToken = document.getElementById('reset-2fa-token').value;

    if (newPassword !== confirmPassword) {
        showAlert('Passwords do not match', 'error');
        return;
    }

    if (newPassword.length < 4) {
        showAlert('Password must be at least 4 characters', 'error');
        return;
    }

    try {
        const requestBody = {
            token,
            new_password: newPassword
        };

        // Add 2FA token if provided
        if (twoFactorToken) {
            requestBody.two_factor_token = twoFactorToken;
        }

        await apiCall('/api/user-portal/reset-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody)
        });

        showAlert('Password has been reset successfully! Please log in.', 'success');
        setTimeout(() => {
            window.location.href = '/user-portal';
        }, 2000);
    } catch (err) {
        showAlert(err.message, 'error');
    }
});

// Initialize on page load
(async () => {
    await loadBranding();
    await checkAuth();
})();
