/**
 * SecureMail — Login Page Authentication Logic
 * Extracted from inline <script type="module"> in login.html for CSP compliance.
 */

import { Mail } from './mail.js';

// Auto-redirect if already signed in
Mail.restoreSession().then(session => {
    if (session) window.location.href = 'index.html';
});

const RATE_LIMIT_ATTEMPTS = 5;
const RATE_LIMIT_DURATION_MS = 30000;
let failedAttempts = 0;
let lockoutUntil = 0;
let lockoutTimer = null;

function isLockedOut() { return Date.now() < lockoutUntil; }
function startLockout() {
  lockoutUntil = Date.now() + RATE_LIMIT_DURATION_MS;
  failedAttempts = 0;
  const banner = document.getElementById('lockout-banner');
  const countdown = document.getElementById('lockout-countdown');
  banner.classList.add('active');
  lockoutTimer = setInterval(() => {
    const rem = Math.ceil((lockoutUntil - Date.now()) / 1000);
    if (rem <= 0) { clearInterval(lockoutTimer); banner.classList.remove('active'); }
    else { countdown.textContent = rem; }
  }, 500);
}

// Google Login
document.getElementById('google-login-btn').addEventListener('click', async () => {
  document.getElementById('loader').style.display = 'flex';
  try {
    await Mail.loginWithGoogle();
    window.location.href = 'index.html';
  } catch (err) {
    if (err.code !== 'auth/popup-closed-by-user') alert(err.message);
  } finally {
    document.getElementById('loader').style.display = 'none';
  }
});

// Email Login
document.getElementById('form-login').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (isLockedOut()) return;
  const email = document.getElementById('login-email').value.trim();
  const pass = document.getElementById('login-password').value;
  const errEl = document.getElementById('login-error');

  errEl.style.display = 'none';
  document.getElementById('loader').style.display = 'flex';

  try {
    await Mail.loginWithEmail(email, pass);
    window.location.href = 'index.html';
  } catch (err) {
    failedAttempts++;
    if (failedAttempts >= RATE_LIMIT_ATTEMPTS) startLockout();
    errEl.textContent = "Invalid email or password.";
    errEl.style.display = 'block';
  } finally {
    document.getElementById('loader').style.display = 'none';
  }
});

document.getElementById('forgot-password-btn').addEventListener('click', async () => {
  const email = document.getElementById('login-email').value.trim();
  if (!email) return alert("Enter your email first.");
  try {
    await Mail.forgotPassword(email);
  } catch(e) { /* ignore */ }
  alert("If an account exists for this email, a reset link has been sent.");
});
