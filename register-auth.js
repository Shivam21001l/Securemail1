/**
 * SecureMail — Register Page Authentication Logic
 * Extracted from inline <script type="module"> in register.html for CSP compliance.
 */

import { Mail } from './mail.js';

function updateStep(step) {
  if (step > 1) {
    document.getElementById(`spin-${step-1}`).style.display = 'none';
    document.getElementById(`check-${step-1}`).style.display = 'inline';
    document.getElementById(`step-${step-1}`).classList.replace('active', 'done');
  }
  if (step <= 4) {
    document.getElementById(`step-${step}`).classList.add('active');
    document.getElementById(`spin-${step}`).style.display = 'inline';
  }
  if (window.lucide) lucide.createIcons();
}

// Google Reg
document.getElementById('google-register-btn').addEventListener('click', async () => {
  try {
    const res = await Mail.registerGooglePrompt();
    if (res.isNewUser) {
      document.getElementById('step-google').style.display = 'none';
      document.getElementById('form-register').style.display = 'none';
      document.getElementById('reg-divider').style.display = 'none';
      document.getElementById('step-username').style.display = 'block';
    } else { window.location.href = 'index.html'; }
  } catch (err) {
    if (err.code !== 'auth/popup-closed-by-user') alert(err.message);
  }
});

document.getElementById('step-username').addEventListener('submit', async (e) => {
  e.preventDefault();
  const user = document.getElementById('reg-username').value.trim();
  if (!user || user.length < 3) {
    document.getElementById('reg-error-username').textContent = 'Username must be 3-20 characters.';
    document.getElementById('reg-error-username').style.display = 'block';
    return;
  }
  document.getElementById('progress-overlay').style.display = 'flex';
  try {
    await Mail.registerWithGoogle(user, updateStep);
    updateStep(5); setTimeout(() => window.location.href = 'index.html', 800);
  } catch (err) {
    alert(err.message);
    document.getElementById('progress-overlay').style.display = 'none';
  }
});

// Email Reg
document.getElementById('reg-email').addEventListener('input', (e) => {
  const email = e.target.value.trim();
  const val = document.getElementById('username-preview-val');
  const box = document.getElementById('username-preview');
  if (email.includes('@')) {
    val.textContent = email.split('@')[0] + '_xxxx';
    box.style.display = 'block';
  } else { box.style.display = 'none'; }
});

document.getElementById('form-register').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('reg-email').value.trim();
  const pass = document.getElementById('reg-password').value;
  const conf = document.getElementById('reg-confirm').value;
  const errEl = document.getElementById('reg-error');

  if (pass.length < 10) { errEl.textContent = 'Password must be at least 10 characters.'; errEl.style.display = 'block'; return; }
  if (pass !== conf) { errEl.textContent = 'Passwords do not match.'; errEl.style.display = 'block'; return; }
  errEl.style.display = 'none';

  document.getElementById('progress-overlay').style.display = 'flex';
  try {
    await Mail.registerWithEmail(email, pass, updateStep);
    updateStep(5); setTimeout(() => window.location.href = 'index.html', 800);
  } catch (err) {
    alert(err.message);
    document.getElementById('progress-overlay').style.display = 'none';
  }
});
