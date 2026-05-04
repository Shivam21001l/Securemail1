/**
 * SecureMail — UI Helpers (Global scope)
 * Extracted from inline <script> in index.html for CSP compliance.
 * Loaded as a regular script (non-module) so functions are globally accessible.
 */

// Password toggle (used on auth pages)
function togglePw(id, btn) {
  const inp = document.getElementById(id);
  if (!inp) return;
  const isText = inp.type === 'text';
  inp.type = isText ? 'password' : 'text';
}

// Tab switch (auth pages)
function switchTab(tab) {
  const isLogin = tab === 'login';
  const loginForm = document.getElementById('form-login');
  const regForm = document.getElementById('form-register');
  const tabLogin = document.getElementById('tab-login');
  const tabReg = document.getElementById('tab-register');
  if (!loginForm || !regForm) return;
  const outForm = isLogin ? regForm : loginForm;
  const inForm = isLogin ? loginForm : regForm;
  outForm.style.opacity = '0'; outForm.style.transform = 'translateY(8px)';
  setTimeout(() => {
    outForm.style.display = 'none'; inForm.style.display = 'flex';
    inForm.style.opacity = '0'; inForm.style.transform = 'translateY(8px)';
    requestAnimationFrame(() => { inForm.style.opacity = '1'; inForm.style.transform = 'translateY(0)'; });
  }, 180);
  if (tabLogin) tabLogin.classList.toggle('auth-tab-active', isLogin);
  if (tabReg) tabReg.classList.toggle('auth-tab-active', !isLogin);
}

// Sidebar toggle (mobile)
function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebar-overlay');
  if (!sidebar) return;
  const isOpen = sidebar.classList.toggle('sidebar-open');
  if (overlay) overlay.classList.toggle('sidebar-overlay-show', isOpen);
}

// Initialize Lucide icons on load
window.addEventListener('load', () => {
  if (window.lucide) lucide.createIcons();
});

// DOMContentLoaded: bind buttons that had inline onclick handlers
document.addEventListener('DOMContentLoaded', () => {
  // Sidebar close button
  const sidebarCloseBtn = document.getElementById('sidebar-close-btn');
  if (sidebarCloseBtn) sidebarCloseBtn.addEventListener('click', toggleSidebar);

  // Hamburger button
  const hamburgerBtn = document.getElementById('hamburger-btn');
  if (hamburgerBtn) hamburgerBtn.addEventListener('click', toggleSidebar);

  // FAB compose button (openCompose is exposed by app.js on window)
  const fabCompose = document.getElementById('fab-compose');
  if (fabCompose) {
    fabCompose.addEventListener('click', () => {
      if (window.openCompose) window.openCompose();
    });
  }

  // Keys modal close button
  const keysModalClose = document.getElementById('keys-modal-close-btn');
  if (keysModalClose) {
    keysModalClose.addEventListener('click', () => {
      document.getElementById('keys-modal').style.display = 'none';
    });
  }

  // Profile modal close button
  const profileModalClose = document.getElementById('profile-modal-close-btn');
  if (profileModalClose) {
    profileModalClose.addEventListener('click', () => {
      document.getElementById('profile-modal').style.display = 'none';
    });
  }

  // Profile modal cancel button
  const profileCancelBtn = document.getElementById('profile-cancel-btn');
  if (profileCancelBtn) {
    profileCancelBtn.addEventListener('click', () => {
      document.getElementById('profile-modal').style.display = 'none';
    });
  }

  // Profile form — prevent default submission
  const profileForm = document.getElementById('profile-form');
  if (profileForm) {
    profileForm.addEventListener('submit', (e) => e.preventDefault());
  }

  // Login form — prevent default submission
  const loginForm = document.getElementById('form-login');
  if (loginForm) {
    loginForm.addEventListener('submit', (e) => e.preventDefault());
  }

  // Register form — prevent default submission
  const registerForm = document.getElementById('form-register');
  if (registerForm) {
    registerForm.addEventListener('submit', (e) => e.preventDefault());
  }

  // Initialize Lucide icons (ensure DOM elements are present)
  if (window.lucide) lucide.createIcons();
});
