/**
 * SecureMail — App UI Controller
 * Drives the redesigned dark glassmorphic UI.
 */

import { Mail } from './mail.js';
import {
    classifyEmail, getSectionInfo, SYSTEM_SECTIONS, PRESET_TEMPLATES,
    loadCustomSections, saveCustomSections,
    loadSenderRules, saveSenderRules,
    loadUserRole, saveUserRole,
    loadManualOverrides, saveManualOverrides,
    getRolePresets
} from './classify.js';

// ─── Security Enforcement ──────────────────────────────────────────────────
const TRUSTED_PROJECT_ID = 'mail-de6a5'; 

function assertConfigIntegrity() {
    const projectId = window.CONFIG?.firebase?.projectId;
    if (projectId !== TRUSTED_PROJECT_ID) {
        document.body.innerHTML = `
            <div style="height:100vh;display:flex;align-items:center;justify-content:center;background:#0a0a0c;color:#fff;font-family:sans-serif;text-align:center;padding:20px;">
                <div>
                    <h1 style="color:#ef4444;">Security Alert</h1>
                    <p>Application configuration mismatch detected. Access denied for security reasons.</p>
                </div>
            </div>`;
        throw new Error("Config integrity check failed.");
    }
}

// ─── Session + State ─────────────────────────────────────────────────────────
let session = null;
let currentFolder = 'inbox';
let currentEmail = null;
let composeMode = 'new';
let currentDraftId = null;
let idleTimer = null;
const SESSION_TIMEOUT_MS = 15 * 60 * 1000;

// ── Classification state ─────────────────────────────────────────────────────────────────
let activeSection = 'primary';   // currently selected tab ID
let customSections = [];           // loaded from localStorage
let senderRules = {};           // {email|domain: sectionId}
let manualOverrides = {};          // {emailId: sectionId}
let activeFilters = new Set();    // active filter pills
let allEmailsCache = [];           // current folder's full list

// ─── Layout helpers ───────────────────────────────────────────────────────────
const isMobile = () => window.innerWidth <= 768;

function showEmailContent() {
    const detail = $('mail-detail-pane');
    const empty = $('content-empty-state');
    if (detail) {
        detail.style.display = '';
        // On mobile: slide in from the right via CSS class
        if (isMobile()) detail.classList.add('detail-open');
    }
    if (empty) empty.style.display = 'none';
}
function hideEmailContent() {
    const detail = $('mail-detail-pane');
    const empty = $('content-empty-state');
    if (detail) {
        detail.classList.remove('detail-open');
        if (!isMobile()) detail.style.display = 'none';
    }
    if (empty && !isMobile()) empty.style.display = '';
}

// ─── DOM Helpers ─────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const q = sel => document.querySelector(sel);
const qa = sel => [...document.querySelectorAll(sel)];
const show = el => { const e = typeof el === 'string' ? $(el) : el; if (e) e.style.display = ''; };
const hide = el => { const e = typeof el === 'string' ? $(el) : el; if (e) e.style.display = 'none'; };

// ─── SEO / Search Console Helpers ───────────────────────────────────────────

/**
 * Pings IndexNow (Bing/Yandex) to notify them of site updates.
 * Call this from the console or an admin button after a major update!
 */
async function indexNowPing() {
    const key = window.CONFIG?.indexNow?.key || '773ad00b252043e49758bdfb56b4a937';
    const url = window.CONFIG?.indexNow?.url || 'https://mail-de6a5.web.app/';
    const pingUrl = `https://www.bing.com/indexnow?url=${encodeURIComponent(url)}&key=${key}`;

    console.log('IndexNow: Pinging Bing/Yandex for instant indexing...');
    try {
        const res = await fetch(pingUrl);
        if (res.ok) {
            toast('IndexNow: Indexing request sent successfully!', 'success');
            console.log('IndexNow: Success');
        } else {
            console.warn('IndexNow: Ping failed (HTTP ' + res.status + ')');
        }
    } catch (e) {
        console.error('IndexNow Error:', e);
    }
}

// Make it available globally for manual triggers
window.indexNowPing = indexNowPing;
// ─── Initialization ──────────────────────────────────────────────────────────
window.addEventListener('load', () => {
    if (window.lucide) lucide.createIcons();
});
// ─── Avatar ──────────────────────────────────────────────────────────────────
const AV_COLORS = ['#6366f1', '#8b5cf6', '#06b6d4', '#ec4899', '#f59e0b', '#10b981', '#ef4444'];
function avColor(str) {
    let h = 0;
    for (const c of str) h = (h * 31 + c.charCodeAt(0)) & 0xffff;
    return AV_COLORS[h % AV_COLORS.length];
}
function makeAv(str, size = 36) {
    const bg = avColor(str);
    const initials = str.slice(0, 2).toUpperCase();
    return `<div class="av-circle" style="width:${size}px;height:${size}px;background:${bg};font-size:${Math.round(size * .38)}px;">${initials}</div>`;
}

// ─── Toast ───────────────────────────────────────────────────────────────────
    // Initialize icons in the new elements
    if (window.lucide) lucide.createIcons();
}

/** Modern Toast Component */
function toast(msg, type = 'info', duration = 3500) {
    const container = $('toast-container') || document.body;
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    
    const iconName = type === 'error' ? 'alert-circle' : type === 'success' ? 'check-circle' : 'info';
    el.innerHTML = `
        <i data-lucide="${iconName}" class="toast-icon"></i>
        <div class="toast-body">${msg}</div>
        <button class="toast-close">&times;</button>
    `;

    container.appendChild(el);
    requestAnimationFrame(() => el.classList.add('toast-show'));

    const dismiss = () => {
        el.classList.remove('toast-show');
        setTimeout(() => el.remove(), 300);
    };

    el.querySelector('.toast-close').onclick = dismiss;
    setTimeout(dismiss, duration);
    if (window.lucide) lucide.createIcons();
}

// ─── Folders ─────────────────────────────────────────────────────────────────
// ─── Loader ──────────────────────────────────────────────────────────────────
function showLoader(msg = 'Loading…') {
    $('loader-msg').textContent = msg;
    show('loader-overlay');
}
function hideLoader() { hide('loader-overlay'); }

// ─── Relative Time ───────────────────────────────────────────────────────────
function relTime(iso) {
    const d = new Date(iso), now = new Date();
    if (d.toDateString() === now.toDateString())
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (now - d < 7 * 86400000)
        return d.toLocaleDateString([], { weekday: 'short' });
    return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

// ─── Password Strength ───────────────────────────────────────────────────────
function calcStrength(pw) {
    let score = 0;
    if (pw.length >= 8) score++;
    if (pw.length >= 12) score++;
    if (/[A-Z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    return score; // 0-5
}

function updateStrengthMeter(pw) {
    const fill = $('strength-fill');
    const label = $('strength-label');
    if (!fill) return;
    const score = calcStrength(pw);
    const colors = ['#ef4444', '#ef4444', '#f59e0b', '#f59e0b', '#22c55e', '#22c55e'];
    const labels = ['Too weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very strong'];
    fill.style.width = `${Math.max(score / 5 * 100, pw ? 10 : 0)}%`;
    fill.style.background = colors[score] || '#ef4444';
    label.textContent = pw ? labels[score] : 'Enter a password';
}

// ─── Session Idle Timeout (15 min) ───────────────────────────────────────────
function resetIdleTimer() {
    clearTimeout(idleTimer);
    if (!session) return;
    idleTimer = setTimeout(lockSession, SESSION_TIMEOUT_MS);
}

function lockSession() {
    session = null;
    currentEmail = null;
    currentDraftId = null;
    // Clear DOM sensitive content
    const detail = $('mail-detail-content');
    if (detail) detail.innerHTML = '';
    toast('Session locked due to inactivity. Please sign in again.', 'info', 5000);
    Mail.logout().then(() => { window.location.href = 'login.html'; });
}

['click', 'keydown', 'mousemove', 'touchstart', 'scroll'].forEach(evt =>
    document.addEventListener(evt, resetIdleTimer, { passive: true })
);

// ─── Auth Helpers ────────────────────────────────────────────────────────────
async function renderAuth() {
    assertConfigIntegrity();
    session = await Mail.restoreSession();
    if (!session) {
        window.location.href = 'login.html';
        return;
    }
    await renderApp();
}

function getSavedAccounts() {
    try { return JSON.parse(localStorage.getItem('sm_accounts') || '[]'); }
    catch { return []; }
}

function saveAccount(email) {
    const saved = getSavedAccounts();
    if (!saved.includes(email)) {
        saved.push(email);
        localStorage.setItem('sm_accounts', JSON.stringify(saved.slice(-5)));
    }
}

// ─── App Render ──────────────────────────────────────────────────────────────
async function renderApp() {
    show('app-screen');

    let profileData = {};
    try {
        profileData = await Mail.loadUserProfile(session.username);
    } catch (e) { console.warn('Could not load profile data', e); }
    session.profile = profileData || {};

    const displayName = session.profile.nickname || session.username;

    // Set user avatar + username in sidebar
    let avHtml;
    if (session.profile.photo) {
        // CSP-safe: no inline onerror; error handler attached below
        avHtml = `<img class="av-safe-img" src="${escHtml(session.profile.photo)}" 
            style="width:100%;height:100%;object-fit:cover;border-radius:50%;" 
            data-fallback="${escHtml(makeAv(displayName, 30))}" alt="Avatar">`;
    } else {
        avHtml = makeAv(displayName, 30);
    }

    const topAv = $('user-avatar-topbar');
    if (topAv) topAv.innerHTML = avHtml;
    const dropAv = $('dropdown-avatar');
    if (dropAv) dropAv.innerHTML = avHtml;

    // CSP-safe: attach error handlers programmatically (no inline onerror)
    document.querySelectorAll('.av-safe-img').forEach(img => {
        img.addEventListener('error', function() {
            const fallbackHtml = this.getAttribute('data-fallback');
            if (fallbackHtml) {
                const wrapper = document.createElement('div');
                wrapper.innerHTML = fallbackHtml;
                this.replaceWith(wrapper.firstElementChild || wrapper);
            }
        }, { once: true });
    });


    const dropName = $('dropdown-name');
    if (dropName) dropName.textContent = displayName;
    const sbName = $('sidebar-username');
    if (sbName) sbName.textContent = displayName;

    // Load classification state
    initSections();

    hideEmailContent();
    await renderFolder('inbox');
    await updateInboxBadge();

    // Show role selector only on first login (no role stored)
    checkRoleModal();
}

async function renderFolder(folder) {
    currentFolder = folder;
    activeSection = 'primary'; // reset to Primary tab on folder switch
    activeFilters.clear();
    hideEmailContent();

    // Update active folder button
    qa('.folder-btn').forEach(b => b.classList.toggle('folder-active', b.dataset.folder === folder));

    // Update folder title
    const titles = { inbox: 'Inbox', starred: 'Starred', sent: 'Sent', drafts: 'Drafts', trash: 'Trash' };
    const folderTitle = $('folder-title');
    if (folderTitle) folderTitle.textContent = titles[folder] || folder;

    const mailList = $('mail-list');
    if (mailList) mailList.innerHTML = renderSkeletons(5);

    try {
        let emails;
        if (folder === 'starred') {
            emails = await Mail.getStarred(session.username);
        } else {
            emails = await Mail.getFolder(session.username, folder);
        }
        allEmailsCache = emails;
        renderTabBar(emails);           // build section tabs with unread counts
        renderEmailList(emails, folder, activeSection);
    } catch (e) {
        console.error(e);
        toast('Failed to load emails.', 'error');
    }
}

function renderEmailList(emails, folder, sectionFilter = activeSection) {
    const list = $('mail-list');
    if (!list) return;

    // Apply section filter + active filter pills + search query
    const searchQ = ($('filter-search') ? $('filter-search').value : '').toLowerCase().trim();
    const now = Date.now();
    const oneWeek = 7 * 24 * 60 * 60 * 1000;

    const visible = emails.filter(email => {
        // Check manual override first, then auto-classify
        const secId = manualOverrides[email.id] ||
            classifyEmail(email, customSections, senderRules).section;
        if (secId !== sectionFilter) return false;
        // Active filter pills
        if (activeFilters.has('unread') && email.read) return false;
        if (activeFilters.has('starred') && !email.starred) return false;
        if (activeFilters.has('week') && (now - (email.timestamp || 0)) > oneWeek) return false;
        // Search within section
        if (searchQ) {
            const haystack = `${email.from} ${email.subject}`.toLowerCase();
            if (!haystack.includes(searchQ)) return false;
        }
        return true;
    });

    if (!visible.length) {
        list.innerHTML = `
          <div class="empty-state">
            <i data-lucide="mail-search" style="width:40px; height:40px; stroke-width:1; color:var(--text-muted); opacity:0.5; margin-bottom:12px;"></i>
            <div class="empty-state-title">No messages here</div>
            <div class="empty-state-sub">Nothing in this section</div>
          </div>`;
        if (window.lucide) lucide.createIcons();
        return;
    }

    const lockSvg = `<i data-lucide="lock" style="width:11px; height:11px;"></i>`;
    const starSvg = `<i data-lucide="star" style="width:13px; height:13px;"></i>`;

    list.innerHTML = visible.map(email => {
        const isUnread = !email.read;
        const isStarred = email.starred;
        const sender = folder === 'sent' ? `To: ${email.to}` : email.from;

        // Classify email for badges + color bar
        const secId = manualOverrides[email.id] || classifyEmail(email, customSections, senderRules).section;
        const classified = classifyEmail(email, customSections, senderRules);
        const subTag = manualOverrides[email.id] ? null : classified.subTag;
        const sInfo = getSectionInfo(secId, customSections);

        // Only show badge label if it's not Primary
        const badgeHtml = sInfo.badgeLabel
            ? `<div class="section-badge" style="background:${sInfo.badgeBg};color:${sInfo.color};border:1px solid ${sInfo.color}33">${sInfo.badgeLabel}</div>`
            : '';
        const subBadgeHtml = subTag
            ? `<div class="sub-badge" style="background:${sInfo.badgeBg};color:${sInfo.color}">${subTag}</div>`
            : '';

        return `
          <div class="mail-item ${isUnread ? 'unread' : ''}" data-id="${email.id}" data-folder="${folder}" data-section="${secId}" draggable="true" role="button" tabindex="0" aria-label="Email from ${escHtml(sender)}: ${escHtml(email.subject || '')}">
            <div class="mail-item-sec-bar" style="background:${sInfo.color}"></div>
            <div class="mail-item-av">${makeAv(email.from, 38)}</div>
            <div class="mail-item-content">
              <div class="mail-item-row1">
                <span class="mail-item-from">${escHtml(sender)}</span>
                <span class="mail-item-time">${relTime(email.timestamp)}</span>
              </div>
              <div class="mail-item-row2">
                ${isUnread ? '<span class="mail-item-unread-dot"></span>' : ''}
                <span class="mail-item-subject">${escHtml(email.subject || '(no subject)')}</span>
              </div>
            </div>
            <div class="mail-item-right">
              ${badgeHtml}${subBadgeHtml}
              <button class="mail-item-star ${isStarred ? 'starred' : ''}" data-id="${email.id}" aria-label="${isStarred ? 'Unstar' : 'Star'} email" title="Star">${starSvg}</button>
              <span class="mail-lock-icon" title="Encrypted">${lockSvg}</span>
            </div>
          </div>`;
    }).join('');

    // Staggered entrance animation
    qa('.mail-item').forEach((item, idx) => {
        item.style.opacity = '0';
        item.style.transform = 'translateY(10px)';
        setTimeout(() => {
            item.style.transition = 'opacity 0.4s ease, transform 0.4s cubic-bezier(0.2, 0.8, 0.2, 1)';
            item.style.opacity = '1';
            item.style.transform = 'translateY(0)';
        }, idx * 30);
    });

    // Bind click + star events
    qa('.mail-item').forEach(item => {
        item.addEventListener('click', e => {
            if (e.target.closest('.mail-item-star')) return;
            const emailData = emails.find(em => em.id === item.dataset.id);
            if (emailData) openEmail(emailData, item.dataset.folder);
        });
        item.addEventListener('keydown', e => {
            if (e.key === 'Enter' || e.key === ' ') item.click();
        });
        item.addEventListener('contextmenu', e => {
            e.preventDefault();
            const emailData = emails.find(em => em.id === item.dataset.id);
            if (emailData) showCtxMenu(e, emailData);
        });
        // Drag-to-classify
        item.addEventListener('dragstart', e => {
            e.dataTransfer.setData('text/plain', item.dataset.id);
            item.classList.add('dragging');
        });
        item.addEventListener('dragend', () => item.classList.remove('dragging'));
    });

    qa('.mail-item-star').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const id = btn.dataset.id;
            try {
                const starred = await Mail.toggleStar(session.username, folder, id);
                btn.classList.toggle('starred', starred);
                btn.setAttribute('aria-label', (starred ? 'Unstar' : 'Star') + ' email');
            } catch (e) { console.error(e); }
        });
    });

    if (window.lucide) lucide.createIcons();
}

async function openEmail(emailRecord, folder) {
    currentEmail = { emailRecord, folder };
    showEmailContent();

    const detailContent = $('mail-detail-content');
    if (detailContent) detailContent.innerHTML = `<div class="mail-detail-card"><div class="decrypt-loading"><div class="decrypt-spinner"></div><div class="decrypt-label">Decrypting with RSA-2048…</div></div></div>`;

    try {
        const { body, verified } = await Mail.readEmail(session, emailRecord, folder);

        const lockSvg = `<i data-lucide="lock" style="width:11px; height:11px;"></i>`;
        const chkSvg = `<i data-lucide="check" style="width:11px; height:11px;"></i>`;
        const warnSvg = `<i data-lucide="alert-triangle" style="width:11px; height:11px;"></i>`;
        detailContent.innerHTML = `
          <div class="mail-detail-card">
            <h2 class="detail-subject">${escHtml(emailRecord.subject || '(no subject)')}</h2>
            <div class="detail-meta">
              <div class="detail-meta-av">${makeAv(emailRecord.from, 42)}</div>
              <div class="detail-meta-info">
                <div class="detail-meta-name">${escHtml(emailRecord.from)}</div>
                <div class="detail-meta-email">to ${escHtml(emailRecord.to)}</div>
                <div class="detail-meta-info-sub">
                   <div class="detail-meta-time">${new Date(emailRecord.timestamp).toLocaleString()}</div>
                   <div class="detail-badges-row">
                     <div class="detail-sig-badge ${verified ? '' : 'unverified'}">${verified ? chkSvg : warnSvg} ${verified ? 'SIGNATURE VERIFIED' : 'VERIFY FAILED'}</div>
                     <div class="detail-sig-badge detail-enc-badge">${lockSvg} ENCRYPTED</div>
                   </div>
                </div>
              </div>
            </div>
            <hr class="detail-divider" />
            <div class="detail-body">${escHtml(body)}</div>
          </div>`;
        if (window.lucide) lucide.createIcons();
        await updateInboxBadge();
    } catch (e) {
        console.error(e);
        toast('Failed to decrypt email.', 'error');
        detailContent.innerHTML = `<div class="mail-detail-card"><div class="decrypt-loading"><div class="decrypt-label">Decryption failed</div></div></div>`;
    }
}

async function updateInboxBadge() {
    try {
        const count = await Mail.getUnreadCount(session.username);
        const badge = $('inbox-badge');
        if (badge) {
            if (count > 0) { badge.textContent = count; show(badge); }
            else { hide(badge); }
        }
    } catch { /* ignore */ }
}

// ─── Classification helpers ──────────────────────────────────────────────────

function initSections() {
    customSections = loadCustomSections();
    senderRules = loadSenderRules();
    manualOverrides = loadManualOverrides();
}

function checkRoleModal() {
    if (!loadUserRole()) {
        // First time user — show role selector after a short delay
        setTimeout(() => { if ($('role-modal')) $('role-modal').style.display = ''; }, 600);
    }
}

function renderSkeletons(n) {
    const row = `<div class="skeleton-row">
      <div class="skeleton-av"></div>
      <div class="skeleton-lines">
        <div class="skeleton-line"></div>
        <div class="skeleton-line skeleton-line-short"></div>
      </div>
    </div>`;
    return Array.from({ length: n }, () => row).join('');
}

/** Build the tab bar with all system + custom sections + unread counts. */
function renderTabBar(emails) {
    const container = $('section-tabs');
    if (!container) return;

    // Clear existing tab buttons before re-rendering
    container.querySelectorAll('.tab-btn').forEach(b => b.remove());

    const allSections = [
        ...SYSTEM_SECTIONS,
        ...customSections.map(s => ({
            id: s.id, label: s.name, color: s.color, colorVar: s.color,
            badgeLabel: s.name.slice(0, 6).toUpperCase(),
            badgeBg: hexToRgba(s.color, 0.12)
        }))
    ];

    allSections.forEach(sec => {
        // Count unread emails classified into this section
        const unread = emails.filter(e => {
            const secId = manualOverrides[e.id] || classifyEmail(e, customSections, senderRules).section;
            return secId === sec.id && !e.read;
        }).length;

        const btn = document.createElement('button');
        btn.className = 'tab-btn' + (sec.id === activeSection ? ' tab-active' : '');
        btn.dataset.section = sec.id;
        btn.setAttribute('role', 'tab');
        btn.setAttribute('aria-selected', sec.id === activeSection);
        if (sec.id === activeSection) {
            btn.style.borderBottomColor = sec.color;
        }
        btn.innerHTML = sec.label +
            (unread > 0
                ? ` <span class="tab-badge" style="background:${sec.badgeBg};color:${sec.color}">${unread}</span>`
                : '');

        btn.addEventListener('click', () => {
            activeSection = sec.id;
            renderTabBar(allEmailsCache);
            renderEmailList(allEmailsCache, currentFolder, sec.id);
        });

        // Drag-to-classify: drop target on tabs
        btn.addEventListener('dragover', e => {
            e.preventDefault();
            btn.classList.add('drag-over');
            btn.style.borderBottomColor = sec.color;
        });
        btn.addEventListener('dragleave', () => btn.classList.remove('drag-over'));
        btn.addEventListener('drop', e => {
            e.preventDefault();
            btn.classList.remove('drag-over');
            const emailId = e.dataTransfer.getData('text/plain');
            if (!emailId) return;
            const prev = manualOverrides[emailId];
            manualOverrides[emailId] = sec.id;
            saveManualOverrides(manualOverrides);
            renderTabBar(allEmailsCache);
            renderEmailList(allEmailsCache, currentFolder, activeSection);
            // Toast with undo
            toastWithUndo(`Moved to ${sec.label}`, () => {
                if (prev) manualOverrides[emailId] = prev;
                else delete manualOverrides[emailId];
                saveManualOverrides(manualOverrides);
                renderTabBar(allEmailsCache);
                renderEmailList(allEmailsCache, currentFolder, activeSection);
            });
        });

        container.appendChild(btn);
    });
}

function hexToRgba(hex, a) {
    if (!hex || !hex.startsWith('#')) return `rgba(0,200,255,${a})`;
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    return `rgba(${r},${g},${b},${a})`;
}

/** Show right-click context menu for an email row. */
function showCtxMenu(e, emailRecord) {
    const menu = $('ctx-menu');
    if (!menu) return;

    // Build section move options
    const list = $('ctx-section-list');
    const allSections = [...SYSTEM_SECTIONS, ...customSections.map(s => ({ id: s.id, label: s.name, color: s.color }))];
    list.innerHTML = allSections.map(sec =>
        `<button class="ctx-item" data-sec="${sec.id}" role="menuitem" style="color:${sec.id === 'spam' ? 'var(--red)' : ''}">
          <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${sec.color};margin-right:4px"></span>
          ${sec.label}
        </button>`
    ).join('');

    list.querySelectorAll('.ctx-item[data-sec]').forEach(btn => {
        btn.addEventListener('click', () => {
            const prev = manualOverrides[emailRecord.id];
            manualOverrides[emailRecord.id] = btn.dataset.sec;
            saveManualOverrides(manualOverrides);
            menu.style.display = 'none';
            renderTabBar(allEmailsCache);
            renderEmailList(allEmailsCache, currentFolder, activeSection);
            const secInfo = allSections.find(s => s.id === btn.dataset.sec);
            toastWithUndo(`Moved to ${secInfo?.label || btn.dataset.sec}`, () => {
                if (prev) manualOverrides[emailRecord.id] = prev;
                else delete manualOverrides[emailRecord.id];
                saveManualOverrides(manualOverrides);
                renderTabBar(allEmailsCache);
                renderEmailList(allEmailsCache, currentFolder, activeSection);
            });
        });
    });

    // Spam shortcut
    $('ctx-mark-spam').onclick = () => {
        manualOverrides[emailRecord.id] = 'spam';
        saveManualOverrides(manualOverrides);
        menu.style.display = 'none';
        renderTabBar(allEmailsCache);
        renderEmailList(allEmailsCache, currentFolder, activeSection);
        toast('Marked as spam', 'success');
    };

    // Always-classify-sender rule
    $('ctx-sender-rule').onclick = () => {
        const currentSec = manualOverrides[emailRecord.id] || activeSection;
        const from = (emailRecord.from || '').toLowerCase();
        senderRules[from] = currentSec;
        saveSenderRules(senderRules);
        menu.style.display = 'none';
        toast(`Sender always → ${currentSec}`, 'success');
    };

    // Position menu
    const vw = window.innerWidth, vh = window.innerHeight;
    let x = e.clientX, y = e.clientY;
    menu.style.display = '';
    const mw = menu.offsetWidth || 220;
    const mh = menu.offsetHeight || 200;
    if (x + mw > vw) x = vw - mw - 8;
    if (y + mh > vh) y = vh - mh - 8;
    menu.style.left = x + 'px';
    menu.style.top = y + 'px';
    menu.style.animation = 'none';
    requestAnimationFrame(() => { menu.style.animation = ''; });
}

/** Toast with an Undo button and 4s progress bar. */
function toastWithUndo(msg, undoFn) {
    const container = $('toast-container');
    if (!container) return;
    const t = document.createElement('div');
    t.className = 'toast toast-success';
    t.innerHTML = `${escHtml(msg)}<button class="toast-undo-btn">Undo</button><div class="toast-progress"></div>`;
    container.appendChild(t);
    requestAnimationFrame(() => t.classList.add('toast-show'));

    const undoBtn = t.querySelector('.toast-undo-btn');
    const timer = setTimeout(() => t.remove(), 4200);
    undoBtn.addEventListener('click', () => {
        clearTimeout(timer);
        t.remove();
        if (undoFn) undoFn();
    });
}

/** Create a new custom section from form data. */
function createCustomSection(name, color, keywords, senders) {
    const id = `sec_${Date.now()}`;
    const newSec = { id, name, color, keywords, senders };
    customSections.push(newSec);
    saveCustomSections(customSections);
    renderTabBar(allEmailsCache);
    toast(`Section "${name}" created`, 'success');
    return newSec;
}

// ─── Compose ─────────────────────────────────────────────────────────────────
function openCompose(opts = {}) {
    $('compose-to').value = opts.to || '';
    $('compose-subject').value = opts.subject || '';
    $('compose-body').value = opts.body || '';
    composeMode = opts.mode || 'new';
    currentDraftId = opts.draftId || null;
    const panel = $('compose-modal');
    if (panel) {
        panel.style.display = '';
        // Re-trigger slide-up animation
        panel.style.animation = 'none';
        requestAnimationFrame(() => {
            panel.style.animation = '';
        });
    }
    $('compose-to').focus();
}

async function handleSend() {
    const to = $('compose-to').value.trim();
    const subject = $('compose-subject').value.trim();
    const body = $('compose-body').value;
    if (!to || !body) { toast('Recipient and message body are required.', 'error'); return; }

    showLoader('Encrypting and sending message…');
    try {
        await Mail.sendEmail(session, to, subject, body);
        if (currentDraftId) {
            await Mail.deleteDraft(session.username, currentDraftId);
            currentDraftId = null;
        }
        hide('compose-modal');
        $('compose-to').value = $('compose-subject').value = $('compose-body').value = '';
        toast('Message encrypted and sent!', 'success');
        if (currentFolder === 'sent') await renderFolder('sent');
    } catch (e) {
        toast(e.message || 'Send failed.', 'error');
        console.error(e);
    } finally { hideLoader(); }
}

async function handleSaveDraft() {
    const draftData = {
        to: $('compose-to').value.trim(),
        subject: $('compose-subject').value.trim(),
        body: $('compose-body').value,
        from: session.username
    };
    showLoader('Saving draft…');
    try {
        if (currentDraftId) await Mail.deleteDraft(session.username, currentDraftId);
        currentDraftId = await Mail.saveDraft(session.username, draftData);
        hide('compose-modal');
        toast('Draft saved.', 'success');
        if (currentFolder === 'drafts') await renderFolder('drafts');
    } catch (e) {
        toast('Failed to save draft.', 'error');
    } finally { hideLoader(); }
}

// ─── Search ──────────────────────────────────────────────────────────────────
function handleSearch(query) {
    const q2 = query.toLowerCase().trim();
    if (!q2) { qa('.mail-item').forEach(i => i.style.display = ''); return; }
    qa('.mail-item').forEach(item => {
        const text = item.textContent.toLowerCase();
        item.style.display = text.includes(q2) ? '' : 'none';
    });
}

// ─── Keys Modal ──────────────────────────────────────────────────────────────
function showKeysModal() {
    const body = $('keys-modal-body');
    if (!body || !session) return;
    const short = k => k ? (k.slice(0, 48) + '…') : 'N/A';
    body.innerHTML = `
      <div class="key-block">
        <div class="key-block-title">Your Email (Identity)</div>
        <div class="key-block-value">${escHtml(session.username)}</div>
      </div>
      <div class="key-block">
        <div class="key-block-title">RSA-2048 Encryption Public Key (SPKI · Base64)</div>
        <div class="key-block-value">${short(session.rsaPub)}</div>
      </div>
      <div class="key-block">
        <div class="key-block-title">RSA-PSS Signing Public Key (SPKI · Base64)</div>
        <div class="key-block-value">${short(session.sigPub)}</div>
      </div>
      <div class="key-block">
        <div class="key-block-title">Encryption Standard</div>
        <div class="key-block-value">AES-256-GCM body · RSA-OAEP-2048 key wrap · RSA-PSS signatures · PBKDF2-SHA256-600k key derivation</div>
      </div>`;
    show('keys-modal');
}

// ─── Escape HTML ─────────────────────────────────────────────────────────────
function escHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// ─── Logout ──────────────────────────────────────────────────────────────────
async function handleLogout() {
    clearTimeout(idleTimer);
    session = null;
    currentEmail = null;
    const detail = $('mail-detail-content');
    if (detail) detail.innerHTML = '';
    hide('user-menu');
    try {
        await Mail.logout();
    } catch (e) {
        console.error('Firebase Auth signout error:', e);
    }
    // Always force redirect
    window.location.href = 'login.html';
}

// ═══════════════════════════════════════════════════════════════
//  INIT: Wire all event listeners after DOM ready
// ═══════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', async () => {

    // Sidebar overlay click → close sidebar
    const sidebarOverlay = $('sidebar-overlay');
    if (sidebarOverlay) {
        sidebarOverlay.addEventListener('click', () => {
            const sb = $('sidebar');
            if (sb) sb.classList.remove('sidebar-open');
            sidebarOverlay.classList.remove('sidebar-overlay-show');
        });
    }



    // Folder navigation
    qa('.folder-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            if (!session) return;
            renderFolder(btn.dataset.folder);
            // On mobile: auto-close the sidebar drawer after navigating
            if (isMobile()) {
                toggleSidebar(); // Call the new global function to close the sidebar
            }
        });
    });

    // Compose
    $('compose-btn').addEventListener('click', () => openCompose());
    $('send-btn').addEventListener('click', handleSend);
    $('save-draft-btn').addEventListener('click', handleSaveDraft);
    $('compose-close').addEventListener('click', () => {
        hide('compose-modal');
        currentDraftId = null;
    });
    $('compose-minimize').addEventListener('click', () => hide('compose-modal'));

    // Search
    $('search-input').addEventListener('input', e => handleSearch(e.target.value));

    // Refresh
    $('refresh-btn').addEventListener('click', async () => {
        if (!session) return;
        await renderFolder(currentFolder);
        toast('Refreshed', 'info', 1500);
    });

    // Keys modal
    $('keys-btn').addEventListener('click', () => {
        if (!session) return;
        showKeysModal();
    });

    // Detail toolbar
    $('detail-back-btn').addEventListener('click', () => {
        hideEmailContent();
    });

    // Refresh spin animation
    $('refresh-btn').addEventListener('click', function () {
        this.classList.remove('spin');
        void this.offsetWidth; // reflow
        this.querySelector('svg').classList.add('spin');
        setTimeout(() => this.querySelector('svg').classList.remove('spin'), 600);
    }, { capture: true });

    $('detail-star-btn').addEventListener('click', async () => {
        if (!currentEmail) return;
        const { emailRecord, folder } = currentEmail;
        try {
            const starred = await Mail.toggleStar(session.username, folder, emailRecord.id);
            toast(starred ? 'Starred' : 'Unstarred', 'success', 1500);
        } catch (e) { toast('Failed to star.', 'error'); }
    });

    $('detail-trash-btn').addEventListener('click', async () => {
        if (!currentEmail) return;
        const { emailRecord, folder } = currentEmail;
        showLoader('Moving to trash…');
        try {
            await Mail.moveToTrash(session.username, folder, emailRecord.id);
            hide('mail-detail-pane');
            show('mail-list-pane');
            await renderFolder(currentFolder);
            toast('Moved to trash.', 'success');
        } catch (e) { toast('Failed.', 'error'); }
        finally { hideLoader(); }
    });

    $('detail-reply-btn').addEventListener('click', () => {
        if (!currentEmail) return;
        const { emailRecord } = currentEmail;
        openCompose({
            to: emailRecord.from,
            subject: `Re: ${emailRecord.subject}`,
            mode: 'reply'
        });
    });

    // Classification — filter pills
    qa('.filter-pill').forEach(pill => {
        pill.addEventListener('click', () => {
            const f = pill.dataset.filter;
            if (activeFilters.has(f)) {
                activeFilters.delete(f);
                pill.classList.remove('filter-active');
            } else {
                activeFilters.add(f);
                pill.classList.add('filter-active');
            }
            renderEmailList(allEmailsCache, currentFolder, activeSection);
        });
    });

    // Classification — filter search
    if ($('filter-search')) {
        $('filter-search').addEventListener('input', () => {
            renderEmailList(allEmailsCache, currentFolder, activeSection);
        });
    }

    // Classification — filter toggle button (in list-header)
    const listHeader = document.querySelector('.list-header');
    if (listHeader) {
        const filterToggle = document.createElement('button');
        filterToggle.className = 'filter-toggle-btn';
        filterToggle.innerHTML = 'Filter &#8964;';
        filterToggle.title = 'Quick filters';
        filterToggle.setAttribute('aria-label', 'Toggle filter bar');
        listHeader.appendChild(filterToggle);
        filterToggle.addEventListener('click', () => {
            const fb = $('filter-bar');
            fb && fb.classList.toggle('filter-open');
        });
    }

    // Classification — dismiss context menu on outside click
    document.addEventListener('click', () => {
        const m = $('ctx-menu');
        if (m) m.style.display = 'none';
    });

    // ── New Section Button ───────────────────────────────────────────
    if ($('new-section-btn')) {
        $('new-section-btn').addEventListener('click', () => {
            // Reset form
            $('ns-name').value = '';
            $('ns-counter').textContent = '0/32';
            kwArr = []; senderArr = []; pickedColor = '#00c8ff';
            renderPills();
            updatePreview();
            // Reset color swatches to cyan
            qa('.color-swatch').forEach(s => s.classList.remove('color-swatch-active'));
            const defaultSwatch = document.querySelector('.color-swatch[data-color="#00c8ff"]');
            if (defaultSwatch) defaultSwatch.classList.add('color-swatch-active');

            // Render template grid from PRESET_TEMPLATES
            const grid = $('template-grid');
            if (grid) {
                grid.innerHTML = PRESET_TEMPLATES.map((tpl, i) =>
                    `<button class="template-btn" data-tpl-i="${i}" title="Use ${tpl.name} template">
                      <div class="template-btn-dot" style="background:${tpl.color}22;color:${tpl.color}">${tpl.icon}</div>
                      <span>${tpl.name}</span>
                    </button>`
                ).join('');

                grid.querySelectorAll('.template-btn').forEach(btn => {
                    btn.addEventListener('click', () => {
                        const tpl = PRESET_TEMPLATES[+btn.dataset.tplI];
                        // Pre-fill form
                        $('ns-name').value = tpl.name;
                        $('ns-counter').textContent = `${tpl.name.length}/32`;
                        kwArr = [...tpl.keywords];
                        senderArr = [...(tpl.senders || [])];
                        pickedColor = tpl.color;
                        renderPills();
                        // Select matching color swatch
                        qa('.color-swatch').forEach(s => s.classList.remove('color-swatch-active'));
                        const sw = document.querySelector(`.color-swatch[data-color="${tpl.color}"]`);
                        if (sw) sw.classList.add('color-swatch-active');
                        updatePreview();
                        // Highlight selected template
                        grid.querySelectorAll('.template-btn').forEach(b => {
                            b.classList.toggle('tpl-selected', b === btn);
                            if (b === btn) {
                                b.style.borderColor = tpl.color;
                                b.style.background = tpl.color + '15';
                            } else {
                                b.style.borderColor = '';
                                b.style.background = '';
                            }
                        });
                    });
                });
            }

            $('new-section-modal').style.display = '';
        });
    }

    // ── Custom Section Modal wiring ──────────────────────────────────
    let kwArr = []; let senderArr = []; let pickedColor = '#00c8ff';

    function renderPills() {
        const kwWrap = $('kw-pills');
        const sWrap = $('sender-pills');
        if (kwWrap) kwWrap.innerHTML = kwArr.map((k, i) =>
            `<span class="pill-tag">${escHtml(k)}<button class="pill-rm" data-i="${i}" aria-label="Remove keyword">×</button></span>`
        ).join('');
        if (sWrap) sWrap.innerHTML = senderArr.map((s, i) =>
            `<span class="pill-tag sender-pill">${escHtml(s)}<button class="pill-rm sender-rm" data-i="${i}" aria-label="Remove sender">×</button></span>`
        ).join('');
        // Bind remove buttons
        if (kwWrap) kwWrap.querySelectorAll('.pill-rm:not(.sender-rm)').forEach(btn => {
            btn.addEventListener('click', () => { kwArr.splice(+btn.dataset.i, 1); renderPills(); updatePreview(); });
        });
        if (sWrap) sWrap.querySelectorAll('.sender-rm').forEach(btn => {
            btn.addEventListener('click', () => { senderArr.splice(+btn.dataset.i, 1); renderPills(); });
        });
    }

    function updatePreview() {
        const name = ($('ns-name') ? $('ns-name').value.trim() : '') || 'Section Name';
        const color = pickedColor;
        if ($('ns-preview-name')) $('ns-preview-name').textContent = name;
        if ($('ns-preview-dot')) $('ns-preview-dot').style.background = color;
        if ($('ns-preview-bar')) $('ns-preview-bar').style.background = color;
        if ($('ns-preview-badge')) {
            $('ns-preview-badge').textContent = name.slice(0, 6).toUpperCase();
            $('ns-preview-badge').style.color = color;
            $('ns-preview-badge').style.background = hexToRgba(color, 0.12);
        }
    }

    if ($('ns-name')) {
        $('ns-name').addEventListener('input', () => {
            const v = $('ns-name').value;
            $('ns-counter').textContent = `${v.length}/32`;
            updatePreview();
        });
    }

    // Keyword input → pill on Enter/comma
    if ($('ns-kw-input')) {
        $('ns-kw-input').addEventListener('keydown', e => {
            if (e.key === 'Enter' || e.key === ',') {
                e.preventDefault();
                const v = $('ns-kw-input').value.replace(',', '').trim();
                if (v && !kwArr.includes(v)) { kwArr.push(v); renderPills(); updatePreview(); }
                $('ns-kw-input').value = '';
            }
        });
    }

    // Sender input → pill on Enter
    if ($('ns-sender-input')) {
        $('ns-sender-input').addEventListener('keydown', e => {
            if (e.key === 'Enter') {
                e.preventDefault();
                const v = $('ns-sender-input').value.trim();
                if (v && !senderArr.includes(v)) { senderArr.push(v); renderPills(); }
                $('ns-sender-input').value = '';
            }
        });
    }

    // Color swatches
    qa('.color-swatch').forEach(sw => {
        sw.addEventListener('click', () => {
            qa('.color-swatch').forEach(s => s.classList.remove('color-swatch-active'));
            sw.classList.add('color-swatch-active');
            pickedColor = sw.dataset.color;
            updatePreview();
        });
    });

    // Create section button
    if ($('create-section-btn')) {
        $('create-section-btn').addEventListener('click', () => {
            const name = $('ns-name').value.trim();
            if (!name) {
                $('ns-name-error').style.display = '';
                $('ns-name').classList.add('field-error');
                $('ns-name').animate([{ transform: 'translateX(-5px)' }, { transform: 'translateX(5px)' }, { transform: 'translateX(0)' }], { duration: 300, iterations: 2 });
                return;
            }
            if (!kwArr.length && !senderArr.length) {
                $('ns-kw-warn').style.display = '';
                return;
            }
            $('ns-name-error').style.display = 'none';
            $('ns-kw-warn').style.display = 'none';
            createCustomSection(name, pickedColor, [...kwArr], [...senderArr]);
            kwArr = []; senderArr = [];
            $('new-section-modal').style.display = 'none';
        });
    }

    // Cancel / close section modal
    [$('close-section-modal'), $('cancel-section-btn')].forEach(btn => {
        if (btn) btn.addEventListener('click', () => {
            $('new-section-modal').style.display = 'none';
        });
    });

    // ── Role Selector Modal ──────────────────────────────────────────
    if ($('role-cards')) {
        $('role-cards').querySelectorAll('.role-card').forEach(card => {
            card.addEventListener('click', () => {
                qa('.role-card').forEach(c => c.classList.remove('selected'));
                card.classList.add('selected');
                const role = card.dataset.role;
                saveUserRole(role);
                // Close modal — no sections auto-created.
                // User adds their own via + New Section.
                $('role-modal').style.display = 'none';
                toast(`Inbox ready! Use + New Section to organise your mail.`, 'success', 4000);
            });
        });
    }

    if ($('role-skip')) {
        $('role-skip').addEventListener('click', () => {
            saveUserRole('other');
            $('role-modal').style.display = 'none';
        });
    }

    // User pill → dropdown
    if ($('user-pill-btn')) {
        $('user-pill-btn').addEventListener('click', e => {
            e.stopPropagation();
            const menu = $('user-menu');
            const isHidden = menu.style.display === 'none' || !menu.style.display;
            menu.style.display = isHidden ? '' : 'none';
        });
    }

    // Edit Profile Modal
    if ($('edit-profile-btn')) {
        $('edit-profile-btn').addEventListener('click', () => {
            hide('user-menu');
            if (!session || !session.profile) return;
            $('prof-nickname').value = session.profile.nickname || '';
            $('prof-photo').value = session.profile.photo || '';
            $('prof-gender').value = session.profile.gender || '';
            $('prof-age').value = session.profile.age || '';
            $('prof-phone').value = session.profile.phone || '';
            show('profile-modal');
        });
    }

    if ($('profile-form')) {
        $('profile-form').addEventListener('submit', async e => {
            e.preventDefault();
            const profileData = {
                nickname: $('prof-nickname').value.trim(),
                photo: $('prof-photo').value.trim(),
                gender: $('prof-gender').value,
                age: $('prof-age').value ? Number($('prof-age').value) : null,
                phone: $('prof-phone').value.trim()
            };
            const btn = $('save-profile-btn');
            btn.textContent = 'Saving...';
            btn.disabled = true;
            try {
                await Mail.saveUserProfile(session.username, profileData);
                toast('Profile updated successfully!', 'success');
                session.profile = { ...session.profile, ...profileData };
                await renderApp(); // Re-render to update avatars & names
                hide('profile-modal');
            } catch (err) {
                toast('Failed to save profile.', 'error');
                console.error(err);
            } finally {
                btn.textContent = 'Save Changes';
                btn.disabled = false;
            }
        });
    }

    document.addEventListener('click', () => hide('user-menu'));

    if ($('logout-menu-btn')) $('logout-menu-btn').addEventListener('click', handleLogout);

    // Initial auth render
    await renderAuth();
});

// Expose helpers for inline HTML
window._app = { toast, openCompose };
window.openCompose = openCompose;
