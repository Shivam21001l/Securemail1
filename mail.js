/**
 * SecureMail — Mail Logic (Firebase + AES-256-GCM Edition)
 * =========================================================
 * Auth:     Firebase Email/Password + Google (re-derived keys)
 * Security: AES-256-GCM (body) + RSA-OAEP-2048 (key wrap)
 *           RSA-PSS-2048 (signatures) + PBKDF2-SHA256 600k iter (key protection)
 *           Private keys stored encrypted in Firestore; decrypted keys kept ONLY in memory.
 */

import { initializeApp } from "https://www.gstatic.com/firebasejs/10.14.1/firebase-app.js";
import { initializeAppCheck, ReCaptchaV3Provider } from "https://www.gstatic.com/firebasejs/10.14.1/firebase-app-check.js";
import {
    getAuth,
    signInWithPopup,
    GoogleAuthProvider,
    signInWithEmailAndPassword,
    createUserWithEmailAndPassword,
    sendPasswordResetEmail,
    signOut
} from "https://www.gstatic.com/firebasejs/10.14.1/firebase-auth.js";
import {
    initializeFirestore, persistentLocalCache, persistentMultipleTabManager,
    doc, setDoc, getDoc, collection, getDocs, deleteDoc, updateDoc
} from "https://www.gstatic.com/firebasejs/10.14.1/firebase-firestore.js";

// In-memory key storage (never persisted to storage, lost on page reload)
let _sessionKeys = null;

const firebaseConfig = window.CONFIG?.firebase || {
  apiKey: "AIzaSyDYsxo9JwP1xD5-AjX04WuRHcs139woZLc",
  authDomain: "mail-de6a5.firebaseapp.com",
  projectId: "mail-de6a5",
  storageBucket: "mail-de6a5.firebasestorage.app",
  messagingSenderId: "4792532998",
  appId: "1:4792532998:web:e4fdd313d7aee35dce0387",
  measurementId: "G-6ST8NWKW10"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = initializeFirestore(app, {
  localCache: persistentLocalCache({ tabManager: persistentMultipleTabManager() })
});

// ─── App Check (Anti-Bot) ──────────────────────────────────────
const siteKey = window.CONFIG?.appCheck?.recaptchaSiteKey;
if (siteKey) {
    try {
        initializeAppCheck(app, {
            provider: new ReCaptchaV3Provider(siteKey),
            isTokenAutoRefreshEnabled: true
        });
        console.log("Firebase App Check initialized.");
    } catch (e) {
        console.warn("App Check failed to initialize:", e);
    }
}

// ═══════════════════════════════════════════════════════════════
//  PRIMITIVE CRYPTO HELPERS
// ═══════════════════════════════════════════════════════════════

const Crypto = (() => {
    const enc = new TextEncoder();
    const dec = new TextDecoder();

    /** Convert ArrayBuffer ↔ Base64 */
    const toB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
    const fromB64 = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

    // ── AES-256-GCM ──────────────────────────────────────────────────

    async function generateMessageKey() {
        return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    }

    async function aesEncrypt(plaintext, aesKey) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const cipherBuf = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv, tagLength: 128 },
            aesKey,
            enc.encode(plaintext)
        );
        return { iv: toB64(iv), ciphertext: toB64(cipherBuf) };
    }

    async function aesDecrypt({ iv, ciphertext }, aesKey) {
        const plainBuf = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: fromB64(iv), tagLength: 128 },
            aesKey,
            fromB64(ciphertext)
        );
        return dec.decode(plainBuf);
    }

    // ── RSA-OAEP-2048 ────────────────────────────────────────────────

    async function generateRSAKeyPair() {
        return crypto.subtle.generateKey(
            { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
            true,
            ["encrypt", "decrypt"]
        );
    }

    async function exportRSAPublicKey(key) {
        return toB64(await crypto.subtle.exportKey("spki", key));
    }

    async function importRSAPublicKey(b64) {
        return crypto.subtle.importKey("spki", fromB64(b64), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
    }

    async function exportRSAPrivateKey(key) {
        return toB64(await crypto.subtle.exportKey("pkcs8", key));
    }

    async function importRSAPrivateKey(b64) {
        // High Security: Private key is non-extractable after import
        return crypto.subtle.importKey("pkcs8", fromB64(b64), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
    }

    async function wrapAESKey(aesKey, rsaPublicKey) {
        const rawKey = await crypto.subtle.exportKey("raw", aesKey);
        const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, rsaPublicKey, rawKey);
        return toB64(wrapped);
    }

    async function unwrapAESKey(wrappedB64, rsaPrivateKey) {
        const rawKey = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, rsaPrivateKey, fromB64(wrappedB64));
        return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
    }

    // ── RSA-PSS Signatures ───────────────────────────────────────────

    async function generateSigKeyPair() {
        return crypto.subtle.generateKey(
            { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
            true,
            ["sign", "verify"]
        );
    }

    async function exportSigPublicKey(key) {
        return toB64(await crypto.subtle.exportKey("spki", key));
    }

    async function importSigPublicKey(b64) {
        return crypto.subtle.importKey("spki", fromB64(b64), { name: "RSA-PSS", hash: "SHA-256" }, false, ["verify"]);
    }

    async function exportSigPrivateKey(key) {
        return toB64(await crypto.subtle.exportKey("pkcs8", key));
    }

    async function importSigPrivateKey(b64) {
        return crypto.subtle.importKey("pkcs8", fromB64(b64), { name: "RSA-PSS", hash: "SHA-256" }, false, ["sign"]);
    }

    async function signData(data, sigPrivateKey) {
        const sig = await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, sigPrivateKey, enc.encode(data));
        return toB64(sig);
    }

    async function verifyData(data, sigB64, sigPublicKeyB64) {
        try {
            const key = await importSigPublicKey(sigPublicKeyB64);
            return crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, key, fromB64(sigB64), enc.encode(data));
        } catch { return false; }
    }

    // ── PBKDF2-SHA256 (600k iterations) ──────────────────

    async function deriveKey(passphrase, saltB64) {
        const salt = fromB64(saltB64);
        const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
        return crypto.subtle.deriveKey(
            { name: "PBKDF2", salt, iterations: 600_000, hash: "SHA-256" },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    }

    async function protectKey(privateKeyB64, passphrase) {
        const salt = crypto.getRandomValues(new Uint8Array(32));
        const saltB64 = toB64(salt);
        const derivedKey = await deriveKey(passphrase, saltB64);
        const payload = await aesEncrypt(privateKeyB64, derivedKey);
        return JSON.stringify({ salt: saltB64, ...payload });
    }

    async function unprotectKey(protectedJSON, passphrase) {
        const { salt, iv, ciphertext } = JSON.parse(protectedJSON);
        const derivedKey = await deriveKey(passphrase, salt);
        return aesDecrypt({ iv, ciphertext }, derivedKey);
    }

    async function derivePassphraseFromAuth(uid) {
        const domainSalt = enc.encode('securemail-v2-keywrap-salt-2026');
        const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(uid), 'PBKDF2', false, ['deriveKey']);
        const derivedKey = await crypto.subtle.deriveKey(
            { name: "PBKDF2", salt: domainSalt, iterations: 600_000, hash: "SHA-256" },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
        const rawBytes = await crypto.subtle.exportKey("raw", derivedKey);
        return Array.from(new Uint8Array(rawBytes)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    return {
        generateMessageKey, aesEncrypt, aesDecrypt,
        generateRSAKeyPair, exportRSAPublicKey, importRSAPublicKey, exportRSAPrivateKey, importRSAPrivateKey,
        wrapAESKey, unwrapAESKey,
        generateSigKeyPair, exportSigPublicKey, importSigPublicKey, exportSigPrivateKey, importSigPrivateKey,
        signData, verifyData,
        protectKey, unprotectKey, derivePassphraseFromAuth,
        toB64, fromB64
    };
})();

// ═══════════════════════════════════════════════════════════════
//  USERNAME UTILITIES
// ═══════════════════════════════════════════════════════════════

function generateUsernameFromEmail(email) {
    const local = (email.split('@')[0] || 'user').toLowerCase().replace(/[^a-z0-9_]/g, '_').slice(0, 14);
    const randomBytes = new Uint8Array(2);
    crypto.getRandomValues(randomBytes);
    const suffix = Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    return `${local}_${suffix}`;
}

async function claimUsername(email, uid) {
    for (let i = 0; i < 5; i++) {
        const username = generateUsernameFromEmail(email);
        const nameSnap = await getDoc(doc(db, 'usernames', username));
        if (!nameSnap.exists()) {
            await setDoc(doc(db, 'usernames', username), { uid });
            return username;
        }
    }
    throw new Error('Username generation failed.');
}

// ═══════════════════════════════════════════════════════════════
//  MAIL API
// ═══════════════════════════════════════════════════════════════

const Mail = (() => {

    async function getUserPublicKeys(username) {
        const snap = await getDoc(doc(db, 'users', username, 'profile', 'data'));
        return snap.exists() ? { rsaPub: snap.data().publicEncryptKey, sigPub: snap.data().publicSignKey } : null;
    }

    async function setupSession(user, username) {
        const keysDoc = await getDoc(doc(db, 'users', username, 'keys', 'data'));
        const profileDoc = await getDoc(doc(db, 'users', username, 'profile', 'data'));
        if (!keysDoc.exists() || !profileDoc.exists()) throw new Error('Account incomplete.');

        const { encryptedPrivateKey, encryptedSignKey } = keysDoc.data();
        const { publicEncryptKey: rsaPub, publicSignKey: sigPub } = profileDoc.data();

        const passphrase = await Crypto.derivePassphraseFromAuth(user.uid);
        const rsaPrivB64 = await Crypto.unprotectKey(encryptedPrivateKey, passphrase);
        const sigPrivB64 = await Crypto.unprotectKey(encryptedSignKey, passphrase);

        _sessionKeys = {
            username, rsaPub, sigPub,
            rsaPriv: await Crypto.importRSAPrivateKey(rsaPrivB64),
            sigPriv: await Crypto.importSigPrivateKey(sigPrivB64)
        };
        sessionStorage.setItem('sm_uid', user.uid);
    }

    async function registerGooglePrompt() {
        const result = await signInWithPopup(auth, new GoogleAuthProvider());
        const dirSnap = await getDoc(doc(db, 'directories', result.user.uid));
        if (dirSnap.exists()) {
            await setupSession(result.user, dirSnap.data().username);
            return { isNewUser: false, user: result.user };
        }
        return { isNewUser: true, user: result.user };
    }

    async function registerWithGoogle(username, onProgress) {
        const user = auth.currentUser;
        if (onProgress) onProgress(1);
        await setDoc(doc(db, 'usernames', username), { uid: user.uid });
        await setDoc(doc(db, 'directories', user.uid), { username });

        if (onProgress) onProgress(2);
        const encPair = await Crypto.generateRSAKeyPair();
        const sigPair = await Crypto.generateSigKeyPair();

        if (onProgress) onProgress(3);
        const passphrase = await Crypto.derivePassphraseFromAuth(user.uid);
        const rsaPrivProtected = await Crypto.protectKey(await Crypto.exportRSAPrivateKey(encPair.privateKey), passphrase);
        const sigPrivProtected = await Crypto.protectKey(await Crypto.exportSigPrivateKey(sigPair.privateKey), passphrase);

        await setDoc(doc(db, 'users', username, 'profile', 'data'), {
            email: user.email,
            publicEncryptKey: await Crypto.exportRSAPublicKey(encPair.publicKey),
            publicSignKey: await Crypto.exportSigPublicKey(sigPair.publicKey),
            createdAt: new Date().toISOString()
        });
        await setDoc(doc(db, 'users', username, 'keys', 'data'), {
            encryptedPrivateKey: rsaPrivProtected, encryptedSignKey: sigPrivProtected, createdAt: new Date().toISOString()
        });

        _sessionKeys = {
            username,
            rsaPub: await Crypto.exportRSAPublicKey(encPair.publicKey),
            sigPub: await Crypto.exportSigPublicKey(sigPair.publicKey),
            rsaPriv: encPair.privateKey,
            sigPriv: sigPair.privateKey
        };
        sessionStorage.setItem('sm_uid', user.uid);
        if (onProgress) onProgress(4);
        return true;
    }

    async function loginWithGoogle() {
        const result = await signInWithPopup(auth, new GoogleAuthProvider());
        const dirSnap = await getDoc(doc(db, 'directories', result.user.uid));
        if (!dirSnap.exists()) throw new Error('No account found.');
        await setupSession(result.user, dirSnap.data().username);
        return { username: dirSnap.data().username };
    }

    async function registerWithEmail(email, password, onProgress) {
        if (onProgress) onProgress(1);
        const credential = await createUserWithEmailAndPassword(auth, email, password);
        const username = await claimUsername(email, credential.user.uid);
        await setDoc(doc(db, 'directories', credential.user.uid), { username });

        if (onProgress) onProgress(2);
        const encPair = await Crypto.generateRSAKeyPair();
        const sigPair = await Crypto.generateSigKeyPair();

        if (onProgress) onProgress(3);
        const passphrase = await Crypto.derivePassphraseFromAuth(credential.user.uid);
        const rsaPrivB64 = await Crypto.exportRSAPrivateKey(encPair.privateKey);
        const sigPrivB64 = await Crypto.exportSigPrivateKey(sigPair.privateKey);

        await setDoc(doc(db, 'users', username, 'profile', 'data'), {
            email, publicEncryptKey: await Crypto.exportRSAPublicKey(encPair.publicKey),
            publicSignKey: await Crypto.exportSigPublicKey(sigPair.publicKey), createdAt: new Date().toISOString()
        });
        await setDoc(doc(db, 'users', username, 'keys', 'data'), {
            encryptedPrivateKey: await Crypto.protectKey(rsaPrivB64, passphrase),
            encryptedSignKey: await Crypto.protectKey(sigPrivB64, passphrase), createdAt: new Date().toISOString()
        });

        _sessionKeys = {
            username, rsaPub: await Crypto.exportRSAPublicKey(encPair.publicKey),
            sigPub: await Crypto.exportSigPublicKey(sigPair.publicKey),
            rsaPriv: encPair.privateKey, sigPriv: sigPair.privateKey
        };
        sessionStorage.setItem('sm_uid', credential.user.uid);
        if (onProgress) onProgress(4);
        return { username };
    }

    async function loginWithEmail(email, password) {
        const credential = await signInWithEmailAndPassword(auth, email, password);
        const dirSnap = await getDoc(doc(db, 'directories', credential.user.uid));
        if (!dirSnap.exists()) throw new Error('Auth/NotRegistered');
        await setupSession(credential.user, dirSnap.data().username);
        return { username: dirSnap.data().username };
    }

    async function forgotPassword(email) {
        try { await sendPasswordResetEmail(auth, email); } catch {}
    }

    async function getFolder(username, folder) {
        const snap = await getDocs(collection(db, `users/${username}/${folder}`));
        const emails = [];
        snap.forEach(d => emails.push(d.data()));
        return emails.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }

    async function getEmail(username, folder, id) {
        const snap = await getDoc(doc(db, `users/${username}/${folder}`, id));
        return snap.exists() ? snap.data() : null;
    }

    async function sendEmail(session, to, subject, body) {
        const keys = await getUserPublicKeys(to);
        if (!keys) throw new Error('Recipient not found.');

        const sessionKey = await Crypto.generateMessageKey();
        const encryptedBody = await Crypto.aesEncrypt(body, sessionKey);
        const signature = await Crypto.signData(body, session.sigPriv);

        const id = `${Date.now()}-${crypto.getRandomValues(new Uint32Array(1))[0].toString(36)}`;
        const emailRecord = {
            id, from: session.username, to, subject, encryptedBody, encVersion: 2, signature,
            senderSigPub: session.sigPub,
            wrappedKeyForRecipient: await Crypto.wrapAESKey(sessionKey, await Crypto.importRSAPublicKey(keys.rsaPub)),
            wrappedKeyForSender: await Crypto.wrapAESKey(sessionKey, await Crypto.importRSAPublicKey(session.rsaPub)),
            timestamp: new Date().toISOString(), read: false, starred: false
        };

        await setDoc(doc(db, `users/${to}/inbox`, id), emailRecord);
        await setDoc(doc(db, `users/${session.username}/sent`, id), emailRecord);
        return emailRecord;
    }

    async function readEmail(session, email, folder) {
        const wrappedKey = folder === 'sent' ? email.wrappedKeyForSender : email.wrappedKeyForRecipient;
        const sessionKey = await Crypto.unwrapAESKey(wrappedKey, session.rsaPriv);
        const body = await Crypto.aesDecrypt(email.encryptedBody, sessionKey);
        const verified = await Crypto.verifyData(body, email.signature, email.senderSigPub);
        // Mark as read
        const ref = doc(db, `users/${session.username}/${folder}`, email.id);
        await updateDoc(ref, { read: true });
        return { body, verified };
    }

    async function toggleStar(username, folder, id) {
        const ref = doc(db, `users/${username}/${folder}`, id);
        const snap = await getDoc(ref);
        if (snap.exists()) {
            const starred = !snap.data().starred;
            await updateDoc(ref, { starred });
            return starred;
        }
        return false;
    }

    async function moveToTrash(username, folder, id) {
        const ref = doc(db, `users/${username}/${folder}`, id);
        const snap = await getDoc(ref);
        if (snap.exists()) {
            await setDoc(doc(db, `users/${username}/trash`, id), snap.data());
            await deleteDoc(ref);
        }
    }

    async function saveDraft(username, data) {
        const id = `draft-${Date.now()}`;
        await setDoc(doc(db, `users/${username}/drafts`, id), { ...data, id, timestamp: new Date().toISOString(), read: true });
        return id;
    }

    async function deleteDraft(username, id) {
        await deleteDoc(doc(db, `users/${username}/drafts`, id));
    }

    async function getUnreadCount(username) {
        const snap = await getDocs(collection(db, `users/${username}/inbox`));
        let count = 0;
        snap.forEach(d => { if (!d.data().read) count++; });
        return count;
    }

    async function getStarred(username) {
        const [i, s] = await Promise.all([getDocs(collection(db, `users/${username}/inbox`)), getDocs(collection(db, `users/${username}/sent`))]);
        const all = [];
        i.forEach(d => { if (d.data().starred) all.push(d.data()); });
        s.forEach(d => { if (d.data().starred) all.push(d.data()); });
        return all.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }

    async function saveUserProfile(username, data) { await setDoc(doc(db, 'users', username, 'profile', 'data'), data, { merge: true }); }
    async function loadUserProfile(username) {
        const snap = await getDoc(doc(db, 'users', username, 'profile', 'data'));
        return snap.exists() ? snap.data() : null;
    }

    async function restoreSession() {
        // High Security: returns _sessionKeys only if they exist in memory.
        // On page reload, this is null, forcing re-login to re-decrypt keys.
        return _sessionKeys;
    }

    function logout() {
        _sessionKeys = null;
        sessionStorage.removeItem('sm_uid');
        return signOut(auth);
    }

    return {
        registerGooglePrompt, registerWithGoogle, loginWithGoogle,
        registerWithEmail, loginWithEmail, forgotPassword,
        restoreSession, logout,
        getUserPublicKeys, saveUserProfile, loadUserProfile,
        getFolder, getEmail, sendEmail, readEmail,
        toggleStar, moveToTrash, saveDraft, deleteDraft,
        getUnreadCount, getStarred
    };
})();

window.Mail = Mail;
export { Mail };
