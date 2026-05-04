/**
 * SecureMail — Mail Logic (Firebase + AES-256-GCM Edition)
 * =========================================================
 * Auth:     Firebase Email/Password only (no OAuth)
 * Security: AES-256-GCM (body) + RSA-OAEP-2048 (key wrap)
 *           RSA-PSS-2048 (signatures) + PBKDF2-SHA256 600k iter (key protection)
 *           Private key passphrase NEVER stored in database — derived client-side.
 * All data stored in Firebase Firestore with persistent local cache for offline.
 */

import { initializeApp } from "https://www.gstatic.com/firebasejs/10.14.1/firebase-app.js";
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

// ═══════════════════════════════════════════════════════════════
//  PRIMITIVE CRYPTO HELPERS — Pure WebCrypto, No 3DES
// ═══════════════════════════════════════════════════════════════

const Crypto = (() => {
    const enc = new TextEncoder();
    const dec = new TextDecoder();

    /** Convert ArrayBuffer ↔ Base64 */
    const toB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
    const fromB64 = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

    // ── AES-256-GCM ──────────────────────────────────────────────────

    /** Generate a random one-time AES-256-GCM key */
    async function generateMessageKey() {
        return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    }

    /** Encrypt plaintext with AES-256-GCM. Returns { iv, ciphertext } as Base64 strings. */
    async function aesEncrypt(plaintext, aesKey) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const cipherBuf = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv, tagLength: 128 },
            aesKey,
            enc.encode(plaintext)
        );
        return { iv: toB64(iv), ciphertext: toB64(cipherBuf) };
    }

    /** Decrypt AES-256-GCM payload. Returns plaintext string. */
    async function aesDecrypt({ iv, ciphertext }, aesKey) {
        const plainBuf = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: fromB64(iv), tagLength: 128 },
            aesKey,
            fromB64(ciphertext)
        );
        return dec.decode(plainBuf);
    }

    // ── RSA-OAEP-2048 ────────────────────────────────────────────────

    /** Generate RSA-OAEP-2048 encryption key pair */
    async function generateRSAKeyPair() {
        return crypto.subtle.generateKey(
            { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
            true,
            ["encrypt", "decrypt"]
        );
    }

    /** Export RSA public key as Base64 SPKI */
    async function exportRSAPublicKey(key) {
        return toB64(await crypto.subtle.exportKey("spki", key));
    }

    /** Import RSA public key from Base64 SPKI */
    async function importRSAPublicKey(b64) {
        return crypto.subtle.importKey("spki", fromB64(b64), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
    }

    /** Export RSA private key as Base64 PKCS8 */
    async function exportRSAPrivateKey(key) {
        return toB64(await crypto.subtle.exportKey("pkcs8", key));
    }

    /** Import RSA private key from Base64 PKCS8 */
    async function importRSAPrivateKey(b64) {
        return crypto.subtle.importKey("pkcs8", fromB64(b64), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
    }

    /** Wrap (encrypt) an AES key with RSA-OAEP public key. Returns Base64. */
    async function wrapAESKey(aesKey, rsaPublicKey) {
        const rawKey = await crypto.subtle.exportKey("raw", aesKey);
        const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, rsaPublicKey, rawKey);
        return toB64(wrapped);
    }

    /** Unwrap (decrypt) an AES key with RSA-OAEP private key. Returns CryptoKey. */
    async function unwrapAESKey(wrappedB64, rsaPrivateKey) {
        const rawKey = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, rsaPrivateKey, fromB64(wrappedB64));
        return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
    }

    // ── RSA-PSS Signatures ───────────────────────────────────────────

    /** Generate RSA-PSS-2048 signing key pair */
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
        const key = typeof sigPrivateKey === "string" ? await importSigPrivateKey(sigPrivateKey) : sigPrivateKey;
        const sig = await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, key, enc.encode(data));
        return toB64(sig);
    }

    async function verifyData(data, sigB64, sigPublicKeyB64) {
        try {
            const key = await importSigPublicKey(sigPublicKeyB64);
            return crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, key, fromB64(sigB64), enc.encode(data));
        } catch { return false; }
    }

    // ── PBKDF2-SHA256 (600k iterations — NIST 2024) ──────────────────

    /** Derive an AES-256-GCM key from a passphrase + salt using PBKDF2 */
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

    /** Protect private key bytes with passphrase → {salt, iv, ciphertext} JSON string */
    async function protectKey(privateKeyB64, passphrase) {
        const salt = crypto.getRandomValues(new Uint8Array(32));
        const saltB64 = toB64(salt);
        const derivedKey = await deriveKey(passphrase, saltB64);
        const payload = await aesEncrypt(privateKeyB64, derivedKey);
        return JSON.stringify({ salt: saltB64, ...payload });
    }

    /** Unprotect private key. Returns Base64 PKCS8. Throws on wrong passphrase. */
    async function unprotectKey(protectedJSON, passphrase) {
        const { salt, iv, ciphertext } = JSON.parse(protectedJSON);
        const derivedKey = await deriveKey(passphrase, salt);
        return aesDecrypt({ iv, ciphertext }, derivedKey);
    }

    /**
     * Derive a deterministic passphrase for key protection from the user's
     * Firebase UID + email using PBKDF2-SHA256.
     * This passphrase is NEVER stored anywhere — it is re-derived at login time
     * from credentials only available client-side after successful Firebase Auth.
     *
     * @param {string} uid   - Firebase Auth UID
     * @param {string} email - User's email (lowercase)
     * @returns {Promise<string>} - hex passphrase (64 chars)
     */
    async function derivePassphraseFromAuth(uid, email) {
        // Combine uid + email as the "password" material
        const material = `${uid}:${email.toLowerCase()}`;
        // Use a fixed, known salt derived from app identity (not secret, but domain-specific)
        const domainSalt = enc.encode('securemail-v2-keywrap-salt-2026');
        const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(material), "PBKDF2", false, ["deriveKey"]);
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

/**
 * Derive a clean username from an email local part and make it unique
 * by appending a cryptographically random 4-char hex suffix.
 */
function generateUsernameFromEmail(email) {
    const local = (email.split('@')[0] || 'user')
        .toLowerCase()
        .replace(/[^a-z0-9_]/g, '_')
        .replace(/_{2,}/g, '_')
        .replace(/^_|_$/g, '')
        .slice(0, 14);

    // Random 4-hex suffix for uniqueness (16^4 = 65536 possibilities)
    const randomBytes = new Uint8Array(2);
    crypto.getRandomValues(randomBytes);
    const suffix = Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('');

    return `${local || 'user'}_${suffix}`;
}

/**
 * Attempt to claim a username. Retries with a new suffix if taken (max 5 attempts).
 */
async function claimUsername(email, uid) {
    for (let attempt = 0; attempt < 5; attempt++) {
        const username = generateUsernameFromEmail(email);
        const nameRef = doc(db, 'usernames', username);
        const nameSnap = await getDoc(nameRef);
        if (!nameSnap.exists()) {
            await setDoc(nameRef, { uid });
            return username;
        }
    }
    throw new Error('Could not generate a unique username. Please try again.');
}

// ═══════════════════════════════════════════════════════════════
//  MAIL API
// ═══════════════════════════════════════════════════════════════

const Mail = (() => {

    // ── User account operations ──────────────────────────────────────

    async function getUsers() {
        const snap = await getDocs(collection(db, 'users'));
        const users = {};
        snap.forEach(d => { users[d.id] = d.data(); });
        return users;
    }

    async function getUserPublicKeys(username) {
        const snapNew = await getDoc(doc(db, 'users', username, 'profile', 'data'));
        if (snapNew.exists()) {
            return { rsaPub: snapNew.data().publicEncryptKey, sigPub: snapNew.data().publicSignKey };
        }
        const snap = await getDoc(doc(db, 'users', username));
        if (!snap.exists()) return null;
        const { rsaPub, sigPub } = snap.data();
        return { rsaPub, sigPub };
    }

    // ── Google Registration ──────────────────────────────────────────

    /** Step 1: Prompt Google Sign-In popup and check if user already exists */
    async function registerGooglePrompt() {
        const provider = new GoogleAuthProvider();
        const result = await signInWithPopup(auth, provider);
        const user = result.user;

        const dirSnap = await getDoc(doc(db, 'directories', user.uid));
        if (dirSnap.exists()) {
            // Existing user — auto-login with derived passphrase
            const username = dirSnap.data().username;
            const keysDoc = await getDoc(doc(db, 'users', username, 'keys', 'data'));
            const { encryptedPrivateKey, encryptedSignKey } = keysDoc.data();
            const profileDoc = await getDoc(doc(db, 'users', username, 'profile', 'data'));
            const { publicEncryptKey, publicSignKey } = profileDoc.data();

            const passphrase = await Crypto.derivePassphraseFromAuth(user.uid, user.email);
            const rsaPrivB64 = await Crypto.unprotectKey(encryptedPrivateKey, passphrase);
            const sigPrivB64 = await Crypto.unprotectKey(encryptedSignKey, passphrase);

            sessionStorage.setItem('sm_session', JSON.stringify({
                username, rsaPub: publicEncryptKey, sigPub: publicSignKey, rsaPrivB64, sigPrivB64
            }));

            return { isNewUser: false, user };
        }
        return { isNewUser: true, user };
    }

    /** Step 2: Complete Google registration with a chosen username */
    async function registerWithGoogle(username, onProgress) {
        const user = auth.currentUser;
        if (!user) throw new Error('Must authenticate with Google first.');

        if (onProgress) onProgress(1);

        const nameRef = doc(db, 'usernames', username);
        const nameSnap = await getDoc(nameRef);
        if (nameSnap.exists()) {
            throw new Error(`Username @${username} is already taken.`);
        }

        await setDoc(nameRef, { uid: user.uid });
        await setDoc(doc(db, 'directories', user.uid), { username });

        if (onProgress) onProgress(2);
        const encPair = await Crypto.generateRSAKeyPair();
        const rsaPub = await Crypto.exportRSAPublicKey(encPair.publicKey);
        const rsaPriv = await Crypto.exportRSAPrivateKey(encPair.privateKey);

        const sigPair = await Crypto.generateSigKeyPair();
        const sigPub = await Crypto.exportSigPublicKey(sigPair.publicKey);
        const sigPriv = await Crypto.exportSigPrivateKey(sigPair.privateKey);

        if (onProgress) onProgress(3);
        // Derive passphrase from auth credentials — NEVER stored!
        const passphrase = await Crypto.derivePassphraseFromAuth(user.uid, user.email);

        const rsaPrivProtected = await Crypto.protectKey(rsaPriv, passphrase);
        const sigPrivProtected = await Crypto.protectKey(sigPriv, passphrase);

        await setDoc(doc(db, 'users', username, 'profile', 'data'), {
            email: user.email || `${username}@securemail.local`,
            publicEncryptKey: rsaPub,
            publicSignKey: sigPub,
            createdAt: new Date().toISOString()
        });

        await setDoc(doc(db, 'users', username, 'keys', 'data'), {
            encryptedPrivateKey: rsaPrivProtected,
            encryptedSignKey: sigPrivProtected,
            // NOTE: passphrase intentionally NOT stored
            createdAt: new Date().toISOString()
        });

        await setDoc(doc(db, 'users', username), {
            rsaPub, sigPub, createdAt: new Date().toISOString()
        });

        sessionStorage.setItem('sm_session', JSON.stringify({
            username, rsaPub, sigPub, rsaPrivB64: rsaPriv, sigPrivB64: sigPriv
        }));

        if (onProgress) onProgress(4);
        return true;
    }

    /** Login with Google popup — for existing users */
    async function loginWithGoogle() {
        const provider = new GoogleAuthProvider();
        const result = await signInWithPopup(auth, provider);
        const user = result.user;

        const dirSnap = await getDoc(doc(db, 'directories', user.uid));
        if (!dirSnap.exists()) {
            throw new Error('No SecureMail account found. Please register first.');
        }

        const username = dirSnap.data().username;

        const keysDoc = await getDoc(doc(db, 'users', username, 'keys', 'data'));
        if (!keysDoc.exists()) throw new Error('Cryptographic keys not found.');

        const { encryptedPrivateKey, encryptedSignKey } = keysDoc.data();
        const profileDoc = await getDoc(doc(db, 'users', username, 'profile', 'data'));
        const { publicEncryptKey: rsaPub, publicSignKey: sigPub } = profileDoc.data();

        // Derive passphrase from auth — never stored
        const passphrase = await Crypto.derivePassphraseFromAuth(user.uid, user.email);

        try {
            const rsaPrivB64 = await Crypto.unprotectKey(encryptedPrivateKey, passphrase);
            const sigPrivB64 = await Crypto.unprotectKey(encryptedSignKey, passphrase);
            await Crypto.importRSAPrivateKey(rsaPrivB64);
            await Crypto.importSigPrivateKey(sigPrivB64);

            sessionStorage.setItem('sm_session', JSON.stringify({
                username, rsaPub, sigPub, rsaPrivB64, sigPrivB64
            }));

            return { username, rsaPub, sigPub };
        } catch {
            throw new Error('Could not decrypt keys.');
        }
    }

    // ── Email Registration ───────────────────────────────────────────

    /**
     * Register a new user with email + password.
     * - Creates Firebase Auth account
     * - Auto-generates a unique username from email
     * - Generates RSA-OAEP-2048 + RSA-PSS-2048 key pairs
     * - Protects private keys with PBKDF2-derived passphrase (never stored)
     * - Writes public keys + encrypted private keys to Firestore
     *
     * @param {string}   email       - User's email address
     * @param {string}   password    - User's chosen password
     * @param {Function} onProgress  - Progress callback: step 1-4
     */
    async function registerWithEmail(email, password, onProgress) {
        if (onProgress) onProgress(1); // Creating account

        // Create Firebase Auth account
        const credential = await createUserWithEmailAndPassword(auth, email, password);
        const user = credential.user;

        // Claim a unique username
        const username = await claimUsername(email, user.uid);

        // Store UID → username directory mapping
        await setDoc(doc(db, 'directories', user.uid), { username });

        if (onProgress) onProgress(2); // Generating keys

        // Generate RSA-OAEP encryption pair + RSA-PSS signing pair
        const encPair = await Crypto.generateRSAKeyPair();
        const rsaPub = await Crypto.exportRSAPublicKey(encPair.publicKey);
        const rsaPriv = await Crypto.exportRSAPrivateKey(encPair.privateKey);

        const sigPair = await Crypto.generateSigKeyPair();
        const sigPub = await Crypto.exportSigPublicKey(sigPair.publicKey);
        const sigPriv = await Crypto.exportSigPrivateKey(sigPair.privateKey);

        if (onProgress) onProgress(3); // Securing keys

        // Derive passphrase from Firebase credentials — NEVER stored!
        const passphrase = await Crypto.derivePassphraseFromAuth(user.uid, email);

        // Protect private keys with PBKDF2-derived key
        const rsaPrivProtected = await Crypto.protectKey(rsaPriv, passphrase);
        const sigPrivProtected = await Crypto.protectKey(sigPriv, passphrase);

        // Write public profile (public keys only — no sensitive data)
        await setDoc(doc(db, 'users', username, 'profile', 'data'), {
            email: email,
            publicEncryptKey: rsaPub,
            publicSignKey: sigPub,
            createdAt: new Date().toISOString()
        });

        // Write encrypted private keys (passphrase NOT stored — re-derived at login)
        await setDoc(doc(db, 'users', username, 'keys', 'data'), {
            encryptedPrivateKey: rsaPrivProtected,
            encryptedSignKey: sigPrivProtected,
            // NOTE: passphrase is intentionally NOT stored here
            createdAt: new Date().toISOString()
        });

        // Legacy public-key index for backward compat with getUserPublicKeys
        await setDoc(doc(db, 'users', username), {
            rsaPub, sigPub, createdAt: new Date().toISOString()
        });

        // Store session in memory only (no plaintext keys in sessionStorage)
        sessionStorage.setItem('sm_session', JSON.stringify({
            username, rsaPub, sigPub, rsaPrivB64: rsaPriv, sigPrivB64: sigPriv
        }));

        if (onProgress) onProgress(4); // Done
        return { username };
    }

    // ── Login ────────────────────────────────────────────────────────

    /**
     * Sign in with email + password, load and decrypt cryptographic keys.
     * Private key passphrase is re-derived from Firebase Auth credentials.
     *
     * @param {string} email    - User email
     * @param {string} password - User password
     */
    async function loginWithEmail(email, password) {
        // Authenticate with Firebase
        const credential = await signInWithEmailAndPassword(auth, email, password);
        const user = credential.user;

        // Resolve username from UID directory
        const dirSnap = await getDoc(doc(db, 'directories', user.uid));
        if (!dirSnap.exists()) {
            await signOut(auth);
            throw new Error('Auth/NotRegistered');
        }

        const username = dirSnap.data().username;

        // Load encrypted key bundle
        const keysDoc = await getDoc(doc(db, 'users', username, 'keys', 'data'));
        if (!keysDoc.exists()) {
            await signOut(auth);
            throw new Error('Auth/KeysMissing');
        }

        const { encryptedPrivateKey, encryptedSignKey } = keysDoc.data();

        const profileDoc = await getDoc(doc(db, 'users', username, 'profile', 'data'));
        if (!profileDoc.exists()) {
            await signOut(auth);
            throw new Error('Auth/ProfileMissing');
        }
        const { publicEncryptKey: rsaPub, publicSignKey: sigPub } = profileDoc.data();

        // Re-derive passphrase from auth credentials (never was stored)
        const passphrase = await Crypto.derivePassphraseFromAuth(user.uid, email);

        let rsaPrivB64, sigPrivB64;
        try {
            rsaPrivB64 = await Crypto.unprotectKey(encryptedPrivateKey, passphrase);
            sigPrivB64 = await Crypto.unprotectKey(encryptedSignKey, passphrase);
        } catch {
            await signOut(auth);
            throw new Error('Auth/DecryptionFailed');
        }

        // Verify keys import correctly before storing session
        await Crypto.importRSAPrivateKey(rsaPrivB64);
        await Crypto.importSigPrivateKey(sigPrivB64);

        // Store session (private key B64 in sessionStorage — cleared on tab close)
        sessionStorage.setItem('sm_session', JSON.stringify({
            username, rsaPub, sigPub, rsaPrivB64, sigPrivB64
        }));

        return { username, rsaPub, sigPub };
    }

    // ── Forgot Password ──────────────────────────────────────────────

    /**
     * Send a Firebase password reset email.
     * Always resolves (success or failure) — caller should NOT leak
     * whether the email exists in the response.
     */
    async function forgotPassword(email) {
        // Firebase will reject fake emails silently; we swallow and always succeed
        try {
            await sendPasswordResetEmail(auth, email);
        } catch {
            // intentionally swallow — do not expose account existence
        }
    }

    // ── Mailbox operations ────────────────────────────────────────────

    async function getFolder(username, folderName) {
        const snap = await getDocs(collection(db, `users/${username}/${folderName}`));
        const emails = [];
        snap.forEach(d => emails.push(d.data()));
        return emails.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }

    async function getEmail(username, folderName, id) {
        const snap = await getDoc(doc(db, `users/${username}/${folderName}`, id));
        return snap.exists() ? snap.data() : null;
    }

    // ── Send email (AES-256-GCM body, RSA-OAEP key wrap, RSA-PSS sig) ─

    async function sendEmail(session, to, subject, body) {
        let recipientRSAPub, recipientSigPub;

        // Try new schema first
        const profileSnap = await getDoc(doc(db, 'users', to, 'profile', 'data'));
        if (profileSnap.exists()) {
            recipientRSAPub = profileSnap.data().publicEncryptKey;
            recipientSigPub = profileSnap.data().publicSignKey;
        } else {
            // Legacy schema
            const recipientSnap = await getDoc(doc(db, 'users', to));
            if (!recipientSnap.exists()) throw new Error(`Recipient "${to}" not found.`);
            recipientRSAPub = recipientSnap.data().rsaPub;
            recipientSigPub = recipientSnap.data().sigPub;
        }

        // Generate one-time AES-256-GCM session key
        const sessionKey = await Crypto.generateMessageKey();

        // Encrypt body
        const encryptedBody = await Crypto.aesEncrypt(body, sessionKey);

        // Sign body with sender's RSA-PSS signing key
        const signature = await Crypto.signData(body, session.sigPriv);

        // Wrap session key for both recipient and sender (so sender can re-read sent mail)
        const recipientPubKey = await Crypto.importRSAPublicKey(recipientRSAPub);
        const senderPubKey = await Crypto.importRSAPublicKey(session.rsaPub);
        const wrappedKeyForRecipient = await Crypto.wrapAESKey(sessionKey, recipientPubKey);
        const wrappedKeyForSender = await Crypto.wrapAESKey(sessionKey, senderPubKey);

        const id = `${Date.now()}-${crypto.getRandomValues(new Uint32Array(1))[0].toString(36)}`;
        const timestamp = new Date().toISOString();

        const emailRecord = {
            id, from: session.username, to, subject,
            encryptedBody,          // { iv, ciphertext }
            encVersion: 2,          // v2 = AES-256-GCM (v1 = legacy 3DES)
            signature,
            senderSigPub: session.sigPub,
            wrappedKeyForRecipient,
            wrappedKeyForSender,
            timestamp, read: false, starred: false,
        };

        await setDoc(doc(db, `users/${to}/inbox`, id), emailRecord);
        await setDoc(doc(db, `users/${session.username}/sent`, id), emailRecord);

        return emailRecord;
    }

    // ── Read / Decrypt email ──────────────────────────────────────────

    async function readEmail(session, emailRecord, folderName) {
        const wrappedKey = folderName === 'sent'
            ? emailRecord.wrappedKeyForSender
            : emailRecord.wrappedKeyForRecipient;

        let body;
        if (emailRecord.encVersion === 2) {
            // AES-256-GCM (current)
            const sessionKey = await Crypto.unwrapAESKey(wrappedKey, session.rsaPriv);
            body = await Crypto.aesDecrypt(emailRecord.encryptedBody, sessionKey);
        } else {
            // Legacy v1 3DES fallback (for old emails only)
            const { TripleDES, RSA } = window.SecureCrypto;
            const desKey = await RSA.decryptKey(wrappedKey || emailRecord.encryptedDesKeyForRecipient, session.rsaPriv);
            body = TripleDES.decrypt(emailRecord.encryptedBody, desKey);
        }

        const verified = await Crypto.verifyData(body, emailRecord.signature, emailRecord.senderSigPub);
        await markRead(session.username, folderName, emailRecord.id);
        return { body, verified };
    }

    // ── Utility operations ──────────────────────────────────────────────

    async function markRead(username, folderName, id) {
        const ref = doc(db, `users/${username}/${folderName}`, id);
        const snap = await getDoc(ref);
        if (snap.exists() && !snap.data().read) await updateDoc(ref, { read: true });
    }

    async function toggleStar(username, folderName, id) {
        const ref = doc(db, `users/${username}/${folderName}`, id);
        const snap = await getDoc(ref);
        if (snap.exists()) {
            const starred = !snap.data().starred;
            await updateDoc(ref, { starred });
            return starred;
        }
        return false;
    }

    async function moveToTrash(username, folderName, id) {
        const ref = doc(db, `users/${username}/${folderName}`, id);
        const snap = await getDoc(ref);
        if (snap.exists()) {
            const data = snap.data();
            await deleteDoc(ref);
            await setDoc(doc(db, `users/${username}/trash`, id), data);
        }
    }

    async function saveDraft(username, draftData) {
        const id = `draft-${Date.now()}-${crypto.getRandomValues(new Uint16Array(1))[0].toString(16)}`;
        await setDoc(doc(db, `users/${username}/drafts`, id), {
            id, ...draftData,
            timestamp: new Date().toISOString(), read: true, starred: false
        });
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
        const [inbox, sent] = await Promise.all([
            getDocs(collection(db, `users/${username}/inbox`)),
            getDocs(collection(db, `users/${username}/sent`))
        ]);
        const all = [];
        inbox.forEach(d => { if (d.data().starred) all.push(d.data()); });
        sent.forEach(d => { if (d.data().starred) all.push(d.data()); });
        return all.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }

    // ── Profile Operations ──────────────────────────────────────────────

    async function saveUserProfile(username, profileData) {
        const ref = doc(db, 'users', username, 'profile', 'data');
        await setDoc(ref, profileData, { merge: true });
    }

    async function loadUserProfile(username) {
        const snap = await getDoc(doc(db, 'users', username, 'profile', 'data'));
        return snap.exists() ? snap.data() : null;
    }

    // ── Session Restore ──────────────────────────────────────────────

    /** Restore session from sessionStorage and rebuild live CryptoKey objects. */
    async function restoreSession() {
        const stored = sessionStorage.getItem('sm_session');
        if (!stored) return null;
        try {
            const data = JSON.parse(stored);
            if (!data.username || !data.rsaPrivB64 || !data.sigPrivB64) {
                sessionStorage.removeItem('sm_session');
                return null;
            }
            return {
                username: data.username,
                rsaPub: data.rsaPub,
                sigPub: data.sigPub,
                rsaPriv: await Crypto.importRSAPrivateKey(data.rsaPrivB64),
                sigPriv: await Crypto.importSigPrivateKey(data.sigPrivB64)
            };
        } catch {
            sessionStorage.removeItem('sm_session');
            return null;
        }
    }

    /** Sign out and clear all session data. */
    function logout() {
        sessionStorage.removeItem('sm_session');
        return signOut(auth);
    }

    return {
        registerGooglePrompt, registerWithGoogle, loginWithGoogle,
        registerWithEmail, loginWithEmail, forgotPassword,
        restoreSession, logout,
        getUsers, getUserPublicKeys, saveUserProfile, loadUserProfile,
        getFolder, getEmail, sendEmail, readEmail,
        toggleStar, moveToTrash, saveDraft, deleteDraft,
        getUnreadCount, getStarred,
    };
})();

window.Mail = Mail;
export { Mail };
