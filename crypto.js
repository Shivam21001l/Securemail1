/**
 * SecureMail Crypto Engine
 * ========================
 * - Triple DES (3DES/CBC) - email body encryption via CryptoJS
 * - RSA-OAEP 2048-bit     - asymmetric key transport (Web Crypto API)
 * - RSA-PSS SHA-256       - digital signatures (Web Crypto API)
 * - PBKDF2 + AES-256      - protect private keys in storage
 */

/* ─────────────────────────────────────────────
   1.  TRIPLE DES  (symmetric body encryption)
───────────────────────────────────────────── */
const TripleDES = {
  /**
   * Generate a random 24-byte (192-bit) 3DES key as hex string.
   */
  generateKey() {
    const bytes = new Uint8Array(24);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  /**
   * Encrypt plaintext with Triple DES (CBC mode, random IV).
   * Returns "ivHex:ciphertextHex"
   */
  encrypt(plaintext, keyHex) {
    const key   = CryptoJS.enc.Hex.parse(keyHex);
    const iv    = CryptoJS.lib.WordArray.random(8); // 64-bit IV for 3DES
    const ct    = CryptoJS.TripleDES.encrypt(plaintext, key, {
      iv,
      mode   : CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });
    return iv.toString(CryptoJS.enc.Hex) + ':' + ct.ciphertext.toString(CryptoJS.enc.Hex);
  },

  /**
   * Decrypt a message produced by encrypt().
   */
  decrypt(cipherBundle, keyHex) {
    const [ivHex, ctHex] = cipherBundle.split(':');
    const key            = CryptoJS.enc.Hex.parse(keyHex);
    const iv             = CryptoJS.enc.Hex.parse(ivHex);
    const cipherParams   = CryptoJS.lib.CipherParams.create({
      ciphertext: CryptoJS.enc.Hex.parse(ctHex),
    });
    const decrypted = CryptoJS.TripleDES.decrypt(cipherParams, key, {
      iv,
      mode   : CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });
    return decrypted.toString(CryptoJS.enc.Utf8);
  },
};


/* ─────────────────────────────────────────────
   2.  RSA-OAEP  (key transport / PKI)
───────────────────────────────────────────── */
const RSA = {
  /**
   * Generate an RSA-OAEP 2048-bit key pair.
   * Returns { publicKey: CryptoKey, privateKey: CryptoKey }
   */
  async generateKeyPair() {
    return crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,  // extractable
      ['encrypt', 'decrypt']
    );
  },

  /** Export public key as Base64 DER string */
  async exportPublicKey(key) {
    const buf = await crypto.subtle.exportKey('spki', key);
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  },

  /** Export private key as Base64 DER string */
  async exportPrivateKey(key) {
    const buf = await crypto.subtle.exportKey('pkcs8', key);
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  },

  /** Import a Base64 public key for encryption */
  async importPublicKey(b64) {
    const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return crypto.subtle.importKey('spki', buf, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
  },

  /** Import a Base64 private key for decryption */
  async importPrivateKey(b64) {
    const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return crypto.subtle.importKey('pkcs8', buf, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
  },

  /**
   * Encrypt a short string (3DES key hex) with recipient RSA public key.
   * Returns Base64 ciphertext.
   */
  async encryptKey(plainHex, recipientPublicKeyB64) {
    const pubKey  = await this.importPublicKey(recipientPublicKeyB64);
    const encoded = new TextEncoder().encode(plainHex);
    const buf     = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, encoded);
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  },

  /**
   * Decrypt a 3DES key hex with own RSA private key.
   */
  async decryptKey(encryptedB64, privateKeyB64) {
    const privKey = await this.importPrivateKey(privateKeyB64);
    const buf     = Uint8Array.from(atob(encryptedB64), c => c.charCodeAt(0));
    const dec     = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privKey, buf);
    return new TextDecoder().decode(dec);
  },
};


/* ─────────────────────────────────────────────
   3.  RSA-PSS  (digital signatures)
───────────────────────────────────────────── */
const DSig = {
  /**
   * Generate an RSA-PSS 2048-bit signing key pair.
   */
  async generateKeyPair() {
    return crypto.subtle.generateKey(
      { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify']
    );
  },

  async exportPublicKey(key) {
    const buf = await crypto.subtle.exportKey('spki', key);
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  },

  async exportPrivateKey(key) {
    const buf = await crypto.subtle.exportKey('pkcs8', key);
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  },

  async importPublicKey(b64) {
    const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return crypto.subtle.importKey('spki', buf, { name: 'RSA-PSS', hash: 'SHA-256' }, true, ['verify']);
  },

  async importPrivateKey(b64) {
    const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return crypto.subtle.importKey('pkcs8', buf, { name: 'RSA-PSS', hash: 'SHA-256' }, true, ['sign']);
  },

  /**
   * Sign a string with the sender's private signing key.
   * Returns Base64 signature.
   */
  async sign(message, privateKeyB64) {
    const privKey = await this.importPrivateKey(privateKeyB64);
    const encoded = new TextEncoder().encode(message);
    const sigBuf  = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, privKey, encoded);
    return btoa(String.fromCharCode(...new Uint8Array(sigBuf)));
  },

  /**
   * Verify a signature against sender's public signing key.
   * Returns true / false.
   */
  async verify(message, signatureB64, publicKeyB64) {
    try {
      const pubKey  = await this.importPublicKey(publicKeyB64);
      const encoded = new TextEncoder().encode(message);
      const sigBuf  = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));
      return await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, pubKey, sigBuf, encoded);
    } catch {
      return false;
    }
  },
};


/* ─────────────────────────────────────────────
   4.  PRIVATE KEY STORAGE (PBKDF2 + AES-256)
       Wraps a Base64 private key with a user passphrase.
───────────────────────────────────────────── */
const KeyStore = {
  /**
   * Derive a 256-bit AES-CBC key from a passphrase + salt (PBKDF2, 200k iterations).
   */
  async _deriveKey(passphrase, salt) {
    const baseKey = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-CBC', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  /**
   * Encrypt a private key (Base64 string) with a passphrase.
   * Returns JSON: { salt, iv, ct } all Base64.
   */
  async protect(privateKeyB64, passphrase) {
    const salt    = crypto.getRandomValues(new Uint8Array(16));
    const iv      = crypto.getRandomValues(new Uint8Array(16));
    const aesKey  = await this._deriveKey(passphrase, salt);
    const ctBuf   = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv },
      aesKey,
      new TextEncoder().encode(privateKeyB64)
    );
    const toB64 = u8 => btoa(String.fromCharCode(...u8));
    return JSON.stringify({ salt: toB64(salt), iv: toB64(iv), ct: toB64(new Uint8Array(ctBuf)) });
  },

  /**
   * Decrypt a protected private key JSON blob with a passphrase.
   */
  async unprotect(blob, passphrase) {
    const { salt, iv, ct } = JSON.parse(blob);
    const fromB64 = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const aesKey  = await this._deriveKey(passphrase, fromB64(salt));
    const ptBuf   = await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv: fromB64(iv) },
      aesKey,
      fromB64(ct)
    );
    return new TextDecoder().decode(ptBuf);
  },
};

/* Export for use in other modules */
window.SecureCrypto = { TripleDES, RSA, DSig, KeyStore };
