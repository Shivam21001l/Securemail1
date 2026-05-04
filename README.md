# SecureMail

SecureMail is a modern, dark-themed, end-to-end encrypted mail platform. It uses industry-standard cryptographic algorithms to ensure that only the sender and recipient can read the messages.

## Features
- **End-to-End Encryption**: Uses AES-256-GCM for message bodies and RSA-OAEP-2048 for key wrapping.
- **Digital Signatures**: RSA-PSS-2048 for verifying the sender's identity.
- **Smart Classification**: Automatically organizes emails into Primary, Social, and Spam categories, with support for custom user-defined sections.
- **Zero-Knowledge Architecture**: Private keys are protected by a passphrase derived client-side; they are never stored in plain text on the server.
- **Firebase Integration**: Leverages Firebase for Authentication and Firestore for real-time data storage with offline support.

## Security Architecture
1. **Passphrase Derivation**: A deterministic passphrase is re-derived at login from the user's unique authentication credentials (UID + Email) using PBKDF2-SHA256 with 600,000 iterations.
2. **Key Protection**: Private keys are encrypted using the derived passphrase before being stored in Firestore.
3. **Session Management**: Decrypted private keys are stored only in `sessionStorage` and are cleared when the tab is closed.

## Getting Started

### Prerequisites
- A Firebase project.
- A web server to host the static files.

### Configuration
1. Copy `config.template.js` to `config.js`.
2. Fill in your Firebase project configuration in `config.js`.
3. (Optional) Provide your IndexNow key and site URL for SEO indexing.

```javascript
window.CONFIG = {
  firebase: {
    apiKey: "YOUR_FIREBASE_API_KEY",
    authDomain: "YOUR_PROJECT_ID.firebaseapp.com",
    projectId: "YOUR_PROJECT_ID",
    storageBucket: "YOUR_PROJECT_ID.firebasestorage.app",
    messagingSenderId: "YOUR_MESSAGING_SENDER_ID",
    appId: "YOUR_APP_ID",
    measurementId: "YOUR_MEASUREMENT_ID"
  },
  // ...
};
```

### Deployment
Upload the files (excluding `config.js` if deploying to a public repo) to your hosting provider. Ensure `config.js` is present on the server for the app to function.

## License
Private - All Rights Reserved.
