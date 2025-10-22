/**
 * Secure Vault - A client-side encrypted vault for storing classified info.
 * Author: Your Name
 * License: MIT
 * 
 * Uses Web Crypto API AES-GCM encryption with password-derived keys (PBKDF2).
 * Data stored in encrypted form in localStorage.
 */

const STORAGE_KEY = "secureVault:data";
const SALT_KEY = "secureVault:salt";
const IV_LENGTH = 12; // AES-GCM standard IV length in bytes

/**
 * Util: Encode string to ArrayBuffer
 * @param {string} str 
 * @returns {Uint8Array}
 */
function encodeUTF8(str) {
  return new TextEncoder().encode(str);
}

/**
 * Util: Decode ArrayBuffer to string
 * @param {ArrayBuffer} buffer 
 * @returns {string}
 */
function decodeUTF8(buffer) {
  return new TextDecoder().decode(buffer);
}

/**
 * Generate random bytes (for salt or IV)
 * @param {number} length 
 * @returns {Uint8Array}
 */
function getRandomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Derive a cryptographic key from a password and salt using PBKDF2
 * @param {string} password 
 * @param {Uint8Array} salt 
 * @returns {Promise<CryptoKey>}
 */
async function deriveKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encodeUTF8(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 250_000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypt data (string) using AES-GCM
 * @param {CryptoKey} key 
 * @param {string} data 
 * @returns {Promise<string>} Base64 encoded string containing IV + ciphertext
 */
async function encrypt(key, data) {
  const iv = getRandomBytes(IV_LENGTH);
  const encodedData = encodeUTF8(data);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    encodedData
  );

  // Concatenate IV + encrypted data
  const buffer = new Uint8Array(iv.length + encrypted.byteLength);
  buffer.set(iv, 0);
  buffer.set(new Uint8Array(encrypted), iv.length);

  return btoa(String.fromCharCode(...buffer));
}

/**
 * Decrypt Base64 encoded string containing IV + ciphertext using AES-GCM
 * @param {CryptoKey} key 
 * @param {string} data Base64 encoded string
 * @returns {Promise<string>} Decrypted string
 */
async function decrypt(key, data) {
  const buffer = Uint8Array.from(atob(data), c => c.charCodeAt(0));
  const iv = buffer.slice(0, IV_LENGTH);
  const ciphertext = buffer.slice(IV_LENGTH);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    key,
    ciphertext
  );
  return decodeUTF8(decrypted);
}

/**
 * Save encrypted vault data to localStorage
 * @param {string} encryptedData 
 */
function saveVault(encryptedData) {
  localStorage.setItem(STORAGE_KEY, encryptedData);
}

/**
 * Load encrypted vault data from localStorage
 * @returns {string|null}
 */
function loadVault() {
  return localStorage.getItem(STORAGE_KEY);
}

/**
 * Save salt to localStorage
 * @param {Uint8Array} salt 
 */
function saveSalt(salt) {
  localStorage.setItem(SALT_KEY, btoa(String.fromCharCode(...salt)));
}

/**
 * Load salt from localStorage
 * @returns {Uint8Array|null}
 */
function loadSalt() {
  const b64 = localStorage.getItem(SALT_KEY);
  if (!b64) return null;
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

/**
 * Vault state and cryptographic key
 */
const vault = {
  entries: [],
  cryptoKey: null,
  salt: null,
};

/**
 * Render entries list
 */
function renderEntries() {
  const container = document.getElementById("entries-list");
  container.innerHTML = "";

  if (vault.entries.length === 0) {
    container.textContent = "Your vault is empty.";
    return;
  }

  vault.entries.forEach(({ id, title, content }) => {
    const entryEl = document.createElement("article");
    entryEl.className = "entry-item";
    entryEl.dataset.id = id;

    const titleEl = document.createElement("h2");
    titleEl.className = "entry-title";
    titleEl.textContent = title;

    const contentEl = document.createElement("pre");
    contentEl.className = "entry-content";
    contentEl.textContent = content;

    const actionsEl = document.createElement("div");
    actionsEl.className = "entry-actions";

    // Delete button
    const deleteBtn = document.createElement("button");
    deleteBtn.title = "Delete Entry";
    deleteBtn.textContent = "🗑️";
    deleteBtn.addEventListener("click", () => deleteEntry(id));

    actionsEl.appendChild(deleteBtn);

    entryEl.appendChild(titleEl);
    entryEl.appendChild(contentEl);
    entryEl.appendChild(actionsEl);

    container.appendChild(entryEl);
  });
}

/**
 * Add new entry to vault
 * @param {string} title 
 * @param {string} content 
 */
function addEntry(title, content) {
  if (!title || !content) {
    showEntryError("Title and content cannot be empty.");
    return;
  }

  const newEntry = {
    id: crypto.randomUUID(),
    title: title.trim(),
    content: content.trim(),
  };

  vault.entries.push(newEntry);
  saveVaultData().then(() => {
    renderEntries();
    clearEntryForm();
  });
}

/**
 * Delete entry by id
 * @param {string} id 
 */
function deleteEntry(id) {
  vault.entries = vault.entries.filter(e => e.id !== id);
  saveVaultData().then(renderEntries);
}

/**
 * Save vault entries encrypted to localStorage
 * @returns {Promise<void>}
 */
async function saveVaultData() {
  const plaintext = JSON.stringify(vault.entries);
  const encryptedData = await encrypt(vault.cryptoKey, plaintext);
  saveVault(encryptedData);
}

/**
 * Load vault entries by decrypting stored data
 * @returns {Promise<boolean>} true if successful
 */
async function loadVaultData() {
  const encryptedData = loadVault();
  if (!encryptedData) {
    vault.entries = [];
    return true;
  }

  try {
    const decrypted = await decrypt(vault.cryptoKey, encryptedData);
    vault.entries = JSON.parse(decrypted);
    return true;
  } catch (err) {
    console.error("Failed to decrypt vault:", err);
    return false;
  }
}

/**
 * Clear input form after adding entry
 */
function clearEntryForm() {
  document.getElementById("entry-title").value = "";
  document.getElementById("entry-content").value = "";
  hideEntryError();
}

/**
 * Show login error
 * @param {string} message 
 */
function showLoginError(message) {
  const el = document.getElementById("login-error");
  el.textContent = message;
}

/**
 * Clear login error
 */
function hideLoginError() {
  showLoginError("");
}

/**
 * Show entry form error
 * @param {string} message 
 */
function showEntryError(message) {
  const el = document.getElementById("entry-error");
  el.textContent = message;
}

/**
 * Clear entry form error
 */
function hideEntryError() {
  showEntryError("");
}

/**
 * Initialize vault: setup event listeners and UI
 */
function init() {
  const unlockBtn = document.getElementById("unlock-btn");
  const logoutBtn = document.getElementById("logout-btn");
  const addEntryBtn = document.getElementById("add-entry-btn");

  unlockBtn.addEventListener("click", handleUnlock);
  logoutBtn.addEventListener("click", handleLogout);
  addEntryBtn.addEventListener("click", handleAddEntry);

  // Enter key support for login
  document.getElementById("master-password").addEventListener("keypress", e => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleUnlock();
    }
  });

  // Enter key support for add entry (Ctrl+Enter to add)
  document.getElementById("entry-content").addEventListener("keydown", e => {
    if (e.key === "Enter" && e.ctrlKey) {
      e.preventDefault();
      handleAddEntry();
    }
  });
}

/**
 * Handle vault unlock process
 */
async function handleUnlock() {
  hideLoginError();

  const passwordInput = document.getElementById("master-password");
  const password = passwordInput.value;

  if (!password) {
    showLoginError("Please enter your master password.");
    return;
  }

  try {
    // Load or generate salt
    let salt = loadSalt();
    if (!salt) {
      salt = getRandomBytes(16);
      saveSalt(salt);
    }

    vault.salt = salt;
    vault.cryptoKey = await deriveKey(password, salt);

    // Try to load and decrypt vault
    const success = await loadVaultData();
    if (!success) {
      showLoginError("Invalid password or corrupted vault.");
      vault.cryptoKey = null;
      return;
    }

    // Clear password input for security
    passwordInput.value = "";

    // Switch UI
    showVaultSection();

    // Render vault content
    renderEntries();

  } catch (err) {
    console.error("Unlock error:", err);
    showLoginError("An error occurred during unlock.");
  }
}

/**
 * Handle vault lock / logout
 */
function handleLogout() {
  vault.cryptoKey = null;
  vault.entries = [];
  hideEntryError();
  hideLoginError();

  // Clear UI inputs
  document.getElementById("master-password").value = "";

  // Switch UI
  showLoginSection();
}

/**
 * Handle adding a new entry
 */
function handleAddEntry() {
  hideEntryError();

  const titleInput = document.getElementById("entry-title");
  const contentInput = document.getElementById("entry-content");

  const title = titleInput.value.trim();
  const content = contentInput.value.trim();

  if (!title || !content) {
    showEntryError("Both title and content are required.");
    return;
  }

  addEntry(title, content);
}

/**
 * Show vault section, hide login
 */
function showVaultSection() {
  document.getElementById("login-section").classList.replace("visible", "hidden");
  document.getElementById("vault-section").classList.replace("hidden", "visible");
}

/**
 * Show login section, hide vault
 */
function showLoginSection() {
  document.getElementById("vault-section").classList.replace("visible", "hidden");
  document.getElementById("login-section").classList.replace("hidden", "visible");
}

// Initialize app on DOM ready
document.addEventListener("DOMContentLoaded", init);
