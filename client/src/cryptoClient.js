// cryptoClient.js

// Convert an ArrayBuffer to a Base64 string.
export function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    bytes.forEach((b) => (binary += String.fromCharCode(b)));
    return window.btoa(binary);
  }
  
  // Convert a Base64 string to an ArrayBuffer.
  export function base64ToArrayBuffer(base64) {
    if (!base64) {
      console.error("base64ToArrayBuffer received undefined");
      throw new Error("Undefined Base64 string");
    }
    try {
      const cleaned = base64.replace(/\s/g, '');
      const binary = window.atob(cleaned);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes.buffer;
    } catch (error) {
      console.error("Error decoding Base64:", error, "Input string:", base64);
      throw error;
    }
  }
  
  
  // Derive an AES-GCM key from a password and salt using PBKDF2.
  export async function deriveKey(password, saltBuffer) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBuffer,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }
  
  // Encrypt data with an AES-GCM key.
  export async function encryptData(dataBuffer, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      dataBuffer
    );
    return { iv, encrypted: encryptedBuffer };
  }
  
  // Decrypt data with an AES-GCM key.
  export async function decryptData(encryptedBuffer, iv, key) {
    return crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      encryptedBuffer
    );
  }
  