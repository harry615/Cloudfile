import React, { useState, useEffect, useCallback } from 'react';
import './App.css';
import {
  deriveKey,
  encryptData,
  decryptData,
  arrayBufferToBase64,
  base64ToArrayBuffer
} from './cryptoClient';


function App() {
  const [loginData, setLoginData] = useState({ name: '', password: '' });
  const [signupData, setSignupData] = useState({ name: '', age: '', password: '' });
  const [user, setUser] = useState(null);
  const [files, setFiles] = useState([]);
  const [fileToUpload, setFileToUpload] = useState(null);
  const [shareLink, setShareLink] = useState("");
  const [shareExpiry, setShareExpiry] = useState(60); // default expiry in minutes
  const [error, setError] = useState('');
  const [showSignup, setShowSignup] = useState(false);

  // On mount, restore user session (public data only)
  useEffect(() => {
    const storedUser = localStorage.getItem('user');
    if (storedUser) {
      setUser(JSON.parse(storedUser));
    }
  }, []);

  // Wrap listFiles in useCallback so that it is stable.
  const listFiles = useCallback(async () => {
    if (!user) return;
    try {
      const response = await fetch(`http://localhost:8000/users/${user.id}/files/`);
      if (!response.ok) {
        setError("Failed to fetch files.");
        return;
      }
      const data = await response.json();
      setFiles(data);
      setError('');
    } catch (err) {
      setError("List files error: " + err.message);
    }
  }, [user]);

  // Update localStorage when user changes; store only public data.
  useEffect(() => {
    if (user) {
      const { password, ...publicUser } = user;
      localStorage.setItem('user', JSON.stringify(publicUser));
      listFiles();
    } else {
      localStorage.removeItem('user');
    }
  }, [user, listFiles]);

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch('http://localhost:8000/users/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(loginData)
      });
      if (!response.ok) {
        const err = await response.json();
        setError(err.detail || 'Login failed');
        return;
      }
      const data = await response.json();
      // Store plaintext password in state (for key derivation), but do not persist it.
      data.password = loginData.password;
      

      if (data.salt) { // Did backend return a salt
        // Convert the base64 encoded salt to an array buffer
        const saltBuffer = base64ToArrayBuffer(data.salt);
        // Derive a key from the user's password and the salt 
        const kek = await deriveKey(data.password, saltBuffer);
        // Export the derived key as raw bytes
        const exportedKey = await crypto.subtle.exportKey("raw", kek);
        // Convert the key to base64 for easier debugging/logging
        const keyBase64 = arrayBufferToBase64(exportedKey);
        console.log("Derived Key (Base64):", keyBase64);
        console.log("Our current data.iv:", data.iv);
        const ivBuffer = base64ToArrayBuffer(data.iv);
        const encryptedPrivateKeyBuffer = base64ToArrayBuffer(data.encrypted_private_key);

        // Decrypt the encrypted private key using AES-GCM.
        const decryptedPrivateKeyBuffer = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: new Uint8Array(ivBuffer) },
          kek,
          encryptedPrivateKeyBuffer
        );
        
        // Convert the decrypted private key to Base64 for easier usage (or to a PEM string if needed).
        const decryptedPrivateKeyBase64 = arrayBufferToBase64(decryptedPrivateKeyBuffer);
        console.log("Decrypted Private Key (Base64):", decryptedPrivateKeyBase64);
        const pemPrivateKey = `-----BEGIN PRIVATE KEY-----\n${decryptedPrivateKeyBase64.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
        console.log("Decrypted Private Key (PEM):", pemPrivateKey);
        data.decrypted_private_key = pemPrivateKey;

        
      } else {
        console.warn("No salt provided in user data")
      }
      setUser(data);
      setError('');
    } catch (err) {
      setError(err.message);
    }
  };

  const handleSignup = async (e) => {
    e.preventDefault();
    try {
      // Generate a random salt - 16 bytes
      const saltBuffer = crypto.getRandomValues(new Uint8Array(16));
      const saltBase64 = arrayBufferToBase64(saltBuffer);

      // Derive a key from the user's password and the salt , THIS IS THE KEK
      const derivedKey = await deriveKey(signupData.password, saltBuffer);

      // Generate an RSA key pair for the user using the web crypto API
      const keyPair = await crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256"
        },
        true,
        ["encrypt","decrypt"]       
      );

      // Export the public key to spki Array buffer , then convert to base64
      const publicKeyBuffer = await crypto.subtle.exportKey("spki", keyPair.publicKey);
      const publicKeyBase64 = arrayBufferToBase64(publicKeyBuffer);

      // wrap with PEM headers

      const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${publicKeyBase64}\n-----END PUBLIC KEY-----`;
      
      // export the private key ready for encryption
      const privateKeyBuffer = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

      // Encrypt the private key using the derived key with AES-GCM , THIS IS FOR RSA FILE SHARING
      const iv = crypto.getRandomValues(new Uint8Array(12)); // 12 Byte IV for AES-GCM
      const encryptedPrivateKeyBuffer = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        derivedKey,
        privateKeyBuffer
      );

      // Convert the encrypted private key an IV to Base64 for transmission

      const encryptedPrivateKeyBase64 = arrayBufferToBase64(encryptedPrivateKeyBuffer);
      const ivBase64 = arrayBufferToBase64(iv);

      // Signup payload

      const payload = {
        name: signupData.name,
        age: signupData.age ? Number(signupData.age) : null,
        // For auth you can send a hashed password
        password: signupData.password,
        salt : saltBase64,
        public_key: publicKeyPem,
        encrypted_private_key: encryptedPrivateKeyBase64,
        iv: ivBase64
      };

      const response = await fetch('http://localhost:8000/users/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const err = await response.json();
        setError(err.detail || 'Signup failed');
        return;
      }
      const data = await response.json();
      data.password = signupData.password;
      setUser(data);
      setError('');
    } catch (err) {
      setError(err.message);
    }
  };

  // Upload file with client-side encryption.
  /*
  const uploadFile = async () => {
    if (!fileToUpload) {
      setError("No file selected.");
      return;
    }
    try {
      const fileBuffer = await fileToUpload.arrayBuffer();
      const fileKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
      const { iv: fileIv, encrypted: encryptedFileBuffer } = await encryptData(fileBuffer, fileKey);
      const fileKeyRaw = await crypto.subtle.exportKey("raw", fileKey);
      const saltBuffer = base64ToArrayBuffer(user.salt);
      const kek = await deriveKey(user.password, saltBuffer);
      const { iv: keyIv, encrypted: encryptedFileKeyBuffer } = await encryptData(fileKeyRaw, kek);
      const fileIvBase64 = arrayBufferToBase64(fileIv);
      const keyIvBase64 = arrayBufferToBase64(keyIv);
      const encryptedFileKeyBase64 = arrayBufferToBase64(encryptedFileKeyBuffer);
      const encryptedBlob = new Blob([fileIv, encryptedFileBuffer]);
      const formData = new FormData();
      formData.append("file", encryptedBlob, fileToUpload.name);
      
      const response = await fetch(`http://localhost:8000/users/${user.id}/upload/`, {
        method: "POST",
        body: formData,
        headers: {
          "X-Encrypted-File-Key": encryptedFileKeyBase64,
          "X-File-Key-IV": keyIvBase64,
          "X-File-Data-IV": fileIvBase64,
        }
      });
      
      if (!response.ok) {
        setError("Upload failed.");
        return;
      }
      const data = await response.json();
      console.log("Uploaded file:", data);
      setError("");
      listFiles();
    } catch (err) {
      setError("Upload error: " + err.message);
    }
  };
*/
const uploadFile = async () => {
  if (!fileToUpload) {
    setError("No file selected.");
    return;
  }
  try {
    // Read file as an array buffer
    const fileBuffer = await fileToUpload.arrayBuffer();

    // Generate a unique file key (AES-GCM 256bit)
    const fileKey = await crypto.subtle.generateKey(
      { name: "AES-GCM", length:256},
      true,
      ["encrypt","decrypt"]
    );

    // Export the raw file key
    const fileKeyRaw = await crypto.subtle.exportKey("raw",fileKey);

    // Derive the user's KEK using password/salt
    const saltBuffer = base64ToArrayBuffer(user.salt);
    const kek = await deriveKey(user.password, saltBuffer);

    // Encrypt the file key with the KEK
    const keyIv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedFileKeyBuffer = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: keyIv},
      kek,
      fileKeyRaw,
    );

    // Encrypt the file data with the file key.
    const fileIv = crypto.getRandomValues(new Uint8Array(12)); // IV for file encryption.
    const encryptedFileBuffer = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: fileIv },
      fileKey,
      fileBuffer  
    );

    // Convert the IV's and encrypted file key to base64
    const fileIvBase64 = arrayBufferToBase64(fileIv);
    const keyIvBase64 = arrayBufferToBase64(keyIv);
    const encryptedFileKeyBase64 = arrayBufferToBase64(encryptedFileKeyBuffer);

    console.log("Encrypted File Key (Base64):", encryptedFileKeyBase64);
    console.log("Key IV (Base64):", keyIvBase64);
    console.log("File Data IV (Base64):", fileIvBase64);

    // Prepare the encrypted file as a blob
    const encryptedBlob = new Blob([new Uint8Array(encryptedFileBuffer)]);

    // Create FormData and append the raw file.
    const formData = new FormData();
    formData.append("file", encryptedBlob, fileToUpload.name);
    formData.append("encrypted_file_key", encryptedFileKeyBase64);
    formData.append("file_key_iv", keyIvBase64);
    formData.append("file_data_iv", fileIvBase64);

    // Make a POST request with encryption headers
    const response = await fetch(`http://localhost:8000/users/${user.id}/upload/`, {
      method: "POST",
      body: formData,     
    });
    
    if (!response.ok) {
      setError("Upload failed.");
      return;
    }
    const data = await response.json();
    console.log("Uploaded file:", data);
    setError("");
    listFiles();
  } catch (err) {
    setError("Upload error: " + err.message);
  }
};
const downloadFile = async (file) => {
  if (file.user_id === user.id) {
    await downloadOwnFile(file.filename);
  } else {
    await downloadSharedFile(file.filename);
  }
};
  // Download file with client-side decryption.
const downloadOwnFile = async (filename) => {
    try {
      const response = await fetch(`http://localhost:8000/users/${user.id}/files/${filename}/download`);
    if (!response.ok) {
        setError("Download failed.");
        return;
      }
      const data = await response.json();
      const encryptedBuffer = base64ToArrayBuffer(data.file_data);
    
      // Convert the other fields from Base64.
      const encryptedFileKeyBuffer = base64ToArrayBuffer(data.encrypted_file_key);
      const keyIv = new Uint8Array(base64ToArrayBuffer(data.file_key_iv));
      const fileDataIv = new Uint8Array(base64ToArrayBuffer(data.file_data_iv));
      
      console.log("Encrypted File Key (Base64) backend:", encryptedFileKeyBuffer);
      console.log("Key IV (Base64)backend:", keyIv);
      console.log("File Data IV (Base64)backend:", fileDataIv);


      if (!encryptedFileKeyBuffer || !keyIv || !fileDataIv) {
        setError("Missing encryption metadata.");
        return;
      }
      
      // Convert header values from base64 to array buffer
      
      // Derive the users KEK 
      const saltBuffer = base64ToArrayBuffer(user.salt);
      const kek = await deriveKey(user.password, saltBuffer);
      
      // Decrypt the file key using the KEK
      const decryptedFileKeyBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM" , iv: keyIv },
        kek,
        encryptedFileKeyBuffer
      );

      const fileKey = await crypto.subtle.importKey(
        "raw",
        decryptedFileKeyBuffer,
        { name: "AES-GCM" },
        true,
        ["decrypt"]
      );
      // Get the encrypted file data as an Arraybuffer
     
      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fileDataIv },
        fileKey,
        encryptedBuffer
      );

      //Create a blob from the decrypted data and trigger a download

      const decryptedBlob = new Blob([new Uint8Array(decryptedBuffer)]);

     
      const url = URL.createObjectURL(decryptedBlob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      setError("");
    } catch (err) {
      setError("Download error: " + err.message);
    }
  };

  const downloadSharedFile = async (filename) => {
    try {
      // Fetch the shared file information (JSON) for the recipient.
      const response = await fetch(`http://localhost:8000/shared-files/${user.id}/${encodeURIComponent(filename)}/download`);
      if (!response.ok) {
        console.error("Error response:", response);
        const errorData = await response.text(); // Try to read the error message.
        console.error("Error response body:", errorData);
        setError("Download failed shared.");
        return;
      }
      const data = await response.json();
      // For shared files, we expect data to contain: file_data, encrypted_file_key, file_data_iv.
      const encryptedBuffer = base64ToArrayBuffer(data.file_data);
      const encryptedFileKeyBuffer = base64ToArrayBuffer(data.encrypted_file_key);
      // For shared files, note: the file key was encrypted with the recipient's RSA public key,
      // so we do not have a file_key_iv (unless you design it that way). We'll assume it's not needed.
  
      // Convert the file data IV.
      const fileDataIv = new Uint8Array(base64ToArrayBuffer(data.file_data_iv));
  
      // Import the recipient's RSA private key.
      // Assume you have a helper function that imports the key; and that the recipient's decrypted private key
      // is stored in user.decrypted_private_key.
      const recipientPrivateKey = await importRecipientPrivateKey(user.decrypted_private_key);
  
      // Decrypt the shared file key using the recipient's RSA private key.
      const decryptedFileKeyBuffer = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        recipientPrivateKey,
        encryptedFileKeyBuffer
      );
  
      // Import the decrypted file key as an AES-GCM key.
      const fileKey = await crypto.subtle.importKey(
        "raw",
        decryptedFileKeyBuffer,
        { name: "AES-GCM" },
        true,
        ["decrypt"]
      );
  
      // Decrypt the file data.
      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fileDataIv },
        fileKey,
        encryptedBuffer
      );
  
      // Create a Blob from the decrypted data and trigger a download.
      const decryptedBlob = new Blob([new Uint8Array(decryptedBuffer)]);
      const url = URL.createObjectURL(decryptedBlob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setError("");
    } catch (err) {
      setError("Download shared file error: " + err.message);
    }
  };
  
  // Delete file function.
  const deleteFile = async (filename) => {
    try {
      const response = await fetch(`http://localhost:8000/users/${user.id}/files/${filename}`, {
        method: "DELETE",
      });
      if (!response.ok) {
        setError("Delete failed.");
        return;
      }
      const data = await response.json();
      console.log(data);
      setError("");
      listFiles();
    } catch (err) {
      setError("Delete error: " + err.message);
    }
  };

// Helper: Import recipient's RSA public key from PEM
async function importRecipientPublicKey(publicKeyPem) {
  const pemHeader = "-----BEGIN PUBLIC KEY-----";
  const pemFooter = "-----END PUBLIC KEY-----";
  const pemContents = publicKeyPem
    .replace(pemHeader, "")
    .replace(pemFooter, "")
    .replace(/\s+/g, "");
  const binaryDerString = window.atob(pemContents);
  const binaryDer = new Uint8Array(binaryDerString.length);
  for (let i = 0; i < binaryDerString.length; i++) {
    binaryDer[i] = binaryDerString.charCodeAt(i);
  }
  return crypto.subtle.importKey(
    "spki",
    binaryDer.buffer,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  )
};
async function importRecipientPrivateKey(privateKeyPem) {
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  let pemContents = privateKeyPem;
  if (privateKeyPem.startsWith(pemHeader)) {
    pemContents = privateKeyPem
      .replace(pemHeader, "")
      .replace(pemFooter, "")
      .replace(/\s+/g, "");
  }
  const binaryDerString = window.atob(pemContents);
  const binaryDer = new Uint8Array(binaryDerString.length);
  for (let i = 0; i < binaryDerString.length; i++) {
    binaryDer[i] = binaryDerString.charCodeAt(i);
  }
  return crypto.subtle.importKey(
    "pkcs8",
    binaryDer.buffer,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt"]
  );
}


const shareFile = async (filename, recipientUsername) => {
  try {
    // 1. Fetch recipient's public key (ensure backend returns a PEM string)
    const recipientRes = await fetch(`http://localhost:8000/users/by-name/${recipientUsername}`);
    if (!recipientRes.ok) {
      setError("Recipient not found.");
      return;
    }
    
    const recipient = await recipientRes.json();

    console.log("Recipient:", recipient);
    console.log("Recipient public key:", recipient.public_key);

    const recipientPublicKey = recipient.public_key;
    if (!recipientPublicKey) {
      setError("Recipient public key missing.");
      return;
    } 
    
    // 2. Get file record from state
    const fileRecord = files.find(f => f.filename === filename);
    if (!fileRecord) {
      setError("File not found.");
      return;
    }
    
    // 3. Derive KEK using plaintext password and salt (which is stored in user state as Base64)
    const saltBuffer = base64ToArrayBuffer(user.salt);
    const kek = await deriveKey(user.password, saltBuffer);
    
    // 4. Decrypt the file key using the stored encrypted file key and its IV
    const encryptedFileKeyBuffer = base64ToArrayBuffer(fileRecord.encrypted_file_key);
    const keyIv = new Uint8Array(base64ToArrayBuffer(fileRecord.file_key_iv));

    const decryptedFileKeyBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: keyIv },
      kek,
      encryptedFileKeyBuffer
    );

    // 5. Encrypt the file key with the recipient's public key
    const recipientPublicKey2 = await importRecipientPublicKey(recipient.public_key);
    const encryptedKeyForRecipient = await crypto.subtle.encrypt(
      { name: "RSA-OAEP"},
      recipientPublicKey2,
      decryptedFileKeyBuffer
    );

    const sharedFileKeyBase64 = arrayBufferToBase64(encryptedKeyForRecipient);

    // 6. Send the shared file key to the backend
    const shareRes = await fetch(`http://localhost:8000/users/${user.id}/share/${filename}?recipient_id=${recipient.id}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ shared_file_key: sharedFileKeyBase64 })
    });
    if (!shareRes.ok) {
      setError("Share failed.");
      return;
    }
    const shareData = await shareRes.json();
    console.log("Share response:", shareData);
    alert("File shared successfully!");
  } catch (err) {
    console.error("Share error:", err);
    setError("Share error: " + err.message);
  }
};
   // Generate a share link by calling the backend endpoint
const generateExpiringShareLink = async (filename) => {
  try {
    const response = await fetch(
      `http://localhost:8000/users/${user.id}/files/${filename}/shareLink?expiry=${shareExpiry}`
    );
    if (!response.ok) {
      setError("Failed to generate expiring share link.");
      return;
    }
    const data = await response.json();
    setShareLink(data.share_link);
    alert(`Expiring share link (expires in ${shareExpiry} minutes): ${data.share_link}`);
  } catch (err) {
    setError("Expiring share link error: " + err.message);
  }
};



  const handleLogout = () => {
    setUser(null);
    setFiles([]);
    setError("");
    localStorage.removeItem("user");
  };

  return (
    <div className="App">
      {!user ? (
        showSignup ? (
          <div>
            <h2>Sign Up</h2>
            <form onSubmit={handleSignup}>
              <input
                type="text"
                placeholder="Name"
                value={signupData.name}
                onChange={(e) => setSignupData({ ...signupData, name: e.target.value })}
              />
              <input
                type="number"
                placeholder="Age (optional)"
                value={signupData.age}
                onChange={(e) => setSignupData({ ...signupData, age: e.target.value })}
              />
              <input
                type="password"
                placeholder="Password"
                value={signupData.password}
                onChange={(e) => setSignupData({ ...signupData, password: e.target.value })}
              />
              <button type="submit">Sign Up</button>
            </form>
            <button onClick={() => setShowSignup(false)}>Back to Login</button>
            {error && <p style={{ color: "red" }}>{error}</p>}
          </div>
        ) : (
          <div>
            <h2>Login</h2>
            <form onSubmit={handleLogin}>
              <input
                type="text"
                placeholder="Name"
                value={loginData.name}
                onChange={(e) => setLoginData({ ...loginData, name: e.target.value })}
              />
              <input
                type="password"
                placeholder="Password"
                value={loginData.password}
                onChange={(e) => setLoginData({ ...loginData, password: e.target.value })}
              />
              <button type="submit">Login</button>
            </form>
            <button onClick={() => setShowSignup(true)}>Sign Up</button>
            {error && <p style={{ color: "red" }}>{error}</p>}
          </div>
        )
      ) : (
        <div>
          <h2>Welcome, {user.name}!</h2>
          <button onClick={handleLogout}>Logout</button>
          <div>
            <input type="file" onChange={(e) => setFileToUpload(e.target.files[0])} />
            <button onClick={uploadFile}>Upload File</button>
          </div>
          <h3>Your Files</h3>
          <ul>
            {files.map((file) => (
              <li key={file.id}>
                {file.filename}{" "}
                <button onClick={() => downloadFile(file)}>Download</button>{" "}
                <button onClick={() => deleteFile(file.filename)}>Delete</button>{" "}
                <ShareFile file={file} shareFile={shareFile} generateExpiringShareLink={generateExpiringShareLink}></ShareFile>              
              </li>
            ))}

          </ul>
          {shareLink && (
            <div>
              <h4>Share Link</h4>
              <p>{shareLink}</p>
            </div>
          )}
          {error && <p style={{ color: "red" }}>{error}</p>}
        </div>
      )}
    </div>
  );
}

// Component for sharing a file by recipient username.
const ShareFile = ({ file, shareFile, generateExpiringShareLink }) => {
  const [recipientUsername, setRecipientUsername] = useState("");
  return (
    <div>
      <div style={{ marginTop: '5px' }}>
        <input
          type="text"
          placeholder="Recipient username"
          value={recipientUsername}
          onChange={(e) => setRecipientUsername(e.target.value)}
        />
        <button onClick={() => shareFile(file.filename, recipientUsername)}>
          Share with Recipient
        </button>
      </div>
      <div style={{ marginTop: '5px' }}>
        <button onClick={() => generateExpiringShareLink(file.filename)}>
          Generate Expiring Share Link
        </button>
      </div>
    </div>
  );
};

// Placeholder RSA encryption function using Web Crypto API.
async function encryptWithRSA(dataBuffer, recipientPublicKey) {
  return crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    recipientPublicKey,
    dataBuffer
  );
}

export default App;
