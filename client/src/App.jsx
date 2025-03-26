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
      setUser(data);
      setError('');
    } catch (err) {
      setError(err.message);
    }
  };

  const handleSignup = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch('http://localhost:8000/users/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: signupData.name,
          age: signupData.age ? Number(signupData.age) : null,
          password: signupData.password
        })
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
    // Create FormData and append the raw file.
    const formData = new FormData();
    formData.append("file", fileToUpload, fileToUpload.name);

    // Make a POST request without any encryption headers.
    const response = await fetch(`http://localhost:8000/users/${user.id}/upload/`, {
      method: "POST",
      body: formData
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

  // Download file with client-side decryption.
  const downloadFile = async (filename) => {
    try {
      const response = await fetch(`http://localhost:8000/users/${user.id}/files/${filename}`);
      if (!response.ok) {
        setError("Download failed.");
        return;
      }
      /*
      const encryptedFileKeyBase64 = response.headers.get("X-Encrypted-File-Key");
      const keyIvBase64 = response.headers.get("X-File-Key-IV");
      const fileDataIvBase64 = response.headers.get("X-File-Data-IV");
      
      if (!encryptedFileKeyBase64 || !keyIvBase64 || !fileDataIvBase64) {
        setError("Missing encryption metadata.");
        return;
      }
      
      const encryptedFileKeyBuffer = base64ToArrayBuffer(encryptedFileKeyBase64);
      const keyIv = new Uint8Array(base64ToArrayBuffer(keyIvBase64));
      const fileDataIv = new Uint8Array(base64ToArrayBuffer(fileDataIvBase64));
      
      const saltBuffer = base64ToArrayBuffer(user.salt);
      const kek = await deriveKey(user.password, saltBuffer);
      
      const fileKeyRaw = await decryptData(encryptedFileKeyBuffer, keyIv, kek);
      const fileKey = await crypto.subtle.importKey(
        "raw",
        fileKeyRaw,
        { name: "AES-GCM" },
        true,
        ["decrypt"]
      );
      */
      const encryptedBlob = await response.blob();
      //const encryptedBuffer = await encryptedBlob.arrayBuffer();
      // Assume first 12 bytes of the blob are the file IV (or use header fileDataIv)
      //const ciphertext = encryptedBuffer.slice(12);
      
      //const decryptedBuffer = await decryptData(ciphertext, fileDataIv, fileKey);
      
      const url = URL.createObjectURL(encryptedBlob);
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
    /*
    if (!recipient.public_key) {
      setError("Recipient public key missing.");
      return;
    } */
    
    // 2. Get file record from state
    const fileRecord = files.find(f => f.filename === filename);
    if (!fileRecord) {
      setError("File not found.");
      return;
    }
    
    /* 3. Derive KEK using plaintext password and salt (which is stored in user state as Base64)
    const saltBuffer = base64ToArrayBuffer(user.salt);
    const kek = await deriveKey(user.password, saltBuffer);
    
    // 4. Decrypt the file key using the stored encrypted file key and its IV
    const encryptedFileKeyBuffer = base64ToArrayBuffer(fileRecord.encrypted_file_key);
    const keyIvBuffer = base64ToArrayBuffer(fileRecord.file_key_iv);
    const fileKeyRaw = await decryptData(encryptedFileKeyBuffer, new Uint8Array(keyIvBuffer), kek);
    
    // 5. Encrypt the file key with the recipient's public key
    const recipientPublicKey = await importRecipientPublicKey(recipient.public_key);
    const sharedFileKeyBuffer = await crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      recipientPublicKey,
      fileKeyRaw
    );
    const sharedFileKeyBase64 = arrayBufferToBase64(sharedFileKeyBuffer);
    */
    // 6. Send the shared file key to the backend
    const shareRes = await fetch(`http://localhost:8000/users/${user.id}/share/${filename}?recipient_id=${recipient.id}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ })//shared_file_key: sharedFileKeyBase64 })
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
                <button onClick={() => downloadFile(file.filename)}>Download</button>{" "}
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
