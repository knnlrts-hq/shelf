// ── Config ──────────────────────────────────────────────────
const SUPABASE_URL = 'https://cxylcljlxdizvqlcioee.supabase.co';
const SUPABASE_KEY = 'sb_publishable_BhPS6OwiH31kIeF6GNyEAg_e0vMseib';
const BUCKET = 'private-blobs';
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

const sb = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

// ── State ───────────────────────────────────────────────────
let encryptionKey = null;  // CryptoKey, held in memory only

// ── DOM refs ────────────────────────────────────────────────
const loginScreen   = document.getElementById('login-screen');
const appScreen     = document.getElementById('app-screen');
const loginForm     = document.getElementById('login-form');
const loginError    = document.getElementById('login-error');
const signOutBtn    = document.getElementById('sign-out-btn');

// ── Encryption ──────────────────────────────────────────────
// Fixed salt for PBKDF2. Changing this invalidates all encrypted files.
const PBKDF2_SALT = new Uint8Array([
  0x73, 0x68, 0x65, 0x6c, 0x66, 0x2d, 0x73, 0x61,
  0x6c, 0x74, 0x2d, 0x76, 0x31, 0x2d, 0x30, 0x30
]);
// ASCII bytes of "shelf-salt-v1-00"

const PBKDF2_ITERATIONS = 100_000;
const IV_LENGTH = 12; // bytes, required by AES-GCM

async function deriveKey(passphrase) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: PBKDF2_SALT,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,        // not extractable
    ['encrypt', 'decrypt']
  );
}

async function encryptBlob(key, plainBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plainBytes
  );
  // Prepend IV to ciphertext: [ IV (12 bytes) | ciphertext ]
  const result = new Uint8Array(IV_LENGTH + ciphertext.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(ciphertext), IV_LENGTH);
  return result;
}

async function decryptBlob(key, encryptedBytes) {
  const data = new Uint8Array(encryptedBytes);
  const iv         = data.slice(0, IV_LENGTH);
  const ciphertext = data.slice(IV_LENGTH);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );
  return plaintext; // ArrayBuffer
}

// ── DOM refs (file table) ───────────────────────────────────
const fileTableBody = document.getElementById('file-table-body');
const emptyState    = document.getElementById('empty-state');
const fileTable     = document.getElementById('file-table');

// ── Load files ──────────────────────────────────────────────
async function loadFiles() {
  const { data: rows, error } = await sb
    .from('blob_index')
    .select('id, filename, content_type, size_bytes, created_at')
    .order('created_at', { ascending: false });

  if (error) {
    console.error('Failed to load files:', error.message);
    return;
  }

  // Clear table
  fileTableBody.textContent = '';

  if (!rows || rows.length === 0) {
    fileTable.hidden = true;
    emptyState.hidden = false;
    return;
  }

  fileTable.hidden = false;
  emptyState.hidden = true;

  for (const row of rows) {
    const tr = document.createElement('tr');

    // Filename cell
    const tdName = document.createElement('td');
    tdName.textContent = row.filename;
    tr.appendChild(tdName);

    // Size cell
    const tdSize = document.createElement('td');
    tdSize.textContent = formatBytes(row.size_bytes);
    tr.appendChild(tdSize);

    // Date cell
    const tdDate = document.createElement('td');
    tdDate.textContent = new Date(row.created_at).toLocaleDateString();
    tr.appendChild(tdDate);

    // Actions cell
    const tdActions = document.createElement('td');

    const dlBtn = document.createElement('button');
    dlBtn.textContent = 'Download';
    dlBtn.className = 'btn btn-primary btn-sm';
    dlBtn.addEventListener('click', () => downloadFile(row.id, dlBtn));
    tdActions.appendChild(dlBtn);

    const delBtn = document.createElement('button');
    delBtn.textContent = 'Delete';
    delBtn.className = 'btn btn-danger btn-sm';
    delBtn.addEventListener('click', () => deleteFile(row.id, delBtn));
    tdActions.appendChild(delBtn);

    tr.appendChild(tdActions);
    fileTableBody.appendChild(tr);
  }
}

// ── Download ────────────────────────────────────────────────
async function downloadFile(blobId, btn) {
  btn.disabled = true;
  btn.textContent = 'Decrypting…';

  try {
    // Get metadata
    const { data: row, error: rowError } = await sb
      .from('blob_index')
      .select('object_path, filename, content_type')
      .eq('id', blobId)
      .single();

    if (rowError) throw rowError;

    // Download encrypted blob from Storage
    const { data: encryptedBlob, error: dlError } = await sb.storage
      .from(BUCKET)
      .download(row.object_path);

    if (dlError) throw dlError;

    // Decrypt
    const encryptedBytes = await encryptedBlob.arrayBuffer();
    const plainBytes = await decryptBlob(encryptionKey, encryptedBytes);

    // Trigger browser download
    const blob = new Blob([plainBytes], { type: row.content_type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = row.filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (err) {
    if (err.message && err.message.includes('decrypt')) {
      alert('Decryption failed — wrong passphrase?');
    } else {
      alert('Download failed: ' + err.message);
    }
  } finally {
    btn.disabled = false;
    btn.textContent = 'Download';
  }
}

// ── Delete ──────────────────────────────────────────────────
async function deleteFile(blobId, btn) {
  if (!confirm('Delete this file permanently?')) return;

  btn.disabled = true;
  btn.textContent = 'Deleting…';

  try {
    // Get metadata (we need object_path)
    const { data: row, error: rowError } = await sb
      .from('blob_index')
      .select('object_path')
      .eq('id', blobId)
      .single();

    if (rowError) throw rowError;

    // Delete from Storage first
    const { error: storageError } = await sb.storage
      .from(BUCKET)
      .remove([row.object_path]);

    if (storageError) throw storageError;

    // Delete metadata row
    const { error: dbError } = await sb
      .from('blob_index')
      .delete()
      .eq('id', blobId);

    if (dbError) throw dbError;

    await loadFiles();
  } catch (err) {
    alert('Delete failed: ' + err.message);
    btn.disabled = false;
    btn.textContent = 'Delete';
  }
}

// ── DOM refs (upload) ───────────────────────────────────────
const dropZone      = document.getElementById('drop-zone');
const fileInput     = document.getElementById('file-input');
const fileInfo      = document.getElementById('file-info');
const fileInfoName  = document.getElementById('file-info-name');
const fileInfoSize  = document.getElementById('file-info-size');
const uploadBtn     = document.getElementById('upload-btn');
const clearFileBtn  = document.getElementById('clear-file-btn');
const uploadStatus  = document.getElementById('upload-status');

let selectedFile = null;

// ── Helpers ─────────────────────────────────────────────────
function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function sanitizeFilename(name) {
  return name.replace(/[^\w.\- ]+/g, '_');
}

function showUploadStatus(msg, isError) {
  uploadStatus.textContent = msg;
  uploadStatus.hidden = false;
  uploadStatus.style.color = isError ? '#dc2626' : '#16a34a';
}

function clearUploadStatus() {
  uploadStatus.hidden = true;
}

const ALLOWED_TYPES = new Set([
  'text/plain',
  'text/markdown',
  'application/pdf',
  'application/octet-stream',
]);

function validateFile(file) {
  if (file.size > MAX_FILE_SIZE) {
    return `File too large (${formatBytes(file.size)}). Max is ${formatBytes(MAX_FILE_SIZE)}.`;
  }
  // Be lenient: some .md files have no MIME type. Allow empty type.
  if (file.type && !ALLOWED_TYPES.has(file.type)) {
    return `File type "${file.type}" not allowed. Use .txt, .md, or .pdf.`;
  }
  return null; // valid
}

// ── File selection ──────────────────────────────────────────
function selectFile(file) {
  const err = validateFile(file);
  if (err) {
    showUploadStatus(err, true);
    selectedFile = null;
    fileInfo.hidden = true;
    return;
  }
  clearUploadStatus();
  selectedFile = file;
  fileInfoName.textContent = file.name;
  fileInfoSize.textContent = formatBytes(file.size);
  fileInfo.hidden = false;
}

function clearFile() {
  selectedFile = null;
  fileInfo.hidden = true;
  fileInput.value = '';
  clearUploadStatus();
}

dropZone.addEventListener('click', () => fileInput.click());

dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
  dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  if (e.dataTransfer.files.length > 0) {
    selectFile(e.dataTransfer.files[0]);
  }
});

fileInput.addEventListener('change', () => {
  if (fileInput.files.length > 0) {
    selectFile(fileInput.files[0]);
  }
});

clearFileBtn.addEventListener('click', clearFile);

// ── Upload ──────────────────────────────────────────────────
uploadBtn.addEventListener('click', async () => {
  if (!selectedFile || !encryptionKey) return;

  uploadBtn.disabled = true;
  showUploadStatus('Encrypting…', false);

  try {
    const { data: userData } = await sb.auth.getUser();
    const user = userData.user;
    if (!user) throw new Error('Not signed in');

    // Read file bytes
    const plainBytes = await selectedFile.arrayBuffer();

    // Encrypt
    const encryptedBytes = await encryptBlob(encryptionKey, plainBytes);

    // Build path: userId/blobId/sanitizedFilename
    const blobId = crypto.randomUUID();
    const safeName = sanitizeFilename(selectedFile.name);
    const objectPath = `${user.id}/${blobId}/${safeName}`;

    showUploadStatus('Uploading…', false);

    // Upload to Storage
    const { error: uploadError } = await sb.storage
      .from(BUCKET)
      .upload(objectPath, encryptedBytes, {
        contentType: 'application/octet-stream', // always octet-stream (encrypted)
        upsert: false,
      });

    if (uploadError) throw uploadError;

    // Insert metadata
    const { error: metaError } = await sb.from('blob_index').insert({
      id: blobId,
      owner_id: user.id,
      bucket_id: BUCKET,
      object_path: objectPath,
      filename: selectedFile.name,  // original name (for display)
      content_type: selectedFile.type || 'application/octet-stream',
      size_bytes: selectedFile.size, // original size (before encryption)
    });

    if (metaError) {
      // Cleanup orphaned storage object
      await sb.storage.from(BUCKET).remove([objectPath]);
      throw metaError;
    }

    showUploadStatus('Uploaded successfully.', false);
    clearFile();
    await loadFiles();
  } catch (err) {
    showUploadStatus('Upload failed: ' + err.message, true);
  } finally {
    uploadBtn.disabled = false;
  }
});

// ── Auth ────────────────────────────────────────────────────
function showLogin() {
  loginScreen.hidden = false;
  appScreen.hidden   = true;
  encryptionKey      = null;   // wipe key on sign out
}

function showApp() {
  loginScreen.hidden = true;
  appScreen.hidden   = false;
}

function showLoginError(msg) {
  loginError.textContent = msg;
  loginError.hidden      = false;
}

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  loginError.hidden = true;

  const email      = document.getElementById('email').value.trim();
  const password   = document.getElementById('password').value;
  const passphrase = document.getElementById('passphrase').value;

  if (!passphrase) {
    showLoginError('Encryption passphrase is required.');
    return;
  }

  const { error } = await sb.auth.signInWithPassword({ email, password });
  if (error) {
    showLoginError(error.message);
    return;
  }

  encryptionKey = await deriveKey(passphrase);

  // Clear passphrase from the form immediately after use
  document.getElementById('passphrase').value = '';

  showApp();
  await loadFiles();
});

signOutBtn.addEventListener('click', async () => {
  await sb.auth.signOut();
  showLogin();
});

// ── Session check on page load ──────────────────────────────
// Always show login — user must re-enter passphrase every session.
showLogin();
