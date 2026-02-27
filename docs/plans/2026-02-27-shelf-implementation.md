# Shelf — Implementation Plan

**Date**: 2026-02-27
**Design doc**: `docs/plans/2026-02-27-shelf-design.md`
**Branch**: `claude/file-sharing-tool-oxqoC`

Read the design doc first. This plan implements that design.

---

## Prerequisites

Before writing any code, complete these manual steps in the Supabase dashboard.
You cannot test anything until these are done.

### P1. Create a Supabase Auth user

1. Go to https://supabase.com/dashboard → your project → Authentication → Users.
2. Click "Add user" → "Create new user".
3. Enter an email and a strong password. Remember these — they are the only
   credentials for the app.
4. Note the user's UUID shown in the Users table. You will need it to verify
   RLS policies later.

### P2. (Optional) Disable sign-ups

1. Go to Authentication → Settings → Auth Settings.
2. Toggle off "Allow new users to sign up".
3. This prevents anyone from creating a new account via the API.

### P3. Create the Storage bucket

1. Go to Storage → New bucket.
2. Name: `private-blobs`
3. Public: **off** (private).
4. File size limit: `10485760` (10 MB).
5. Allowed MIME types: `text/plain, text/markdown, application/pdf, application/octet-stream`

### P4. Create the `blob_index` table

1. Go to SQL Editor → New query.
2. Run:

```sql
create table public.blob_index (
  id          uuid primary key default gen_random_uuid(),
  owner_id    uuid not null references auth.users(id) on delete cascade,
  bucket_id   text not null default 'private-blobs',
  object_path text not null unique,
  filename    text not null,
  content_type text not null,
  size_bytes  bigint not null check (size_bytes >= 0 and size_bytes <= 10485760),
  created_at  timestamptz not null default now()
);
```

3. Verify: go to Table Editor → `blob_index` should appear with 0 rows.

### P5. Enable RLS and create table policies

1. In SQL Editor, run:

```sql
alter table public.blob_index enable row level security;

create policy "blob_index select own"
  on public.blob_index for select to authenticated
  using (owner_id = auth.uid());

create policy "blob_index insert own"
  on public.blob_index for insert to authenticated
  with check (owner_id = auth.uid());

create policy "blob_index delete own"
  on public.blob_index for delete to authenticated
  using (owner_id = auth.uid());
```

2. Verify: go to Authentication → Policies → `blob_index` should show 3 policies.

### P6. Create Storage policies

1. In SQL Editor, run:

```sql
create policy "storage select own blobs"
  on storage.objects for select to authenticated
  using (
    bucket_id = 'private-blobs'
    and owner_id = (select auth.uid())
  );

create policy "storage insert own blobs"
  on storage.objects for insert to authenticated
  with check (
    bucket_id = 'private-blobs'
    and (storage.folder(name))[1] = (select auth.uid()::text)
  );

create policy "storage delete own blobs"
  on storage.objects for delete to authenticated
  using (
    bucket_id = 'private-blobs'
    and owner_id = (select auth.uid())
  );
```

2. Verify: go to Storage → Policies → `objects` table should show 3 new policies
   scoped to `private-blobs`.

### P7. Verify the setup

Before writing any app code, verify the Supabase config works:

1. Open the Supabase SQL Editor.
2. Try inserting a row into `blob_index` as the anonymous role — it should fail
   (RLS blocks it).
3. Go to Storage → `private-blobs` → try uploading a test file via the dashboard
   (this uses the service role, so it bypasses RLS — just confirms the bucket
   exists and works).
4. Delete the test file.

---

## Tasks

Each task is a single commit. Tasks must be done in order — later tasks depend on
earlier ones. Each task states: what to do, which file(s) to touch, how to test it,
and what to commit.

---

### Task 1: Scaffold `index.html` with login screen

**What**: Create `index.html` at the repo root with the HTML skeleton, CSP meta tag,
Supabase SDK script tag, CSS, and the login form. No JS logic yet — just the static
markup and styles.

**File**: `index.html` (create)

**Details**:

1. `<!DOCTYPE html>`, `<html lang="en">`, `<head>` with:
   - `<meta charset="UTF-8">`
   - `<meta name="viewport" content="width=device-width, initial-scale=1.0">`
   - `<title>Shelf</title>`
   - CSP meta tag (see design doc §8)
   - `<style>` block with all CSS (see below)
2. `<body>` with two top-level `<div>` containers:
   - `<div id="login-screen">` — the login form
   - `<div id="app-screen" hidden>` — the main app (empty for now)
3. Supabase SDK script tag:
   ```html
   <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>
   ```
   Include an `integrity` attribute. To get the SRI hash:
   - Go to https://www.srihash.org/
   - Paste the CDN URL
   - Copy the `integrity` value
   - Add `crossorigin="anonymous"`
4. An empty `<script>` block at the end of `<body>` for app JS (added in later tasks).

**CSS to include** (inline in `<style>`):

- Reset: `*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }`
- Body: `font-family: system-ui, sans-serif; background: #f5f5f5; color: #1a1a1a; min-height: 100vh;`
- `.login-container`: centered card (max-width ~400px, white background, padding, border-radius, box-shadow)
- `.login-container h1`: app title styling
- `.form-group`: label + input wrapper (margin-bottom)
- `.form-group label`: block, font-weight 600
- `.form-group input`: full width, padding, border, border-radius
- `.btn`: button base style (padding, background, color, border, border-radius, cursor pointer)
- `.btn-primary`: blue background, white text
- `.btn-danger`: red background, white text
- `.error-message`: red text, hidden by default
- `.header`: flex row, justify-between, align-center, padding, background white, box-shadow
- `.drop-zone`: dashed border, large padding, text-align center, cursor pointer, transition on hover/drag
- `.drop-zone.dragover`: highlighted border color
- `.file-table`: full width, border-collapse, striped rows
- `.file-table th, .file-table td`: padding, text-align left
- `.file-info`: selected file display (name, size) before upload
- `.status-message`: status/error area

**Login form HTML**:

```html
<div id="login-screen" class="login-container">
  <h1>Shelf</h1>
  <form id="login-form" autocomplete="on">
    <div class="form-group">
      <label for="email">Email</label>
      <input type="email" id="email" name="email" required autocomplete="email">
    </div>
    <div class="form-group">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required autocomplete="current-password">
    </div>
    <div class="form-group">
      <label for="passphrase">Encryption passphrase</label>
      <input type="password" id="passphrase" name="passphrase" required autocomplete="off"
        placeholder="Used to encrypt/decrypt your files">
    </div>
    <button type="submit" class="btn btn-primary">Sign In</button>
    <p id="login-error" class="error-message" hidden></p>
  </form>
</div>
```

**How to test**:

1. Open `index.html` directly in a browser (`file:///path/to/shelf/index.html`).
2. You should see a centered login card with three inputs and a button.
3. The main app area should be hidden.
4. Inspect the page: verify the CSP meta tag is present.
5. Open the browser console: verify the Supabase SDK loaded (type `window.supabase`
   — it should not be `undefined`). NOTE: if opened via `file://`, CSP
   `connect-src` may cause console warnings — that's expected. It works correctly
   when served over HTTP/HTTPS.
6. Check there are no console errors (other than the CSP file:// warning).

**Commit**: `feat: scaffold index.html with login screen and CSS`

---

### Task 2: Add the main app screen markup

**What**: Add the HTML for the main app screen — header bar, drop zone, and file
table. Still no JS logic.

**File**: `index.html` (edit)

**Details**:

Inside `<div id="app-screen" hidden>`, add:

```html
<header class="header">
  <h1>Shelf</h1>
  <button id="sign-out-btn" class="btn" type="button">Sign Out</button>
</header>

<main class="main-content">
  <section class="upload-section">
    <div id="drop-zone" class="drop-zone" tabindex="0" role="button"
         aria-label="Drop files here or click to browse">
      <p>Drop files here or click to browse</p>
      <p class="drop-zone-hint">Max 10 MB — text, markdown, PDF</p>
    </div>
    <input type="file" id="file-input" hidden
      accept=".txt,.md,.markdown,.pdf,text/plain,text/markdown,application/pdf">
    <div id="file-info" class="file-info" hidden>
      <span id="file-info-name"></span>
      <span id="file-info-size"></span>
      <button id="upload-btn" class="btn btn-primary" type="button">Upload</button>
      <button id="clear-file-btn" class="btn" type="button">Clear</button>
    </div>
    <p id="upload-status" class="status-message" hidden></p>
  </section>

  <section class="files-section">
    <h2>Your files</h2>
    <table id="file-table" class="file-table">
      <thead>
        <tr>
          <th>Filename</th>
          <th>Size</th>
          <th>Uploaded</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="file-table-body">
      </tbody>
    </table>
    <p id="empty-state" class="empty-state">No files yet. Drop one above.</p>
  </section>
</main>
```

**Additional CSS** (add to existing `<style>`):

- `.main-content`: max-width ~800px, margin auto, padding
- `.upload-section`, `.files-section`: margin-bottom
- `.drop-zone-hint`: small, muted text
- `.file-info`: flex row, align-center, gap
- `.empty-state`: muted text, centered

**How to test**:

1. Temporarily remove `hidden` from `<div id="app-screen">` in the HTML.
2. Open in browser — you should see the header, drop zone, and empty file table.
3. Verify the layout looks reasonable.
4. Re-add `hidden` before committing.

**Commit**: `feat: add main app screen markup (drop zone + file table)`

---

### Task 3: Implement Supabase client initialization and auth

**What**: In the `<script>` block, initialize the Supabase client and implement
the login/logout flow. Wire up the login form and sign-out button.

**File**: `index.html` (edit — the `<script>` block)

**Details**:

```javascript
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

  // Derive encryption key (implemented in Task 4)
  encryptionKey = await deriveKey(passphrase);

  // Clear passphrase from the form
  document.getElementById('passphrase').value = '';

  showApp();
  await loadFiles();  // implemented in Task 6
});

signOutBtn.addEventListener('click', async () => {
  await sb.auth.signOut();
  showLogin();
});

// ── Session check on page load ──────────────────────────────
// If there is a persisted Supabase session (JWT in localStorage),
// we still require the passphrase — so always show login.
// The user must re-enter the passphrase every session.
showLogin();
```

**Important notes for the implementer**:

- `deriveKey()` is called here but defined in Task 4. For this task, add a
  temporary stub: `async function deriveKey(passphrase) { return null; }`
- `loadFiles()` is called here but defined in Task 6. Add a stub:
  `async function loadFiles() {}`
- The session check intentionally always shows the login screen. Even if Supabase
  has a cached JWT, we need the passphrase to derive the key. The cached session
  means `signInWithPassword` will succeed instantly (Supabase reuses the session).

**How to test**:

1. Serve the file over HTTP. Easiest: `python3 -m http.server 8000` in the repo
   root, then open `http://localhost:8000`.
   (The CSP `connect-src` only allows HTTPS to Supabase, which works from localhost.)
2. Enter valid email + password + any passphrase → should sign in, login screen
   hides, app screen appears.
3. Enter wrong email/password → should show error message.
4. Enter valid email/password but empty passphrase → should show
   "Encryption passphrase is required."
5. Click "Sign Out" → should return to login screen.
6. Open browser console → verify no errors.

**Commit**: `feat: implement Supabase auth (login/logout flow)`

---

### Task 4: Implement encryption module

**What**: Implement `deriveKey()`, `encryptBlob()`, and `decryptBlob()` using
the Web Crypto API. Replace the stub from Task 3.

**File**: `index.html` (edit — the `<script>` block)

**Details**:

Place this code **before** the auth section (so `deriveKey` is defined before
it's called):

```javascript
// ── Encryption ──────────────────────────────────────────────
// Fixed salt for PBKDF2. Changing this invalidates all encrypted files.
const PBKDF2_SALT = new Uint8Array([
  0x73, 0x68, 0x65, 0x6c, 0x66, 0x2d, 0x73, 0x61,
  0x6c, 0x74, 0x2d, 0x76, 0x31, 0x2d, 0x30, 0x30
]);
// That's the ASCII bytes of "shelf-salt-v1-00" — easy to document/recover.

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
```

**Remove** the `deriveKey` stub from Task 3.

**How to test**:

Write a temporary test at the bottom of the `<script>` block (remove it before
committing, or wrap it in an `if (false)` block):

```javascript
// ── Manual crypto test (remove after verifying) ─────────────
(async () => {
  const key = await deriveKey('test-passphrase');
  const original = new TextEncoder().encode('Hello, Shelf!');
  const encrypted = await encryptBlob(key, original);
  const decrypted = await decryptBlob(key, encrypted);
  const result = new TextDecoder().decode(decrypted);
  console.assert(result === 'Hello, Shelf!', 'Crypto round-trip failed');
  console.log('Crypto round-trip OK:', result);

  // Verify wrong passphrase fails
  const wrongKey = await deriveKey('wrong-passphrase');
  try {
    await decryptBlob(wrongKey, encrypted);
    console.error('ERROR: decryption with wrong key should have thrown');
  } catch (e) {
    console.log('Wrong-key rejection OK:', e.message);
  }
})();
```

1. Open the page in browser, open console.
2. You should see "Crypto round-trip OK: Hello, Shelf!" and "Wrong-key rejection OK: ...".
3. If not, the crypto implementation is broken — do not proceed.
4. **Remove the test code** before committing.

**Commit**: `feat: implement client-side encryption (AES-GCM + PBKDF2)`

---

### Task 5: Implement file upload

**What**: Wire up the drop zone and upload button. When a file is selected and
the user clicks "Upload", encrypt the file and store it in Supabase Storage +
`blob_index`.

**File**: `index.html` (edit — the `<script>` block)

**Details**:

```javascript
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
```

**How to test**:

1. Serve over HTTP (`python3 -m http.server 8000`).
2. Sign in with valid credentials + passphrase.
3. Drop a small `.txt` file onto the drop zone → file info should appear.
4. Click "Upload" → status should show "Encrypting…" then "Uploading…" then
   "Uploaded successfully."
5. Go to Supabase dashboard → Storage → `private-blobs` → you should see a
   folder with your user ID, containing the encrypted file.
6. Go to Table Editor → `blob_index` → you should see a metadata row.
7. Test validation: try uploading a file > 10 MB → should show size error.
8. Try uploading a `.exe` file → should show type error (unless its MIME is
   `application/octet-stream`, which may be allowed).

**Commit**: `feat: implement encrypted file upload with drag-and-drop`

---

### Task 6: Implement file table and download

**What**: Implement `loadFiles()` to populate the file table from `blob_index`,
and add the download button handler that decrypts and triggers a browser download.

**File**: `index.html` (edit — the `<script>` block)

**Details**:

Replace the `loadFiles` stub with:

```javascript
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
```

**Additional CSS** (add to `<style>`):

```css
.btn-sm {
  padding: 0.25rem 0.5rem;
  font-size: 0.875rem;
  margin-right: 0.25rem;
}
```

**How to test**:

1. Sign in. If you uploaded a file in Task 5, it should appear in the table.
2. Click "Download" → the file should download with its original filename.
3. Open the downloaded file → verify its contents match the original.
4. Sign out and sign back in with a **different passphrase** → click download →
   should show "Decryption failed — wrong passphrase?" alert.
5. Sign out and sign in with the **correct passphrase** → download should work again.
6. Upload 2-3 files → table should list all, newest first.
7. If no files exist, you should see "No files yet. Drop one above."

**Commit**: `feat: implement file table listing and encrypted download`

---

### Task 7: Implement file deletion

**What**: Implement `deleteFile()` — prompts for confirmation, deletes from Storage,
then deletes from `blob_index`, then refreshes the table.

**File**: `index.html` (edit — the `<script>` block)

**Details**:

```javascript
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
```

**How to test**:

1. Upload a file (or use one from earlier testing).
2. Click "Delete" → confirm dialog should appear.
3. Click "Cancel" → nothing should happen.
4. Click "Delete" → confirm → row should disappear from table.
5. Check Supabase dashboard: Storage file should be gone, `blob_index` row
   should be gone.
6. Delete all files → empty state message should appear.

**Commit**: `feat: implement file deletion`

---

### Task 8: Add `.nojekyll` and test GitHub Pages readiness

**What**: Add `.nojekyll` file so GitHub Pages serves the raw HTML without
Jekyll processing. Verify the app works when served as a static site.

**Files**:
- `.nojekyll` (create — empty file)

**Details**:

1. Create an empty `.nojekyll` file at repo root:
   ```bash
   touch .nojekyll
   ```

2. Verify `index.html` has no Jekyll-incompatible patterns (shouldn't, since
   we're not using Jekyll at all — `.nojekyll` tells GitHub to skip it).

**How to test**:

1. Run `python3 -m http.server 8000` in the repo root.
2. Open `http://localhost:8000`.
3. Run through the full flow:
   - Sign in (email + password + passphrase)
   - Upload a `.txt` file
   - Verify it appears in the table
   - Download it → verify contents match
   - Upload a `.md` file
   - Upload a `.pdf` file
   - Download both → verify contents
   - Delete one file → verify it disappears
   - Sign out → verify login screen appears
   - Sign back in → verify files are still listed

This is your **acceptance test**. Every step must pass.

**Commit**: `chore: add .nojekyll for GitHub Pages`

---

### Task 9: Final security review and polish

**What**: Review the entire `index.html` for security issues and code quality.
This is a checklist — go through each item.

**File**: `index.html` (edit if issues found)

**Security checklist**:

- [ ] CSP meta tag is present and restrictive (no `unsafe-eval`, minimal `unsafe-inline`)
- [ ] No `innerHTML` anywhere in the JS code
- [ ] No `document.write` anywhere
- [ ] No `eval()` anywhere
- [ ] File names are sanitized before use in Storage paths
- [ ] File size is validated client-side before upload
- [ ] File type is validated client-side before upload
- [ ] Only the publishable key appears in the source — no `service_role`, no
      DB passwords, no Neon keys
- [ ] The encryption passphrase is cleared from the form after login
- [ ] The `encryptionKey` is set to `null` on sign-out
- [ ] `upsert: false` is used on Storage uploads (no accidental overwrites)
- [ ] Error messages do not leak internal details (no stack traces shown to user)
- [ ] SRI hash is present on the Supabase CDN script tag
- [ ] `autocomplete="off"` is set on the passphrase input

**Code quality checklist**:

- [ ] No unused variables or dead code
- [ ] No `console.log` statements left in (except `console.error` for actual errors)
- [ ] Consistent code style (semicolons, quotes, indentation)
- [ ] Form submission uses `e.preventDefault()`
- [ ] All async functions have try/catch error handling
- [ ] Buttons are disabled during async operations to prevent double-clicks

**How to test**: Re-run the acceptance test from Task 8.

**Commit**: `chore: security review and final polish`

---

## Summary of commits

| #  | Commit message                                              |
|----|-------------------------------------------------------------|
| 1  | `feat: scaffold index.html with login screen and CSS`       |
| 2  | `feat: add main app screen markup (drop zone + file table)` |
| 3  | `feat: implement Supabase auth (login/logout flow)`         |
| 4  | `feat: implement client-side encryption (AES-GCM + PBKDF2)` |
| 5  | `feat: implement encrypted file upload with drag-and-drop`  |
| 6  | `feat: implement file table listing and encrypted download`  |
| 7  | `feat: implement file deletion`                              |
| 8  | `chore: add .nojekyll for GitHub Pages`                     |
| 9  | `chore: security review and final polish`                   |

## Testing reference

The app has no automated test suite. It is a single HTML file with no build step.
Testing is manual. Here is a quick reference for the key test scenarios:

| Scenario                        | Expected result                          |
|---------------------------------|------------------------------------------|
| Sign in with wrong password     | Error message shown, no app access       |
| Sign in with empty passphrase   | Error message, sign-in blocked           |
| Sign in with correct credentials| App screen shown, file table loads       |
| Upload .txt file (< 10 MB)     | Encrypts, uploads, appears in table      |
| Upload .pdf file (< 10 MB)     | Same as above                            |
| Upload file > 10 MB            | Rejected with size error                 |
| Upload .exe file                | Rejected with type error                 |
| Download with correct passphrase| File decrypts, downloads with original name |
| Download with wrong passphrase  | "Decryption failed" error                |
| Delete file                     | Confirmation, then removed from table + Supabase |
| Sign out                        | Login screen shown, encryption key wiped |
| View page source                | Only publishable key visible, no secrets |

## Supabase documentation references

These are the docs the implementer should consult if they get stuck:

- **Supabase JS Client (createClient, auth, storage, from)**: https://supabase.com/docs/reference/javascript/
- **Supabase Auth (signInWithPassword)**: https://supabase.com/docs/reference/javascript/auth-signinwithpassword
- **Supabase Storage (upload, download, remove)**: https://supabase.com/docs/reference/javascript/storage-from-upload
- **Supabase RLS**: https://supabase.com/docs/guides/database/postgres/row-level-security
- **Storage Policies**: https://supabase.com/docs/guides/storage/security/access-control
- **Web Crypto API**: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
- **PBKDF2 (Web Crypto)**: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey
- **AES-GCM (Web Crypto)**: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt
