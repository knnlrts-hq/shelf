# Paste Text Feature — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Let users paste text into a textarea and save it as a named file, as an alternative to the file-upload dropzone.

**Architecture:** A two-tab UI ("Upload File" / "Paste Text") above the existing upload area. The paste-text tab collects a filename and textarea content, encodes the text to UTF-8 bytes, then feeds those bytes into the exact same encrypt → upload → insert-metadata pipeline that file uploads already use. No database schema changes. No new dependencies.

**Tech Stack:** Vanilla HTML/CSS/JS (no framework, no build step), Supabase JS SDK v2.98.0 (already loaded via CDN), Web Crypto API (already used for encryption).

**Design doc:** `docs/plans/2026-03-07-paste-text-design.md`

---

## Codebase Orientation

Before touching any code, read these two files in their entirety. They are the whole application:

| File | Lines | What it does |
|---|---|---|
| `index.html` | 281 | All HTML markup + all CSS (inline `<style>` tag). No external stylesheet. |
| `app.js` | 449 | All JavaScript. Loaded at bottom of `<body>`. No modules, no bundler. |

There is no `package.json`, no build step, no test runner, no TypeScript. You edit the files directly and open `index.html` in a browser to test.

**Key patterns to follow:**
- DOM refs are declared as `const` at the top of each section: `const el = document.getElementById('id');`
- Sections are separated by banner comments: `// ── Section Name ──────────`
- Status messages use `showUploadStatus(msg, isError)` (defined at `app.js:257`)
- File sizes are formatted with `formatBytes(bytes)` (defined at `app.js:247`)
- Filenames are sanitized with `sanitizeFilename(name)` (defined at `app.js:253`)
- The upload pipeline (encrypt → storage → metadata) lives at `app.js:336-395`

---

## Task 1: Add Tab CSS

**Files:**
- Modify: `index.html:132-134` (after `.upload-section` rule, before `.files-section` rule)

**Step 1: Add the CSS rules**

Insert the following CSS immediately after the `.upload-section` block (line 134) and before the `.files-section` block (line 136) in the `<style>` tag:

```css
    /* Upload tabs */
    .upload-tabs {
      display: flex;
      gap: 0;
      margin-bottom: 0;
    }

    .upload-tab {
      padding: 0.5rem 1.25rem;
      background: none;
      border: none;
      border-bottom: 2px solid transparent;
      cursor: pointer;
      font-size: 0.95rem;
      color: #6b7280;
      transition: color 0.2s, border-color 0.2s;
    }

    .upload-tab:hover {
      color: #1a1a1a;
    }

    .upload-tab.active {
      color: #2563eb;
      border-bottom-color: #2563eb;
      font-weight: 600;
    }

    /* Paste text panel */
    .paste-panel {
      margin-top: 0.75rem;
    }

    .paste-panel .form-group {
      margin-bottom: 0.75rem;
    }

    .paste-panel textarea {
      width: 100%;
      padding: 0.5rem 0.75rem;
      border: 1px solid #ccc;
      border-radius: 4px;
      font-family: ui-monospace, 'Cascadia Code', 'Source Code Pro', Menlo, Consolas, monospace;
      font-size: 0.9rem;
      resize: vertical;
      line-height: 1.5;
    }

    .paste-panel .byte-counter {
      font-size: 0.8rem;
      color: #6b7280;
      text-align: right;
      margin-top: 0.25rem;
    }

    .paste-panel .byte-counter.over-limit {
      color: #dc2626;
      font-weight: 600;
    }
```

**Step 2: Verify visually**

Open `index.html` in a browser. The page should look exactly the same as before — these styles don't apply to anything yet. No visible change confirms you haven't broken existing CSS.

**Step 3: Commit**

```bash
git add index.html
git commit -m "style: add CSS for upload tabs and paste-text panel"
```

---

## Task 2: Add Tab HTML Markup

**Files:**
- Modify: `index.html:240-255` (the `<section class="upload-section">` block)

**Step 1: Replace the upload section HTML**

Find this block in `index.html` (lines 240-255):

```html
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
```

Replace it with:

```html
      <section class="upload-section">
        <div class="upload-tabs">
          <button id="tab-upload" class="upload-tab active" type="button">Upload File</button>
          <button id="tab-paste" class="upload-tab" type="button">Paste Text</button>
        </div>

        <!-- Upload File panel (default visible) -->
        <div id="panel-upload">
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
        </div>

        <!-- Paste Text panel (hidden by default) -->
        <div id="panel-paste" class="paste-panel" hidden>
          <div class="form-group">
            <label for="paste-filename">Filename</label>
            <input type="text" id="paste-filename" placeholder="e.g. notes.md">
          </div>
          <div class="form-group">
            <label for="paste-text">Text content</label>
            <textarea id="paste-text" rows="8" placeholder="Paste your text here…"></textarea>
            <div id="byte-counter" class="byte-counter">0 bytes / 10 MB</div>
          </div>
          <button id="paste-upload-btn" class="btn btn-primary" type="button">Upload</button>
          <button id="paste-clear-btn" class="btn" type="button">Clear</button>
        </div>

        <p id="upload-status" class="status-message" hidden></p>
      </section>
```

**What changed and why:**
- Added a `.upload-tabs` div with two tab buttons (`#tab-upload`, `#tab-paste`)
- Wrapped the existing dropzone + file-input + file-info in `#panel-upload` (no changes to those elements — their IDs, classes, and attributes are identical)
- Added `#panel-paste` (hidden by default) with filename input, textarea, byte counter, and upload/clear buttons
- `#upload-status` remains outside both panels (shared)

**Step 2: Verify in browser**

Open `index.html` in a browser and sign in. You should see:
- Two tab buttons ("Upload File" / "Paste Text") above the dropzone
- "Upload File" tab has blue underline (active state from CSS)
- The dropzone looks and works exactly as before (click, drag-drop)
- Clicking "Paste Text" tab does nothing yet (no JS wired up)

The existing file upload must still work. Test it: select a `.txt` file, verify it appears in the file info bar, click Upload, confirm it appears in the table.

**Step 3: Commit**

```bash
git add index.html
git commit -m "markup: add tab switcher and paste-text panel HTML"
```

---

## Task 3: Add Tab Switching Logic

**Files:**
- Modify: `app.js` — add new section after the existing upload DOM refs block (after line 244)

**Step 1: Add DOM refs and tab switching code**

In `app.js`, find this line (244):

```js
let selectedFile = null;
```

Insert the following immediately after it:

```js

// ── Tabs ───────────────────────────────────────────────────
const tabUpload  = document.getElementById('tab-upload');
const tabPaste   = document.getElementById('tab-paste');
const panelUpload = document.getElementById('panel-upload');
const panelPaste  = document.getElementById('panel-paste');

function switchTab(activeTab) {
  const isUpload = activeTab === 'upload';

  tabUpload.classList.toggle('active', isUpload);
  tabPaste.classList.toggle('active', !isUpload);
  panelUpload.hidden = !isUpload;
  panelPaste.hidden = isUpload;

  clearUploadStatus();
}

tabUpload.addEventListener('click', () => switchTab('upload'));
tabPaste.addEventListener('click', () => switchTab('paste'));
```

**Step 2: Verify in browser**

1. Open `index.html`, sign in
2. Click "Paste Text" tab → dropzone disappears, textarea panel appears, "Paste Text" tab has blue underline
3. Click "Upload File" tab → dropzone reappears, textarea panel disappears, "Upload File" tab has blue underline
4. Switch several times rapidly → no flicker, no errors in console
5. While on Upload File tab, the existing file upload still works end-to-end

**Step 3: Commit**

```bash
git add app.js
git commit -m "feat: add tab switching between Upload File and Paste Text"
```

---

## Task 4: Add Content-Type Map and Filename Validation

**Files:**
- Modify: `app.js` — add new section after the Tabs section (after the `tabPaste` click listener)

**Step 1: Add the extension-to-content-type map**

Insert the following after the tab switching code you just added:

```js

// ── Paste helpers ──────────────────────────────────────────
const EXT_CONTENT_TYPE = {
  txt:      'text/plain',
  md:       'text/markdown',
  markdown: 'text/markdown',
  json:     'application/json',
  csv:      'text/csv',
  html:     'text/html',
  htm:      'text/html',
  xml:      'application/xml',
  yaml:     'text/yaml',
  yml:      'text/yaml',
};

function contentTypeFromFilename(filename) {
  const dot = filename.lastIndexOf('.');
  if (dot === -1 || dot === filename.length - 1) return 'application/octet-stream';
  const ext = filename.slice(dot + 1).toLowerCase();
  return EXT_CONTENT_TYPE[ext] || 'application/octet-stream';
}

function validatePasteFilename(filename) {
  if (!filename) {
    return 'Filename is required and must include an extension (e.g. notes.md)';
  }
  const dot = filename.lastIndexOf('.');
  if (dot <= 0 || dot === filename.length - 1) {
    return 'Filename is required and must include an extension (e.g. notes.md)';
  }
  return null; // valid
}
```

**Why `dot <= 0`:** This rejects both "no dot" (`dot === -1`) and "dot-only prefix" like `.txt` (`dot === 0`) in one check.

**Step 2: Verify these functions work**

Open the browser console (F12) on the loaded page and run:

```js
// These are now global (no modules), so you can call them directly:
contentTypeFromFilename('notes.md')       // → 'text/markdown'
contentTypeFromFilename('data.json')      // → 'application/json'
contentTypeFromFilename('thing.xyz')      // → 'application/octet-stream'
contentTypeFromFilename('README.MD')      // → 'text/markdown' (case-insensitive)

validatePasteFilename('')                 // → error string
validatePasteFilename('foo')              // → error string
validatePasteFilename('.txt')             // → error string
validatePasteFilename('foo.')             // → error string
validatePasteFilename('notes.md')         // → null (valid)
validatePasteFilename('a.b')              // → null (valid)
```

**Step 3: Commit**

```bash
git add app.js
git commit -m "feat: add content-type extension map and filename validation"
```

---

## Task 5: Add Byte Counter

**Files:**
- Modify: `app.js` — add DOM refs and input listener after the paste helpers section

**Step 1: Add byte counter logic**

Insert the following after the `validatePasteFilename` function:

```js

// ── Paste DOM refs ─────────────────────────────────────────
const pasteFilename  = document.getElementById('paste-filename');
const pasteText      = document.getElementById('paste-text');
const byteCounter    = document.getElementById('byte-counter');
const pasteUploadBtn = document.getElementById('paste-upload-btn');
const pasteClearBtn  = document.getElementById('paste-clear-btn');

const textEncoder = new TextEncoder();

function updateByteCounter() {
  const byteLength = textEncoder.encode(pasteText.value).byteLength;
  const overLimit = byteLength > MAX_FILE_SIZE;
  byteCounter.textContent = `${formatBytes(byteLength)} / ${formatBytes(MAX_FILE_SIZE)}`;
  byteCounter.classList.toggle('over-limit', overLimit);
}

pasteText.addEventListener('input', updateByteCounter);
```

**Why a shared `TextEncoder` instance:** Creating a `TextEncoder` is cheap but there's no reason to create one per keystroke. We also reuse it during upload (Task 6).

**Step 2: Verify in browser**

1. Sign in, switch to "Paste Text" tab
2. Type a few characters in the textarea → byte counter updates (e.g. "5 bytes / 10 MB")
3. Paste a large block of text → counter reflects the total
4. Type an emoji like 😀 → counter shows 4 bytes (UTF-8 encoding of emoji), not 1 or 2
5. Clear the textarea → counter shows "0 bytes / 10 MB"

**Step 3: Commit**

```bash
git add app.js
git commit -m "feat: add live byte counter for paste textarea"
```

---

## Task 6: Add Paste Upload Handler and Clear Button

This is the main feature task. It wires the "Upload" button in the paste panel to the existing encrypt → upload → insert pipeline.

**Files:**
- Modify: `app.js` — add handler after the byte counter code from Task 5

**Step 1: Add clear and upload handlers**

Insert the following after the `pasteText.addEventListener('input', updateByteCounter);` line:

```js

function clearPaste() {
  pasteFilename.value = '';
  pasteText.value = '';
  updateByteCounter();
  clearUploadStatus();
}

pasteClearBtn.addEventListener('click', clearPaste);

pasteUploadBtn.addEventListener('click', async () => {
  if (!encryptionKey) return;

  // Validate filename
  const filename = pasteFilename.value.trim();
  const filenameErr = validatePasteFilename(filename);
  if (filenameErr) {
    showUploadStatus(filenameErr, true);
    return;
  }

  // Validate text content
  const text = pasteText.value;
  if (!text) {
    showUploadStatus('Text content cannot be empty.', true);
    return;
  }

  // Encode and check size
  const plainBytes = textEncoder.encode(text);
  if (plainBytes.byteLength > MAX_FILE_SIZE) {
    showUploadStatus(`Text exceeds ${formatBytes(MAX_FILE_SIZE)} limit.`, true);
    return;
  }

  pasteUploadBtn.disabled = true;
  showUploadStatus('Encrypting…', false);

  try {
    const { data: userData } = await sb.auth.getUser();
    const user = userData.user;
    if (!user) throw new Error('Not signed in');

    // Encrypt
    const encryptedBytes = await encryptBlob(encryptionKey, plainBytes);

    // Build path
    const blobId = crypto.randomUUID();
    const safeName = sanitizeFilename(filename);
    const objectPath = `${user.id}/${blobId}/${safeName}`;

    showUploadStatus('Uploading…', false);

    // Upload to Storage
    const { error: uploadError } = await sb.storage
      .from(BUCKET)
      .upload(objectPath, encryptedBytes, {
        contentType: 'application/octet-stream',
        upsert: false,
      });

    if (uploadError) throw uploadError;

    // Insert metadata
    const contentType = contentTypeFromFilename(filename);
    const { error: metaError } = await sb.from('blob_index').insert({
      id: blobId,
      owner_id: user.id,
      bucket_id: BUCKET,
      object_path: objectPath,
      filename: filename,
      content_type: contentType,
      size_bytes: plainBytes.byteLength,
    });

    if (metaError) {
      await sb.storage.from(BUCKET).remove([objectPath]);
      throw metaError;
    }

    showUploadStatus('Uploaded successfully.', false);
    clearPaste();
    await loadFiles();
  } catch (err) {
    showUploadStatus('Upload failed: ' + err.message, true);
  } finally {
    pasteUploadBtn.disabled = false;
  }
});
```

**What this does, line by line:**
- `clearPaste()` — resets filename input, textarea, byte counter, and status message. Used by the Clear button and after successful upload.
- The upload handler mirrors the existing file-upload handler at `app.js:336-395` exactly, with three differences:
  1. Bytes come from `TextEncoder.encode(text)` instead of `file.arrayBuffer()`
  2. Filename comes from the text input instead of `file.name`
  3. Content type comes from `contentTypeFromFilename()` instead of `file.type`

**Step 2: End-to-end manual test**

Run through these scenarios in the browser:

| # | Action | Expected result |
|---|---|---|
| 1 | Switch to Paste Text, leave both fields empty, click Upload | Error: "Text content cannot be empty." |
| 2 | Type text but leave filename empty, click Upload | Error: "Filename is required and must include an extension (e.g. notes.md)" |
| 3 | Enter filename `foo` (no extension), type text, click Upload | Same filename error |
| 4 | Enter filename `notes.md`, type "Hello world", click Upload | Status shows "Encrypting…" → "Uploading…" → "Uploaded successfully." File appears in table. |
| 5 | Click Download on the new `notes.md` row | File downloads. Open it — contents are "Hello world". |
| 6 | Click Delete on the `notes.md` row | Confirmation dialog → file removed from table. |
| 7 | Enter filename `data.json`, paste `{"key": "value"}`, Upload | Appears in table. Download gives valid JSON file. |
| 8 | Paste text with emoji: `Hello 🌍`, filename `emoji.txt`, Upload → Download | Content round-trips correctly including the emoji. |
| 9 | Switch to Upload File tab, upload a `.txt` file via dropzone | Still works. Both pasted and uploaded files coexist in the table. |
| 10 | Click Clear on paste panel | Filename, textarea, byte counter all reset. |

**Step 3: Commit**

```bash
git add app.js
git commit -m "feat: add paste-text upload with validation and clear"
```

---

## Task 7: Final Integration Test and Cleanup

**Files:**
- No code changes expected. This task is verification only.

**Step 1: Full regression test**

Run through every scenario from the design doc's test list (`docs/plans/2026-03-07-paste-text-design.md`, "Manual Test Scenarios" section). The complete list:

**Happy paths:**
1. Switch to Paste Text tab → textarea and filename input visible, dropzone hidden
2. Switch back to Upload File tab → dropzone visible, textarea hidden
3. Paste text, enter filename `notes.md`, click Upload → encrypts, uploads, appears in file table
4. Download the pasted file → decrypts, downloads as `notes.md`, content matches
5. Delete the pasted file → same behavior as any uploaded file
6. Multi-byte characters (emoji, CJK) → byte counter accurate, round-trips correctly

**Validation:**
7. Upload with empty textarea → error "Text content cannot be empty."
8. Upload with no filename → error about filename required
9. Upload with filename without extension (`foo`) → error about needing extension
10. Paste >10 MB of text → byte counter turns red, upload rejected with size error

**Integration:**
11. Upload a file via dropzone, then paste a text file → both appear in table, both downloadable
12. Reload page (re-sign-in) → pasted files still listed and downloadable

**Step 2: Browser compatibility spot-check**

If you have access, also test in:
- Chrome (primary target)
- Firefox
- Safari (if on macOS)

The features used (`TextEncoder`, `crypto.subtle`, `classList.toggle`, `hidden` attribute) are supported in all modern browsers.

**Step 3: Check for console errors**

Open DevTools (F12), switch between tabs, upload via both methods, download, delete. The console should be clean — no errors, no warnings.

**Step 4: If everything passes, commit a final message**

Only if you made any small fixes during verification:

```bash
git add index.html app.js
git commit -m "fix: address issues found during paste-text integration testing"
```

If no fixes were needed, skip this commit.

---

## Summary of All Commits

| # | Commit message | Files |
|---|---|---|
| 1 | `style: add CSS for upload tabs and paste-text panel` | `index.html` |
| 2 | `markup: add tab switcher and paste-text panel HTML` | `index.html` |
| 3 | `feat: add tab switching between Upload File and Paste Text` | `app.js` |
| 4 | `feat: add content-type extension map and filename validation` | `app.js` |
| 5 | `feat: add live byte counter for paste textarea` | `app.js` |
| 6 | `feat: add paste-text upload with validation and clear` | `app.js` |
| 7 | *(only if fixes needed)* `fix: address issues found during integration testing` | `index.html`, `app.js` |

## Lines of Code Estimate

- CSS: ~45 lines added to `index.html`
- HTML: ~25 lines added to `index.html` (net, after wrapping existing dropzone)
- JS: ~90 lines added to `app.js`
- Total: ~160 lines across 2 files
