# Paste Text Feature — Design

**Date:** 2026-03-07
**Status:** Approved

## Problem

Shelf currently only supports file uploads via drag-and-drop or file picker. Users who have text content on their clipboard (code snippets, notes, config files) must first save it to a local file before uploading. This adds friction.

## Solution

Add a "Paste Text" tab alongside the existing file upload UI. Users switch between "Upload File" and "Paste Text" tabs. In paste mode, they enter a filename (with extension), paste text into a textarea, and upload. The text is encoded to UTF-8 bytes and flows through the same encrypt → upload → store pipeline as file uploads. Downloaded files are indistinguishable from file-uploaded ones.

## Decisions

| Question | Decision |
|---|---|
| UI pattern | Two tabs above upload area ("Upload File" / "Paste Text") |
| File naming | User-specified filename with extension; any extension allowed |
| Content type | Derived from extension via lookup map; fallback `application/octet-stream` |
| Size limit | Same 10 MB limit as file uploads |
| Clipboard files (images, etc.) | Out of scope — text only for now |
| Extension allowlist | None — any extension accepted (it's just text bytes) |
| Database changes | None — `blob_index` schema unchanged |
| Testing | Manual testing with documented scenarios |

## UI Layout

```
┌──────────────┐┌──────────────┐
│ Upload File  ││  Paste Text  │   ← tab switcher
└──────────────┘└──────────────┘
┌─────────────────────────────┐
│                             │
│   [dropzone or textarea]    │   ← only one visible at a time
│                             │
└─────────────────────────────┘
```

**Upload File tab** (default active): existing dropzone, file-input, file-info, upload button. No changes.

**Paste Text tab** shows:
1. **Filename input** — text input, placeholder "e.g. notes.md". Required. Must contain a dot with non-empty parts on both sides.
2. **Textarea** — `<textarea>` with placeholder "Paste your text here…". ~8 rows. Monospace font.
3. **Byte counter** — below textarea: "X bytes / 10 MB". Updates on input (debounced). Red when over limit.
4. **Upload button** — same styling as existing upload button. Enabled only when filename and textarea are non-empty.

The `#upload-status` message area is shared across both tabs.

## Data Flow

1. **Validate** — filename has extension, textarea non-empty, byte size ≤ 10 MB
2. **Encode** — `new TextEncoder().encode(text)` → `Uint8Array`
3. **Derive content_type** — extension lookup map (see below)
4. **Encrypt** — `encryptBlob(encryptionKey, plainBytes)` (existing function)
5. **Upload** — `sb.storage.from(BUCKET).upload(...)` (existing pattern)
6. **Insert metadata** — `blob_index` insert (existing pattern) with filename from input, content_type from step 3, size_bytes from encoded byte length
7. **Success** — clear form, reload file table

No schema changes. No new Supabase tables, columns, or RLS policies.

## Content-Type Extension Map

```
.txt               → text/plain
.md, .markdown     → text/markdown
.json              → application/json
.csv               → text/csv
.html, .htm        → text/html
.xml               → application/xml
.yaml, .yml        → text/yaml
(everything else)  → application/octet-stream
```

## Validation Rules

**Filename:**
- Required
- Must contain at least one dot
- Must have non-empty string before and after the last dot (e.g., `a.txt` valid, `.txt` invalid, `foo` invalid, `foo.` invalid)
- Sanitized via existing `sanitizeFilename()` for storage path

**Text content:**
- Must be non-empty (whitespace-only is valid content)
- UTF-8 encoded byte size must be ≤ 10 MB

**Error messages** (displayed via existing `showUploadStatus`):
- "Filename is required and must include an extension (e.g. notes.md)"
- "Text content cannot be empty"
- "Text exceeds 10 MB limit"

## Clipboard Size Limits

No browser-enforced limit on textarea paste size. The practical limit is device memory. Browsers handle multi-MB pastes without issue. Our constraint is the existing 10 MB Supabase/DB limit. The byte counter gives users real-time feedback.

## Out of Scope (YAGNI)

- Pasting files/images via ClipboardEvent API
- Syntax highlighting in textarea
- Auto-detecting content type from content
- Editing files after upload
- Preview before upload

## Files Changed

- `index.html` — tab switcher markup, paste-text panel HTML, tab CSS
- `app.js` — tab switching logic, paste-text validation, content-type map, upload handler for text mode

## Manual Test Scenarios

**Happy paths:**
1. Switch to Paste Text tab → textarea and filename input visible, dropzone hidden
2. Switch back to Upload File tab → dropzone visible, textarea hidden
3. Paste text, enter filename `notes.md`, click Upload → encrypts, uploads, appears in file table
4. Download the pasted file → decrypts, downloads as `notes.md`, content matches
5. Delete the pasted file → same behavior as any uploaded file
6. Multi-byte characters (emoji, CJK) → byte counter accurate, round-trips correctly

**Validation:**
7. Upload with empty textarea → error
8. Upload with no filename → error
9. Upload with filename without extension (`foo`) → error
10. Paste >10 MB text → byte counter red, upload rejected

**Integration:**
11. Upload via dropzone, then paste text → both in table, both downloadable
12. Reload page → pasted files persist and download correctly
