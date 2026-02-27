# Shelf — Design Document

**Date**: 2026-02-27
**Status**: Approved

## 1. Purpose

Shelf is a personal file-sharing tool. Upload a file from one device, download it
from any other browser-enabled device. It targets a single user who wants a
lightweight, encrypted, browser-based file locker backed by Supabase.

## 2. Decisions

| Decision               | Choice                                              |
|------------------------|-----------------------------------------------------|
| Auth model             | Single Supabase Auth email+password account          |
| Sign-up                | Disabled in UI; optionally disabled at project level |
| Encryption             | Client-side AES-GCM via Web Crypto API               |
| Key management         | Passphrase entered at login; PBKDF2-derived key held in memory only |
| File size limit        | 10 MB                                                |
| Hosting                | GitHub Pages from repo root (`index.html`)           |
| Framework              | None — vanilla HTML/CSS/JS, single file              |
| External dependency    | `@supabase/supabase-js@2` loaded from jsDelivr CDN  |

## 3. Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Browser (index.html)                                        │
│                                                              │
│  ┌──────────┐   ┌───────────┐   ┌───────────────────────┐   │
│  │ Login UI │──▶│ Supabase  │──▶│ Derive AES-GCM key    │   │
│  │          │   │ Auth      │   │ from passphrase via    │   │
│  │ email    │   │ signIn()  │   │ PBKDF2 (in memory)    │   │
│  │ password │   └───────────┘   └───────────────────────┘   │
│  │ passphrase│                                               │
│  └──────────┘                                                │
│                                                              │
│  ┌──────────────────────────────────────────────────┐        │
│  │ Main App                                          │        │
│  │                                                    │        │
│  │  Drop Zone ──▶ encrypt(file) ──▶ Storage.upload() │        │
│  │                                  + blob_index.insert()     │
│  │                                                    │        │
│  │  File Table ◀── blob_index.select()               │        │
│  │    ├── Download: Storage.download() ──▶ decrypt() │        │
│  │    └── Delete:   Storage.remove() + blob_index.delete()   │
│  └──────────────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────────────┘
        │                        │
        │  publishable key +     │
        │  user JWT              │
        ▼                        ▼
┌──────────────────────────────────────────────────────────────┐
│  Supabase                                                     │
│                                                              │
│  Auth ─── issues JWT on sign-in                              │
│  Storage ─── private-blobs bucket (RLS-protected)            │
│  Postgres ── blob_index table (RLS-protected)                │
└──────────────────────────────────────────────────────────────┘
```

### Data flow

1. User opens `index.html` → login screen appears.
2. User enters email, password, encryption passphrase.
3. Browser calls `supabase.auth.signInWithPassword({ email, password })`.
4. On success, derive AES-GCM key: `passphrase → PBKDF2(SHA-256, 100k iterations, fixed salt) → 256-bit CryptoKey`.
5. Key is held in a JS variable. Never serialized. Never persisted.
6. Login screen hides; main app (drop zone + file table) appears.
7. Browser fetches `blob_index` rows to populate the file table.

**Upload**:
1. User drops/selects a file (≤ 10 MB, allowed MIME type).
2. Browser reads file as `ArrayBuffer`.
3. Generate random 12-byte IV.
4. `AES-GCM.encrypt(key, iv, plaintext)` → ciphertext.
5. Prepend IV: `blob = IV (12 bytes) || ciphertext`.
6. `supabase.storage.from('private-blobs').upload(objectPath, blob)`.
7. `supabase.from('blob_index').insert({ ... metadata })`.
8. Refresh file table.

**Download**:
1. User clicks download on a row.
2. Read metadata from `blob_index`.
3. `supabase.storage.from('private-blobs').download(objectPath)` → encrypted blob.
4. Split blob: first 12 bytes = IV, rest = ciphertext.
5. `AES-GCM.decrypt(key, iv, ciphertext)` → plaintext.
6. Create `Blob` → create object URL → trigger `<a download>` click.

**Delete**:
1. User clicks delete on a row.
2. Read metadata from `blob_index`.
3. `supabase.storage.from('private-blobs').remove([objectPath])`.
4. `supabase.from('blob_index').delete().eq('id', blobId)`.
5. Refresh file table.

## 4. File structure

```
shelf/
├── index.html              ← entire app
├── docs/
│   └── plans/
│       ├── 2026-02-27-shelf-design.md          ← this file
│       └── 2026-02-27-shelf-implementation.md  ← implementation plan
└── .nojekyll               ← tells GitHub Pages not to process with Jekyll
```

`index.html` contains:
- `<meta>` CSP tag
- `<style>` block (all CSS)
- HTML markup (login screen + main app)
- `<script src="...supabase-js@2">` (CDN)
- `<script>` block (all application JS)

## 5. UI design

### Login screen

Visible when no active Supabase session. Centered card with:

- App title: "Shelf"
- Email input (pre-filled or not)
- Password input
- Encryption passphrase input (type=password, separate from Supabase password)
- "Sign In" button
- Error message area (hidden by default)
- No sign-up link. No forgot-password link.

### Main app

Visible after authentication.

**Header bar**: "Shelf" title on left, "Sign Out" button on right.

**Drop zone**: Large dashed-border area. Text: "Drop files here or click to browse".
Accepts drag-and-drop and click-to-select. Shows selected file name, size, and type
before upload. "Upload" button. Status/error message area.

**File table**: Below the drop zone.

| Filename | Size | Uploaded | Actions |
|----------|------|----------|---------|
| notes.md | 2.1 KB | 2026-02-27 | [Download] [Delete] |

- Sorted newest first.
- Empty state: "No files yet. Drop one above."
- Download button triggers decrypt + browser download.
- Delete button triggers confirmation prompt → delete from Storage + DB.

## 6. Encryption design

### Algorithm

AES-GCM, 256-bit key, via Web Crypto API (`crypto.subtle`).

### Key derivation

```
passphrase (string)
  → TextEncoder.encode()
  → crypto.subtle.importKey("raw", ..., "PBKDF2", false, ["deriveKey"])
  → crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: FIXED_SALT, iterations: 100_000, hash: "SHA-256" },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,             // not extractable
      ["encrypt", "decrypt"]
    )
```

`FIXED_SALT`: A hardcoded 16-byte `Uint8Array` in the app source. Acceptable for
single-user; the passphrase provides the entropy. Changing the salt invalidates all
previously encrypted files, so it is intentionally fixed.

### Encrypted blob format

```
[ IV: 12 bytes ] [ ciphertext: variable length ]
```

The IV is generated fresh per file with `crypto.getRandomValues(new Uint8Array(12))`.

### Threat model

**Protected against**: Supabase data breach, DB dump, Storage bucket access by
unauthorized parties, Supabase employees, anyone without the passphrase.

**Not protected against**: An attacker who has the passphrase AND Supabase
credentials. XSS on the page while the key is in memory (mitigated by CSP).
A compromised CDN serving a malicious Supabase SDK (mitigated by SRI hash).

## 7. Supabase configuration

### Project details

- Project URL: `https://cxylcljlxdizvqlcioee.supabase.co`
- Publishable key: `sb_publishable_BhPS6OwiH31kIeF6GNyEAg_e0vMseib`

### Pre-requisites (manual dashboard setup)

1. **Create one user** in Auth → Users → Add user (email + password).
2. **Disable sign-ups** (optional): Auth → Settings → disable "Allow new users to sign up".
3. **Create bucket** `private-blobs`: Storage → New bucket, private, 10 MB limit,
   allowed MIME types: `text/plain`, `text/markdown`, `application/pdf`,
   `application/octet-stream`.
4. **Create table** `blob_index`:

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

5. **Enable RLS**:

```sql
alter table public.blob_index enable row level security;
```

6. **Table RLS policies**:

```sql
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

7. **Storage RLS policies**:

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

## 8. Security hardening

### Content Security Policy (meta tag)

```html
<meta http-equiv="Content-Security-Policy"
  content="
    default-src 'none';
    script-src 'self' https://cdn.jsdelivr.net;
    style-src 'self' 'unsafe-inline';
    connect-src https://cxylcljlxdizvqlcioee.supabase.co;
    img-src 'self';
    font-src 'none';
    object-src 'none';
    base-uri 'none';
    form-action 'none';
  ">
```

### XSS prevention

- All DOM writes use `textContent` or `createElement` + `setAttribute`.
- No `innerHTML`, no `document.write`, no `eval`.
- File names sanitized: `name.replace(/[^\w.\- ]+/g, '_')`.

### No secrets in client code

- Only the publishable/anon key appears in `index.html`.
- No `service_role` key, no Postgres connection string, no Neon keys.
- The publishable key is designed for browser use — RLS is the access control layer.

### Subresource Integrity

- The Supabase CDN `<script>` tag includes an `integrity` attribute (SRI hash)
  to detect CDN tampering.

### HTTPS

- GitHub Pages enforces HTTPS.
- All Supabase API calls go over HTTPS.

## 9. Error handling

- Auth errors: show message below login form (e.g., "Invalid credentials").
- Upload errors: show message below drop zone; if metadata insert fails after
  storage upload, attempt cleanup (delete the orphaned storage object).
- Download errors: show inline error on the file row.
- Delete errors: show inline error on the file row.
- Network errors: generic "Network error, try again" message.
- Encryption errors: "Decryption failed — wrong passphrase?" message.

## 10. Scope boundaries (YAGNI)

**In scope**:
- Login, upload, download, delete
- Client-side encryption/decryption
- File table with metadata
- GitHub Pages hosting

**Out of scope** (do not build):
- Sign-up flow
- Forgot password
- File previews
- File sharing / public links
- Folders / organization
- Search / filter
- Multiple users
- Offline mode
- Service worker / PWA
- Dark mode toggle
- Mobile-specific UI
- File versioning
- Resumable uploads (files ≤ 10 MB)
- Analytics / telemetry
