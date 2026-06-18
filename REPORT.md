# Laporan Pentest: PRISMA (prisma.artiga.id)
## Paperless Working System Koarmada III

**Tanggal:** 18 Juni 2026
**Target:** https://prisma.artiga.id
**Scope:** Single domain, owned application
**Tester:** Automated pentest pipeline
**Identifying Header:** X-Bug-Bounty: 9a8e2b69

---

## Ringkasan Eksekutif

Pengujian keamanan dilakukan pada aplikasi PRISMA (Paperless Working System Koarmada III) di `prisma.artiga.id`. Aplikasi ini berbasis Go backend dengan template Mantis Bootstrap 5, di-deploy di balik Cloudflare.

Ditemukan **7 temuan keamanan** dengan rincian:
- **HIGH:** 2
- **MEDIUM:** 3
- **LOW:** 2

Aplikasi memiliki fondasi keamanan yang baik (CSRF protection, auth redirect, security headers, file type validation), namun ada kelemahan signifikan pada **authorization/access control** antar role dan **information disclosure**.

---

## Temuan Berdasarkan Severity

---

### [HIGH-01] Broken Access Control - API User Search Tanpa Filter Role

**Severity:** HIGH
**CWE:** CWE-862 (Missing Authorization)
**Endpoint:** `GET /api/users/search?q=`

**Deskripsi:**
Endpoint `/api/users/search` mengembalikan data seluruh user ke SEMUA role termasuk `staf` (role terendah). Tidak ada pembedaan akses - staf mendapat response identik (6618 bytes) dengan superadmin.

**Data yang bocor:**
- UUID seluruh user (`id`)
- Username
- Position (jabatan, level, organization_id)
- Timestamps internal (`created_at`, `updated_at`, `created_by`)
- Organization structure dan hierarchy level

**PoC:**
```bash
# Login sebagai staf, lalu:
curl -s "https://prisma.artiga.id/api/users/search?q=" \
  -H "Cookie: jual_kirim_admin_session=<STAF_SESSION>"
```

**Response (dipotong):**
```json
{"results":[
  {"id":"d29c1a6c-47c3-4d15-ac1d-385439c6d1cb","text":"Superadmin","username":"Superadmin"},
  {"id":"c3c93c6a-...",
   "position":{"id":"2a5d77fc-...","name":"SETUM KOARMADA III","level":6,
   "organization_id":"1e0d1375-...","created_by":"d29c1a6c-..."},
   "text":"Setum1","username":"Setum1"},
  ...
]}
```

**Dampak:**
- Penyerang dengan akun staf bisa memetakan seluruh struktur organisasi
- UUID user bisa digunakan untuk serangan IDOR lebih lanjut
- Internal timestamps membocorkan kapan user dibuat/dimodifikasi

**Rekomendasi:**
1. Batasi endpoint ini hanya untuk role `superadmin` atau role yang membutuhkan
2. Filter field yang dikembalikan - hanya `id` dan `text` untuk autocomplete, hapus `position`, `organization_id`, `created_at`, `created_by`
3. Implementasi row-level filtering berdasarkan scope user yang login

```go
// Contoh fix di handler
func (h *Handler) SearchUsers(c *gin.Context) {
    currentUser := auth.GetCurrentUser(c)
    if !currentUser.HasPermission("users.search.full") {
        // Return hanya id + display name
        results := h.userService.SearchMinimal(q, currentUser.OrganizationID)
        c.JSON(200, gin.H{"results": results})
        return
    }
    // ... full results untuk admin
}
```

---

### [HIGH-02] Broken Access Control - Forced Browsing ke Form Surat Masuk

**Severity:** HIGH
**CWE:** CWE-285 (Improper Authorization)
**Endpoint:** `GET /entry-surat/tambah-surat-masuk`

**Deskripsi:**
Halaman `/entry-surat/tambah-surat-masuk` tidak ada di menu navigasi untuk role non-admin, tetapi bisa diakses langsung (forced browsing) oleh SEMUA role yang login. Halaman ini menampilkan form lengkap untuk menambah surat masuk termasuk file upload.

**Access Matrix:**
| Role | Menu Visible | Direct Access | Status |
|------|-------------|---------------|--------|
| superadmin | Ya | 200 (154KB) | Expected |
| pangkoarmada | Tidak | 200 (151KB) | **BUG** |
| kadisinfolahta | Tidak | 200 (151KB) | **BUG** |
| staf | Tidak | 200 (151KB) | **BUG** |

**PoC:**
```bash
# Login sebagai staf, akses langsung:
curl -s -o /dev/null -w "%{http_code}" \
  "https://prisma.artiga.id/entry-surat/tambah-surat-masuk" \
  -H "Cookie: jual_kirim_admin_session=<STAF_SESSION>"
# Response: 200 (halaman form lengkap)
```

**Dampak:**
- User non-admin bisa membuat surat masuk tanpa otorisasi
- Bypass workflow approval yang seharusnya membatasi siapa boleh entry surat
- Form termasuk file upload yang bisa disalahgunakan

**Rekomendasi:**
1. Tambahkan middleware authorization check per-route, bukan hanya hide menu di frontend
2. Implementasi role-based access control (RBAC) di level router/handler

```go
// Contoh middleware
func RequirePermission(perm string) gin.HandlerFunc {
    return func(c *gin.Context) {
        user := auth.GetCurrentUser(c)
        if !user.HasPermission(perm) {
            c.Redirect(302, "/dashboard")
            c.Abort()
            return
        }
        c.Next()
    }
}

// Router
r.GET("/entry-surat/tambah-surat-masuk", RequirePermission("surat.create"), handler.TambahSuratMasuk)
```

---

### [MEDIUM-01] Broken Access Control - Admin Endpoints Return 500 Instead of 403

**Severity:** MEDIUM
**CWE:** CWE-280 (Improper Handling of Insufficient Permissions)
**Endpoints:** `/data-master/users`, `/data-master/role`, `/data-master/jabatan`, `/security/malware`, `/report/surat-keluar`

**Deskripsi:**
Saat user non-admin mengakses endpoint admin, server mengembalikan **HTTP 500 Internal Server Error** dengan body kosong (0 bytes), bukan 403 Forbidden atau redirect. Ini menandakan authorization check dilakukan dengan cara yang menyebabkan crash/panic, bukan proper denial.

**Access Matrix (non-superadmin roles):**
| Endpoint | Expected | Actual |
|----------|----------|--------|
| /data-master/users | 403 atau redirect | 500 (0b) |
| /data-master/role | 403 atau redirect | 500 (0b) |
| /data-master/jabatan | 403 atau redirect | 500 (0b) |
| /security/malware | 403 atau redirect | 500 (0b) |
| /report/surat-keluar | 403 atau redirect | 500 (0b) |

**Dampak:**
- Information disclosure: penyerang tahu endpoint itu ada (500 vs 404)
- Kemungkinan unhandled panic di Go yang bisa mengekspos stack trace di production log
- Bisa dieksploitasi untuk resource exhaustion jika panic handler lambat

**Rekomendasi:**
1. Authorization check harus dilakukan SEBELUM logic handler, bukan di dalamnya
2. Return 403 atau redirect ke dashboard, bukan panic
3. Cek error handling - kemungkinan nil pointer dereference saat cek role

---

### [MEDIUM-02] Information Disclosure - Upload Response Leaks Server Path

**Severity:** MEDIUM
**CWE:** CWE-200 (Exposure of Sensitive Information)
**Endpoint:** `POST /api/inbox/upload-temp`

**Deskripsi:**
Response upload mengembalikan path filesystem server di field `file`.

**PoC:**
```bash
curl -s "https://prisma.artiga.id/api/inbox/upload-temp" \
  -X POST -H "X-CSRF-Token: <token>" \
  -b "jual_kirim_admin_session=<session>" \
  -F "file=@test.pdf"
```

**Response:**
```json
{"file":"/tmp/1781744007_test.pdf","name":"test.pdf","success":true}
```

**Dampak:**
- Path `/tmp/` mengkonfirmasi OS Linux dan temporary file location
- Timestamp di filename (`1781744007`) membocorkan server time
- Informasi ini membantu penyerang merencanakan serangan path traversal

**Rekomendasi:**
1. Return hanya file ID atau relative reference, bukan absolute path
2. Contoh response yang aman: `{"id": "abc123", "name": "test.pdf", "success": true}`

---

### [MEDIUM-03] Session Cookie Missing SameSite Attribute

**Severity:** MEDIUM
**CWE:** CWE-1275 (Sensitive Cookie with Improper SameSite Attribute)
**Cookie:** `jual_kirim_admin_session`

**Deskripsi:**
Session cookie dikirim tanpa attribute `SameSite`. Meskipun browser modern default ke `Lax`, ini sebaiknya di-set eksplisit.

**Cookie flags saat ini:**
- HttpOnly: Ya (baik)
- Secure: Ya (baik)
- SameSite: **Tidak di-set** (kurang)
- Path: / (OK)

**Rekomendasi:**
```go
// Di session configuration
store.Options = &sessions.Options{
    Path:     "/",
    MaxAge:   86400,
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteStrictMode, // Tambahkan ini
}
```

---

### [LOW-01] Information Disclosure - Session Cookie Name Leaks Internal Project Name

**Severity:** LOW
**CWE:** CWE-200 (Information Exposure)

**Deskripsi:**
Session cookie bernama `jual_kirim_admin_session` yang mengindikasikan nama project internal ("jual kirim"). Ini tidak sesuai dengan aplikasi PRISMA dan membocorkan bahwa codebase di-reuse dari project lain.

**Rekomendasi:**
Ganti nama cookie menjadi generic: `prisma_session` atau `__Host-session`

---

### [LOW-02] No Login Rate Limiting

**Severity:** LOW
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)

**Deskripsi:**
5 percobaan login gagal berturut-turut tidak menghasilkan lockout, delay, atau CAPTCHA. Semua mengembalikan 302 redirect (normal failed login flow).

**Catatan mitigasi:** Cloudflare mungkin memberikan rate limiting di layer atasnya, dan password policy server-side sudah mensyaratkan min 6 karakter + kombinasi huruf besar/kecil/angka/simbol. Namun application-level rate limiting tetap disarankan.

**Rekomendasi:**
1. Implementasi rate limit: max 5 attempts per 15 menit per IP/username
2. Setelah 10 gagal: temporary lockout 30 menit
3. Tambahkan CAPTCHA setelah 3 gagal

---

## Hal yang AMAN (Tidak Ditemukan Bug)

| Area | Status | Detail |
|------|--------|--------|
| Authentication | AMAN | Semua endpoint redirect ke /login tanpa cookie |
| CSRF Protection | AMAN | Token validated di semua POST, 400 pada token invalid/kosong/salah |
| XSS (Reflected) | AMAN | Input di-escape, tidak ada refleksi di /api/users/search |
| SQL Injection | AMAN | Parameterized query, time-based test 0.35s (no delay) |
| File Upload Types | AMAN | Hanya .pdf/.docx/.xlsx/.jpg/.jpeg/.png/.gif/.bmp/.webp diterima, SVG/HTML/PHP ditolak |
| Security Headers | AMAN | CSP, HSTS (preload), X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy |
| Exposed Paths | AMAN | /.env, /.git/config, /swagger.json, /actuator, /phpinfo semua 404 |
| CORS | AMAN | Tidak ada Access-Control-Allow-Origin header pada evil origin |
| Open Redirect | AMAN | /login?next= tidak di-redirect ke external |
| Password Policy | AMAN | Min 6 karakter, wajib kombinasi huruf besar/kecil/angka/simbol (server-side validated) |
| API Unauth | AMAN | Semua /api/* endpoint return 302 tanpa session |
| WebSocket | AMAN | 302 tanpa auth, 403 untuk role non-authorized |

---

## Stack Teknis Teridentifikasi

| Komponen | Detail |
|----------|--------|
| Backend | Go (gorilla/sessions) |
| Frontend | Mantis Bootstrap 5 Admin Template |
| CDN/WAF | Cloudflare |
| Database | PostgreSQL (inferred dari pg_sleep test response) |
| Session | Cookie-based, gorilla/securecookie |
| JS Libraries | jQuery 3.6.0, DataTables 1.13.7, SweetAlert2, jQuery Validate, ApexCharts |
| Realtime | WebSocket at /ws |

---

## Prioritas Perbaikan

| Prioritas | Finding | Estimasi Effort |
|-----------|---------|----------------|
| 1 (segera) | HIGH-01: API user search leaks data | 2-4 jam |
| 2 (segera) | HIGH-02: Forced browsing tambah surat | 1-2 jam |
| 3 (minggu ini) | MEDIUM-01: 500 instead of 403 | 2-3 jam |
| 4 (minggu ini) | MEDIUM-02: Upload path leak | 30 menit |
| 5 (minggu ini) | MEDIUM-03: SameSite cookie | 15 menit |
| 6 (sprint ini) | LOW-01: Cookie name | 15 menit |
| 7 (sprint ini) | LOW-02: Login rate limit | 2-3 jam |

---

## Effort Log

- **Akun diuji:** 4 (superadmin, pangkoarmada, kadisinfolahta, staf disinfolahta)
- **Endpoint di-crawl:** 16 pages + 12 API endpoints
- **Access matrix:** 4 roles x 8 restricted endpoints = 32 combinations tested
- **Upload tests:** 5 file types (pdf, php, html, svg, double-ext)
- **Injection tests:** SQLi (boolean + time-based), XSS (reflected), CSRF bypass (3 methods)
- **Auth tests:** Session fixation, login rate limit (5 attempts), password policy (weak passwords)
- **Infrastructure:** Exposed paths (12 paths), CORS, open redirect, WebSocket auth, security headers
- **Mobile:** N/A (no mobile app in scope)
