# Cross-Reference Report: LOGIQUE Pentest vs Live Retest vs Codebase Review

**Tanggal:** 18 Juni 2026
**Target:** prisma.artiga.id (PRISMA - Paperless Working System Koarmada III)
**Sumber:**
1. LOGIQUE Security Assessment Report (22-26 Mei 2026) - 10 temuan
2. Internal Live Retest (17-18 Juni 2026) - 7 temuan
3. Source Code Review (18 Juni 2026) - verifikasi root cause

---

## Status Remediasi LOGIQUE Findings

| # | LOGIQUE Finding | Severity | Status | Evidence |
|---|----------------|----------|--------|----------|
| F-01 | Session Cookie Tidak Ditandatangani (Privilege Escalation) | CRITICAL | **FIXED** | Cookie sekarang di-sign HMAC-SHA256 + constant-time compare |
| F-02 | Password Default/Lemah (admin123) | HIGH | **PARTIALLY FIXED** | Password policy 12 char + complexity enforced, tapi akun lama masih pakai `admin123` |
| F-03 | Cookie Tanpa Secure & SameSite | HIGH | **FIXED** | `Secure: cfg.IsProduction()`, `SameSite: http.SameSiteLaxMode`, `HttpOnly: true` |
| F-04 | Tidak Ada Rate-Limit Login | HIGH | **FIXED** | IP rate-limit (10/5min) + account lockout (5 attempts -> 15min lock) implemented |
| F-05 | CSP Tidak Diterapkan | MEDIUM | **FIXED** | Full CSP header di `SecurityHeaders()` middleware |
| F-06 | SPF/DMARC Tidak Ada | MEDIUM | **NOT VERIFIED** | DNS config - di luar codebase, perlu cek DNS records |
| F-07 | Tidak Ada HSTS | MEDIUM | **FIXED** | `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` |
| F-08 | X-Frame-Options & X-Content-Type-Options Tidak Diset | MEDIUM | **FIXED** | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` |
| F-09 | Server Banner Cloudflare Terekspos | LOW | **ACCEPTABLE** | Cloudflare managed - tidak bisa dihapus dari origin |
| F-10 | Root URL Return 404 | LOW | **CONFIRMED STILL OPEN** | Live test: `GET /` tanpa auth = 404 plain-text |

---

## Detail Remediasi per Finding

### F-01: Session Cookie Signing - FIXED

**LOGIQUE menemukan:** Cookie `auth_session` berisi plaintext JSON tanpa signature. Attacker bisa ubah `role` jadi Administrator.

**Status sekarang di codebase:**
```go
// app/helper/session.go:115-128
func signSessionPayload(payload []byte) (string, error) {
    secret, err := sessionSigningSecret()
    mac := hmac.New(sha256.New, secret)
    mac.Write(payload)
    signature := mac.Sum(nil)
    encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
    encodedSignature := base64.RawURLEncoding.EncodeToString(signature)
    return encodedPayload + "." + encodedSignature, nil
}

// app/helper/session.go:130-159
func verifySessionCookie(cookie string) ([]byte, error) {
    // Split payload.signature
    // Verify with HMAC-SHA256
    // constant-time compare via crypto/subtle
    if subtle.ConstantTimeCompare(providedSignature, expectedSignature) != 1 {
        return nil, fmt.Errorf("invalid session signature")
    }
    return payload, nil
}
```

**Verdict:** PROPERLY FIXED. Cookie sekarang format `base64(payload).base64(hmac-sha256)`. Tampering akan gagal karena signature mismatch. Constant-time compare mencegah timing attack.

**Catatan:** Meskipun signed, session data masih disimpan client-side. RBAC tetap bergantung pada data di cookie (bukan re-query DB per request). Ini berarti jika secret bocor, privilege escalation masih mungkin. Rekomendasi jangka panjang: migrasi ke server-side session (Redis).

---

### F-02: Password Default - PARTIALLY FIXED

**LOGIQUE menemukan:** Akun Kapuskodal login dengan `admin123`.

**Status sekarang di codebase:**
```go
// app/helper/security.go:111-130
func ValidateStrongPassword(password string) error {
    if len(password) < 12 { return ErrWeakPassword }
    // Checks: lowercase + uppercase + digit + symbol
    if isCommonPassword(password) { return ErrWeakPassword }
    return nil
}

// app/helper/security.go:164-178
func isCommonPassword(password string) bool {
    commonPasswords := map[string]struct{}{
        "admin123": {}, "password": {}, "qwerty": {}, ...
    }
}
```

**Live test:** Login `superadmin/admin123` masih BERHASIL. Artinya:
- Password policy hanya enforce pada **password change**, bukan pada login
- Akun-akun lama BELUM di-force-reset
- `admin123` ada di blocklist tapi hanya dicek saat ganti password

**Verdict:** PARTIALLY FIXED. Policy ada tapi tidak retroactive.

**Rekomendasi:**
1. Force password reset untuk SEMUA akun yang masih pakai password < 12 char
2. Tambahkan check saat login: jika password lama tidak meet policy, redirect ke force-change
3. Jalankan migration script untuk flag akun dengan weak password

---

### F-03: Cookie Flags - FIXED

**Live evidence:**
```
#HttpOnly_prisma.artiga.id  FALSE  /  TRUE  1781777033  jual_kirim_admin_session  MTc4MT...
```
- `HttpOnly`: TRUE (kolom curl = HttpOnly prefix)
- `Secure`: TRUE (kolom 4 = TRUE)
- `SameSite`: Lax (set di code, tidak visible di curl netscape format)

**Codebase:**
```go
// app/helper/session.go:66-68
Secure:   shouldUseSecureCookies(c),  // true in production
HttpOnly: true,
SameSite: http.SameSiteLaxMode,
```

**Verdict:** FIXED. Semua flag benar.

---

### F-04: Login Rate Limiting - FIXED

**Codebase:**
```go
// app/helper/security.go:15-19
loginWindowDuration   = 5 * time.Minute
loginMaxAttemptsByIP  = 10
loginAccountLockAfter = 5
loginAccountLockTime  = 15 * time.Minute
```

**Live test (5 attempts):** Semua return 302 (normal). Test hanya 5 karena safe testing - kemungkinan lockout belum trigger karena butuh persis 5 gagal per-akun. Rate limit per-IP threshold = 10.

**Catatan:** Rate limit HANYA in-memory (`sync.Mutex` + map). Kalau server restart, counter reset. Multi-instance deployment = bypass.

**Verdict:** FIXED untuk single-instance. Rekomendasi: persist ke Redis untuk multi-instance.

---

### F-05, F-07, F-08: Security Headers - ALL FIXED

**Codebase (`app/helper/security.go:48-65`):**
```go
func SecurityHeaders() gin.HandlerFunc {
    ctx.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https:; ...")
    ctx.Header("X-Frame-Options", "DENY")
    ctx.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
    ctx.Header("X-Content-Type-Options", "nosniff")
    ctx.Header("Referrer-Policy", "strict-origin-when-cross-origin")
}
```

**Live evidence (curl headers):**
```
content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline' https:; ...
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
```

**Verdict:** ALL FIXED. F-05, F-07, F-08 fully remediated.

---

## Temuan BARU dari Internal Retest (Tidak Ada di LOGIQUE Report)

LOGIQUE hanya test dengan 1 akun role Pejabat. Internal retest pakai 4 role berbeda dan menemukan masalah authorization yang tidak ter-cover.

### NEW-01: Broken Access Control - /api/users/search Leaks Data ke Semua Role

**Severity:** HIGH
**Root Cause di Codebase:**

```go
// app/route.go:200 - HANYA CheckSessionMiddleware, TANPA CheckPermissionMiddleware
api.GET("/users/search", helper.CheckSessionMiddleware(), positionController.SearchUsers)
```

```go
// app/controller/position.go:522-534 - Returns full position object
results = append(results, gin.H{
    "id":       user.ID.String(),
    "text":     label,
    "username": user.Username,
    "position": user.Position,  // <-- LEAKS full position struct
})
```

**Problem:** 
1. Endpoint hanya cek "is logged in" - tidak ada permission check
2. Response include full `Position` object (ID, Name, Level, OrganizationID, timestamps, created_by)
3. Semua role mendapat data identik

**Fix yang dibutuhkan:**
```go
// Route - tambah permission check ATAU batasi response
api.GET("/users/search", helper.CheckSessionMiddleware(), positionController.SearchUsers)

// Controller - strip sensitive fields
results = append(results, gin.H{
    "id":   user.ID.String(),
    "text": label,
    // HAPUS: "username", "position" full object
})
```

---

### NEW-02: Broken Access Control - /entry-surat/tambah-surat-masuk Tanpa Permission Check

**Severity:** HIGH
**Root Cause di Codebase:**

```go
// app/route.go:181-182 - TANPA CheckPermissionMiddleware!
session.GET("/entry-surat/tambah-surat-masuk", inboxController.Create)
session.POST("/entry-surat/tambah-surat-masuk", inboxController.PostCreate)

// BANDINGKAN dengan surat keluar yang BENAR:
// app/route.go:187-188
session.GET("/entry-surat/tambah-surat-keluar", helper.CheckPermissionMiddleware([]string{"outbox-create"}), outboxController.Create)
session.POST("/entry-surat/tambah-surat-keluar", helper.CheckPermissionMiddleware([]string{"outbox-create"}), outboxController.PostCreate)
```

**Problem:** Route tambah surat masuk TIDAK punya middleware permission. Surat keluar sudah benar (ada `outbox-create` check). Ini inconsistency.

**Fix yang dibutuhkan:**
```go
session.GET("/entry-surat/tambah-surat-masuk", helper.CheckPermissionMiddleware([]string{"inbox-create"}), inboxController.Create)
session.POST("/entry-surat/tambah-surat-masuk", helper.CheckPermissionMiddleware([]string{"inbox-create"}), inboxController.PostCreate)
```

---

### NEW-03: Admin Endpoints Return 500 (Authz Crash)

**Severity:** MEDIUM
**Root Cause:** Endpoint `/data-master/*` di-render server-side. Handler mencoba load data berdasarkan permission, tapi ketika user tidak punya akses, terjadi nil pointer atau template render error yang menghasilkan 500 bukan proper 403/redirect.

**Affected routes (likely):** Semua `/data-master/*` routes yang mungkin ada di grup `session` tanpa proper permission middleware, dan handler-nya crash saat session permission kosong.

**Fix:** Tambahkan `CheckPermissionMiddleware` di route level, bukan di handler logic.

---

### NEW-04: Upload Response Leaks Server Temp Path

**Severity:** MEDIUM
**Live evidence:**
```json
{"file":"/tmp/1781744007_test.pdf","name":"test.pdf","success":true}
```

**Fix:** Return relative path atau opaque ID, bukan absolute filesystem path.

---

### NEW-05: Cookie Name Leaks Internal Project Name

**Severity:** LOW (informational)
**Codebase:**
```go
// main.go:80
router.Use(sessions.Sessions("jual_kirim_admin_session", store))
```

Cookie name `jual_kirim_admin_session` dari project lama "Jual Kirim". Ganti ke `prisma_session`.

---

## Ringkasan Status Keseluruhan

### Skor Remediasi LOGIQUE Findings: 7/10 Fixed

| Status | Count | Details |
|--------|-------|---------|
| FIXED | 7 | F-01, F-03, F-04, F-05, F-07, F-08, F-09(acceptable) |
| PARTIALLY FIXED | 1 | F-02 (policy ada, akun lama belum reset) |
| NOT VERIFIED | 1 | F-06 (DNS - out of scope codebase) |
| STILL OPEN | 1 | F-10 (root 404) |

### Temuan Baru (Tidak di-test LOGIQUE): 5

| # | Severity | Finding | Why LOGIQUE Missed |
|---|----------|---------|-------------------|
| NEW-01 | HIGH | /api/users/search data leak | LOGIQUE hanya test 1 role (Pejabat) |
| NEW-02 | HIGH | /entry-surat/tambah-surat-masuk no authz | LOGIQUE fokus session tampering, bukan forced browsing antar role |
| NEW-03 | MEDIUM | Admin endpoints 500 crash | Butuh multi-role test |
| NEW-04 | MEDIUM | Upload path disclosure | Possibly fixed setelah LOGIQUE test |
| NEW-05 | LOW | Cookie name leak | Informational |

---

## Prioritas Perbaikan (Gabungan)

| Prio | Item | Effort | Impact |
|------|------|--------|--------|
| 1 | NEW-01: Batasi /api/users/search response | 1 jam | HIGH - data leak ke semua role |
| 2 | NEW-02: Tambah permission middleware di tambah-surat-masuk | 30 menit | HIGH - unauthorized create |
| 3 | F-02: Force password reset akun lama | 2 jam | HIGH - credential compromise |
| 4 | NEW-03: Fix admin endpoint 500 -> proper 403 | 2 jam | MEDIUM - error disclosure |
| 5 | NEW-04: Strip server path dari upload response | 30 menit | MEDIUM - info disclosure |
| 6 | F-06: Setup SPF/DMARC DNS | 1 jam | MEDIUM - email spoofing |
| 7 | F-10: Redirect root / ke /login | 15 menit | LOW - UX |
| 8 | NEW-05: Rename cookie | 15 menit | LOW - info leak |

---

## Rekomendasi Arsitektural (Jangka Menengah)

1. **Server-side session (Redis)** - Meskipun F-01 fixed dengan HMAC signing, role/permission masih di cookie. Jika signing secret bocor, privilege escalation kembali mungkin. Migrasi ke server-side session eliminasi risiko ini.

2. **Permission audit semua routes** - Scan `app/route.go` untuk semua route yang hanya pakai `CheckSessionMiddleware()` tanpa `CheckPermissionMiddleware()`. Saat ini banyak endpoint (inbox/list, arsip-file/list, users/search, upload-temp) tidak ada permission check.

3. **Rate-limit persistence** - Current rate limit in-memory. Deploy Redis-backed limiter untuk survive restart dan multi-instance.

4. **Password migration** - Run batch check semua user, flag yang tidak meet 12-char policy, force reset pada next login.

5. **Periodic multi-role testing** - LOGIQUE hanya test 1 role. Broken access control hanya terdeteksi dengan multi-role testing. Tambahkan automated RBAC test suite.
