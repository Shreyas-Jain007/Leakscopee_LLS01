#include "util.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- allocation ------------------------------------------------------------ */
void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) die("out of memory");
    return p;
}

void *xcalloc(size_t n, size_t sz) {
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p) die("out of memory");
    return p;
}

void *xrealloc(void *p, size_t n) {
    p = realloc(p, n ? n : 1);
    if (!p) die("out of memory");
    return p;
}

char *xstrdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *d = xmalloc(n);
    memcpy(d, s, n);
    return d;
}

char *xasprintf(const char *fmt, ...) {
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) die("formatting error");
    char *s = xmalloc((size_t)n + 1);
    vsnprintf(s, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    return s;
}

void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("leakscope: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(2);
}

/* ---- bytes ----------------------------------------------------------------- */
Bytes bytes_new(size_t len) {
    Bytes b = { xcalloc(len ? len : 1, 1), len };
    return b;
}

Bytes bytes_copy(const uint8_t *src, size_t len) {
    Bytes b = bytes_new(len);
    if (len) memcpy(b.data, src, len);
    return b;
}

Bytes bytes_dup(Bytes b) { return bytes_copy(b.data, b.len); }

bool bytes_eq(Bytes a, Bytes b) {
    return a.len == b.len && (a.len == 0 || memcmp(a.data, b.data, a.len) == 0);
}

void bytes_free(Bytes *b) {
    free(b->data);
    b->data = NULL;
    b->len = 0;
}

char *bytes_hex(const uint8_t *p, size_t n) {
    static const char hx[] = "0123456789abcdef";
    char *s = xmalloc(n * 2 + 1);
    for (size_t i = 0; i < n; i++) {
        s[2 * i] = hx[p[i] >> 4];
        s[2 * i + 1] = hx[p[i] & 15];
    }
    s[n * 2] = 0;
    return s;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool hex_decode(const char *s, Bytes *out) {
    /* bytes.fromhex() tolerates whitespace between byte pairs. */
    size_t n = strlen(s);
    Bytes b = bytes_new(n / 2 + 1);
    size_t k = 0;
    for (size_t i = 0; i < n;) {
        if (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') { i++; continue; }
        if (i + 1 >= n) { bytes_free(&b); return false; }
        int hi = hexval(s[i]), lo = hexval(s[i + 1]);
        if (hi < 0 || lo < 0) { bytes_free(&b); return false; }
        b.data[k++] = (uint8_t)(hi << 4 | lo);
        i += 2;
    }
    b.len = k;
    *out = b;
    return true;
}

int bit_length_u64(uint64_t v) { return v ? 64 - __builtin_clzll(v) : 0; }

/* ---- Python-compatible MT19937 -------------------------------------------- */
#define MT_N 624
#define MT_M 397

static void mt_init_genrand(PyRandom *r, uint32_t s) {
    r->mt[0] = s;
    for (int i = 1; i < MT_N; i++)
        r->mt[i] = 1812433253u * (r->mt[i - 1] ^ (r->mt[i - 1] >> 30)) + (uint32_t)i;
    r->mti = MT_N;
}

void pyrandom_seed(PyRandom *r, uint64_t seed) {
    /* CPython: key = 32-bit little-endian words of abs(seed) ([0] for 0). */
    uint32_t key[2];
    int klen = 0;
    key[klen++] = (uint32_t)seed;
    if (seed >> 32) key[klen++] = (uint32_t)(seed >> 32);

    mt_init_genrand(r, 19650218u);
    int i = 1, j = 0;
    for (int k = (MT_N > klen ? MT_N : klen); k; k--) {
        r->mt[i] = (r->mt[i] ^ ((r->mt[i - 1] ^ (r->mt[i - 1] >> 30)) * 1664525u))
                   + key[j] + (uint32_t)j;
        i++; j++;
        if (i >= MT_N) { r->mt[0] = r->mt[MT_N - 1]; i = 1; }
        if (j >= klen) j = 0;
    }
    for (int k = MT_N - 1; k; k--) {
        r->mt[i] = (r->mt[i] ^ ((r->mt[i - 1] ^ (r->mt[i - 1] >> 30)) * 1566083941u))
                   - (uint32_t)i;
        i++;
        if (i >= MT_N) { r->mt[0] = r->mt[MT_N - 1]; i = 1; }
    }
    r->mt[0] = 0x80000000u;
    r->mti = MT_N;
}

uint32_t pyrandom_u32(PyRandom *r) {
    static const uint32_t mag01[2] = { 0u, 0x9908b0dfu };
    uint32_t y;
    if (r->mti >= MT_N) {
        int kk;
        for (kk = 0; kk < MT_N - MT_M; kk++) {
            y = (r->mt[kk] & 0x80000000u) | (r->mt[kk + 1] & 0x7fffffffu);
            r->mt[kk] = r->mt[kk + MT_M] ^ (y >> 1) ^ mag01[y & 1];
        }
        for (; kk < MT_N - 1; kk++) {
            y = (r->mt[kk] & 0x80000000u) | (r->mt[kk + 1] & 0x7fffffffu);
            r->mt[kk] = r->mt[kk + (MT_M - MT_N)] ^ (y >> 1) ^ mag01[y & 1];
        }
        y = (r->mt[MT_N - 1] & 0x80000000u) | (r->mt[0] & 0x7fffffffu);
        r->mt[MT_N - 1] = r->mt[MT_M - 1] ^ (y >> 1) ^ mag01[y & 1];
        r->mti = 0;
    }
    y = r->mt[r->mti++];
    y ^= (y >> 11);
    y ^= (y << 7) & 0x9d2c5680u;
    y ^= (y << 15) & 0xefc60000u;
    y ^= (y >> 18);
    return y;
}

uint32_t pyrandom_randrange(PyRandom *r, uint32_t n) {
    /* CPython _randbelow_with_getrandbits: k = n.bit_length(); rejection-sample
     * getrandbits(k), which for k <= 32 is the top k bits of one output. */
    int k = bit_length_u64(n);
    uint32_t v;
    do {
        v = k >= 32 ? pyrandom_u32(r) : pyrandom_u32(r) >> (32 - k);
    } while (v >= n);
    return v;
}

/* ---- u64 hash set ---------------------------------------------------------- */
static size_t mix64(uint64_t k) {
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdull;
    k ^= k >> 33;
    return (size_t)k;
}

void u64set_init(U64Set *s) {
    s->cap = 256;
    s->keys = xcalloc(s->cap, sizeof(uint64_t));
    s->used = xcalloc(s->cap, 1);
    s->live = s->filled = 0;
}

void u64set_free(U64Set *s) {
    free(s->keys);
    free(s->used);
    memset(s, 0, sizeof(*s));
}

static void u64set_grow(U64Set *s) {
    U64Set n;
    n.cap = s->live * 4 > 256 ? s->live * 4 : 256;
    /* keep capacity a power of two */
    size_t c = 1;
    while (c < n.cap) c <<= 1;
    n.cap = c;
    n.keys = xcalloc(n.cap, sizeof(uint64_t));
    n.used = xcalloc(n.cap, 1);
    n.live = n.filled = 0;
    for (size_t i = 0; i < s->cap; i++)
        if (s->used[i] == 1) u64set_add(&n, s->keys[i]);
    u64set_free(s);
    *s = n;
}

bool u64set_has(const U64Set *s, uint64_t k) {
    size_t m = s->cap - 1, i = mix64(k) & m;
    while (s->used[i]) {
        if (s->used[i] == 1 && s->keys[i] == k) return true;
        i = (i + 1) & m;
    }
    return false;
}

void u64set_add(U64Set *s, uint64_t k) {
    if ((s->filled + 1) * 2 > s->cap) u64set_grow(s);
    size_t m = s->cap - 1, i = mix64(k) & m;
    size_t tomb = (size_t)-1;
    while (s->used[i]) {
        if (s->used[i] == 1 && s->keys[i] == k) return;
        if (s->used[i] == 2 && tomb == (size_t)-1) tomb = i;
        i = (i + 1) & m;
    }
    if (tomb != (size_t)-1) {
        i = tomb;
    } else {
        s->filled++;
    }
    s->used[i] = 1;
    s->keys[i] = k;
    s->live++;
}

void u64set_del(U64Set *s, uint64_t k) {
    size_t m = s->cap - 1, i = mix64(k) & m;
    while (s->used[i]) {
        if (s->used[i] == 1 && s->keys[i] == k) {
            s->used[i] = 2;
            s->live--;
            return;
        }
        i = (i + 1) & m;
    }
}

/* ---- paths ------------------------------------------------------------------ */
static char *normpath(const char *p) {
    bool abs = p[0] == '/';
    size_t n = strlen(p);
    char *buf = xstrdup(p);
    const char **parts = xmalloc((n + 1) * sizeof(char *));
    size_t np = 0;
    for (char *tok = strtok(buf, "/"); tok; tok = strtok(NULL, "/")) {
        if (strcmp(tok, ".") == 0) continue;
        if (strcmp(tok, "..") == 0) {
            if (np && strcmp(parts[np - 1], "..") != 0) { np--; continue; }
            if (abs) continue;
        }
        parts[np++] = tok;
    }
    char *out = xmalloc(n + 3);
    size_t k = 0;
    if (abs) out[k++] = '/';
    for (size_t i = 0; i < np; i++) {
        if (i) out[k++] = '/';
        size_t l = strlen(parts[i]);
        memcpy(out + k, parts[i], l);
        k += l;
    }
    if (k == 0) out[k++] = '.';
    out[k] = 0;
    free(parts);
    free(buf);
    return out;
}

char *path_abspath(const char *p) {
    if (p[0] == '/') return normpath(p);
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd)) die("getcwd: %s", strerror(errno));
    char *j = path_join(cwd, p);
    char *r = normpath(j);
    free(j);
    return r;
}

char *path_dirname(const char *p) {
    const char *s = strrchr(p, '/');
    if (!s) return xstrdup("");
    size_t n = (size_t)(s - p);
    /* keep a lone leading "/" */
    while (n > 1 && p[n - 1] == '/') n--;
    if (n == 0) n = 1;
    char *d = xmalloc(n + 1);
    memcpy(d, p, n);
    d[n] = 0;
    return d;
}

char *path_join(const char *a, const char *b) {
    if (b[0] == '/' || a[0] == 0) return xstrdup(b);
    size_t la = strlen(a);
    return xasprintf("%s%s%s", a, a[la - 1] == '/' ? "" : "/", b);
}

const char *path_basename(const char *p) {
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

char *read_file(const char *path, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 4096, len = 0;
    char *buf = xmalloc(cap);
    for (;;) {
        if (len + 4096 + 1 > cap) { cap *= 2; buf = xrealloc(buf, cap); }
        size_t r = fread(buf + len, 1, cap - len - 1, f);
        len += r;
        if (r == 0) break;
    }
    int err = ferror(f);
    fclose(f);
    if (err) { free(buf); return NULL; }
    buf[len] = 0;
    if (len_out) *len_out = len;
    return buf;
}
