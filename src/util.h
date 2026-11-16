/* Small shared utilities: allocation, growable vectors, byte strings, a
 * Python-compatible Mersenne Twister, a u64 hash set, and path helpers. */
#ifndef LEAKSCOPE_UTIL_H
#define LEAKSCOPE_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---- allocation (abort on OOM) ------------------------------------------ */
void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t sz);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);
char *xasprintf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Print "leakscope: <msg>" to stderr and exit(2). */
void die(const char *fmt, ...) __attribute__((format(printf, 1, 2), noreturn));

/* ---- growable vector ------------------------------------------------------
 *   VEC(int) v = {0};  VEC_PUSH(&v, 3);  v.data[0];  VEC_FREE(&v);         */
#define VEC(T) struct { T *data; size_t len, cap; }
#define VEC_PUSH(v, x)                                                        \
    do {                                                                      \
        if ((v)->len == (v)->cap) {                                           \
            (v)->cap = (v)->cap ? (v)->cap * 2 : 16;                          \
            (v)->data = xrealloc((v)->data, (v)->cap * sizeof(*(v)->data));   \
        }                                                                     \
        (v)->data[(v)->len++] = (x);                                          \
    } while (0)
#define VEC_FREE(v) do { free((v)->data); (v)->data = NULL; (v)->len = (v)->cap = 0; } while (0)

/* ---- byte strings (the secret vector) ------------------------------------ */
typedef struct {
    uint8_t *data;
    size_t len;
} Bytes;

Bytes bytes_new(size_t len);                 /* zero-filled */
Bytes bytes_copy(const uint8_t *src, size_t len);
Bytes bytes_dup(Bytes b);
bool bytes_eq(Bytes a, Bytes b);
void bytes_free(Bytes *b);
char *bytes_hex(const uint8_t *p, size_t n); /* lowercase hex, malloc'd */
/* Parse a hex string; returns false on malformed input. */
bool hex_decode(const char *s, Bytes *out);

typedef VEC(Bytes) BytesVec;
typedef VEC(uint64_t) U64Vec;

/* ---- integers ------------------------------------------------------------ */
int bit_length_u64(uint64_t v);              /* Python int.bit_length() */

/* ---- Mersenne Twister, bit-compatible with CPython's random.Random -------
 * random.Random(seed) for a non-negative integer seed, and randrange(n) for
 * n <= 2^32, produce exactly the same stream as here, so sample sets (and
 * therefore witnesses) match the original Python LeakScope byte for byte.   */
typedef struct {
    uint32_t mt[624];
    int mti;
} PyRandom;

void pyrandom_seed(PyRandom *r, uint64_t seed);
uint32_t pyrandom_u32(PyRandom *r);
uint32_t pyrandom_randrange(PyRandom *r, uint32_t n);

/* ---- open-addressing hash set of u64 (tainted memory bytes) ------------- */
typedef struct {
    uint64_t *keys;
    uint8_t *used;      /* 0 = empty, 1 = live, 2 = tombstone */
    size_t cap, live, filled;
} U64Set;

void u64set_init(U64Set *s);
void u64set_free(U64Set *s);
bool u64set_has(const U64Set *s, uint64_t k);
void u64set_add(U64Set *s, uint64_t k);
void u64set_del(U64Set *s, uint64_t k);

/* ---- paths ---------------------------------------------------------------- */
/* Lexical normalisation like Python's os.path.abspath (no symlink resolution). */
char *path_abspath(const char *p);
char *path_dirname(const char *p);
char *path_join(const char *a, const char *b);   /* os.path.join semantics */
const char *path_basename(const char *p);
char *read_file(const char *path, size_t *len_out);  /* NUL-terminated */

#endif
