/*
 * LeakScope benchmark targets.
 *
 * Each function is a small, self-contained leaf routine (no libc calls) so it
 * can be emulated directly from its entry symbol.  Functions come in pairs: a
 * leaky pattern and a constant-time / mitigated counterpart.  A manifest in
 * ../manifests/ describes each one's entry symbol and which argument is secret.
 *
 * Build with -fno-builtin so the compiler does not fold byte loops into memcmp,
 * and -fno-stack-protector so there are no __stack_chk_fail calls into libc.
 */

#include <stddef.h>
#include <stdint.h>

/* A table the compiler cannot constant-fold away (filled at load time for
 * native runs; its *contents* are irrelevant to the address-channel leak). */
unsigned char g_sbox[256];
__attribute__((constructor)) static void init_sbox(void) {
    for (int i = 0; i < 256; i++) g_sbox[i] = (unsigned char)(i * 7 + 3);
}

/* ---- 1. secret-dependent branch (LEAKY) -------------------------------
 * Early-out comparison: the loop exits at the first mismatching byte, so the
 * number of iterations -- and the branch decisions -- reveal the secret.      */
int pw_check_bad(const unsigned char *guess, const unsigned char *secret, int n) {
    for (int i = 0; i < n; i++) {
        if (guess[i] != secret[i])
            return i + 1;            /* position leaks through control flow */
    }
    return 0;
}

/* ---- 2. constant-time compare (SAFE) ---------------------------------- */
int ct_eq(const unsigned char *a, const unsigned char *b, int n) {
    unsigned char d = 0;
    for (int i = 0; i < n; i++)
        d |= (unsigned char)(a[i] ^ b[i]);    /* no secret-dependent branch */
    /* branchless "d == 0 ? 1 : 0" */
    return (int)(1u & ((unsigned)(d - 1) >> 8));
}

/* ---- 3. secret-indexed table lookup (LEAKY) ---------------------------
 * The address g_sbox + key[i] depends on the secret, so the touched cache line
 * leaks it -- the classic AES T-table side channel.                           */
unsigned sbox_lookup_bad(const unsigned char *key, int n) {
    unsigned acc = 0;
    for (int i = 0; i < n; i++)
        acc += g_sbox[key[i]];       /* secret-dependent load address */
    return acc;
}

/* ---- 4. table-free mixing (SAFE) -------------------------------------
 * Reads the secret only at public addresses key+i; no secret-dependent
 * address, no branch on the secret.                                           */
unsigned no_table(const unsigned char *key, int n) {
    unsigned acc = 0;
    for (int i = 0; i < n; i++) {
        unsigned x = key[i];
        acc += x * 31u + 7u;         /* arithmetic only */
    }
    return acc;
}

/* ---- 5. variable-time division (LEAKY) -------------------------------
 * x86 DIV/IDIV latency depends on the operand magnitude, so a secret dividend
 * leaks through timing.                                                        */
unsigned long mod_bad(unsigned long dividend_secret, unsigned long modulus) {
    return dividend_secret % modulus;    /* data-dependent div latency */
}

/* ---- 6. multiply-based reduction (SAFE) ------------------------------
 * Fixed-latency multiply/shift; no data-dependent instruction.                */
unsigned long mul_hash_safe(unsigned long x) {
    x ^= x >> 33;
    x *= 0xFF51AFD7ED558CCDull;
    x ^= x >> 29;
    return x;
}

/* ---- 7. Spectre-v1 gadget (LEAKY, speculative only) ------------------
 * When idx >= pub_len the bounds check fails and nothing secret is touched
 * architecturally.  Under a misprediction of that branch, secret[idx] is read
 * transiently and transmitted through the cache via `probe`.                  */
unsigned char spectre_gadget(size_t idx, const unsigned char *secret,
                             size_t pub_len, unsigned char *probe) {
    unsigned char v = 0;
    if (idx < pub_len) {                     /* mispredicted branch */
        unsigned char s = secret[idx];       /* transient out-of-policy read */
        v = probe[(size_t)s * 64];           /* cache-line transmit */
    }
    return v;
}

/* ---- 8. Spectre-shaped gadget on PUBLIC data (SAFE) ------------------
 * This has the exact shape of a Spectre-v1 gadget and handles a secret, but the
 * transiently-indexed buffer g_pubtab is public, so a misprediction leaks
 * nothing secret.  A correct analyser must report SAFE despite the suspicious
 * shape.  (The secret is consumed only at public addresses, in constant time.) */
unsigned char g_pubtab[4096];
__attribute__((constructor)) static void init_pubtab(void) {
    for (int i = 0; i < 4096; i++) g_pubtab[i] = (unsigned char)(i * 5 + 1);
}
unsigned char spectre_safe(size_t idx, const unsigned char *secret,
                           size_t pub_len, unsigned char *probe) {
    unsigned acc = 0;
    for (int i = 0; i < 16; i++) acc += secret[i];   /* secret at public addrs */
    unsigned char v = (unsigned char)acc;
    if (idx < pub_len) {
        unsigned char s = g_pubtab[idx];             /* PUBLIC transient read */
        v ^= probe[(size_t)s * 64];
    }
    return v;
}

/* ---- 10. naive source-level mask, defeated by the optimizer (LEAKY) ---
 * The source tries to steer the pointer to a public buffer when out of bounds,
 * but at -O2 the compiler rewrites it back into a secret-dependent transient
 * access -- demonstrating that the *source* cannot be trusted, only the binary.*/
static const unsigned char g_zeros[64] = {0};
unsigned char spectre_masked_src(size_t idx, const unsigned char *secret,
                                 size_t pub_len, unsigned char *probe) {
    size_t in = (idx < pub_len);
    size_t mask = in ? ~(size_t)0 : 0;
    const unsigned char *src = in ? secret : g_zeros;
    unsigned char s = src[idx & mask];
    unsigned char v = probe[(size_t)s * 64];
    return v;
}

/* ---- 9. branches/tables on PUBLIC data (SAFE but suspicious) ----------
 * Has branches and a table lookup -- but every one is driven by public data,
 * so a correct analyser must still report SAFE.                               */
unsigned public_branch(const unsigned char *secret, int pub_flag,
                       const unsigned char *pubtab) {
    unsigned acc = 0;
    if (pub_flag & 1) acc += 11; else acc += 22;   /* branch on public */
    acc += pubtab[pub_flag & 7];                   /* public index */
    for (int i = 0; i < 16; i++)
        acc += secret[i];                          /* secret at public addr */
    return acc;
}

int main(void) { return 0; }
