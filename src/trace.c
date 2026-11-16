#include "trace.h"

#include <stdlib.h>
#include <string.h>

#include "taint.h"

void trace_init(Trace *t, Bytes secret) {
    memset(t, 0, sizeof *t);
    t->secret = bytes_dup(secret);
    t->halted_reason = "returned";
}

void trace_free(Trace *t) {
    bytes_free(&t->secret);
    VEC_FREE(&t->branches);
    VEC_FREE(&t->mem);
    VEC_FREE(&t->timing);
    if (t->taint) {
        taint_free(t->taint);
        free(t->taint);
    }
    memset(t, 0, sizeof *t);
}

static bool br_eq(const BranchEvent *x, const BranchEvent *y) {
    return x->pc == y->pc && x->taken == y->taken;
}

static bool mem_eq(const MemEvent *x, const MemEvent *y) {
    return x->pc == y->pc && x->line == y->line && x->is_write == y->is_write;
}

static bool tim_eq(const TimingEvent *x, const TimingEvent *y) {
    return x->pc == y->pc && strcmp(x->mnemonic, y->mnemonic) == 0 &&
           bit_length_u64(x->operand) == bit_length_u64(y->operand);
}

static bool acc_eq(const SpecAccess *x, const SpecAccess *y) {
    return x->pc == y->pc && x->line == y->line;
}

/* Generic "first differing element" over two event vectors. */
#define FIRST_DIV(A, B, EQ, PC_OUT)                                           \
    do {                                                                      \
        size_t n_ = (A)->len < (B)->len ? (A)->len : (B)->len;                \
        for (size_t i_ = 0; i_ < n_; i_++) {                                  \
            if (!EQ(&(A)->data[i_], &(B)->data[i_])) {                        \
                *(PC_OUT) = (A)->data[i_].pc;                                 \
                return true;                                                  \
            }                                                                 \
        }                                                                     \
        if ((A)->len != (B)->len) {                                           \
            /* one run executed an extra event the other never reached */     \
            *(PC_OUT) = ((A)->len > (B)->len ? (A) : (B))->data[n_].pc;       \
            return true;                                                      \
        }                                                                     \
        return false;                                                         \
    } while (0)

bool first_cf_divergence(const Trace *a, const Trace *b, uint64_t *pc) {
    FIRST_DIV(&a->branches, &b->branches, br_eq, pc);
}

bool first_mem_divergence(const Trace *a, const Trace *b, uint64_t *pc) {
    FIRST_DIV(&a->mem, &b->mem, mem_eq, pc);
}

bool first_timing_divergence(const Trace *a, const Trace *b, uint64_t *pc) {
    FIRST_DIV(&a->timing, &b->timing, tim_eq, pc);
}

bool first_access_divergence(const SpecAccesses *a, const SpecAccesses *b, uint64_t *pc) {
    FIRST_DIV(a, b, acc_eq, pc);
}

bool trace_cf_equal(const Trace *a, const Trace *b) {
    uint64_t pc;
    return !first_cf_divergence(a, b, &pc);
}

bool trace_mem_equal(const Trace *a, const Trace *b) {
    uint64_t pc;
    return !first_mem_divergence(a, b, &pc);
}
