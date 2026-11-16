/* Trace data structures and channel comparison.
 *
 * A trace is the record of one concrete execution of a target function under
 * one concrete secret value.  We keep three observation channels, matching the
 * three things a side-channel attacker can measure:
 *
 *   control flow  -- the ordered list of conditional-branch decisions
 *   data address  -- the ordered list of cache lines touched by loads/stores
 *   timing class  -- the ordered list of variable-latency instructions executed,
 *                    together with the operand values that drive their latency
 *
 * Two executions that differ on any channel differ in something an attacker can
 * observe.  If the only thing that changed between the two executions was the
 * secret, that difference *is* a leak, and the two secrets are its proof.
 */
#ifndef LEAKSCOPE_TRACE_H
#define LEAKSCOPE_TRACE_H

#include <stdbool.h>
#include <stdint.h>

#include "util.h"

#define CACHE_LINE_BITS 6   /* 64-byte cache line; address >> 6 is the line index */

typedef struct {
    uint64_t pc;        /* address of the conditional-branch instruction */
    bool taken;         /* whether the architectural run took it */
} BranchEvent;

typedef struct {
    uint64_t pc;        /* address of the instruction performing the access */
    uint64_t line;      /* touched cache line (address >> CACHE_LINE_BITS) */
    bool is_write;
} MemEvent;

typedef struct {
    uint64_t pc;            /* address of the variable-latency instruction */
    const char *mnemonic;   /* "div" / "idiv" (static storage) */
    uint64_t operand;       /* the value whose magnitude drives the latency */
} TimingEvent;

/* A transient load observed under forced mis-speculation. */
typedef struct {
    uint64_t pc;
    uint64_t line;
} SpecAccess;

typedef VEC(SpecAccess) SpecAccesses;

struct TaintState;

typedef struct {
    Bytes secret;
    VEC(BranchEvent) branches;
    VEC(MemEvent) mem;
    VEC(TimingEvent) timing;
    uint64_t instr_count;
    const char *halted_reason;      /* "returned" | "budget" | "unmapped" | "ucerror" */
    struct TaintState *taint;       /* only for taint-tracked runs */
} Trace;

void trace_init(Trace *t, Bytes secret);   /* takes a copy of secret */
void trace_free(Trace *t);

/* Channel fingerprints are order-sensitive; these compare them for equality. */
bool trace_cf_equal(const Trace *a, const Trace *b);
bool trace_mem_equal(const Trace *a, const Trace *b);

/* First divergence on each channel: returns true and sets *pc if the channel
 * differs.  When one sequence is a strict prefix of the other, the pc is that
 * of the first extra event in the longer one.  The timing channel buckets the
 * operand by bit length (the latency class of a division). */
bool first_cf_divergence(const Trace *a, const Trace *b, uint64_t *pc);
bool first_mem_divergence(const Trace *a, const Trace *b, uint64_t *pc);
bool first_timing_divergence(const Trace *a, const Trace *b, uint64_t *pc);
bool first_access_divergence(const SpecAccesses *a, const SpecAccesses *b, uint64_t *pc);

#endif
