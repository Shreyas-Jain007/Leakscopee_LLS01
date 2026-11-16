/* A lightweight register + memory + flags taint engine for x86-64.
 *
 * For each executed instruction the engine answers three microarchitectural
 * questions:
 *
 *   - Is a branch about to be decided on secret-derived flags?      (branch leak)
 *   - Is a load/store address derived from a secret?                (address leak)
 *   - Does a variable-latency instruction consume a secret operand? (timing leak)
 *
 * Taint is seeded on the secret inputs at function entry and propagated forward
 * with a deliberately conservative "any tainted source taints every
 * destination" rule, decoded from Capstone operand metadata.  It is used to
 * *discover* candidate leak sites (including ones a particular pair of secrets
 * did not happen to expose).
 *
 * The engine never decides a leak on its own; every reported finding is
 * confirmed by the differential engine with a concrete witness pair.  Taint only
 * says where to look, so conservative over-tainting costs time, never soundness.
 */
#ifndef LEAKSCOPE_TAINT_H
#define LEAKSCOPE_TAINT_H

#include <stdbool.h>
#include <stdint.h>

#include <capstone/capstone.h>

#include "util.h"

/* Pseudo-register slot for the flags register. */
#define TAINT_FLAGS ((int)X86_REG_ENDING)
#define TAINT_NREGS ((int)X86_REG_ENDING + 1)

/* Instructions whose latency is operand-dependent on real microarchitectures. */
bool taint_is_variable_time(const char *mnemonic);

/* Ordered pc -> count / pc -> mnemonic maps (insertion order is significant:
 * it decides which candidate sites are probed first). */
typedef struct {
    uint64_t pc;
    uint64_t count;
    const char *mnemonic;
} SiteEntry;
typedef VEC(SiteEntry) SiteMap;

typedef struct TaintState {
    bool regs[TAINT_NREGS];      /* canonical tainted registers (+ TAINT_FLAGS) */
    U64Set mem;                  /* tainted memory byte addresses */
    SiteMap branch_sites;        /* pc -> count  (branch on secret flags) */
    SiteMap addr_sites;          /* pc -> count  (secret-dependent address) */
    SiteMap timing_sites;        /* pc -> mnemonic */
} TaintState;

/* Canonicalise a Capstone register: every GPR sub-register maps to its 64-bit
 * parent (EAX, AX, AL, AH -> RAX); RIP and EFLAGS map to -1 (handled
 * separately); everything else (xmm, ymm, segment regs, ...) maps to itself. */
int taint_canon(x86_reg r);

void taint_init(TaintState *st);
void taint_free(TaintState *st);
void taint_seed_reg(TaintState *st, x86_reg r);
void taint_seed_mem(TaintState *st, uint64_t addr, uint64_t len);

/* Reads the live 64-bit value of a canonical GPR (0 for anything else). */
typedef uint64_t (*TaintRegReader)(void *ctx, int canon_reg);

/* Propagate taint across one executed instruction and record candidates.
 * The instruction must have been decoded with detail on. */
void taint_step(TaintState *st, csh cs, const cs_insn *insn,
                TaintRegReader read_reg, void *ctx);

#endif
