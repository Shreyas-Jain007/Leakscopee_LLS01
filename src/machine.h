/* The emulated machine: load an ELF, place inputs, run, collect a Trace.
 *
 * Built on the Unicorn CPU emulator.  We map the target's PT_LOAD segments,
 * build a stack and an input arena, place the public and secret parameters
 * according to the System V AMD64 calling convention, and run the chosen entry
 * function to its return.  Hooks record the observable channels (control flow,
 * data address, timing) and, optionally, drive the taint engine.
 *
 * The same machine offers machine_run_speculative(), which explores a bounded
 * mis-speculation window past a conditional branch -- the engine needed to
 * catch Spectre-v1-style leaks that never appear in an architectural run.
 */
#ifndef LEAKSCOPE_MACHINE_H
#define LEAKSCOPE_MACHINE_H

#include <stdbool.h>
#include <stdint.h>

#include <capstone/capstone.h>

#include "elfload.h"
#include "target.h"
#include "trace.h"

#define PAGE_SIZE_EMU 0x1000ull
#define STACK_BASE    0x7F0000000000ull
#define STACK_SIZE    0x40000ull           /* 256 KiB stack is plenty for leaf targets */
#define ARENA_BASE    0x5F0000000000ull
#define ARENA_SIZE    0x80000ull           /* 512 KiB input arena */
#define SENTINEL_RET  0x1337DEAD0000ull    /* return address that halts emulation */

typedef struct {
    uint64_t addr;
    cs_insn *insn;     /* NULL = slot empty */
} DecodeSlot;

typedef struct {
    uint64_t begin, size;
} MapRange;

typedef struct {
    const Target *target;
    LoadedBinary bin;
    uint64_t entry;
    csh cs;
    DecodeSlot *cache;      /* open-addressing decode cache, keyed by address */
    size_t cache_cap, cache_len;
    MapRange *ranges;       /* merged page ranges to map in every fresh machine */
    size_t nranges;
} Machine;

/* Build a machine for target; on failure returns false with a message. */
bool machine_init(Machine *m, const Target *t, char *err, size_t errlen);
void machine_free(Machine *m);

/* Architectural run on one secret.  The caller owns the trace (trace_free). */
void machine_run(Machine *m, Bytes secret, bool with_taint, Trace *out);

/* Force the mispredicted path at branch_pc and record the cache lines touched
 * by loads in a bounded window.  Returns an empty list if the branch is never
 * reached or is not a conditional branch.  Caller frees with VEC_FREE. */
void machine_run_speculative(Machine *m, Bytes secret, uint64_t branch_pc,
                             uint64_t window, SpecAccesses *out);

/* Architectural direction of the conditional branch at bpc for this secret:
 * returns 1 = taken, 0 = not taken, -1 = not reached / undecidable. */
int machine_arch_direction(Machine *m, Bytes secret, uint64_t bpc);

#endif
