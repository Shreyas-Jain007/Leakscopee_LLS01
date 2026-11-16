/* Analysis orchestration: turn traces into proven leak findings.
 *
 * Strategy
 *   1. Generate a diverse set of secret samples (structured + random).
 *   2. Run an architectural trace for each, plus a taint-tracked run for a few,
 *      to discover candidate leak sites.
 *   3. Separate the three architectural channels so each leak is attributed to
 *      its *root* cause and proven with a concrete witness pair:
 *        control flow                               -> secret-dependent branch
 *        data address, among samples sharing a path -> secret-dependent memory access
 *        timing, among samples sharing path *and* address trace
 *                                                   -> variable-time instruction
 *   4. Probe conditional branches under forced mis-speculation to catch
 *      Spectre-v1 leaks that never appear architecturally.
 *
 * Every finding carries two secrets that make the chosen channel differ.  Code
 * with no divergence on any channel and no secret-tainted variable-time
 * instruction is reported safe.
 */
#ifndef LEAKSCOPE_ANALYZE_H
#define LEAKSCOPE_ANALYZE_H

#include <stdbool.h>
#include <stdint.h>

#include "machine.h"
#include "target.h"
#include "util.h"

/* Kind strings sort in the same order the report lists findings. */
#define KIND_BRANCH      "secret_dependent_branch"
#define KIND_MEMORY      "secret_dependent_memory"
#define KIND_VARIABLE    "variable_time"
#define KIND_SPECULATIVE "speculative"

typedef struct {
    const char *kind;       /* one of the KIND_* strings (static) */
    uint64_t pc;
    char *detail;
    Bytes witness_a, witness_b;
    bool verified;
    /* speculative findings only */
    bool has_spec;
    uint64_t leak_load_pc;
    uint64_t window;
} Finding;

typedef struct {
    const Target *target;
    bool leaky;             /* verdict: LEAKY / SAFE */
    Finding *findings;
    size_t nfindings;
    size_t samples;
    double instr_avg;
    char **notes;
    size_t nnotes;
} Report;

/* Analyse target with an already-initialised machine for it. */
void analyze(Machine *m, uint64_t extra_samples, Report *out);
void report_free(Report *r);

/* Exposed for tests. */
void gen_samples(size_t secret_len, uint64_t seed, BytesVec *out);
void samples_free(BytesVec *v);

#endif
