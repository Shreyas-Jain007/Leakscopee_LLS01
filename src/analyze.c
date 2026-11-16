#include "analyze.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "taint.h"
#include "trace.h"

#define SAMPLE_SEED 0xC0FFEEull
#define MAX_SPEC_BRANCHES 64

/* ---- secret samples ---------------------------------------------------------- */
static void add_sample(BytesVec *out, size_t L, const uint8_t *b, size_t blen) {
    Bytes s = bytes_new(L);           /* (b + zeros)[:L] */
    memcpy(s.data, b, blen < L ? blen : L);
    for (size_t i = 0; i < out->len; i++) {
        if (bytes_eq(out->data[i], s)) { bytes_free(&s); return; }
    }
    VEC_PUSH(out, s);
}

void gen_samples(size_t secret_len, uint64_t seed, BytesVec *out) {
    size_t L = secret_len ? secret_len : 1;
    uint8_t *buf = xcalloc(L, 1);
    memset(out, 0, sizeof *out);

    memset(buf, 0x00, L); add_sample(out, L, buf, L);
    memset(buf, 0xff, L); add_sample(out, L, buf, L);
    memset(buf, 0x01, L); add_sample(out, L, buf, L);
    memset(buf, 0xaa, L); add_sample(out, L, buf, L);
    memset(buf, 0x55, L); add_sample(out, L, buf, L);
    memset(buf, 0x00, L); buf[0] = 0x80; add_sample(out, L, buf, L);
    /* single hot byte at several positions */
    for (size_t pos = 0; pos < L && pos < 16; pos++) {
        memset(buf, 0, L);
        buf[pos] = 0x01; add_sample(out, L, buf, L);
        buf[pos] = 0xFF; add_sample(out, L, buf, L);
    }
    /* small integers in the first 8 bytes (exercises secret-int branches) */
    static const uint64_t ints[] = { 0, 1, 2, 3, 7, 16, 17, 31, 63, 64, 127, 128,
                                     255, 256, 1023, 4096, 65535 };
    for (size_t k = 0; k < sizeof ints / sizeof ints[0]; k++) {
        uint8_t le[8];
        for (int i = 0; i < 8; i++) le[i] = (uint8_t)(ints[k] >> (8 * i));
        add_sample(out, L, le, 8);
    }
    /* random fill */
    PyRandom rng;
    pyrandom_seed(&rng, seed);
    for (int r = 0; r < 16; r++) {
        for (size_t i = 0; i < L; i++) buf[i] = (uint8_t)pyrandom_randrange(&rng, 256);
        add_sample(out, L, buf, L);
    }
    free(buf);
}

void samples_free(BytesVec *v) {
    for (size_t i = 0; i < v->len; i++) bytes_free(&v->data[i]);
    VEC_FREE(v);
}

/* ---- findings ---------------------------------------------------------------- */
typedef VEC(Finding) FindingVec;

static void push(FindingVec *fs, const char *kind, uint64_t pc, const char *detail,
                 Bytes a, Bytes b, const Finding *spec) {
    for (size_t i = 0; i < fs->len; i++)
        if (fs->data[i].pc == pc && strcmp(fs->data[i].kind, kind) == 0) return;
    Finding f = {0};
    f.kind = kind;
    f.pc = pc;
    f.detail = xstrdup(detail);
    f.witness_a = bytes_dup(a);
    f.witness_b = bytes_dup(b);
    if (spec) {
        f.has_spec = true;
        f.leak_load_pc = spec->leak_load_pc;
        f.window = spec->window;
    }
    VEC_PUSH(fs, f);
}

/* Group leaders: lead[i] = first j <= i whose trace is equal on the chosen
 * channels.  Iterating leaders in index order reproduces "groups in order of
 * first appearance, members in order". */
static void group_leaders(const Trace *tr, size_t n, bool with_mem, size_t *lead) {
    for (size_t i = 0; i < n; i++) {
        lead[i] = i;
        for (size_t j = 0; j < i; j++) {
            if (lead[j] != j) continue;
            if (trace_cf_equal(&tr[j], &tr[i]) && (!with_mem || trace_mem_equal(&tr[j], &tr[i]))) {
                lead[i] = j;
                break;
            }
        }
    }
}

static bool same_direction(Machine *m, uint64_t bpc, Bytes a, Bytes b) {
    int da = machine_arch_direction(m, a, bpc);
    int db = machine_arch_direction(m, b, bpc);
    return da >= 0 && da == db;
}

/* Replay a finding's two witnesses and confirm the claimed channel differs:
 * LeakScope checking its own proofs. */
static bool verify(Machine *m, const Finding *f) {
    uint64_t pc;
    bool ok = false;
    if (strcmp(f->kind, KIND_SPECULATIVE) == 0) {
        SpecAccesses aa, bb;
        machine_run_speculative(m, f->witness_a, f->pc, m->target->spec_window, &aa);
        machine_run_speculative(m, f->witness_b, f->pc, m->target->spec_window, &bb);
        ok = first_access_divergence(&aa, &bb, &pc) &&
             same_direction(m, f->pc, f->witness_a, f->witness_b);
        VEC_FREE(&aa);
        VEC_FREE(&bb);
        return ok;
    }
    Trace ta, tb;
    machine_run(m, f->witness_a, false, &ta);
    machine_run(m, f->witness_b, false, &tb);
    if (strcmp(f->kind, KIND_BRANCH) == 0)
        ok = first_cf_divergence(&ta, &tb, &pc);
    else if (strcmp(f->kind, KIND_MEMORY) == 0)
        ok = trace_cf_equal(&ta, &tb) && first_mem_divergence(&ta, &tb, &pc);   /* same path */
    else if (strcmp(f->kind, KIND_VARIABLE) == 0)
        ok = first_timing_divergence(&ta, &tb, &pc);
    trace_free(&ta);
    trace_free(&tb);
    return ok;
}

/* Two samples whose variable-latency op at pc runs in different magnitude
 * classes (first two classes seen, in sample order). */
static bool timing_witness(const Trace *tr, size_t n, uint64_t pc, size_t *ia, size_t *ib) {
    int first_cls = -1;
    for (size_t i = 0; i < n; i++) {
        for (size_t k = 0; k < tr[i].timing.len; k++) {
            if (tr[i].timing.data[k].pc != pc) continue;
            int cls = bit_length_u64(tr[i].timing.data[k].operand);
            if (first_cls < 0) { first_cls = cls; *ia = i; }
            else if (cls != first_cls) { *ib = i; return true; }
            break;
        }
    }
    return false;
}

static void pc_list_add(U64Vec *v, uint64_t pc) {
    for (size_t i = 0; i < v->len; i++)
        if (v->data[i] == pc) return;
    VEC_PUSH(v, pc);
}

static int cmp_finding(const void *x, const void *y) {
    const Finding *a = x, *b = y;
    int c = strcmp(a->kind, b->kind);
    if (c) return c;
    return a->pc < b->pc ? -1 : a->pc > b->pc;
}

static int cmp_str(const void *x, const void *y) {
    return strcmp(*(const char *const *)x, *(const char *const *)y);
}

void analyze(Machine *m, uint64_t extra_samples, Report *rep) {
    const Target *t = m->target;
    memset(rep, 0, sizeof *rep);
    rep->target = t;

    size_t L = target_secret_len(t);
    if (!L) L = 1;
    BytesVec samples;
    gen_samples(L, SAMPLE_SEED, &samples);
    if (extra_samples) {
        PyRandom rng;
        pyrandom_seed(&rng, 0x1234 + extra_samples);
        for (uint64_t k = 0; k < extra_samples; k++) {
            Bytes s = bytes_new(L);
            for (size_t i = 0; i < L; i++) s.data[i] = (uint8_t)pyrandom_randrange(&rng, 256);
            VEC_PUSH(&samples, s);
        }
    }

    size_t n = samples.len;
    Trace *tr = xcalloc(n, sizeof(Trace));
    for (size_t i = 0; i < n; i++) machine_run(m, samples.data[i], false, &tr[i]);
    /* taint-tracked runs on two representative samples find candidate sites */
    Trace tt[2];
    machine_run(m, samples.data[0], true, &tt[0]);
    machine_run(m, samples.data[1], true, &tt[1]);

    FindingVec fs = {0};
    uint64_t pc;

    /* ---- channel 1: secret-dependent control flow ---------------------- */
    for (size_t i = 1; i < n; i++)
        if (first_cf_divergence(&tr[0], &tr[i], &pc))
            push(&fs, KIND_BRANCH, pc, "branch decision depends on the secret",
                 tr[0].secret, tr[i].secret, NULL);
    /* also compare against a second reference to catch leaks not visible vs the first */
    if (n > 2)
        for (size_t i = 2; i < n; i++)
            if (first_cf_divergence(&tr[1], &tr[i], &pc))
                push(&fs, KIND_BRANCH, pc, "branch decision depends on the secret",
                     tr[1].secret, tr[i].secret, NULL);

    /* ---- channel 2: secret-dependent memory address ---------------------
     * Compared only inside groups that share the same control-flow path, so
     * the address difference is genuinely data-dependent, not a by-product of
     * a different branch. */
    size_t *lead = xcalloc(n, sizeof(size_t));
    group_leaders(tr, n, false, lead);
    for (size_t g = 0; g < n; g++) {
        if (lead[g] != g) continue;
        for (size_t i = g + 1; i < n; i++)
            if (lead[i] == g && first_mem_divergence(&tr[g], &tr[i], &pc))
                push(&fs, KIND_MEMORY, pc, "load/store address depends on the secret (cache leak)",
                     tr[g].secret, tr[i].secret, NULL);
    }

    /* ---- channel 3: variable-time instructions --------------------------
     * Among samples that share path AND address trace, any timing divergence
     * is a pure latency leak. */
    group_leaders(tr, n, true, lead);
    for (size_t g = 0; g < n; g++) {
        if (lead[g] != g) continue;
        for (size_t i = g + 1; i < n; i++)
            if (lead[i] == g && first_timing_divergence(&tr[g], &tr[i], &pc))
                push(&fs, KIND_VARIABLE, pc, "variable-latency instruction consumes a secret operand",
                     tr[g].secret, tr[i].secret, NULL);
    }
    free(lead);
    /* taint-confirmed variable-time sites (proved with a magnitude-changing pair) */
    for (int k = 0; k < 2; k++) {
        const SiteMap *ts = &tt[k].taint->timing_sites;
        for (size_t s = 0; s < ts->len; s++) {
            size_t ia, ib;
            if (!timing_witness(tr, n, ts->data[s].pc, &ia, &ib)) continue;
            char *detail = xasprintf("%s with secret-tainted operand", ts->data[s].mnemonic);
            push(&fs, KIND_VARIABLE, ts->data[s].pc, detail, samples.data[ia], samples.data[ib], NULL);
            free(detail);
        }
    }

    /* ---- channel 4: speculative (Spectre-v1) ----------------------------- */
    U64Vec branch_pcs = {0};
    /* branches flagged by taint come first (most likely bounds checks) */
    for (int k = 0; k < 2; k++) {
        const TaintState *ts = tt[k].taint;
        for (size_t s = 0; s < ts->branch_sites.len; s++) pc_list_add(&branch_pcs, ts->branch_sites.data[s].pc);
        for (size_t s = 0; s < ts->addr_sites.len; s++) pc_list_add(&branch_pcs, ts->addr_sites.data[s].pc);
    }
    for (size_t i = 0; i < n && i < 4; i++)
        for (size_t b = 0; b < tr[i].branches.len; b++) pc_list_add(&branch_pcs, tr[i].branches.data[b].pc);

    Bytes lo = bytes_new(samples.data[0].len), hi = bytes_new(samples.data[0].len);
    memset(hi.data, 0xFF, hi.len);    /* both are always among the samples */
    for (size_t k = 0; k < branch_pcs.len && k < MAX_SPEC_BRANCHES; k++) {
        uint64_t bpc = branch_pcs.data[k];
        SpecAccesses alo, ahi;
        machine_run_speculative(m, lo, bpc, t->spec_window, &alo);
        machine_run_speculative(m, hi, bpc, t->spec_window, &ahi);
        bool diverge = (alo.len || ahi.len) && first_access_divergence(&alo, &ahi, &pc);
        VEC_FREE(&alo);
        VEC_FREE(&ahi);
        if (!diverge) continue;
        /* Require the same architectural direction for both secrets, so the
         * difference is genuinely speculative, not an ordinary branch leak. */
        if (!same_direction(m, bpc, lo, hi)) continue;
        Finding spec = { .leak_load_pc = pc, .window = t->spec_window };
        push(&fs, KIND_SPECULATIVE, bpc,
             "mispredicting this branch leaks the secret through a transient memory access",
             lo, hi, &spec);
    }
    bytes_free(&lo);
    bytes_free(&hi);
    VEC_FREE(&branch_pcs);

    /* ---- verify every finding by replaying its two witnesses ------------- */
    for (size_t i = 0; i < fs.len; i++) fs.data[i].verified = verify(m, &fs.data[i]);

    double sum = 0;
    for (size_t i = 0; i < n; i++) sum += (double)tr[i].instr_count;
    rep->instr_avg = n ? sum / (double)n : 0.0;
    rep->samples = n;
    rep->leaky = fs.len > 0;

    /* notes: runs that did not return normally */
    const char *reasons[8];
    size_t nreasons = 0;
    bool abnormal = false;
    for (size_t i = 0; i < n; i++) {
        const char *r = tr[i].halted_reason;
        if (strcmp(r, "returned") != 0) abnormal = true;
        size_t k;
        for (k = 0; k < nreasons; k++) if (strcmp(reasons[k], r) == 0) break;
        if (k == nreasons && nreasons < 8) reasons[nreasons++] = r;
    }
    if (abnormal) {
        qsort(reasons, nreasons, sizeof(char *), cmp_str);
        size_t cap = 64;
        char *note = xmalloc(cap);
        strcpy(note, "some runs halted early: [");
        for (size_t k = 0; k < nreasons; k++) {
            char *part = xasprintf("%s'%s'", k ? ", " : "", reasons[k]);
            note = xrealloc(note, strlen(note) + strlen(part) + 3);
            strcat(note, part);
            free(part);
        }
        strcat(note, "]");
        rep->notes = xmalloc(sizeof(char *));
        rep->notes[0] = note;
        rep->nnotes = 1;
    }

    if (fs.len) qsort(fs.data, fs.len, sizeof(Finding), cmp_finding);
    rep->findings = fs.data;
    rep->nfindings = fs.len;

    for (size_t i = 0; i < n; i++) trace_free(&tr[i]);
    free(tr);
    trace_free(&tt[0]);
    trace_free(&tt[1]);
    samples_free(&samples);
}

void report_free(Report *r) {
    for (size_t i = 0; i < r->nfindings; i++) {
        free(r->findings[i].detail);
        bytes_free(&r->findings[i].witness_a);
        bytes_free(&r->findings[i].witness_b);
    }
    free(r->findings);
    for (size_t i = 0; i < r->nnotes; i++) free(r->notes[i]);
    free(r->notes);
    memset(r, 0, sizeof *r);
}
