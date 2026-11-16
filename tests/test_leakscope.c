/* End-to-end and unit tests for LeakScope.
 *
 * Run from the repository root (make test does this), after `make -C targets`.
 * Mirrors the original pytest suite: verdicts, self-verification, no false
 * alarms, witnesses that differ, cross-compiler robustness, and unit tests of
 * the trace, taint and manifest layers.  Also checks that the sample generator
 * is bit-compatible with CPython's random module. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "analyze.h"
#include "cli.h"
#include "json.h"
#include "machine.h"
#include "taint.h"
#include "target.h"
#include "trace.h"
#include "util.h"

static int n_pass, n_fail, n_skip;
static char cur_test[256];
static bool cur_failed;

static void begin(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cur_test, sizeof cur_test, fmt, ap);
    va_end(ap);
    cur_failed = false;
}

static void check(bool cond, const char *fmt, ...) {
    if (cond || cur_failed) return;   /* report the first failure per test */
    cur_failed = true;
    va_list ap;
    va_start(ap, fmt);
    printf("FAIL %s: ", cur_test);
    vprintf(fmt, ap);
    putchar('\n');
    va_end(ap);
}

static void end(void) {
    if (cur_failed) n_fail++;
    else n_pass++;
}

static void skip(void) { n_skip++; }

/* ---- benchmark fixtures ------------------------------------------------------ */
static JValue *EXPECT;
static const char *NAMES[64];
static size_t NNAMES;

typedef struct {
    Target t;
    Machine m;
    Report rep;
} Run;

static void run_target(Run *r, const char *name, const char *binary) {
    char err[1024];
    char *mf = xasprintf("targets/manifests/%s.json", name);
    if (!target_load(mf, &r->t, err, sizeof err)) die("%s", err);
    free(mf);
    if (binary) target_set_binary(&r->t, binary);
    if (!machine_init(&r->m, &r->t, err, sizeof err)) die("%s", err);
    analyze(&r->m, 0, &r->rep);
}

static void run_free(Run *r) {
    report_free(&r->rep);
    machine_free(&r->m);
    target_free(&r->t);
}

static const char *exp_verdict(const char *name) { return json_str(json_get(json_get(EXPECT, name), "verdict")); }
static const char *exp_kind(const char *name) { return json_str(json_get(json_get(EXPECT, name), "kind")); }
static bool exp_compiler_dep(const char *name) {
    const JValue *v = json_get(json_get(EXPECT, name), "compiler_dependent");
    return v && v->type == J_BOOL && v->b;
}

static bool has_kind(const Report *r, const char *kind) {
    for (size_t i = 0; i < r->nfindings; i++)
        if (!strcmp(r->findings[i].kind, kind)) return true;
    return false;
}

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* ---- end-to-end -------------------------------------------------------------- */
static void test_end_to_end(void) {
    for (size_t k = 0; k < NNAMES; k++) {
        const char *name = NAMES[k];
        Run r;
        run_target(&r, name, NULL);
        const char *ev = exp_verdict(name), *ek = exp_kind(name);
        const char *got = r.rep.leaky ? "LEAKY" : "SAFE";

        begin("test_verdict[%s]", name);
        check(ev && !strcmp(ev, got), "verdict %s, expected %s", got, ev);
        if (ek) check(has_kind(&r.rep, ek), "expected a %s finding", ek);
        end();

        /* every reported leak must survive replay of its own witness pair */
        begin("test_findings_are_verified[%s]", name);
        for (size_t i = 0; i < r.rep.nfindings; i++)
            check(r.rep.findings[i].verified, "unverified %s@0x%llx", r.rep.findings[i].kind,
                  (unsigned long long)r.rep.findings[i].pc);
        end();

        if (ev && !strcmp(ev, "SAFE")) {
            begin("test_safe_targets_have_no_findings[%s]", name);
            check(r.rep.nfindings == 0, "%zu false alarm(s), first %s", r.rep.nfindings,
                  r.rep.nfindings ? r.rep.findings[0].kind : "");
            end();
        } else {
            skip();
            begin("test_witnesses_differ[%s]", name);
            check(r.rep.nfindings > 0, "no findings");
            for (size_t i = 0; i < r.rep.nfindings; i++)
                check(!bytes_eq(r.rep.findings[i].witness_a, r.rep.findings[i].witness_b),
                      "identical witnesses for %s", r.rep.findings[i].kind);
            end();
        }
        run_free(&r);
    }
}

/* ---- cross-compiler / cross-optimisation robustness --------------------------- */
static void test_cross_compiler(void) {
    static const char *cross[] = { "targets/bin/targets_gcc_O0", "targets/bin/targets_clang_O2" };
    for (size_t b = 0; b < 2; b++) {
        if (access(cross[b], R_OK) != 0) continue;
        for (size_t k = 0; k < NNAMES; k++) {
            const char *name = NAMES[k];
            if (exp_compiler_dep(name)) { skip(); continue; }
            begin("test_cross_compiler[%s-%s]", name, cross[b]);
            Run r;
            run_target(&r, name, cross[b]);
            const char *ev = exp_verdict(name), *got = r.rep.leaky ? "LEAKY" : "SAFE";
            check(ev && !strcmp(ev, got), "%s on %s: %s", name, cross[b], got);
            end();
            run_free(&r);
        }
    }
}

/* ---- unit tests ----------------------------------------------------------------- */
static void test_canon_subregisters(void) {
    begin("test_canon_subregisters");
    check(taint_canon(X86_REG_EAX) == X86_REG_RAX, "eax");
    check(taint_canon(X86_REG_AL) == X86_REG_RAX, "al");
    check(taint_canon(X86_REG_AH) == X86_REG_RAX, "ah");
    check(taint_canon(X86_REG_R9D) == X86_REG_R9, "r9d");
    check(taint_canon(X86_REG_R15B) == X86_REG_R15, "r15b");
    check(taint_canon(X86_REG_XMM3) == X86_REG_XMM3, "xmm3");
    check(taint_canon(X86_REG_RIP) == -1 && taint_canon(X86_REG_EFLAGS) == -1, "rip/eflags");
    end();
}

static uint64_t zero_reader(void *ctx, int reg) { (void)ctx; (void)reg; return 0; }

/* Decode one instruction at addr and run it through the taint engine. */
static void taint_exec(TaintState *st, csh cs, uint64_t addr, const uint8_t *code, size_t n) {
    cs_insn *insn = NULL;
    if (cs_disasm(cs, code, n, addr, 1, &insn) != 1) {
        check(false, "cannot decode instruction at 0x%llx", (unsigned long long)addr);
        return;
    }
    taint_step(st, cs, insn, zero_reader, NULL);
    cs_free(insn, 1);
}

static void test_taint_rip_relative(void) {
    /* Two different instructions reach the same global at 0x402000 through
     * different [rip+disp] displacements: taint must flow through it. */
    begin("test_taint_flows_through_rip_relative_global");
    csh cs;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs) != CS_ERR_OK) { check(false, "cs_open"); end(); return; }
    cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);
    static const uint8_t store_al[] = { 0x88, 0x05, 0xfa, 0x0f, 0x00, 0x00 };  /* 0x401000: mov [rip+0xffa], al */
    static const uint8_t load_bl[]  = { 0x8a, 0x1d, 0xf4, 0x0f, 0x00, 0x00 };  /* 0x401006: mov bl, [rip+0xff4] */
    static const uint8_t load_dl[]  = { 0x8a, 0x15, 0xf4, 0x0f, 0x00, 0x00 };  /* 0x401014: mov dl, [rip+0xff4] -> 0x40200e */
    static const uint8_t store_cl[] = { 0x88, 0x0d, 0xee, 0x0f, 0x00, 0x00 };  /* 0x40100c: mov [rip+0xfee], cl */

    TaintState st;
    taint_init(&st);
    taint_seed_reg(&st, X86_REG_RAX);
    taint_exec(&st, cs, 0x401000, store_al, sizeof store_al);
    check(u64set_has(&st.mem, 0x402000), "store must taint the global's byte at 0x402000");
    check(!u64set_has(&st.mem, 0xffa), "store must not taint the bare displacement");
    taint_exec(&st, cs, 0x401006, load_bl, sizeof load_bl);
    check(st.regs[X86_REG_RBX], "load of the tainted global must taint rbx");
    taint_exec(&st, cs, 0x401014, load_dl, sizeof load_dl);
    check(!st.regs[X86_REG_RDX], "load of a different, clean global must not taint rdx");
    /* overwriting the global with clean data clears its taint */
    taint_exec(&st, cs, 0x40100c, store_cl, sizeof store_cl);
    check(!u64set_has(&st.mem, 0x402000), "clean store must clear the global's taint");
    taint_free(&st);
    cs_close(&cs);
    end();
}

static void test_cf_divergence(void) {
    begin("test_cf_divergence_detects_first_difference");
    Bytes e = bytes_new(0);
    Trace a, b;
    trace_init(&a, e);
    trace_init(&b, e);
    BranchEvent x1 = { 1, true }, x2 = { 2, true }, y2 = { 2, false };
    VEC_PUSH(&a.branches, x1); VEC_PUSH(&a.branches, x2);
    VEC_PUSH(&b.branches, x1); VEC_PUSH(&b.branches, y2);
    uint64_t pc = 0;
    check(first_cf_divergence(&a, &b, &pc) && pc == 2, "pc=%llu", (unsigned long long)pc);
    check(!first_cf_divergence(&a, &a, &pc), "self-divergence");
    /* a strict prefix diverges at the first extra branch */
    b.branches.len = 1;
    check(first_cf_divergence(&a, &b, &pc) && pc == 2, "prefix pc=%llu", (unsigned long long)pc);
    trace_free(&a);
    trace_free(&b);
    bytes_free(&e);
    end();
}

static void test_mem_divergence(void) {
    begin("test_mem_divergence_by_cache_line");
    Bytes e = bytes_new(0);
    Trace a, b;
    trace_init(&a, e);
    trace_init(&b, e);
    MemEvent ma = { 10, 0x100, false }, mb = { 10, 0x200, false };
    VEC_PUSH(&a.mem, ma);
    VEC_PUSH(&b.mem, mb);
    uint64_t pc = 0;
    check(first_mem_divergence(&a, &b, &pc) && pc == 10, "pc=%llu", (unsigned long long)pc);
    trace_free(&a);
    trace_free(&b);
    bytes_free(&e);
    end();
}

static void test_timing_buckets(void) {
    begin("test_timing_divergence_buckets_by_bit_length");
    Bytes e = bytes_new(0);
    Trace a, b;
    trace_init(&a, e);
    trace_init(&b, e);
    TimingEvent ta = { 5, "div", 200 }, tb = { 5, "div", 255 }, tc = { 5, "div", 256 };
    VEC_PUSH(&a.timing, ta);
    VEC_PUSH(&b.timing, tb);
    uint64_t pc;
    check(!first_timing_divergence(&a, &b, &pc), "same class must not diverge");
    b.timing.data[0] = tc;
    check(first_timing_divergence(&a, &b, &pc) && pc == 5, "different class must diverge");
    trace_free(&a);
    trace_free(&b);
    bytes_free(&e);
    end();
}

static void test_manifest_layout(void) {
    begin("test_manifest_secret_vector_layout");
    Target t;
    char err[512];
    bool ok = target_load("targets/manifests/07_spectre_gadget.json", &t, err, sizeof err);
    check(ok, "%s", err);
    if (ok) {
        check(target_secret_len(&t) == 16, "secret_len=%zu", target_secret_len(&t));
        size_t nsecret = 0, len = 0;
        for (size_t i = 0; i < t.nparams; i++)
            if (t.params[i].is_secret) { nsecret++; len = param_secret_len(&t.params[i]); }
        check(nsecret == 1 && len == 16, "slices=%zu len=%zu", nsecret, len);
        target_free(&t);
    }
    end();
}

static void test_python_random_compat(void) {
    /* Reference values: list(random.Random(0xC0FFEE).randrange(256) for _ in range(8))
     * and random.Random(0xC0FFEE).getrandbits(32) in CPython. */
    begin("test_python_random_compat");
    PyRandom r;
    pyrandom_seed(&r, 0xC0FFEE);
    static const uint32_t want[8] = { 88, 8, 62, 219, 97, 152, 240, 208 };
    for (int i = 0; i < 8; i++) {
        uint32_t v = pyrandom_randrange(&r, 256);
        check(v == want[i], "randrange #%d = %u, want %u", i, v, want[i]);
    }
    pyrandom_seed(&r, 0xC0FFEE);
    check(pyrandom_u32(&r) == 4116735509u, "getrandbits(32)");
    end();
}

static void test_sample_set(void) {
    begin("test_sample_set_shape");
    BytesVec s;
    gen_samples(16, 0xC0FFEE, &s);
    check(s.len == 66, "16-byte secret yields %zu samples, want 66", s.len);
    bool zeros = true, ones = true;
    for (size_t i = 0; i < 16 && s.len >= 2; i++) {
        zeros &= s.data[0].data[i] == 0;
        ones &= s.data[1].data[i] == 0xff;
    }
    check(zeros && ones, "samples[0]/[1] must be all-zeros / all-ones");
    for (size_t i = 0; i < s.len; i++)
        for (size_t j = i + 1; j < s.len; j++)
            check(!bytes_eq(s.data[i], s.data[j]), "duplicate samples %zu/%zu", i, j);
    samples_free(&s);
    end();
}

static void test_json_parser(void) {
    begin("test_json_parser");
    char err[128];
    JValue *v = json_parse("{\"a\": [1, -2, 3.5, true, null], \"s\": \"x\\u00e9\\n\", \"a\": 7}", err, sizeof err);
    check(v != NULL, "parse: %s", err);
    if (v) {
        const JValue *a = json_get(v, "a");
        check(a && a->type == J_NUM && a->is_int && a->i == 7, "duplicate key: last wins");
        const char *s = json_str(json_get(v, "s"));
        check(s && !strcmp(s, "x\xc3\xa9\n"), "string escapes");
        json_free(v);
    }
    check(json_parse("{\"a\": }", err, sizeof err) == NULL, "must reject malformed JSON");
    check(json_parse("[1, 2] x", err, sizeof err) == NULL, "must reject trailing data");
    end();
}

static void test_exit_code_contract(void) {
    /* CLI returns 1 for leaky, 0 for safe (CI gate), 2 for errors */
    begin("test_exit_code_contract");
    char *a1[] = { "leakscope", "targets/manifests/01_pw_check_bad.json", "--quiet", NULL };
    char *a2[] = { "leakscope", "targets/manifests/02_ct_eq.json", "--quiet", NULL };
    char *a3[] = { "leakscope", "targets/manifests/does_not_exist.json", "--quiet", NULL };
    int leaky = leakscope_main(3, a1);
    int safe = leakscope_main(3, a2);
    fflush(stdout);
    int bad = leakscope_main(3, a3);
    check(leaky == 1 && safe == 0, "leaky=%d safe=%d", leaky, safe);
    check(bad == 2, "missing manifest exit=%d", bad);
    end();
}

int main(void) {
    char *text = read_file("targets/EXPECTATIONS.json", NULL);
    if (!text) die("run from the repository root (targets/EXPECTATIONS.json not found)");
    char err[256];
    EXPECT = json_parse(text, err, sizeof err);
    free(text);
    if (!EXPECT) die("EXPECTATIONS.json: %s", err);
    for (size_t i = 0; i < EXPECT->n && NNAMES < 64; i++)
        if (EXPECT->keys[i][0] != '_') NAMES[NNAMES++] = EXPECT->keys[i];
    qsort(NAMES, NNAMES, sizeof(char *), cmp_str);
    if (access("targets/bin/targets_gcc_O2", R_OK) != 0)
        die("benchmark binaries missing: run `make -C targets` first");

    test_end_to_end();
    test_cross_compiler();
    test_canon_subregisters();
    test_taint_rip_relative();
    test_cf_divergence();
    test_mem_divergence();
    test_timing_buckets();
    test_manifest_layout();
    test_python_random_compat();
    test_sample_set();
    test_json_parser();
    test_exit_code_contract();

    printf("%d passed, %d skipped, %d failed\n", n_pass, n_skip, n_fail);
    json_free(EXPECT);
    return n_fail ? 1 : 0;
}
