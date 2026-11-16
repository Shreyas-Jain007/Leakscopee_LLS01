/* Run LeakScope over the whole benchmark and check it against ground truth.
 *
 *   leakscope-bench [--binary targets/bin/targets_gcc_O0] [--root DIR]
 *
 * With --binary, every manifest is re-pointed at the given ELF (relative to the
 * repository root), so the same benchmark can be run across compilers and
 * optimisation levels.  Exit code is 0 only if every target matches
 * targets/EXPECTATIONS.json. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "analyze.h"
#include "json.h"
#include "machine.h"
#include "target.h"
#include "util.h"

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Repository root: --root, else the parent of the directory holding this
 * executable (it is built into build/), else the current directory. */
static char *find_root(const char *override) {
    if (override) return path_abspath(override);
    char exe[4096];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n > 0) {
        exe[n] = 0;
        char *d = path_dirname(exe);
        char *root = path_dirname(d);
        free(d);
        char *probe = path_join(root, "targets/EXPECTATIONS.json");
        bool ok = access(probe, R_OK) == 0;
        free(probe);
        if (ok) return root;
        free(root);
    }
    return path_abspath(".");
}

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

int main(int argc, char **argv) {
    const char *binary = NULL, *root_arg = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--binary") && i + 1 < argc) binary = argv[++i];
        else if (!strncmp(argv[i], "--binary=", 9)) binary = argv[i] + 9;
        else if (!strcmp(argv[i], "--root") && i + 1 < argc) root_arg = argv[++i];
        else if (!strncmp(argv[i], "--root=", 7)) root_arg = argv[i] + 7;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            puts("usage: leakscope-bench [--binary ELF] [--root DIR]");
            return 0;
        } else {
            fprintf(stderr, "usage: leakscope-bench [--binary ELF] [--root DIR]\n");
            return 2;
        }
    }

    char *root = find_root(root_arg);
    char *exp_path = path_join(root, "targets/EXPECTATIONS.json");
    char *text = read_file(exp_path, NULL);
    if (!text) die("cannot read %s: %s", exp_path, strerror(errno));
    char jerr[256];
    JValue *expect = json_parse(text, jerr, sizeof jerr);
    free(text);
    if (!expect || expect->type != J_OBJ) die("%s: %s", exp_path, expect ? "not an object" : jerr);

    const char **names = xcalloc(expect->n ? expect->n : 1, sizeof(char *));
    size_t nn = 0, width = 0;
    for (size_t i = 0; i < expect->n; i++) {
        if (expect->keys[i][0] == '_') continue;
        names[nn++] = expect->keys[i];
        if (strlen(expect->keys[i]) > width) width = strlen(expect->keys[i]);
    }
    qsort(names, nn, sizeof(char *), cmp_str);
    char *bin_path = binary ? path_join(root, binary) : NULL;

    int w = (int)width;
    printf("%-*s  %-24s %-24s time   result\n", w, "target", "expected", "got");
    for (int i = 0; i < w + 62; i++) putchar('-');
    putchar('\n');

    bool all_ok = true;
    for (size_t k = 0; k < nn; k++) {
        const JValue *e = json_get(expect, names[k]);
        const char *ev = json_str(json_get(e, "verdict"));
        const char *ekind = json_str(json_get(e, "kind"));
        const JValue *cd = json_get(e, "compiler_dependent");
        bool compiler_dep = cd && cd->type == J_BOOL && cd->b;

        char *mf = xasprintf("%s/targets/manifests/%s.json", root, names[k]);
        char err[1024];
        Target t;
        if (!target_load(mf, &t, err, sizeof err)) die("%s", err);
        if (bin_path) target_set_binary(&t, bin_path);
        Machine m;
        if (!machine_init(&m, &t, err, sizeof err)) die("%s", err);

        double t0 = now();
        Report rep;
        analyze(&m, 0, &rep);
        double dt = now() - t0;

        /* sorted, de-duplicated kinds */
        const char *kinds[4];
        size_t nk = 0;
        bool verified_ok = true;
        for (size_t i = 0; i < rep.nfindings; i++) {
            if (!rep.findings[i].verified) verified_ok = false;
            size_t j;
            for (j = 0; j < nk; j++) if (!strcmp(kinds[j], rep.findings[i].kind)) break;
            if (j == nk && nk < 4) kinds[nk++] = rep.findings[i].kind;
        }
        qsort(kinds, nk, sizeof(char *), cmp_str);

        char got[256], exp_s[256];
        int off = snprintf(got, sizeof got, "%s", rep.leaky ? "LEAKY" : "SAFE");
        if (nk) {
            off += snprintf(got + off, sizeof got - (size_t)off, " [");
            for (size_t j = 0; j < nk; j++)
                off += snprintf(got + off, sizeof got - (size_t)off, "%s%s", j ? "," : "", kinds[j]);
            snprintf(got + off, sizeof got - (size_t)off, "]");
        }
        if (ekind) snprintf(exp_s, sizeof exp_s, "%s [%s]", ev ? ev : "?", ekind);
        else snprintf(exp_s, sizeof exp_s, "%s", ev ? ev : "?");

        bool verdict_ok = ev && !strcmp(ev, rep.leaky ? "LEAKY" : "SAFE");
        bool kind_ok = !ekind;
        for (size_t j = 0; j < nk; j++) if (ekind && !strcmp(ekind, kinds[j])) kind_ok = true;
        /* compiler-dependent targets are checked strictly only on the default
         * build; on other builds their verdict is reported for information */
        bool relaxed = binary && compiler_dep;
        bool good = verified_ok && (relaxed || (verdict_ok && kind_ok));
        all_ok = all_ok && good;
        char flag[32];
        snprintf(flag, sizeof flag, "%s%s", relaxed ? "INFO" : good ? "PASS" : "FAIL",
                 verified_ok ? "" : "(unverified)");
        printf("%-*s  %-24s %-24s %4.1fs  %s\n", w, names[k], exp_s, got, dt, flag);
        fflush(stdout);

        report_free(&rep);
        machine_free(&m);
        target_free(&t);
        free(mf);
    }
    for (int i = 0; i < w + 62; i++) putchar('-');
    putchar('\n');
    puts(all_ok ? "ALL PASS" : "SOME FAILED");

    free(bin_path);
    free(names);
    json_free(expect);
    free(exp_path);
    free(root);
    return all_ok ? 0 : 1;
}
