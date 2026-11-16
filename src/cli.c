#include "cli.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "analyze.h"
#include "machine.h"
#include "report.h"
#include "target.h"

#define LEAKSCOPE_VERSION "1.0.0"

static void usage(FILE *f) {
    fputs("usage: leakscope [-h] [--json FILE] [--extra EXTRA] [--quiet] manifest\n", f);
}

static void help(void) {
    usage(stdout);
    fputs("\nDetect secret-dependent timing/cache/speculative leaks in an x86-64 Linux binary.\n"
          "\npositional arguments:\n"
          "  manifest       path to the target manifest JSON\n"
          "\noptions:\n"
          "  -h, --help     show this help message and exit\n"
          "  --json FILE    write the JSON report here\n"
          "  --extra EXTRA  additional random secret samples to test\n"
          "  --quiet        suppress the human-readable report\n"
          "  --version      print the version and exit\n"
          "\nexit status: 0 = SAFE, 1 = LEAKY, 2 = error\n", stdout);
}

static int arg_error(const char *msg, const char *arg) {
    usage(stderr);
    fprintf(stderr, "leakscope: error: %s%s\n", msg, arg ? arg : "");
    return 2;
}

int leakscope_main(int argc, char **argv) {
    const char *manifest = NULL, *json_out = NULL;
    unsigned long long extra = 0;
    bool quiet = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *val = NULL;
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { help(); return 0; }
        if (!strcmp(a, "--version")) { printf("leakscope %s\n", LEAKSCOPE_VERSION); return 0; }
        if (!strcmp(a, "--quiet")) { quiet = true; continue; }
        if (!strncmp(a, "--json", 6) && (a[6] == 0 || a[6] == '=')) {
            if (a[6] == '=') val = a + 7;
            else if (i + 1 < argc) val = argv[++i];
            else return arg_error("argument --json: expected one argument", NULL);
            json_out = val;
            continue;
        }
        if (!strncmp(a, "--extra", 7) && (a[7] == 0 || a[7] == '=')) {
            if (a[7] == '=') val = a + 8;
            else if (i + 1 < argc) val = argv[++i];
            else return arg_error("argument --extra: expected one argument", NULL);
            char *end;
            errno = 0;
            long long v = strtoll(val, &end, 10);
            if (errno || *end || end == val || v < 0)
                return arg_error("argument --extra: invalid non-negative int value: ", val);
            extra = (unsigned long long)v;
            continue;
        }
        if (a[0] == '-' && a[1]) return arg_error("unrecognized arguments: ", a);
        if (manifest) return arg_error("unrecognized arguments: ", a);
        manifest = a;
    }
    if (!manifest) return arg_error("the following arguments are required: manifest", NULL);

    char err[1024];
    Target t;
    if (!target_load(manifest, &t, err, sizeof err)) {
        fprintf(stderr, "leakscope: %s\n", err);
        return 2;
    }
    Machine m;
    if (!machine_init(&m, &t, err, sizeof err)) {
        fprintf(stderr, "leakscope: %s\n", err);
        target_free(&t);
        return 2;
    }

    Report rep;
    analyze(&m, extra, &rep);

    int rc = 0;
    if (!quiet) report_write_text(stdout, &rep, &m.bin);
    if (json_out) {
        FILE *f = fopen(json_out, "w");
        if (!f) {
            fprintf(stderr, "leakscope: cannot write %s: %s\n", json_out, strerror(errno));
            rc = 2;
        } else {
            report_write_json(f, &rep, &m.bin);
            if (fclose(f) != 0) {
                fprintf(stderr, "leakscope: error writing %s: %s\n", json_out, strerror(errno));
                rc = 2;
            } else if (!quiet) {
                printf("\nJSON written to %s\n", json_out);
            }
        }
    }
    if (!rc) rc = rep.leaky ? 1 : 0;
    fflush(stdout);
    report_free(&rep);
    machine_free(&m);
    target_free(&t);
    return rc;
}
