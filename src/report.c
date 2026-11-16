#include "report.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"

const char *kind_title(const char *kind) {
    if (!strcmp(kind, KIND_BRANCH)) return "Secret-dependent branch";
    if (!strcmp(kind, KIND_MEMORY)) return "Secret-dependent memory access";
    if (!strcmp(kind, KIND_VARIABLE)) return "Variable-time instruction";
    if (!strcmp(kind, KIND_SPECULATIVE)) return "Speculative (transient-execution) leak";
    return kind;
}

static char *hexaddr(uint64_t v) { return xasprintf("0x%" PRIx64, v); }

static char *file_offset(uint64_t pc, uint64_t bias) {
    return pc >= bias ? xasprintf("0x%" PRIx64, pc - bias) : xasprintf("-0x%" PRIx64, bias - pc);
}

static char *location(const LoadedBinary *bin, uint64_t pc) {
    const char *name;
    uint64_t off;
    if (!elf_nearest_symbol(bin, pc, &name, &off)) return xstrdup("?");
    return xasprintf("%s+0x%" PRIx64, name, off);
}

/* Python repr() of a str, enough for parameter names and hex strings. */
static void py_repr_str(FILE *f, const char *s) {
    char q = (strchr(s, '\'') && !strchr(s, '"')) ? '"' : '\'';
    fputc(q, f);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '\\' || *p == (unsigned char)q) { fputc('\\', f); fputc(*p, f); }
        else if (*p == '\n') fputs("\\n", f);
        else if (*p == '\r') fputs("\\r", f);
        else if (*p == '\t') fputs("\\t", f);
        else if (*p < 0x20 || *p == 0x7f) fprintf(f, "\\x%02x", *p);
        else fputc(*p, f);
    }
    fputc(q, f);
}

/* Iterate the secret params with their slice of the witness. */
typedef void (*WitnessFn)(FILE *f, const Param *p, const uint8_t *chunk, size_t len, bool first, int indent);

static void for_each_secret(FILE *f, const Target *t, Bytes w, WitnessFn fn, int indent) {
    size_t off = 0;
    bool first = true;
    for (size_t i = 0; i < t->nparams; i++) {
        const Param *p = &t->params[i];
        if (!p->is_secret) continue;
        size_t ln = param_secret_len(p);
        size_t avail = off < w.len ? w.len - off : 0;
        size_t take = ln < avail ? ln : avail;
        fn(f, p, w.data + (off < w.len ? off : 0), take, first, indent);
        first = false;
        off += ln;
    }
}

static uint64_t le_value(const uint8_t *c, size_t len) {
    uint64_t v = 0;
    for (size_t i = len; i-- > 0;) v = v << 8 | c[i];
    return v;
}

static void witness_py(FILE *f, const Param *p, const uint8_t *c, size_t len, bool first, int indent) {
    (void)indent;
    if (!first) fputs(", ", f);
    py_repr_str(f, p->name);
    fputs(": ", f);
    if (p->kind == KIND_INT) {
        fprintf(f, "%" PRIu64, le_value(c, len));
    } else {
        char *h = bytes_hex(c, len);
        py_repr_str(f, h);
        free(h);
    }
}

static void witness_json(FILE *f, const Param *p, const uint8_t *c, size_t len, bool first, int indent) {
    fprintf(f, "%s\n%*s", first ? "" : ",", indent, "");
    json_write_str(f, p->name);
    fputs(": ", f);
    if (p->kind == KIND_INT) {
        fprintf(f, "%" PRIu64, le_value(c, len));
    } else {
        char *h = bytes_hex(c, len);
        json_write_str(f, h);
        free(h);
    }
}

static bool has_secret_params(const Target *t) {
    for (size_t i = 0; i < t->nparams; i++)
        if (t->params[i].is_secret) return true;
    return false;
}

static void write_witness_json(FILE *f, const Target *t, Bytes w, int indent) {
    if (!has_secret_params(t)) { fputs("{}", f); return; }
    fputc('{', f);
    for_each_secret(f, t, w, witness_json, indent + 2);
    fprintf(f, "\n%*s}", indent, "");
}

static void write_witness_py(FILE *f, const Target *t, Bytes w) {
    fputc('{', f);
    for_each_secret(f, t, w, witness_py, 0);
    fputc('}', f);
}

/* ---- JSON ---------------------------------------------------------------------- */
#define KEY(ind, k) do { fprintf(f, "%*s", (ind), ""); json_write_str(f, (k)); fputs(": ", f); } while (0)

static void json_kv_str(FILE *f, int ind, const char *k, const char *v, bool comma) {
    KEY(ind, k);
    json_write_str(f, v);
    fputs(comma ? ",\n" : "\n", f);
}

void report_write_json(FILE *f, const Report *r, const LoadedBinary *bin) {
    const Target *t = r->target;
    fputs("{\n", f);
    json_kv_str(f, 2, "target", t->name, true);
    json_kv_str(f, 2, "binary", t->binary_path, true);
    json_kv_str(f, 2, "verdict", r->leaky ? "LEAKY" : "SAFE", true);
    KEY(2, "samples"); fprintf(f, "%zu,\n", r->samples);
    KEY(2, "avg_instructions"); fprintf(f, "%.1f,\n", r->instr_avg);
    KEY(2, "secret_bytes"); fprintf(f, "%zu,\n", target_secret_len(t));
    KEY(2, "findings");
    if (!r->nfindings) fputs("[],\n", f);
    else {
        fputs("[\n", f);
        for (size_t i = 0; i < r->nfindings; i++) {
            const Finding *x = &r->findings[i];
            char *addr = hexaddr(x->pc), *foff = file_offset(x->pc, bin->load_bias);
            char *loc = location(bin, x->pc);
            fputs("    {\n", f);
            json_kv_str(f, 6, "kind", x->kind, true);
            json_kv_str(f, 6, "title", kind_title(x->kind), true);
            json_kv_str(f, 6, "address", addr, true);
            json_kv_str(f, 6, "file_offset", foff, true);
            json_kv_str(f, 6, "location", loc, true);
            json_kv_str(f, 6, "detail", x->detail, true);
            KEY(6, "proof"); fputs("{\n", f);
            KEY(8, "secret_a"); write_witness_json(f, t, x->witness_a, 8); fputs(",\n", f);
            KEY(8, "secret_b"); write_witness_json(f, t, x->witness_b, 8); fputs(",\n", f);
            char *ha = bytes_hex(x->witness_a.data, x->witness_a.len);
            char *hb = bytes_hex(x->witness_b.data, x->witness_b.len);
            json_kv_str(f, 8, "secret_a_raw", ha, true);
            json_kv_str(f, 8, "secret_b_raw", hb, false);
            free(ha); free(hb);
            fputs("      },\n", f);
            KEY(6, "extra"); fputs("{\n", f);
            if (x->has_spec) {
                char *lpc = hexaddr(x->leak_load_pc), *lloc = location(bin, x->leak_load_pc);
                json_kv_str(f, 8, "leak_load_pc", lpc, true);
                KEY(8, "window"); fprintf(f, "%" PRIu64 ",\n", x->window);
                KEY(8, "verified"); fprintf(f, "%s,\n", x->verified ? "true" : "false");
                json_kv_str(f, 8, "leak_load_location", lloc, false);
                free(lpc); free(lloc);
            } else {
                KEY(8, "verified"); fprintf(f, "%s\n", x->verified ? "true" : "false");
            }
            fputs("      }\n", f);
            fprintf(f, "    }%s\n", i + 1 < r->nfindings ? "," : "");
            free(addr); free(foff); free(loc);
        }
        fputs("  ],\n", f);
    }
    KEY(2, "notes");
    if (!r->nnotes) fputs("[]\n", f);
    else {
        fputs("[\n", f);
        for (size_t i = 0; i < r->nnotes; i++) {
            fputs("    ", f);
            json_write_str(f, r->notes[i]);
            fputs(i + 1 < r->nnotes ? ",\n" : "\n", f);
        }
        fputs("  ]\n", f);
    }
    fputc('}', f);
}

/* ---- text ---------------------------------------------------------------------- */
void report_write_text(FILE *f, const Report *r, const LoadedBinary *bin) {
    const Target *t = r->target;
    static const char bar[] = "======================================================================";
    fprintf(f, "%s\n", bar);
    fprintf(f, "LeakScope report: %s\n", t->name);
    fprintf(f, "binary: %s\n", t->binary_path);
    fprintf(f, "verdict: %s   (%zu secrets, ~%.1f instr/run)\n",
            r->leaky ? "LEAKY" : "SAFE", r->samples, r->instr_avg);
    fprintf(f, "%s\n", bar);
    if (!r->nfindings) {
        fputs("No secret-dependent behaviour found on any channel.\n"
              "Control flow, memory-access addresses and instruction\n"
              "timings were identical across all tested secrets, and no\n"
              "variable-time instruction consumed secret data.\n", f);
    }
    for (size_t i = 0; i < r->nfindings; i++) {
        const Finding *x = &r->findings[i];
        char *addr = hexaddr(x->pc), *foff = file_offset(x->pc, bin->load_bias);
        char *loc = location(bin, x->pc);
        fprintf(f, "\n[%zu] %s\n", i + 1, kind_title(x->kind));
        fprintf(f, "    where : %s  (%s, file offset %s)\n", loc, addr, foff);
        fprintf(f, "    why   : %s\n", x->detail);
        if (x->has_spec) {
            char *lloc = location(bin, x->leak_load_pc);
            fprintf(f, "    load  : %s (0x%" PRIx64 "), window=%" PRIu64 "\n", lloc, x->leak_load_pc, x->window);
            free(lloc);
        }
        fputs("    proof : two secrets that make this channel differ:\n", f);
        fputs("            A = ", f); write_witness_py(f, t, x->witness_a); fputc('\n', f);
        fputs("            B = ", f); write_witness_py(f, t, x->witness_b); fputc('\n', f);
        free(addr); free(foff); free(loc);
    }
    if (r->nnotes) {
        fputs("\nnotes: ", f);
        for (size_t i = 0; i < r->nnotes; i++) fprintf(f, "%s%s", i ? "; " : "", r->notes[i]);
        fputc('\n', f);
    }
    fprintf(f, "%s\n", bar);
}
