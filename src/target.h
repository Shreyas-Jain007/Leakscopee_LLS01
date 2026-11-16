/* Target description: the binary, its entry point, and which inputs are secret.
 *
 * A target is an x86-64 Linux ELF plus a small JSON manifest that plays the
 * role of the "short description of the entry point and which inputs are
 * secret" each target ships with.
 *
 * Manifest schema (examples in the targets/manifests directory):
 *
 *   {
 *     "name":         "<human name>",
 *     "binary":       "<path to ELF, relative to the manifest>",
 *     "entry":        "<symbol name>" | "0x<hex address>",
 *     "instr_budget": 200000,                  (optional, default 200000)
 *     "spec_window":  48,                      (optional speculative window)
 *     "params": [
 *        {"name":"out", "role":"public", "kind":"outbuf", "size":16},
 *        {"name":"key", "role":"secret", "kind":"inbuf",  "size":16},
 *        {"name":"n",   "role":"public", "kind":"int",    "value":16}
 *     ]
 *   }
 *
 * kind is one of:
 *   int     an integer/pointer passed by value in the next arg register.  A
 *           public int uses "value"; a secret int is driven by the analyser.
 *   inbuf   a buffer of "size" bytes placed in memory; the pointer is passed in
 *           the next arg register.  A public inbuf uses "value" (hex string) or
 *           defaults to zeros; a secret inbuf is driven by the analyser.
 *   outbuf  a zeroed buffer of "size" bytes; pointer passed in the next arg
 *           register.  Always public.
 *
 * Secret params, concatenated in manifest order, define the secret vector the
 * analyser mutates and over which it reports witnesses.
 */
#ifndef LEAKSCOPE_TARGET_H
#define LEAKSCOPE_TARGET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "util.h"

typedef enum { KIND_INT, KIND_INBUF, KIND_OUTBUF } ParamKind;

typedef struct {
    char *name;
    bool is_secret;
    ParamKind kind;
    size_t size;           /* bytes, for buffers */
    bool has_value;        /* public int has "value" */
    uint64_t value;
    bool has_bytes;        /* public inbuf has hex "value" */
    Bytes value_bytes;
} Param;

typedef struct {
    char *name;
    char *binary_path;
    char *entry;
    Param *params;
    size_t nparams;
    uint64_t instr_budget;
    uint64_t spec_window;
    char *manifest_dir;
} Target;

/* Secret bytes contributed by a parameter (8 for a secret int). */
size_t param_secret_len(const Param *p);
size_t target_secret_len(const Target *t);

/* Load a manifest; on failure returns false with a message in err. */
bool target_load(const char *manifest_path, Target *t, char *err, size_t errlen);
void target_free(Target *t);
/* Replace the ELF path (used by --binary overrides). */
void target_set_binary(Target *t, const char *path);

#endif
