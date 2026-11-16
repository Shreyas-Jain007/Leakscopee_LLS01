#include "target.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"

#define MAX_REG_PARAMS 6   /* rdi, rsi, rdx, rcx, r8, r9 */

size_t param_secret_len(const Param *p) {
    if (!p->is_secret) return 0;
    return p->kind == KIND_INBUF ? p->size : 8;   /* int secret = 8 bytes */
}

size_t target_secret_len(const Target *t) {
    size_t n = 0;
    for (size_t i = 0; i < t->nparams; i++) n += param_secret_len(&t->params[i]);
    return n;
}

static bool get_uint(const JValue *v, uint64_t *out) {
    if (!v) return false;
    if (v->type == J_BOOL) { *out = v->b; return true; }
    if (v->type == J_NUM && v->is_int) { *out = (uint64_t)v->i; return true; }
    return false;
}

#define ERR(...) do { snprintf(err, errlen, __VA_ARGS__); goto fail; } while (0)

bool target_load(const char *manifest_path, Target *t, char *err, size_t errlen) {
    memset(t, 0, sizeof *t);
    char jerr[256];
    JValue *root = NULL;
    char *text = read_file(manifest_path, NULL);
    if (!text) {
        snprintf(err, errlen, "cannot read manifest %s: %s", manifest_path, strerror(errno));
        return false;
    }
    root = json_parse(text, jerr, sizeof jerr);
    free(text);
    if (!root) ERR("%s: invalid JSON: %s", manifest_path, jerr);
    if (root->type != J_OBJ) ERR("%s: manifest must be a JSON object", manifest_path);

    const char *name = json_str(json_get(root, "name"));
    const char *binary = json_str(json_get(root, "binary"));
    const JValue *entry = json_get(root, "entry");
    const JValue *params = json_get(root, "params");
    if (!name) ERR("%s: missing string field \"name\"", manifest_path);
    if (!binary) ERR("%s: missing string field \"binary\"", manifest_path);
    if (!entry) ERR("%s: missing field \"entry\"", manifest_path);
    if (!params || params->type != J_ARR) ERR("%s: missing array field \"params\"", manifest_path);

    t->name = xstrdup(name);
    if (entry->type == J_STR) t->entry = xstrdup(entry->str);
    else if (entry->type == J_NUM && entry->is_int) t->entry = xasprintf("%lld", (long long)entry->i);
    else ERR("%s: \"entry\" must be a symbol name or \"0x...\" address", manifest_path);

    {
        char *abs = path_abspath(manifest_path);
        t->manifest_dir = path_dirname(abs);
        free(abs);
    }
    t->binary_path = path_join(t->manifest_dir, binary);

    t->instr_budget = 200000;
    t->spec_window = 48;
    const JValue *jb = json_get(root, "instr_budget");
    const JValue *jw = json_get(root, "spec_window");
    if (jb && !get_uint(jb, &t->instr_budget)) ERR("%s: \"instr_budget\" must be an integer", manifest_path);
    if (jw && !get_uint(jw, &t->spec_window)) ERR("%s: \"spec_window\" must be an integer", manifest_path);
    if ((int64_t)t->instr_budget <= 0) ERR("%s: \"instr_budget\" must be positive", manifest_path);
    if ((int64_t)t->spec_window <= 0) ERR("%s: \"spec_window\" must be positive", manifest_path);

    if (params->n > MAX_REG_PARAMS)
        ERR("%s: at most %d register parameters are supported (got %zu)",
            manifest_path, MAX_REG_PARAMS, params->n);
    t->params = xcalloc(params->n ? params->n : 1, sizeof(Param));
    for (size_t i = 0; i < params->n; i++) {
        const JValue *pd = params->items[i];
        Param *p = &t->params[t->nparams++];
        if (pd->type != J_OBJ) ERR("%s: params[%zu] must be an object", manifest_path, i);
        const char *pname = json_str(json_get(pd, "name"));
        const char *role = json_str(json_get(pd, "role"));
        const char *kind = json_str(json_get(pd, "kind"));
        if (!pname || !role || !kind)
            ERR("%s: params[%zu] needs string \"name\", \"role\" and \"kind\"", manifest_path, i);
        p->name = xstrdup(pname);
        p->is_secret = strcmp(role, "secret") == 0;
        if (!p->is_secret && strcmp(role, "public") != 0)
            ERR("%s: params[%zu] role must be \"public\" or \"secret\"", manifest_path, i);
        if (strcmp(kind, "int") == 0) p->kind = KIND_INT;
        else if (strcmp(kind, "inbuf") == 0) p->kind = KIND_INBUF;
        else if (strcmp(kind, "outbuf") == 0) p->kind = KIND_OUTBUF;
        else ERR("%s: params[%zu] kind must be int, inbuf or outbuf", manifest_path, i);
        if (p->kind == KIND_OUTBUF && p->is_secret)
            ERR("%s: params[%zu]: an outbuf is always public", manifest_path, i);

        uint64_t size = 8;
        const JValue *js = json_get(pd, "size");
        if (js && !get_uint(js, &size)) ERR("%s: params[%zu] \"size\" must be an integer", manifest_path, i);
        if ((int64_t)size < 0 || size > (1u << 30))
            ERR("%s: params[%zu] \"size\" out of range", manifest_path, i);
        p->size = (size_t)size;

        const JValue *val = json_get(pd, "value");
        if (p->kind == KIND_INBUF && val && val->type == J_STR) {
            if (!hex_decode(val->str, &p->value_bytes))
                ERR("%s: params[%zu] \"value\" is not a hex string", manifest_path, i);
            p->has_bytes = true;
        } else if (val && get_uint(val, &p->value)) {
            p->has_value = true;
        }
    }
    json_free(root);
    return true;
fail:
    json_free(root);
    target_free(t);
    return false;
}

void target_free(Target *t) {
    for (size_t i = 0; i < t->nparams; i++) {
        free(t->params[i].name);
        bytes_free(&t->params[i].value_bytes);
    }
    free(t->params);
    free(t->name);
    free(t->binary_path);
    free(t->entry);
    free(t->manifest_dir);
    memset(t, 0, sizeof *t);
}

void target_set_binary(Target *t, const char *path) {
    free(t->binary_path);
    t->binary_path = xstrdup(path);
}
