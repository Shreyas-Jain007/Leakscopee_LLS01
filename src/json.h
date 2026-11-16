/* Minimal JSON reader (enough for manifests and EXPECTATIONS.json) and a
 * string escaper for the report writer. */
#ifndef LEAKSCOPE_JSON_H
#define LEAKSCOPE_JSON_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } JType;

typedef struct JValue JValue;
struct JValue {
    JType type;
    bool b;
    double num;
    bool is_int;          /* number was written without fraction/exponent */
    int64_t i;            /* valid when is_int */
    char *str;            /* J_STR (UTF-8, NUL-terminated) */
    /* J_ARR / J_OBJ: children in document order; keys[] used only by J_OBJ */
    JValue **items;
    char **keys;
    size_t n;
};

/* Parse text; on error returns NULL and writes a message into err. */
JValue *json_parse(const char *text, char *err, size_t errlen);
void json_free(JValue *v);

const JValue *json_get(const JValue *obj, const char *key);  /* NULL if absent */
const char *json_str(const JValue *v);                        /* NULL if not str */

/* Write s as a JSON string literal, ASCII-only like Python's json.dump. */
void json_write_str(FILE *f, const char *s);

#endif
