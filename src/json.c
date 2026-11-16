#include "json.h"

#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

typedef struct {
    const char *p;
    const char *start;
    char *err;
    size_t errlen;
    bool failed;
    int depth;
} Parser;

static void fail(Parser *ps, const char *msg) {
    if (ps->failed) return;
    ps->failed = true;
    /* report line:col of the failure point */
    int line = 1, col = 1;
    for (const char *q = ps->start; q < ps->p; q++) {
        if (*q == '\n') { line++; col = 1; } else col++;
    }
    snprintf(ps->err, ps->errlen, "%s at line %d column %d", msg, line, col);
}

static void skip_ws(Parser *ps) {
    while (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r') ps->p++;
}

static JValue *new_val(JType t) {
    JValue *v = xcalloc(1, sizeof *v);
    v->type = t;
    return v;
}

static void put_utf8(char **buf, size_t *len, size_t *cap, uint32_t cp) {
    if (*len + 5 > *cap) { *cap = *cap * 2 + 8; *buf = xrealloc(*buf, *cap); }
    char *o = *buf + *len;
    if (cp < 0x80) { o[0] = (char)cp; *len += 1; }
    else if (cp < 0x800) { o[0] = (char)(0xC0 | cp >> 6); o[1] = (char)(0x80 | (cp & 63)); *len += 2; }
    else if (cp < 0x10000) {
        o[0] = (char)(0xE0 | cp >> 12); o[1] = (char)(0x80 | ((cp >> 6) & 63));
        o[2] = (char)(0x80 | (cp & 63)); *len += 3;
    } else {
        o[0] = (char)(0xF0 | cp >> 18); o[1] = (char)(0x80 | ((cp >> 12) & 63));
        o[2] = (char)(0x80 | ((cp >> 6) & 63)); o[3] = (char)(0x80 | (cp & 63)); *len += 4;
    }
}

static int hex4(const char *p, uint32_t *out) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        char c = p[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (uint32_t)(c - 'A' + 10);
        else return -1;
    }
    *out = v;
    return 0;
}

static char *parse_string_raw(Parser *ps) {
    /* assumes *ps->p == '"' */
    ps->p++;
    size_t cap = 32, len = 0;
    char *buf = xmalloc(cap);
    for (;;) {
        unsigned char c = (unsigned char)*ps->p;
        if (c == 0) { fail(ps, "unterminated string"); free(buf); return NULL; }
        if (c == '"') { ps->p++; break; }
        if (c < 0x20) { fail(ps, "control character in string"); free(buf); return NULL; }
        if (c == '\\') {
            ps->p++;
            char e = *ps->p++;
            uint32_t cp;
            switch (e) {
            case '"': cp = '"'; break;
            case '\\': cp = '\\'; break;
            case '/': cp = '/'; break;
            case 'b': cp = '\b'; break;
            case 'f': cp = '\f'; break;
            case 'n': cp = '\n'; break;
            case 'r': cp = '\r'; break;
            case 't': cp = '\t'; break;
            case 'u':
                if (hex4(ps->p, &cp)) { fail(ps, "bad \\u escape"); free(buf); return NULL; }
                ps->p += 4;
                if (cp >= 0xD800 && cp < 0xDC00 && ps->p[0] == '\\' && ps->p[1] == 'u') {
                    uint32_t lo;
                    if (!hex4(ps->p + 2, &lo) && lo >= 0xDC00 && lo < 0xE000) {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        ps->p += 6;
                    }
                }
                break;
            default:
                fail(ps, "bad escape");
                free(buf);
                return NULL;
            }
            put_utf8(&buf, &len, &cap, cp);
            continue;
        }
        if (len + 2 > cap) { cap *= 2; buf = xrealloc(buf, cap); }
        buf[len++] = (char)c;
        ps->p++;
    }
    if (len + 1 > cap) buf = xrealloc(buf, len + 1);
    buf[len] = 0;
    return buf;
}

static JValue *parse_value(Parser *ps);

static JValue *parse_number(Parser *ps) {
    const char *s = ps->p;
    bool is_int = true;
    if (*ps->p == '-') ps->p++;
    if (!isdigit((unsigned char)*ps->p)) { fail(ps, "bad number"); return NULL; }
    while (isdigit((unsigned char)*ps->p)) ps->p++;
    if (*ps->p == '.') {
        is_int = false;
        ps->p++;
        if (!isdigit((unsigned char)*ps->p)) { fail(ps, "bad number"); return NULL; }
        while (isdigit((unsigned char)*ps->p)) ps->p++;
    }
    if (*ps->p == 'e' || *ps->p == 'E') {
        is_int = false;
        ps->p++;
        if (*ps->p == '+' || *ps->p == '-') ps->p++;
        if (!isdigit((unsigned char)*ps->p)) { fail(ps, "bad number"); return NULL; }
        while (isdigit((unsigned char)*ps->p)) ps->p++;
    }
    JValue *v = new_val(J_NUM);
    char *tmp = xmalloc((size_t)(ps->p - s) + 1);
    memcpy(tmp, s, (size_t)(ps->p - s));
    tmp[ps->p - s] = 0;
    v->num = strtod(tmp, NULL);
    if (is_int) {
        /* parse via unsigned so values up to 2^64-1 survive (pointers etc.) */
        bool neg = tmp[0] == '-';
        uint64_t u = strtoull(neg ? tmp + 1 : tmp, NULL, 10);
        v->i = neg ? (int64_t)(0 - u) : (int64_t)u;
        v->is_int = true;
    }
    free(tmp);
    return v;
}

static bool match_lit(Parser *ps, const char *lit) {
    size_t n = strlen(lit);
    if (strncmp(ps->p, lit, n) == 0) { ps->p += n; return true; }
    return false;
}

static void push_child(JValue *v, char *key, JValue *child) {
    v->items = xrealloc(v->items, (v->n + 1) * sizeof(JValue *));
    v->items[v->n] = child;
    if (v->type == J_OBJ) {
        v->keys = xrealloc(v->keys, (v->n + 1) * sizeof(char *));
        v->keys[v->n] = key;
    }
    v->n++;
}

static JValue *parse_value(Parser *ps) {
    if (++ps->depth > 200) { fail(ps, "nesting too deep"); return NULL; }
    skip_ws(ps);
    JValue *v = NULL;
    char c = *ps->p;
    if (c == '{') {
        ps->p++;
        v = new_val(J_OBJ);
        skip_ws(ps);
        if (*ps->p == '}') { ps->p++; goto done; }
        for (;;) {
            skip_ws(ps);
            if (*ps->p != '"') { fail(ps, "expected string key"); goto bad; }
            char *key = parse_string_raw(ps);
            if (!key) goto bad;
            skip_ws(ps);
            if (*ps->p != ':') { free(key); fail(ps, "expected ':'"); goto bad; }
            ps->p++;
            JValue *child = parse_value(ps);
            if (!child) { free(key); goto bad; }
            /* duplicate keys: last one wins, as in Python */
            bool replaced = false;
            for (size_t i = 0; i < v->n; i++) {
                if (strcmp(v->keys[i], key) == 0) {
                    json_free(v->items[i]);
                    v->items[i] = child;
                    free(key);
                    replaced = true;
                    break;
                }
            }
            if (!replaced) push_child(v, key, child);
            skip_ws(ps);
            if (*ps->p == ',') { ps->p++; continue; }
            if (*ps->p == '}') { ps->p++; break; }
            fail(ps, "expected ',' or '}'");
            goto bad;
        }
    } else if (c == '[') {
        ps->p++;
        v = new_val(J_ARR);
        skip_ws(ps);
        if (*ps->p == ']') { ps->p++; goto done; }
        for (;;) {
            JValue *child = parse_value(ps);
            if (!child) goto bad;
            push_child(v, NULL, child);
            skip_ws(ps);
            if (*ps->p == ',') { ps->p++; continue; }
            if (*ps->p == ']') { ps->p++; break; }
            fail(ps, "expected ',' or ']'");
            goto bad;
        }
    } else if (c == '"') {
        char *s = parse_string_raw(ps);
        if (!s) return NULL;
        v = new_val(J_STR);
        v->str = s;
    } else if (c == '-' || isdigit((unsigned char)c)) {
        v = parse_number(ps);
    } else if (match_lit(ps, "true")) {
        v = new_val(J_BOOL);
        v->b = true;
    } else if (match_lit(ps, "false")) {
        v = new_val(J_BOOL);
    } else if (match_lit(ps, "null")) {
        v = new_val(J_NULL);
    } else {
        fail(ps, "unexpected character");
    }
done:
    ps->depth--;
    return v;
bad:
    json_free(v);
    return NULL;
}

JValue *json_parse(const char *text, char *err, size_t errlen) {
    Parser ps = { text, text, err, errlen, false, 0 };
    if (errlen) err[0] = 0;
    JValue *v = parse_value(&ps);
    if (v) {
        skip_ws(&ps);
        if (*ps.p) {
            fail(&ps, "trailing data");
            json_free(v);
            return NULL;
        }
    }
    return v;
}

void json_free(JValue *v) {
    if (!v) return;
    for (size_t i = 0; i < v->n; i++) {
        json_free(v->items[i]);
        if (v->keys) free(v->keys[i]);
    }
    free(v->items);
    free(v->keys);
    free(v->str);
    free(v);
}

const JValue *json_get(const JValue *obj, const char *key) {
    if (!obj || obj->type != J_OBJ) return NULL;
    for (size_t i = 0; i < obj->n; i++)
        if (strcmp(obj->keys[i], key) == 0) return obj->items[i];
    return NULL;
}

const char *json_str(const JValue *v) { return v && v->type == J_STR ? v->str : NULL; }

/* Decode one UTF-8 sequence; on malformed input yield U+FFFD and advance 1. */
static uint32_t utf8_next(const unsigned char **pp) {
    const unsigned char *p = *pp;
    uint32_t cp;
    int n;
    if (p[0] < 0x80) { *pp = p + 1; return p[0]; }
    if ((p[0] & 0xE0) == 0xC0) { cp = p[0] & 0x1F; n = 1; }
    else if ((p[0] & 0xF0) == 0xE0) { cp = p[0] & 0x0F; n = 2; }
    else if ((p[0] & 0xF8) == 0xF0) { cp = p[0] & 0x07; n = 3; }
    else { *pp = p + 1; return 0xFFFD; }
    for (int i = 1; i <= n; i++) {
        if ((p[i] & 0xC0) != 0x80) { *pp = p + 1; return 0xFFFD; }
        cp = cp << 6 | (p[i] & 0x3F);
    }
    *pp = p + n + 1;
    return cp;
}

void json_write_str(FILE *f, const char *s) {
    fputc('"', f);
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        unsigned char c = *p;
        if (c == '"') { fputs("\\\"", f); p++; }
        else if (c == '\\') { fputs("\\\\", f); p++; }
        else if (c == '\n') { fputs("\\n", f); p++; }
        else if (c == '\r') { fputs("\\r", f); p++; }
        else if (c == '\t') { fputs("\\t", f); p++; }
        else if (c == '\b') { fputs("\\b", f); p++; }
        else if (c == '\f') { fputs("\\f", f); p++; }
        else if (c < 0x20) { fprintf(f, "\\u%04x", c); p++; }
        else if (c < 0x80) { fputc(c, f); p++; }
        else {
            uint32_t cp = utf8_next(&p);
            if (cp >= 0x10000) {
                cp -= 0x10000;
                fprintf(f, "\\u%04x\\u%04x", 0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF));
            } else {
                fprintf(f, "\\u%04x", cp);
            }
        }
    }
    fputc('"', f);
}
