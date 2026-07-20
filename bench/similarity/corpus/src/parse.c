/* Corpus family: parse_kv (+ refactor positive, API-anchor hard-negative).
 * These share imported APIs (strchr/strtol) to stress anchor-based methods. */

#include <stdlib.h>
#include <string.h>

/* parse_kv family — parse "key=<int>", write key and value out. */
int parse_kv(const char *s, char *key, long *val) {
    const char *eq = strchr(s, '=');
    if (!eq)
        return -1;
    size_t klen = (size_t)(eq - s);
    memcpy(key, s, klen);
    key[klen] = '\0';
    *val = strtol(eq + 1, NULL, 10);
    return 0;
}

/* Renamed vars + reordered statements (positive of parse_kv). */
int parse_kv_r(const char *line, char *out_key, long *out_num) {
    const char *sep = strchr(line, '=');
    if (sep == NULL)
        return -1;
    *out_num = strtol(sep + 1, NULL, 10);
    size_t n = (size_t)(sep - line);
    memcpy(out_key, line, n);
    out_key[n] = '\0';
    return 0;
}

/* Hard negative: shares strchr/strtol but sums a comma-separated int list.
 * An API-set-only method should wrongly match this to parse_kv. */
long parse_csv(const char *s) {
    long total = 0;
    const char *p = s;
    while (p && *p) {
        total += strtol(p, NULL, 10);
        const char *comma = strchr(p, ',');
        if (!comma)
            break;
        p = comma + 1;
    }
    return total;
}
