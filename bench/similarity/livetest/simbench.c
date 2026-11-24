/* simbench -- live smoke-test binary for function-similarity.
 *
 * Build with MinGW gcc -O2 (NO -g, NO -s): the symbol table is kept so IDA
 * reports real function names (free ground truth) while there is NO PDB and NO
 * DWARF debug info, so IDA still performs genuine CFG/function analysis.
 *
 *   gcc -O2 -o simbench.exe simbench.c
 *
 * Every function is __attribute__((noinline)) and reached through an indirect
 * path from main(), so -O2 keeps each as a distinct, analyzable function
 * (no inlining, no dead-code elimination).
 *
 * Designed similarity ground truth (matched by the names IDA recovers):
 *   sum_array      ~ sum_array_while, sum_array_ptr   (refactor twins)
 *   sum_array      !~ xor_array                        (same CFG, different op)
 *   parse_kv       ~ parse_kv_r                         (renamed/reordered twin)
 *   parse_kv       !~ parse_csv                         (shares APIs, different logic)
 *   crc32_bitwise  ~ crc32_lut                          (same identity, diff structure)
 *   crc32_bitwise  !~ adler32, fnv1a                    (checksum loops, diff constants)
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define NOINLINE __attribute__((noinline))

/* --- array reduce family: refactor twins + a structure hard-negative ------- */
NOINLINE long sum_array(const int *a, int n) {
    long s = 0;
    for (int i = 0; i < n; i++) s += a[i];
    return s;
}
NOINLINE long sum_array_while(const int *a, int n) {
    long s = 0; int i = 0;
    while (i < n) { s += a[i]; i++; }
    return s;
}
NOINLINE long sum_array_ptr(const int *base, int count) {
    long acc = 0; const int *p = base, *end = base + count;
    for (; p < end; ++p) acc += *p;
    return acc;
}
NOINLINE long xor_array(const int *a, int n) {   /* same loop shape, different op */
    long s = 0;
    for (int i = 0; i < n; i++) s ^= a[i];
    return s;
}
NOINLINE int max_array(const int *a, int n) {
    int m = a[0];
    for (int i = 1; i < n; i++) if (a[i] > m) m = a[i];
    return m;
}

/* --- parse family: shared libc API anchors (strchr/strtol/memcpy) ---------- */
NOINLINE int parse_kv(const char *s, char *key, long *val) {
    const char *eq = strchr(s, '=');
    if (!eq) return -1;
    size_t kl = (size_t)(eq - s);
    memcpy(key, s, kl); key[kl] = '\0';
    *val = strtol(eq + 1, NULL, 10);
    return 0;
}
NOINLINE int parse_kv_r(const char *line, char *out_key, long *out_num) {
    const char *sep = strchr(line, '=');
    if (sep == NULL) return -1;
    *out_num = strtol(sep + 1, NULL, 10);
    size_t n = (size_t)(sep - line);
    memcpy(out_key, line, n); out_key[n] = '\0';
    return 0;
}
NOINLINE long parse_csv(const char *s) {          /* shares APIs, different logic */
    long total = 0; const char *p = s;
    while (p && *p) {
        total += strtol(p, NULL, 10);
        const char *comma = strchr(p, ',');
        if (!comma) break;
        p = comma + 1;
    }
    return total;
}

/* --- checksum family: crc twins (Type-4) + constant-anchor hard-negatives -- */
NOINLINE uint32_t crc32_bitwise(const uint8_t *d, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= d[i];
        for (int k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1)));
    }
    return ~crc;
}
NOINLINE uint32_t crc32_lut(const uint8_t *d, size_t len) {
    uint32_t t[256];
    for (uint32_t n = 0; n < 256; n++) {
        uint32_t c = n;
        for (int k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        t[n] = c;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) crc = t[(crc ^ d[i]) & 0xFF] ^ (crc >> 8);
    return ~crc;
}
NOINLINE uint32_t adler32(const uint8_t *d, size_t len) {
    uint32_t s1 = 1, s2 = 0;
    for (size_t i = 0; i < len; i++) { s1 = (s1 + d[i]) % 65521u; s2 = (s2 + s1) % 65521u; }
    return (s2 << 16) | s1;
}
NOINLINE uint32_t fnv1a(const uint8_t *d, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) { h ^= d[i]; h *= 16777619u; }
    return h;
}

/* --- unrelated recursion --------------------------------------------------- */
NOINLINE long fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

/* keep every function live + defeat inlining/DCE */
static volatile long g_sink;

int main(void) {
    const int arr[8] = {5, 3, 8, 1, 9, 2, 7, 4};
    const uint8_t bytes[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    char kb[64]; long kv = 0;

    g_sink += sum_array(arr, 8);
    g_sink += sum_array_while(arr, 8);
    g_sink += sum_array_ptr(arr, 8);
    g_sink += xor_array(arr, 8);
    g_sink += max_array(arr, 8);
    g_sink += parse_kv("width=1024", kb, &kv) + kv;
    g_sink += parse_kv_r("height=768", kb, &kv) + kv;
    g_sink += parse_csv("10,20,30,40");
    g_sink += (long)crc32_bitwise(bytes, 8);
    g_sink += (long)crc32_lut(bytes, 8);
    g_sink += (long)adler32(bytes, 8);
    g_sink += (long)fnv1a(bytes, 8);
    g_sink += fib(10);

    printf("%ld\n", g_sink);
    return 0;
}
