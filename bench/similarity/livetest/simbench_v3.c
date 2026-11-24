/* simbench_v3 -- corpus gen 3 (feedback from the v2/v5 ablation).
 *
 * Fixes the two gaps v2 exposed:
 *  - API class now calls a distinctive Win32 IAT import (VirtualAlloc) inside
 *    NON-thunk functions, so the `api` anchor (which captures __imp_* imports)
 *    is actually exercised. v2's `qsort` was statically linked -> classified
 *    "internal" (missed by the external-only api signal) and the sort wrappers
 *    were 2-BB thunks (empty minhash) so candidate-gen never surfaced them.
 *  - more members per class (STR / STRUCT = 3) for a little more statistical
 *    power (12 queries vs 10).
 * Keeps the classes that already worked: CONST/T4 (fnv), CROSS-OPT (mix), STRUCT.
 *
 * Build: gcc -O2 -o simbench_v3.exe simbench_v3.c ; then strip a copy.
 */

#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define NOINLINE __attribute__((noinline))
#define OPT0     __attribute__((optimize("O0"), noinline))

/* --- API anchor: distinctive Win32 import (__imp_VirtualAlloc), non-thunk --- */
NOINLINE void *alloc_zero(size_t n) {
    void *p = VirtualAlloc(NULL, n, MEM_COMMIT, PAGE_READWRITE);
    if (!p) return NULL;
    memset(p, 0, n);
    return p;
}
NOINLINE void *alloc_zero_r(size_t sz) {
    if (sz == 0) return NULL;
    void *m = VirtualAlloc(0, sz, MEM_COMMIT, PAGE_READWRITE);
    if (m) memset(m, 0, sz);
    return m;
}

/* --- STR anchor: shared "%u.%u.%u.%u" literal, 3 members ------------------- */
NOINLINE int parse_ipv4_a(const char *s, unsigned char o[4]) {
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return -1;
    o[0] = (unsigned char)a; o[1] = (unsigned char)b;
    o[2] = (unsigned char)c; o[3] = (unsigned char)d;
    return 0;
}
NOINLINE int parse_ipv4_b(const char *t, unsigned char *p) {
    unsigned w, x, y, z;
    if (sscanf(t, "%u.%u.%u.%u", &w, &x, &y, &z) != 4) return -1;
    p[0] = (unsigned char)w; p[1] = (unsigned char)x;
    p[2] = (unsigned char)y; p[3] = (unsigned char)z;
    return 0;
}
NOINLINE int parse_ipv4_c(const char *in, unsigned char *out) {
    unsigned q[4];
    if (sscanf(in, "%u.%u.%u.%u", &q[0], &q[1], &q[2], &q[3]) != 4) return -1;
    for (int i = 0; i < 4; i++) out[i] = (unsigned char)q[i];
    return 0;
}

/* --- CONST/T4: shared FNV prime immediate, different structure ------------- */
NOINLINE uint32_t fnv_loop(const uint8_t *d, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) { h ^= d[i]; h *= 0x01000193u; }
    return h;
}
NOINLINE uint32_t fnv_unrolled(const uint8_t *d, size_t n) {
    uint32_t h = 2166136261u;
    size_t i = 0;
    for (; i + 4 <= n; i += 4) {
        h = (h ^ d[i]) * 0x01000193u;
        h = (h ^ d[i + 1]) * 0x01000193u;
        h = (h ^ d[i + 2]) * 0x01000193u;
        h = (h ^ d[i + 3]) * 0x01000193u;
    }
    for (; i < n; i++) h = (h ^ d[i]) * 0x01000193u;
    return h;
}

/* --- CROSS-OPT: identical source, -O2 vs -O0 ------------------------------- */
NOINLINE uint32_t mix_o2(uint32_t x) {
    uint32_t s = 0;
    for (int i = 0; i < 8; i++) { s += 0x9E3779B9u; x ^= (x << 4) + s; x ^= (x >> 5) + s; }
    return x;
}
OPT0 uint32_t mix_o0(uint32_t x) {
    uint32_t s = 0;
    for (int i = 0; i < 8; i++) { s += 0x9E3779B9u; x ^= (x << 4) + s; x ^= (x >> 5) + s; }
    return x;
}

/* --- STRUCT: anchor-less, 3 members + a hard-negative --------------------- */
NOINLINE long sum_array(const int *a, int n) { long s = 0; for (int i = 0; i < n; i++) s += a[i]; return s; }
NOINLINE long sum_array_while(const int *a, int n) { long s = 0; int i = 0; while (i < n) { s += a[i]; i++; } return s; }
NOINLINE long sum_array_ptr(const int *b, int c) { long acc = 0; const int *p = b, *e = b + c; for (; p < e; ++p) acc += *p; return acc; }
NOINLINE long xor_array(const int *a, int n) { long s = 0; for (int i = 0; i < n; i++) s ^= a[i]; return s; }  /* hard-neg */

/* --- large distractor ------------------------------------------------------ */
NOINLINE long vm_exec(const uint8_t *code, size_t n) {
    long acc = 0, reg = 0;
    for (size_t i = 0; i < n; i++) {
        switch (code[i] & 7) {
            case 0: acc += reg; break;
            case 1: acc -= reg; break;
            case 2: reg = acc ^ 0x5bd1e995; break;
            case 3: acc <<= 1; break;
            case 4: acc = (acc >> 3) | (acc << 29); break;
            case 5: reg += (long)code[i]; break;
            case 6: if (acc > reg) acc = reg; else reg = acc; break;
            default: acc = ~acc; break;
        }
    }
    return acc + reg;
}

static volatile long g_sink;

int main(void) {
    const int arr[8] = {5, 3, 8, 1, 9, 2, 7, 4};
    const uint8_t by[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    unsigned char ip[4];

    void *p = alloc_zero(64);  g_sink += (long)(size_t)p; if (p) VirtualFree(p, 0, MEM_RELEASE);
    void *q = alloc_zero_r(128); g_sink += (long)(size_t)q; if (q) VirtualFree(q, 0, MEM_RELEASE);
    g_sink += parse_ipv4_a("10.0.0.1", ip) + ip[0];
    g_sink += parse_ipv4_b("192.168.1.1", ip) + ip[1];
    g_sink += parse_ipv4_c("172.16.0.9", ip) + ip[2];
    g_sink += (long)fnv_loop(by, 8);  g_sink += (long)fnv_unrolled(by, 8);
    g_sink += (long)mix_o2(0x1234);   g_sink += (long)mix_o0(0x1234);
    g_sink += sum_array(arr, 8); g_sink += sum_array_while(arr, 8);
    g_sink += sum_array_ptr(arr, 8); g_sink += xor_array(arr, 8);
    g_sink += vm_exec(by, 8);

    printf("%ld\n", g_sink);
    return 0;
}
