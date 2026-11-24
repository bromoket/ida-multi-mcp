/* simbench_v2 -- redesigned similarity smoke corpus (feedback from the v1 ablation).
 *
 * v1 found several corpus artifacts that made signals untestable: libc APIs were
 * ubiquitous (api anchor inert), functions referenced no strings (str inert), and
 * the crc polynomial was sign-extended / folded so Type-4 twins shared no rare
 * constant. v2 fixes this so EACH signal is exercised, and adds a realistic
 * cross-optimization pair. Build with MinGW gcc -O2, then strip a copy.
 *
 * Designed ground-truth classes (mutual positives, matched by name in the
 * symbolized build, by VA in the stripped one):
 *   STR anchor      : parse_ipv4_a  ~ parse_ipv4_b   (share the "%u.%u.%u.%u" literal)
 *   API anchor      : sort_asc      ~ sort_desc      (both call qsort -- rare here)
 *   CONST/Type-4    : fnv_loop      ~ fnv_unrolled   (diff structure, share 0x01000193)
 *   CROSS-OPT       : mix_o2        ~ mix_o0         (identical source, -O2 vs -O0)
 *   STRUCTURE       : sum_array     ~ sum_array_while (anchor-less; tests denom fix)
 *   hard-negative   : xor_array     !~ sum_array      (same CFG, different op)
 *   distractor      : vm_exec        (large switch-VM, rich CFG, singleton)
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define NOINLINE __attribute__((noinline))
#define OPT0     __attribute__((optimize("O0"), noinline))

/* --- STR anchor: both reference the same distinctive format literal --------- */
NOINLINE int parse_ipv4_a(const char *s, unsigned char out[4]) {
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return -1;
    out[0] = (unsigned char)a; out[1] = (unsigned char)b;
    out[2] = (unsigned char)c; out[3] = (unsigned char)d;
    return 0;
}
NOINLINE int parse_ipv4_b(const char *txt, unsigned char *dst) {
    unsigned p, q, r, s;
    if (sscanf(txt, "%u.%u.%u.%u", &p, &q, &r, &s) != 4) return -1;
    dst[0] = (unsigned char)p; dst[1] = (unsigned char)q;
    dst[2] = (unsigned char)r; dst[3] = (unsigned char)s;
    return 0;
}

/* --- API anchor: both call qsort (a rare import in this binary) ------------- */
static int cmp_asc(const void *x, const void *y) { return *(const int *)x - *(const int *)y; }
static int cmp_desc(const void *x, const void *y) { return *(const int *)y - *(const int *)x; }
NOINLINE void sort_asc(int *a, size_t n) { qsort(a, n, sizeof(int), cmp_asc); }
NOINLINE void sort_desc(int *a, size_t n) { qsort(a, n, sizeof(int), cmp_desc); }

/* --- CONST anchor / Type-4: shared FNV prime immediate, different structure - */
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

/* --- CROSS-OPT: identical source body, compiled at -O2 vs -O0 --------------- */
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

/* --- STRUCTURE: anchor-less twins + a same-CFG different-op hard-negative --- */
NOINLINE long sum_array(const int *a, int n) { long s = 0; for (int i = 0; i < n; i++) s += a[i]; return s; }
NOINLINE long sum_array_while(const int *a, int n) { long s = 0; int i = 0; while (i < n) { s += a[i]; i++; } return s; }
NOINLINE long xor_array(const int *a, int n) { long s = 0; for (int i = 0; i < n; i++) s ^= a[i]; return s; }

/* --- LARGE: switch-based mini-VM (rich CFG), singleton distractor ----------- */
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
    int buf[8];
    const uint8_t bytes[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    unsigned char ip[4];
    memcpy(buf, arr, sizeof arr);

    g_sink += parse_ipv4_a("10.0.0.1", ip) + ip[3];
    g_sink += parse_ipv4_b("192.168.1.7", ip) + ip[0];
    sort_asc(buf, 8);  g_sink += buf[0];
    sort_desc(buf, 8); g_sink += buf[0];
    g_sink += (long)fnv_loop(bytes, 8);
    g_sink += (long)fnv_unrolled(bytes, 8);
    g_sink += (long)mix_o2(0x1234);
    g_sink += (long)mix_o0(0x1234);
    g_sink += sum_array(arr, 8);
    g_sink += sum_array_while(arr, 8);
    g_sink += xor_array(arr, 8);
    g_sink += vm_exec(bytes, 8);

    printf("%ld\n", g_sink);
    return 0;
}
