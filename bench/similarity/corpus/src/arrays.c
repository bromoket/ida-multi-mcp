/* Corpus family: sum_array (+ refactor positives, structure hard-negative, distractor).
 * All functions are leaf loops so codegen differences dominate across -O0..-O3. */

/* sum_array family — three hand-authored equivalents (mutual positives). */

long sum_array(const int *a, int n) {
    long s = 0;
    for (int i = 0; i < n; i++)
        s += a[i];
    return s;
}

/* for -> while refactor */
long sum_array_while(const int *a, int n) {
    long s = 0;
    int i = 0;
    while (i < n) {
        s += a[i];
        i++;
    }
    return s;
}

/* index -> pointer walk refactor, renamed vars */
long sum_array_ptr(const int *base, int count) {
    long acc = 0;
    const int *p = base;
    const int *end = base + count;
    for (; p < end; ++p)
        acc += *p;
    return acc;
}

/* Hard negative for sum_array: identical loop/CFG shape, different operation.
 * A structure-only method should wrongly match this to sum_array. */
long xor_array(const int *a, int n) {
    long s = 0;
    for (int i = 0; i < n; i++)
        s ^= a[i];
    return s;
}

/* Distractor: different family (conditional inside the loop -> different CFG). */
int max_array(const int *a, int n) {
    int m = a[0];
    for (int i = 1; i < n; i++) {
        if (a[i] > m)
            m = a[i];
    }
    return m;
}
