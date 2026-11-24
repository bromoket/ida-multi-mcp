/* Corpus family: crc32 (Type-4 hard positive: two very different structures,
 * same identity) + adler32 constant-anchor hard-negative. */

#include <stddef.h>
#include <stdint.h>

/* crc32 family, impl A: bitwise reflected CRC-32, no table. */
uint32_t crc32_bitwise(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1)));
    }
    return ~crc;
}

/* crc32 family, impl B: table-driven reflected CRC-32 (same output as impl A,
 * but an extra table-build loop -> very different CFG). Type-4 hard positive. */
uint32_t crc32_lut(const uint8_t *data, size_t len) {
    uint32_t table[256];
    for (uint32_t n = 0; n < 256; n++) {
        uint32_t c = n;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        table[n] = c;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

/* Hard negative: also a byte-loop checksum, but different constants/logic.
 * Defeats "this looks like a hash loop, must be crc32". */
uint32_t adler32(const uint8_t *data, size_t len) {
    uint32_t s1 = 1, s2 = 0;
    for (size_t i = 0; i < len; i++) {
        s1 = (s1 + data[i]) % 65521u;
        s2 = (s2 + s1) % 65521u;
    }
    return (s2 << 16) | s1;
}
