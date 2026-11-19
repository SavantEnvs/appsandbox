/* lzx_decompress (tools/iso-patch-mac/engine/lzx.c): one WIM LZX chunk, as resource.c calls
 * it for every compressed chunk of an install.wim. The first two input bytes choose the
 * declared uncompressed chunk size (1..32768, the contract in lzx.h); the rest is the
 * compressed chunk. */
#include "lzx.h"
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return -1;
    size_t out_size = ((size_t)data[0] | ((size_t)data[1] << 8)) % 32768 + 1;
    uint8_t *out = malloc(out_size);
    if (!out) return 0;
    (void)lzx_decompress(data + 2, size - 2, out, out_size);
    free(out);
    return 0;
}
