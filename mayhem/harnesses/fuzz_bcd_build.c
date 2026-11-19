/* bcd_build (tools/iso-patch-mac/engine/bcd_patch.c): parses the regf hive
 * \Windows\System32\config\BCD-Template taken from the user-supplied ISO's install.wim,
 * finds the boot-manager / OS-loader / resume objects, and rewrites it into a live BCD
 * (new hbin, nk/vk/lf cells, checksum). GUIDs are the fixed pattern upstream's
 * test_bcd.c uses. */
#include "bcd_patch.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    bcd_guids_t g;
    for (int i = 0; i < 16; i++) { g.disk_guid[i] = 0xD0 + i; g.esp_part_guid[i] = 0xE0 + i; g.win_part_guid[i] = 0x10 + i; }
    uint8_t *out = NULL; size_t out_len = 0;
    if (bcd_build(data, size, &g, &out, &out_len) == 0) free(out);
    return 0;
}
