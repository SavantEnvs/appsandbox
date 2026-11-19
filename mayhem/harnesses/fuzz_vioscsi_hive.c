/* windows_boot_vioscsi (tools/iso-patch-mac/engine/bcd_patch.c): validates and patches the
 * SYSTEM registry hive (\Windows\System32\config\SYSTEM from the user-supplied install.wim)
 * to register the vioscsi boot-start driver: ControlSetNNN enumeration, key/value creation,
 * GroupOrderList tag allocation, DriverDatabase entries. "oem0.inf" is what win_disk.c
 * passes for an image with no OEM drivers yet. */
#include "bcd_patch.h"
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t *out = NULL; size_t out_len = 0;
    if (windows_boot_vioscsi(data, size, "oem0.inf", &out, &out_len) == 0) free(out);
    return 0;
}
