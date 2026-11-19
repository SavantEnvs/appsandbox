/* WIM container + image metadata: wim_open (header, lookup table, XML), then for each
 * image wim_image_open (metadata resource decompression via resource.c/lzx.c, SECURITYDATA)
 * and a bounded DIRENTRY tree walk (names, ADS, tagged items), mirroring upstream's
 * tools/iso-patch-mac/engine/test_wimimg.c. Small file resources are decompressed and
 * SHA-1'd as in test_resource.c. Untrusted source: the user-supplied ISO's install.wim. */
#include "wim.h"
#include "wimimg.h"
#include "sha1.h"
#include "tmpfile.h"

static unsigned long g_visits;

static void walk(wim_t *w, wim_image_t *img, uint64_t off, int depth) {
    if (depth > 32) return;                       /* same bound idea as test_wimimg.c (64) */
    for (int sib = 0; sib < 4096 && g_visits < 20000; sib++) {
        wim_dentry_t d;
        int r = wim_dentry_at(img, off, &d);
        if (r != 1) return;
        g_visits++;
        uint64_t it = d.tagged_offset; wim_tagged_t t; int n = 0;
        while (n++ < 256 && wim_dentry_tagged_next(img, &d, &it, &t) == 1) {}
        for (uint16_t i = 0; i < d.num_ads && i < 256; i++) {
            wim_ads_t a;
            if (wim_dentry_ads(img, &d, i, &a) == 0) (void)wim_lookup_by_hash(w, a.hash);
        }
        uint64_t sdl = 0;
        (void)wim_image_sd(img, d.security_id, &sdl);
        if (!(d.attributes & WIM_FILE_ATTRIBUTE_DIRECTORY)) {
            const wim_resource_t *res = wim_lookup_by_hash(w, d.hash);
            if (res && res->orig_size && res->orig_size <= (1u << 20)) {
                uint8_t *buf = malloc((size_t)res->orig_size);
                if (buf) {
                    if (wim_read_resource(w, res, buf) == 0) {
                        unsigned char h[20]; sha1(buf, (size_t)res->orig_size, h);
                    }
                    free(buf);
                }
            }
        } else if (d.subdir_offset && d.subdir_offset != off) {
            walk(w, img, d.subdir_offset, depth + 1);
        }
        if (d.length == 0) return;
        off = d.self_offset + d.length;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char path[512];
    if (fuzz_write_tmp(path, sizeof path, "wim", data, size) != 0) return 0;
    wim_t *w = wim_open(path);
    if (w) {
        uint32_t count = wim_image_count(w);
        (void)wim_compression(w); (void)wim_chunk_size(w); (void)wim_boot_index(w);
        for (uint32_t idx = 1; idx <= count && idx <= 4; idx++) {
            char lang[64];
            (void)wim_image_default_language(w, idx, lang, sizeof lang);
            (void)wim_image_total_bytes(w, idx);
            wim_image_t *img = wim_image_open(w, idx);
            if (!img) continue;
            (void)wim_image_sd_count(img);
            g_visits = 0;
            wim_dentry_t root;
            if (wim_dentry_at(img, wim_image_root_offset(img), &root) == 1 && root.subdir_offset)
                walk(w, img, root.subdir_offset, 0);
            wim_image_close(img);
        }
        wim_close(w);
    }
    unlink(path);
    return 0;
}
