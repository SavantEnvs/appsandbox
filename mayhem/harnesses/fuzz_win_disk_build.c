/* win_disk_build (tools/iso-patch-mac/engine/win_disk.c): the end-to-end macOS Windows-disk
 * builder over a user-supplied install.wim. Opens the WIM and image 1, patches the image's
 * \Windows\System32\config\SYSTEM hive for vioscsi boot (windows_boot_vioscsi), writes a GPT,
 * applies the dentry tree into the NTFS writer (names, streams, security descriptors, reparse
 * points, hard links), stages the manifest (the two vioscsi driver files), then builds the
 * FAT32 ESP from \Windows\Boot\EFI and the BCD from \Windows\System32\config\BCD-Template
 * (bcd_build).
 *
 * win_disk_build is the body of a one-shot CLI: it keeps its state in file-scope statics (the
 * WIM/image handles, the hard-link/dir/SID maps, the error and file counters) and frees none of
 * it, and on its many early `return`s it also drops the image file handle, the FAT32 writer and
 * the buffers it read out of the WIM. So that every input starts from the same state and memory
 * does not pile up across inputs, this harness is a unity build of win_disk.c (unchanged; its
 * main() is behind WIN_DISK_STANDALONE, which stays undefined):
 *   - malloc/calloc/realloc/strdup/free in win_disk.c, and (via `-include alloc_track.h` on
 *     this target's objects) in ntfs.c, fat32.c, blockio.c and gpt.c, go through a tracker;
 *     whatever one build left allocated is freed after it (hard-link map, dir map and its keys,
 *     SID map, the buffers read out of the WIM, an NTFS/FAT32 writer an early return dropped,
 *     and the parts ntfs_writer_close/fat32_close themselves never free).
 *   - blockio_create/blockio_close/bcd_build call sites are routed through pass-through
 *     wrappers that only record the handle/buffer, so an image file left open by an early
 *     return is closed with upstream's own blockio_close, and the BCD freed.
 *   - the WIM image and WIM are closed with wim_image_close/wim_close, and every counter, flag
 *     and map pointer is reset to its load-time value.
 * No upstream behaviour changes: the wrappers call straight through.
 *
 * Kept across inputs on purpose (read-only after LLVMFuzzerInitialize): NTFS_THREADS=1 (one
 * extract worker, reproducible), and a scratch directory with the two vioscsi driver files the
 * manifest stages, so a well-formed WIM builds a complete disk (rc 0) instead of failing at the
 * staging step. Scratch files (input WIM, manifest, the sparse 1 GiB output image) live under
 * $TMPDIR and are removed after every input. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/stat.h>
#include "blockio.h"
#include "gpt.h"
#include "ntfs.h"
#include "fat32.h"
#include "bcd_patch.h"
#include "wim.h"
#include "wimimg.h"
#include "sha1.h"
#include "win_disk.h"
#include "tmpfile.h"

/* ---- allocation tracker (alloc_track.h): a pointer hash set; worker threads allocate too ---- */
#define TRK_TOMB ((void *)1)
static pthread_mutex_t trk_mtx = PTHREAD_MUTEX_INITIALIZER;
static void **trk_tab;
static size_t trk_cap, trk_used, trk_live;   /* used = live + tombstones */

static size_t trk_slot(void *p, size_t cap) {
    uint64_t h = (uint64_t)(uintptr_t)p;
    h ^= h >> 33; h *= 0xff51afd7ed558ccdull; h ^= h >> 33;
    return (size_t)h & (cap - 1);
}
static int trk_grow(void) {   /* caller holds trk_mtx */
    size_t ncap = trk_cap ? trk_cap : 4096;
    while ((trk_live + 1) * 4 >= ncap) ncap *= 2;
    void **nt = calloc(ncap, sizeof *nt);
    if (!nt) return -1;
    for (size_t i = 0; i < trk_cap; i++) {
        void *p = trk_tab[i];
        if (!p || p == TRK_TOMB) continue;
        size_t s = trk_slot(p, ncap);
        while (nt[s]) s = (s + 1) & (ncap - 1);
        nt[s] = p;
    }
    free(trk_tab);
    trk_tab = nt; trk_cap = ncap; trk_used = trk_live;
    return 0;
}
static void trk_add_locked(void *p) {
    if ((trk_used + 1) * 2 > trk_cap && trk_grow() != 0) return;
    size_t s = trk_slot(p, trk_cap);
    while (trk_tab[s] && trk_tab[s] != TRK_TOMB) s = (s + 1) & (trk_cap - 1);
    if (!trk_tab[s]) trk_used++;
    trk_tab[s] = p; trk_live++;
}
static void trk_del_locked(void *p) {   /* pointers allocated by untracked code are not found */
    if (!trk_cap) return;
    size_t s = trk_slot(p, trk_cap);
    while (trk_tab[s]) {
        if (trk_tab[s] == p) { trk_tab[s] = TRK_TOMB; trk_live--; return; }
        s = (s + 1) & (trk_cap - 1);
    }
}
static void trk_free_all(void) {
    pthread_mutex_lock(&trk_mtx);
    for (size_t i = 0; i < trk_cap; i++) {
        void *p = trk_tab[i];
        if (p && p != TRK_TOMB) free(p);
        trk_tab[i] = NULL;
    }
    trk_used = trk_live = 0;
    pthread_mutex_unlock(&trk_mtx);
}
void asb_trk_adopt(void *p) {
    if (!p) return;
    pthread_mutex_lock(&trk_mtx); trk_add_locked(p); pthread_mutex_unlock(&trk_mtx);
}
void *asb_trk_malloc(size_t n) { void *p = malloc(n); asb_trk_adopt(p); return p; }
void *asb_trk_calloc(size_t a, size_t b) { void *p = calloc(a, b); asb_trk_adopt(p); return p; }
char *asb_trk_strdup(const char *s) { char *p = strdup(s); asb_trk_adopt(p); return p; }
void *asb_trk_realloc(void *p, size_t n) {
    pthread_mutex_lock(&trk_mtx);
    void *q = realloc(p, n);
    if (q) { if (p) trk_del_locked(p); trk_add_locked(q); }
    pthread_mutex_unlock(&trk_mtx);
    return q;
}
void asb_trk_free(void *p) {
    if (!p) return;
    pthread_mutex_lock(&trk_mtx); trk_del_locked(p); pthread_mutex_unlock(&trk_mtx);
    free(p);
}

/* From here on malloc & co. in this file (win_disk.c below) are tracked. */
#include "alloc_track.h"

/* ---- pass-through wrappers at win_disk.c's call sites ---- */
static blockio_t *trk_io;   /* the image file: its fd must be closed, not just its memory freed */
static blockio_t *h_blockio_create(const char *path, uint64_t size) {
    blockio_t *io = blockio_create(path, size);
    trk_io = io;
    return io;
}
static int h_blockio_close(blockio_t *io) { if (io == trk_io) trk_io = NULL; return blockio_close(io); }
static int h_bcd_build(const uint8_t *tpl, size_t tpl_len, const bcd_guids_t *g,
                       uint8_t **out, size_t *out_len) {
    int r = bcd_build(tpl, tpl_len, g, out, out_len);
    if (r == 0) asb_trk_adopt(*out);   /* bcd_patch.c allocates it; win_disk_build never frees it */
    return r;
}

#define blockio_create   h_blockio_create
#define blockio_close    h_blockio_close
#define bcd_build        h_bcd_build
#include "../../tools/iso-patch-mac/engine/win_disk.c"
#undef malloc
#undef calloc
#undef realloc
#undef strdup
#undef free
#undef blockio_create
#undef blockio_close
#undef bcd_build

/* Return win_disk.c's statics to their load-time values. */
static void win_disk_reset(void) {
    if (trk_io) { (void)blockio_close(trk_io); trk_io = NULL; }   /* closes the fd */
    free(g_boot_system);   /* windows_boot_vioscsi's buffer (bcd_patch.c), dropped by early returns */
    g_boot_system = NULL; g_boot_system_len = 0; g_boot_system_written = 0;
    wim_image_close(IMG); IMG = NULL;
    if (W) { wim_close(W); W = NULL; }
    NW = NULL;
    trk_free_all();   /* everything else win_disk/ntfs/fat32/blockio/gpt left allocated */
    g_hl = NULL; g_dirmap = NULL; g_sidmap = NULL; g_nsd = 0; g_pw_seen = NULL;
    memset(&P, 0, sizeof P);
    g_dirs = g_files = g_empty = g_reparse = g_err = g_links = 0; g_bytes = 0;
    g_written = 0; g_total_bytes = 0; g_prog = NULL; g_mon_stop = 0; g_last_pct = 0;
    shared_sid = 0; g_dir_sid = 0; g_windows_ref = 0; g_ts_c = g_ts_a = g_ts_w = 0;
}

/* The vioscsi driver directory the manifest stages from (overridable by the repeat test). */
static char vioscsi_dir[512];
const char *asb_win_disk_vioscsi_dir = NULL;

static void rm_vioscsi_dir(void) {
    char p[600];
    snprintf(p, sizeof p, "%s/vioscsi.inf", vioscsi_dir); unlink(p);
    snprintf(p, sizeof p, "%s/vioscsi.cat", vioscsi_dir); unlink(p);
    rmdir(vioscsi_dir);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    setenv("NTFS_THREADS", "1", 1);
    unsetenv("WIN_DISK_DEBUG_SERIAL");
    const char *dir = getenv("TMPDIR");
    if (!dir || !*dir) dir = "/tmp";
    snprintf(vioscsi_dir, sizeof vioscsi_dir, "%s/asb-vioscsi-XXXXXX", dir);
    if (!mkdtemp(vioscsi_dir)) { snprintf(vioscsi_dir, sizeof vioscsi_dir, "/nonexistent-vioscsi"); return 0; }
    static const char inf[] = "[Version]\r\nSignature=\"$WINDOWS NT$\"\r\nClass=SCSIAdapter\r\n";
    static const char cat[] = "0\x82\x01\x00 vioscsi catalog placeholder";
    char p[600]; FILE *f;
    snprintf(p, sizeof p, "%s/vioscsi.inf", vioscsi_dir);
    if ((f = fopen(p, "wb"))) { fwrite(inf, 1, sizeof inf - 1, f); fclose(f); }
    snprintf(p, sizeof p, "%s/vioscsi.cat", vioscsi_dir);
    if ((f = fopen(p, "wb"))) { fwrite(cat, 1, sizeof cat - 1, f); fclose(f); }
    atexit(rm_vioscsi_dir);
    asb_win_disk_vioscsi_dir = vioscsi_dir;
    return 0;
}

/* One build over `data`; returns win_disk_build's rc (-1 if the scratch files can't be made). */
int asb_win_disk_run(const uint8_t *data, size_t size) {
    char wim[512], manifest[512], img[512];
    if (fuzz_write_tmp(wim, sizeof wim, "wim", data, size) != 0) return -1;
    int mfd = fuzz_tmp_path(manifest, sizeof manifest, "manifest");
    if (mfd < 0) { unlink(wim); return -1; }
    close(mfd);
    int ifd = fuzz_tmp_path(img, sizeof img, "disk");
    if (ifd < 0) { unlink(wim); unlink(manifest); return -1; }
    close(ifd);
    int rc = win_disk_build(wim, img, 1, 1, manifest,
                            asb_win_disk_vioscsi_dir ? asb_win_disk_vioscsi_dir : "/nonexistent-vioscsi", NULL);
    win_disk_reset();
    unlink(wim); unlink(manifest); unlink(img);
    return rc;
}

/* Allocations from win_disk.c still live (0 after every asb_win_disk_run). */
size_t asb_win_disk_live_allocs(void) {
    pthread_mutex_lock(&trk_mtx);
    size_t n = trk_live;
    pthread_mutex_unlock(&trk_mtx);
    return n;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)asb_win_disk_run(data, size);
    return 0;
}
