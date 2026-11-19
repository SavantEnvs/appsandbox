/* squashfs reader (tools/iso-patch/engine/squashfs.c + the vendored xz-embedded decoder):
 * sqfs_open (superblock, id/fragment tables, inode + directory metadata streams), sqfs_walk
 * over the whole tree, and per regular file sqfs_read_file (data blocks + fragments) and
 * sqfs_read_capability (xattr table). Untrusted source: the Ubuntu ISO's filesystem.squashfs
 * that iso-patch unpacks into the ext4 guest disk. Built against mayhem/shim/windows.h. */
#include <stdarg.h>
#include "squashfs.h"
#include "log.h"
#include "tmpfile.h"

/* log.c is Win32-only (FormatMessage, GetLocalTime); squashfs.c only needs these sinks. */
void log_emit(log_level_t lvl, const char *file, int line, const char *fmt, ...) {
    (void)lvl; (void)file; (void)line;
    char buf[1024]; va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
}
void log_hex(log_level_t lvl, const char *label, const void *buf, size_t len) {
    (void)lvl; (void)label; (void)buf; (void)len;
}
void log_win32_fail(const char *file, int line, const char *call, DWORD err) {
    (void)file; (void)line; (void)call; (void)err;
}

static unsigned g_entries;

static int on_entry(const sqfs_entry_t *e, void *user) {
    sqfs_ctx_t *ctx = (sqfs_ctx_t *)user;
    if (++g_entries > 4096) return 1;
    if (e->type == SQFS_REG_TYPE || e->type == SQFS_EREG_TYPE) {
        void *buf = NULL; size_t n = 0;
        /* sqfs_read_file is a bulk read of the declared size; skip sizes no real seed has, so
         * a forged multi-GB size is not an allocator-limit report instead of a parser bug. */
        if (e->size <= (16u << 20) && sqfs_read_file(ctx, e, &buf, &n) == 0) free(buf);
        buf = NULL; n = 0;
        if (sqfs_read_capability(ctx, e, &buf, &n) == 0) free(buf);
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char path[512];
    if (fuzz_write_tmp(path, sizeof path, "sqfs", data, size) != 0) return 0;
    wchar_t wpath[512];
    if (mbstowcs(wpath, path, 512) < 512) {
        sqfs_ctx_t *ctx = sqfs_open(wpath);
        if (ctx) {
            (void)sqfs_sb(ctx);
            g_entries = 0;
            sqfs_walk(ctx, on_entry, ctx);
            sqfs_close(ctx);
        }
    }
    unlink(path);
    return 0;
}
