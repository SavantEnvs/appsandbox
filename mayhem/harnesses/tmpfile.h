/* Write a fuzz input to a private scratch file under $TMPDIR (default /tmp).
 * The engine APIs under test take a path (wim_open, sqfs_open, win_disk_build). */
#ifndef ASB_FUZZ_TMPFILE_H
#define ASB_FUZZ_TMPFILE_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fuzz_tmp_path(char *out, size_t cap, const char *tag) {
    const char *dir = getenv("TMPDIR");
    if (!dir || !*dir) dir = "/tmp";
    int n = snprintf(out, cap, "%s/asb-%s-XXXXXX", dir, tag);
    if (n < 0 || (size_t)n >= cap) return -1;
    int fd = mkstemp(out);
    if (fd < 0) return -1;
    return fd;
}

static int fuzz_write_tmp(char *out, size_t cap, const char *tag, const uint8_t *data, size_t size) {
    int fd = fuzz_tmp_path(out, cap, tag);
    if (fd < 0) return -1;
    size_t done = 0;
    while (done < size) {
        ssize_t w = write(fd, data + done, size - done);
        if (w <= 0) { close(fd); unlink(out); return -1; }
        done += (size_t)w;
    }
    close(fd);
    return 0;
}
#endif
