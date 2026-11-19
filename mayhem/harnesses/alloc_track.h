/* Allocation tracker for the fuzz-win-disk-build target (definitions in fuzz_win_disk_build.c).
 *
 * win_disk_build and the NTFS/FAT32/block-I/O writers it drives were written for a one-shot CLI:
 * they leave their state allocated on many paths (early returns, and ntfs_writer_close /
 * fat32_close do not free all of their writer). For this target only, those sources are
 * compiled with `-include alloc_track.h` (and win_disk.c is #included after it), so their
 * malloc/calloc/realloc/strdup/free go through the tracker and the harness frees whatever one
 * input left behind before the next. The real allocator does the work; nothing else changes. */
#ifndef ASB_ALLOC_TRACK_H
#define ASB_ALLOC_TRACK_H
/* Every system header these sources use, first, so the macros below never touch a libc
 * declaration. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/time.h>

void *asb_trk_malloc(size_t n);
void *asb_trk_calloc(size_t a, size_t b);
void *asb_trk_realloc(void *p, size_t n);
char *asb_trk_strdup(const char *s);
void  asb_trk_free(void *p);
void  asb_trk_adopt(void *p);   /* track a buffer allocated elsewhere */

#undef strdup
#define malloc(n)      asb_trk_malloc(n)
#define calloc(a, b)   asb_trk_calloc(a, b)
#define realloc(p, n)  asb_trk_realloc(p, n)
#define strdup(s)      asb_trk_strdup(s)
#define free(p)        asb_trk_free(p)
#endif
