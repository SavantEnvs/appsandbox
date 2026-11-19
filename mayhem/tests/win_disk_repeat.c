/* Repeat check for the fuzz-win-disk-build harness (mayhem/harnesses/fuzz_win_disk_build.c):
 * the same WIM built several times in ONE process must give the same rc every time, including
 * right after a build that failed (an error used to stick in win_disk.c's g_err), and must leave
 * no win_disk.c allocation behind.
 *
 *   win_disk_repeat <good.wim> <bad.wim>
 * prints one "run <label> rc=<rc> live=<n>" line per build. Sequence:
 *   good, good, bad, good (vioscsi dir missing -> staging errors), good */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int asb_win_disk_run(const uint8_t *data, size_t size);
size_t asb_win_disk_live_allocs(void);
extern const char *asb_win_disk_vioscsi_dir;

static uint8_t *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END); long len = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(len > 0 ? (size_t)len : 1);
    if (!b || fread(b, 1, (size_t)len, f) != (size_t)len) { perror(path); exit(2); }
    fclose(f); *n = (size_t)len; return b;
}

static void run(const char *label, const uint8_t *d, size_t n) {
    int rc = asb_win_disk_run(d, n);
    printf("run %s rc=%d live=%zu\n", label, rc, asb_win_disk_live_allocs());
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s <good.wim> <bad.wim>\n", argv[0]); return 2; }
    LLVMFuzzerInitialize(&argc, &argv);
    size_t gn, bn;
    uint8_t *good = slurp(argv[1], &gn), *bad = slurp(argv[2], &bn);
    run("good1", good, gn);
    run("good2", good, gn);
    run("bad", bad, bn);
    run("good3", good, gn);
    const char *saved = asb_win_disk_vioscsi_dir;
    asb_win_disk_vioscsi_dir = "/nonexistent-vioscsi";
    run("staging-error", good, gn);
    asb_win_disk_vioscsi_dir = saved;
    run("good4", good, gn);
    free(good); free(bad);
    return 0;
}
