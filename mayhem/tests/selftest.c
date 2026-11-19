/* Known-answer checks for the engines upstream ships no Linux test for (squashfs reader,
 * SYSTEM-hive vioscsi patch, BCD build, MCP server, REST validation). Built with normal
 * flags by mayhem/build.sh; run by mayhem/test.sh. Prints one "ok"/"FAIL" line per check and
 * a final "SELFTEST passed=P failed=F" line. Usage: selftest <fixture dir>, where the dir
 * holds sqfs_xz.sqfs, system.hive and bcd.hive (the committed seed files). */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "squashfs.h"
#include "log.h"
#include "bcd_patch.h"
#include "sha1.h"
#include "mcp_server.h"
#include "api_contract.h"

void log_emit(log_level_t l, const char *f, int n, const char *fmt, ...) { (void)l; (void)f; (void)n; (void)fmt; }
void log_hex(log_level_t l, const char *s, const void *b, size_t n) { (void)l; (void)s; (void)b; (void)n; }
void log_win32_fail(const char *f, int n, const char *c, DWORD e) { (void)f; (void)n; (void)c; (void)e; }
int asb_mcp_api_request(unsigned port, const char *token, const char *method, const char *path,
                        const char *body, unsigned timeout, char **response) {
    (void)port; (void)token; (void)timeout;
    char buf[1024];
    snprintf(buf, sizeof buf, "{\"method\":\"%s\",\"path\":\"%s\",\"body\":%s}", method, path, body);
    *response = strdup(buf);
    return 201;
}

/* Expected values for the committed fixtures (the committed seed files). */
#define BCD_GOLDEN_SHA1 "6eb6fc071a0fd9b746be8d57a10ddfd52893bc80"
#define SQFS_EXPECTED_ENTRIES 11   /* /, etc, hostname, usr, bin, tool, link, ping, var, empty, fifo */

static int passed, failed;
static void check(int cond, const char *what) {
    if (cond) { passed++; printf("ok   %s\n", what); }
    else { failed++; printf("FAIL %s\n", what); }
}
static uint8_t *slurp(const char *dir, const char *name, size_t *len) {
    char p[1024]; snprintf(p, sizeof p, "%s/%s", dir, name);
    FILE *f = fopen(p, "rb"); if (!f) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc((size_t)n + 1);
    if (!b || fread(b, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(b); return NULL; }
    fclose(f); *len = (size_t)n; return b;
}
static int contains(const uint8_t *h, size_t n, const char *needle) {
    size_t k = strlen(needle);
    for (size_t i = 0; i + k <= n; i++) if (!memcmp(h + i, needle, k)) return 1;
    return 0;
}
static void hexdigest(const uint8_t *b, size_t n, char out[41]) {
    uint8_t d[20]; sha1(b, n, d);
    for (int i = 0; i < 20; i++) sprintf(out + 2 * i, "%02x", d[i]);
}

/* ---- squashfs ---- */
struct walk { sqfs_ctx_t *ctx; int entries, hostname_ok, tool_ok, link_ok, cap_ok, fifo_ok; };
static int on_entry(const sqfs_entry_t *e, void *u) {
    struct walk *w = u; w->entries++;
    if (!strcmp(e->path, "/etc/hostname")) {
        void *b = NULL; size_t n = 0;
        w->hostname_ok = sqfs_read_file(w->ctx, e, &b, &n) == 0 && n == 7 && !memcmp(b, "ubuntu\n", 7);
        free(b);
    } else if (!strcmp(e->path, "/usr/bin/tool")) {
        void *b = NULL; size_t n = 0;
        if (sqfs_read_file(w->ctx, e, &b, &n) == 0 && n == e->size && n > 9000) {
            char d[41]; hexdigest(b, n, d);
            w->tool_ok = ((uint8_t *)b)[0] == 'x' && ((uint8_t *)b)[8999] == 'x' && !memcmp((uint8_t *)b + n - 5, "2999\n", 5);
        }
        free(b);
    } else if (!strcmp(e->path, "/usr/bin/link")) {
        w->link_ok = e->symlink_target && e->symlink_target_size == 13 && !memcmp(e->symlink_target, "/usr/bin/tool", 13);
    } else if (!strcmp(e->path, "/usr/bin/ping")) {
        void *b = NULL; size_t n = 0;
        w->cap_ok = sqfs_read_capability(w->ctx, e, &b, &n) == 0 && n == 20 && ((uint8_t *)b)[0] == 0x01 && ((uint8_t *)b)[3] == 0x02;
        free(b);
    } else if (!strcmp(e->path, "/var/fifo")) {
        w->fifo_ok = e->type == SQFS_FIFO_TYPE || e->type == SQFS_EFIFO_TYPE;
    }
    return 0;
}
static void test_squashfs(const char *dir) {
    char p[1024]; wchar_t wp[1024];
    snprintf(p, sizeof p, "%s/sqfs_xz.sqfs", dir);
    mbstowcs(wp, p, 1024);
    sqfs_ctx_t *ctx = sqfs_open(wp);
    check(ctx != NULL, "squashfs: sqfs_open(sqfs_xz.sqfs)");
    if (!ctx) return;
    check(sqfs_sb(ctx)->compression_id == SQFS_COMP_XZ && sqfs_sb(ctx)->block_size == 4096, "squashfs: superblock xz/4096");
    struct walk w = { ctx };
    check(sqfs_walk(ctx, on_entry, &w) == 0, "squashfs: sqfs_walk succeeds");
    printf("     squashfs walk visited %d entries\n", w.entries);
    check(w.entries == SQFS_EXPECTED_ENTRIES, "squashfs: walk visits every entry");
    check(w.hostname_ok, "squashfs: /etc/hostname == \"ubuntu\\n\"");
    check(w.tool_ok, "squashfs: /usr/bin/tool multi-block + fragment content");
    check(w.link_ok, "squashfs: /usr/bin/link -> /usr/bin/tool");
    check(w.cap_ok, "squashfs: /usr/bin/ping security.capability xattr (v2, 20 bytes)");
    check(w.fifo_ok, "squashfs: /var/fifo is a FIFO");
    sqfs_close(ctx);
}

/* ---- registry hives ---- */
static void test_hives(const char *dir) {
    size_t n = 0; uint8_t *sys = slurp(dir, "system.hive", &n);
    check(sys != NULL, "vioscsi: read system.hive");
    if (sys) {
        uint8_t *out = NULL; size_t olen = 0;
        int rc = windows_boot_vioscsi(sys, n, "oem0.inf", &out, &olen);
        check(rc == 0, "vioscsi: windows_boot_vioscsi rc == 0");
        if (rc == 0) {
            check(olen > n && !memcmp(out, "regf", 4), "vioscsi: output hive grew");
            check(contains(out, olen, "vioscsi") && contains(out, olen, "SCSI miniport") &&
                  contains(out, olen, ASB_VIOSCSI_DRIVER_PACKAGE), "vioscsi: service + driver package keys present");
            uint32_t s = 0; for (int i = 0; i < 127; i++) { uint32_t v; memcpy(&v, out + 4 * i, 4); s ^= v; }
            uint32_t stored; memcpy(&stored, out + 0x1FC, 4);
            check(stored == (s ? s : 1), "vioscsi: base-block checksum");
            uint8_t *again = NULL; size_t alen = 0;
            check(windows_boot_vioscsi(out, olen, "oem0.inf", &again, &alen) != 0, "vioscsi: re-patching the same INF is refused");
            free(again); free(out);
        }
        out = NULL;
        check(windows_boot_vioscsi(sys, 0x1000, "oem0.inf", &out, &olen) != 0, "vioscsi: truncated hive rejected");
        free(sys);
    }
    uint8_t *tpl = slurp(dir, "bcd.hive", &n);
    check(tpl != NULL, "bcd: read bcd.hive");
    if (tpl) {
        bcd_guids_t g;
        for (int i = 0; i < 16; i++) { g.disk_guid[i] = 0xD0 + i; g.esp_part_guid[i] = 0xE0 + i; g.win_part_guid[i] = 0x10 + i; }
        uint8_t *out = NULL; size_t olen = 0;
        int rc = bcd_build(tpl, n, &g, &out, &olen);
        check(rc == 0, "bcd: bcd_build rc == 0");
        if (rc == 0) {
            char d[41]; hexdigest(out, olen, d);
            printf("     bcd output %zu bytes sha1 %s\n", olen, d);
            check(olen == 20480, "bcd: output size 20480");
            check(!strcmp(d, BCD_GOLDEN_SHA1), "bcd: output matches golden SHA-1");
            check(contains(out, olen, "{a5a30fa2-3d06-4e9f-b5f4-a01df9d1fcba}"), "bcd: {fwbootmgr} object created");
            free(out);
        }
        tpl[0] = 'x';
        check(bcd_build(tpl, n, &g, &out, &olen) == -1, "bcd: bad magic rejected");
        free(tpl);
    }
}

/* ---- MCP server ---- */
static void test_mcp(void) {
    AsbMcp *s = asb_mcp_create(51152, "tok", "9.9", NULL);
    check(s != NULL, "mcp: asb_mcp_create");
    if (!s) return;
    AsbMcpResponse r;
    asb_mcp_request(s, "POST", NULL, "2025-06-18", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\"}}", &r);
    check(r.status == 200 && strlen(r.session) == 32, "mcp: initialize -> 200 + 32-char session");
    check(r.json && strstr(r.json, "\"protocolVersion\":\"2025-06-18\"") && strstr(r.json, "\"version\":\"9.9\""), "mcp: initialize echoes protocol + server version");
    char sid[33]; memcpy(sid, r.session, 33); free(r.json);
    asb_mcp_request(s, "POST", sid, NULL, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}", &r);
    check(r.json && strstr(r.json, "Send notifications/initialized"), "mcp: tools/list before initialized is refused");
    free(r.json);
    asb_mcp_request(s, "POST", sid, NULL, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}", &r);
    check(r.status == 202, "mcp: notification -> 202");
    free(r.json);
    asb_mcp_request(s, "POST", sid, NULL, "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\"}", &r);
    check(r.json && strstr(r.json, "\"vm_create\"") && strstr(r.json, "\"events_subscribe\""), "mcp: tools/list lists vm_create + events_subscribe");
    free(r.json);
    asb_mcp_request(s, "POST", sid, NULL, "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"snapshot_delete_branch\",\"arguments\":{\"vm_id\":\"vm-0000000000000001\",\"snapshot_index\":2,\"branch_index\":1}}}", &r);
    check(r.json && strstr(r.json, "/vm-ids/vm-0000000000000001/snapshots/2/branches/1"), "mcp: tools/call builds the REST route");
    free(r.json);
    asb_mcp_request(s, "POST", sid, NULL, "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"vm_status\",\"arguments\":{\"vm_id\":\"vm-XYZ\"}}}", &r);
    check(r.json && strstr(r.json, "Invalid, missing, or unexpected tool arguments"), "mcp: bad vm_id rejected");
    free(r.json);
    asb_mcp_request(s, "POST", sid, NULL, "{\"jsonrpc\":\"2.0\",\"id\":6,", &r);
    check(r.status == 400 && r.json && strstr(r.json, "-32700"), "mcp: malformed JSON -> 400 / -32700");
    free(r.json);
    asb_mcp_request(s, "POST", "ffffffffffffffffffffffffffffffff", NULL, "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}", &r);
    check(r.status == 404, "mcp: unknown session -> 404");
    free(r.json);
    asb_mcp_destroy(s);
}

/* ---- REST validation ---- */
static void test_api(void) {
    check(asb_api_validate_body(L"{\"ramMb\":4096,\"name\":\"x\"}") == 1, "api: valid body accepted");
    check(asb_api_validate_body(L"{\"ramMb\":\"lots\"}") == 0, "api: string ramMb rejected");
    check(asb_api_validate_body(L"{\"a\":1,\"a\":2}") == 0, "api: duplicate key rejected");
    check(asb_api_validate_request("POST", "/v1/vms/vm-00000000000000ab/input",
          L"{\"actions\":[{\"type\":\"click\",\"x\":1,\"y\":1,\"width\":10,\"height\":10}]}") == 1, "api: input request accepted");
    check(asb_api_validate_request("POST", "/v1/vms/vm-00000000000000ab/input",
          L"{\"actions\":[{\"type\":\"click\",\"x\":10,\"y\":1,\"width\":10,\"height\":10}]}") == 0, "api: out-of-bounds click rejected");
    int snap = 0, branch = 0;
    check(asb_api_snapshot_route("DELETE", L"snapshots/3/branches/1", &snap, &branch) == 5 && snap == 3 && branch == 1, "api: snapshot branch route");
    check(asb_api_snapshot_route("PUT", L"snapshots/x", &snap, &branch) == -1, "api: bad snapshot index");
    uint64_t id = 0;
    const wchar_t *op = asb_api_headless_route("POST", L"ssh/sessions/ssh-00000000000000ff", &id);
    check(op && !wcscmp(op, L"ssh_write") && id == 255, "api: ssh session route");
    check(asb_api_validate_start(L"{\"branchIndex\":1}") == 0, "api: branch without snapshot rejected");
    check(asb_api_parse_port(L"51152") == 51152 && asb_api_parse_port(L"70000") == 0, "api: port parsing");
}

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : ".";
    test_squashfs(dir);
    test_hives(dir);
    test_mcp();
    test_api();
    printf("SELFTEST passed=%d failed=%d\n", passed, failed);
    return failed ? 1 : 0;
}
