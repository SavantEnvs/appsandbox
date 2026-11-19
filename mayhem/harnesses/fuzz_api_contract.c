/* REST API request validation (src/core/api_contract.c + api_json.c): what the app's local
 * /v1 HTTP API runs on every request before dispatching it. Input layout:
 *   byte 0         : method selector (GET/POST/PUT/DELETE)
 *   up to '\n'     : request path (e.g. /v1/vms/vm-.../input, snapshots/3/branches/1)
 *   rest           : JSON body
 * The body is widened byte-for-byte to the NUL-terminated wchar_t text the API code takes.
 * Exercises asb_api_validate_request (catalog route match + JSON-schema check + input
 * action parsing), asb_api_validate_body/start, the headless and snapshot route parsers,
 * asb_api_parse_input, and the api_json_get_* helpers. No state is kept across inputs. */
#include "api_contract.h"
#include "api_json.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char *const methods[] = { "GET", "POST", "PUT", "DELETE" };

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > ASB_API_BODY_MAX + 2048) return -1;
    const char *method = methods[data[0] & 3];
    data++; size--;
    const uint8_t *nl = memchr(data, '\n', size);
    size_t plen = nl ? (size_t)(nl - data) : 0;
    if (plen >= 2048) return -1;
    char path[2048];
    memcpy(path, data, plen); path[plen] = 0;
    const uint8_t *b = nl ? nl + 1 : data;
    size_t blen = size - (size_t)(b - data);

    wchar_t *wpath = calloc(plen + 1, sizeof(wchar_t));
    wchar_t *body = calloc(blen + 1, sizeof(wchar_t));
    if (!wpath || !body) { free(wpath); free(body); return 0; }
    for (size_t i = 0; i < plen; i++) wpath[i] = (unsigned char)path[i];
    for (size_t i = 0; i < blen; i++) body[i] = (unsigned char)b[i];

    (void)asb_api_validate_request(method, path, body);
    (void)asb_api_validate_start(body);
    uint64_t sid = 0;
    (void)asb_api_headless_route(method, wpath, &sid);
    int snap = 0, branch = 0;
    (void)asb_api_snapshot_route(method, wpath, &snap, &branch);
    (void)asb_api_parse_port(wpath);
    (void)asb_api_guest_os(body);

    ApiJsonToken *tokens = calloc(8192, sizeof(*tokens));
    ApiJson json;
    if (tokens && api_json_parse(&json, body, tokens, 8192)) {
        AsbApiInputAction actions[128];
        memset(actions, 0, sizeof actions);
        int count = 0;
        (void)asb_api_parse_input(&json, actions, &count);
        for (int i = 0; i < count && i < 128; i++) free(actions[i].text);
    }
    free(tokens);

    wchar_t out[512]; int iv = 0;
    (void)api_json_get_string(body, L"name", out, 512);
    (void)api_json_get_string(body, L"osType", out, 32);
    (void)api_json_get_int(body, L"ramMb", &iv);
    (void)api_json_get_bool(body, L"force", &iv);
    (void)api_json_has_key(body, L"actions");

    free(wpath); free(body);
    return 0;
}
