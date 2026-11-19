/* MCP JSON-RPC server (src/core/mcp_server.c, api_json.c, api_contract.c): the request
 * handler behind the app's local /mcp HTTP endpoint. Each input is one MCP conversation:
 * a fresh server, an initialize + notifications/initialized handshake, then every
 * '\n'-separated line of the input is POSTed as a JSON-RPC body on that session
 * (tools/list, tools/call argument/route/schema decoding, events_*, ping, ...).
 *
 * Kept per input: nothing. The server (sessions, catalog) is created and destroyed for
 * every input. Environment mocks: asb_mcp_api_request (mcp_http.c's TCP client to the
 * app's own REST port, a trusted peer) and the status-event source return canned JSON
 * instead of touching the network. */
#include "mcp_server.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int asb_mcp_api_request(unsigned port, const char *token, const char *method, const char *path,
                        const char *body, unsigned timeout, char **response) {
    (void)port; (void)token; (void)method; (void)path; (void)timeout;
    /* Reply like the REST API does: a JSON object (the forwarded body when it has one). */
    *response = strdup(body && body[0] == '{' ? body : "{\"ok\":true}");
    return *response ? 200 : 500;
}

static uint64_t ev_cursor(void *ctx) { (void)ctx; return 7; }
static int ev_read(void *ctx, uint64_t *cursor, unsigned timeout, unsigned limit, char **json) {
    (void)ctx; (void)timeout; (void)limit;
    *cursor += 1;
    *json = strdup("{\"events\":[{\"type\":\"vm_state\",\"vmId\":\"vm-0000000000000001\"}],\"droppedEvents\":0}");
    return 200;
}

static void post(AsbMcp *s, const char *session, const char *body, AsbMcpResponse *r) {
    asb_mcp_request(s, "POST", session, "2025-06-18", body, r);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65536) return -1;   /* the HTTP front end caps bodies at ASB_API_BODY_MAX (65535) */
    AsbMcpEvents ev = { NULL, ev_cursor, ev_read };
    AsbMcp *s = asb_mcp_create(51152, "fuzz-token", "1.0", &ev);
    if (!s) return 0;
    AsbMcpResponse r;
    post(s, NULL, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\"}}", &r);
    char session[33];
    memcpy(session, r.session, sizeof session);
    session[32] = 0;
    free(r.json);
    post(s, session, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}", &r);
    free(r.json);

    char *copy = malloc(size + 1);
    if (copy) {
        memcpy(copy, data, size);
        copy[size] = 0;
        char *save = NULL;
        int n = 0;
        for (char *line = strtok_r(copy, "\n", &save); line && n < 32; line = strtok_r(NULL, "\n", &save), n++) {
            post(s, session, line, &r);
            free(r.json);
        }
        free(copy);
    }
    asb_mcp_request(s, "DELETE", session, NULL, NULL, &r);
    free(r.json);
    asb_mcp_destroy(s);
    return 0;
}
