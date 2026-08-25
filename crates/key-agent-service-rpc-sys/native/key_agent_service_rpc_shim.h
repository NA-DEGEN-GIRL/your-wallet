#ifndef YWKAS_KEY_AGENT_SERVICE_RPC_SHIM_H
#define YWKAS_KEY_AGENT_SERVICE_RPC_SHIM_H

#include "key_agent_service_rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef error_status_t(RPC_ENTRY *YWKAS_RPC_EXCHANGE_HANDLER)(
    handle_t call_binding,
    const YWKAS_RPC_FRAME *request,
    YWKAS_RPC_FRAME *response);

RPC_IF_HANDLE ywkas_rpc_client_ifspec(void);
RPC_IF_HANDLE ywkas_rpc_server_ifspec(void);

error_status_t ywkas_rpc_client_exchange(
    handle_t binding,
    const YWKAS_RPC_FRAME *request,
    YWKAS_RPC_FRAME *response);

/*
 * Installs exactly one process-lifetime manager callback. There is
 * intentionally no unregister operation: the callback must remain valid until
 * RPC has stopped, all calls have drained, and the process exits.
 */
error_status_t ywkas_rpc_install_server_handler(
    YWKAS_RPC_EXCHANGE_HANDLER handler);

#ifdef __cplusplus
}
#endif

#endif
