#include "key_agent_service_rpc_shim.h"

#include <stdlib.h>
#include <string.h>
#include <windows.h>

typedef char ywkas_rpc_frame_size_must_be_76[
    (sizeof(YWKAS_RPC_FRAME) == 76U) ? 1 : -1];
typedef char ywkas_rpc_frame_payload_must_follow_length[
    (FIELD_OFFSET(YWKAS_RPC_FRAME, payload) == 4U) ? 1 : -1];

enum {
    YWKAS_HANDLER_EMPTY = 0,
    YWKAS_HANDLER_INSTALLING = 1,
    YWKAS_HANDLER_READY = 2
};

static volatile LONG ywkas_handler_state = YWKAS_HANDLER_EMPTY;
static YWKAS_RPC_EXCHANGE_HANDLER ywkas_handler = NULL;

static void ywkas_zero_frame(YWKAS_RPC_FRAME *frame)
{
    if (frame != NULL) {
        (void)memset(frame, 0, sizeof(*frame));
    }
}

static int ywkas_frame_is_valid(const YWKAS_RPC_FRAME *frame)
{
    unsigned long index;

    if (frame == NULL || frame->length > YWKAS_RPC_FRAME_CAPACITY) {
        return 0;
    }
    for (index = frame->length; index < YWKAS_RPC_FRAME_CAPACITY; ++index) {
        if (frame->payload[index] != 0U) {
            return 0;
        }
    }
    return 1;
}

static error_status_t ywkas_client_status_from_exception(DWORD code)
{
    if (RpcExceptionFilter(code) == EXCEPTION_EXECUTE_HANDLER) {
        return (error_status_t)code;
    }

    /* Unexpected native corruption must not unwind across the Rust FFI. */
    RaiseFailFastException(NULL, NULL, 0);
    return RPC_S_CALL_FAILED;
}

static error_status_t ywkas_server_status_from_exception(DWORD code)
{
    if (RpcExceptionFilter(code) == EXCEPTION_EXECUTE_HANDLER) {
        return RPC_S_CALL_FAILED;
    }

    /* Unexpected native corruption must not unwind across the Rust FFI. */
    RaiseFailFastException(NULL, NULL, 0);
    return RPC_S_CALL_FAILED;
}

void *__RPC_USER MIDL_user_allocate(size_t size)
{
    return malloc(size);
}

void __RPC_USER MIDL_user_free(void *allocation)
{
    free(allocation);
}

RPC_IF_HANDLE ywkas_rpc_client_ifspec(void)
{
    return YwkasRpcClient_YwkasRpc_v1_0_c_ifspec;
}

RPC_IF_HANDLE ywkas_rpc_server_ifspec(void)
{
    return YwkasRpcServer_YwkasRpc_v1_0_s_ifspec;
}

error_status_t ywkas_rpc_client_exchange(
    handle_t binding,
    const YWKAS_RPC_FRAME *request,
    YWKAS_RPC_FRAME *response)
{
    error_status_t status = RPC_S_INVALID_ARG;

    if (binding == NULL || !ywkas_frame_is_valid(request) || response == NULL) {
        ywkas_zero_frame(response);
        return RPC_S_INVALID_ARG;
    }

    ywkas_zero_frame(response);

    RpcTryExcept
    {
        status = YwkasRpcClient_Exchange(binding, request, response);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        status = ywkas_client_status_from_exception(RpcExceptionCode());
    }
    RpcEndExcept

    if (status != RPC_S_OK) {
        ywkas_zero_frame(response);
        return status;
    }
    if (!ywkas_frame_is_valid(response)) {
        ywkas_zero_frame(response);
        return RPC_X_BAD_STUB_DATA;
    }

    return RPC_S_OK;
}

error_status_t ywkas_rpc_install_server_handler(
    YWKAS_RPC_EXCHANGE_HANDLER handler)
{
    if (handler == NULL) {
        return RPC_S_INVALID_ARG;
    }

    if (InterlockedCompareExchange(
            &ywkas_handler_state,
            YWKAS_HANDLER_INSTALLING,
            YWKAS_HANDLER_EMPTY) != YWKAS_HANDLER_EMPTY) {
        return RPC_S_ALREADY_REGISTERED;
    }

    ywkas_handler = handler;
    MemoryBarrier();
    (void)InterlockedExchange(&ywkas_handler_state, YWKAS_HANDLER_READY);
    return RPC_S_OK;
}

error_status_t YwkasRpcServer_Exchange(
    handle_t binding,
    const YWKAS_RPC_FRAME *request,
    YWKAS_RPC_FRAME *response)
{
    YWKAS_RPC_EXCHANGE_HANDLER handler;
    YWKAS_RPC_FRAME candidate;
    error_status_t status;

    (void)binding;
    ywkas_zero_frame(response);
    (void)memset(&candidate, 0, sizeof(candidate));

    if (!ywkas_frame_is_valid(request) || response == NULL) {
        return RPC_S_INVALID_ARG;
    }

    if (InterlockedCompareExchange(
            &ywkas_handler_state,
            YWKAS_HANDLER_READY,
            YWKAS_HANDLER_READY) != YWKAS_HANDLER_READY) {
        return RPC_S_SERVER_UNAVAILABLE;
    }

    handler = ywkas_handler;
    if (handler == NULL) {
        return RPC_S_SERVER_UNAVAILABLE;
    }

    __try
    {
        status = handler(binding, request, &candidate);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        status = ywkas_server_status_from_exception(GetExceptionCode());
    }

    if (status != RPC_S_OK) {
        return status;
    }
    if (!ywkas_frame_is_valid(&candidate)) {
        return RPC_S_INVALID_ARG;
    }

    *response = candidate;
    return RPC_S_OK;
}
