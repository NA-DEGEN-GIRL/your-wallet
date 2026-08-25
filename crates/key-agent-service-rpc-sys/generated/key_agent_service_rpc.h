

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0628 */
/* at Tue Jan 19 12:14:07 2038
 */
/* Compiler settings for idl\key_agent_service_rpc.idl, idl\key_agent_service_rpc.acf:
    Oicf, W4, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0628 
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#pragma warning( disable: 4049 )  /* more than 64k source lines */


/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 475
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */


#ifndef __key_agent_service_rpc_h__
#define __key_agent_service_rpc_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifndef DECLSPEC_XFGVIRT
#if defined(_CONTROL_FLOW_GUARD_XFG)
#define DECLSPEC_XFGVIRT(base, func) __declspec(xfg_virtual(base, func))
#else
#define DECLSPEC_XFGVIRT(base, func)
#endif
#endif

/* Forward Declarations */ 

#ifdef __cplusplus
extern "C"{
#endif 


#ifndef __YwkasRpc_INTERFACE_DEFINED__
#define __YwkasRpc_INTERFACE_DEFINED__

/* interface YwkasRpc */
/* [explicit_handle][ref][version][uuid] */ 

#define	YWKAS_RPC_FRAME_CAPACITY	( 72 )

typedef struct _YWKAS_RPC_FRAME
    {
    unsigned long length;
    byte payload[ 72 ];
    } 	YWKAS_RPC_FRAME;

/* client prototype */
/* [fault_status][comm_status] */ error_status_t YwkasRpcClient_Exchange( 
    /* [in] */ handle_t binding,
    /* [in] */ const YWKAS_RPC_FRAME *request,
    /* [out] */ YWKAS_RPC_FRAME *response);
/* server prototype */
/* [fault_status][comm_status] */ error_status_t YwkasRpcServer_Exchange( 
    /* [in] */ handle_t binding,
    /* [in] */ const YWKAS_RPC_FRAME *request,
    /* [out] */ YWKAS_RPC_FRAME *response);



extern RPC_IF_HANDLE YwkasRpcClient_YwkasRpc_v1_0_c_ifspec;
extern RPC_IF_HANDLE YwkasRpc_v1_0_c_ifspec;
extern RPC_IF_HANDLE YwkasRpcServer_YwkasRpc_v1_0_s_ifspec;
#endif /* __YwkasRpc_INTERFACE_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


