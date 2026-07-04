#ifndef _LWIPOPTS_H
#define _LWIPOPTS_H

#include "lwipopts_examples_common.h"

/* TCP WND must be at least 16 kb to match TLS record size
   or you will get a warning "altcp_tls: TCP_WND is smaller than the RX decrypion buffer, connection RX might stall!" */
#undef TCP_WND
#define TCP_WND  32768

#define LWIP_ALTCP               1
#define LWIP_ALTCP_TLS           1
#define LWIP_ALTCP_TLS_MBEDTLS   1

#define LWIP_DEBUG 1
#define ALTCP_MBEDTLS_DEBUG  LWIP_DBG_ON

#undef MEM_SIZE
#define MEM_SIZE    (96 * 1024)
#define ALTCP_MBEDTLS_PRIVATE_MEM             1
#define ALTCP_MBEDTLS_MEM_NUM_CONTEXTS        1
#undef ALTCP_MBEDTLS_PRIVATE_MEM_SIZE
#define ALTCP_MBEDTLS_PRIVATE_MEM_SIZE    (64 * 1024)
#define ALTCP_MBEDTLS_MEM_INITIAL_ALLOC_SIZE   (40 * 1024)

#undef TCP_QUEUE_OOO
#define TCP_QUEUE_OOO               1
#undef TCP_SND_QUEUELEN
#define TCP_SND_QUEUELEN            (4 * TCP_SND_BUF / TCP_MSS)

#undef MEMP_NUM_ALTCP_TLS_CONTEXT
#define MEMP_NUM_ALTCP_TLS_CONTEXT             2

#endif

#undef CYW43_HOST_NAME
#define CYW43_HOST_NAME (machikania_hostname())
char* machikania_hostname(void);
