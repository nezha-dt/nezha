#ifndef __LIBRESSL_H__
#define __LIBRESSL_H__

#include "common.h"


#ifdef CONFIG_USE_DER
const static char *LIB_LIBRESSL = "lib/liblibressl_der.so";
#else
const static char *LIB_LIBRESSL = "lib/liblibressl_pem.so";
#endif

extern "C"
int verify_cert_mem(const uint8_t *data_cert, uint32_t size_cert);
extern "C"
int verify_cert_mem_libressl(const uint8_t *data_cert, uint32_t size_cert);

#endif  //__LIBRESSL_H__
