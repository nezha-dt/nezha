#ifndef __OPENSSL_H__
#define __OPENSSL_H__

#include "common.h"


#ifdef CONFIG_USE_DER
const static char *LIB_OPENSSL = "lib/libopenssl_der.so";
#else
const static char *LIB_OPENSSL = "lib/libopenssl_pem.so";
#endif

extern "C"
int verify_cert_mem(const uint8_t *data_cert, uint32_t size_cert);
extern "C"
int verify_cert_mem_openssl(const uint8_t *data_cert, uint32_t size_cert);

#endif  //__OPENSSL_H__
