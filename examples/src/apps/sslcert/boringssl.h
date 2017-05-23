#ifndef __BORINGSSL_H__
#define __BORINGSSL_H__

#include "common.h"

#ifdef CONFIG_USE_DER
const static char *LIB_BORINGSSL = "lib/libboringssl_der.so";
#else
const static char *LIB_BORINGSSL = "lib/libboringssl_pem.so";
#endif

extern "C"
int verify_cert_mem(const uint8_t *data_cert, uint32_t size_cert);
extern "C"
int verify_cert_mem_boringssl(const uint8_t *data_cert, uint32_t size_cert);

#endif  //__BORINGSSL_H__
