#include <assert.h>
//#include <pthread.h>
#include <stdint.h>

#include "common.h"
#include "func.h"

// include generic structures for diff-based fuzzing
#include "diff.h"



#ifndef CONFIG_USE_OPENSSL
// just in case openssl is not in the build
int ret_openssl = FAILURE_INTERNAL;
#endif

#define INCLUDE(name) \
static fp_t verify_cert_ ##name = NULL; \
static void *h_ ##name = NULL; \
int ret_ ##name = FAILURE_INTERNAL; \
uint8_t * cert_chain_ ##name = NULL; \
size_t cert_chain_sz_ ##name;

uint8_t * cert_chain_pem_init = NULL;
uint8_t * cert_chain_pem = NULL;
size_t cert_chain_sz_pem;

#ifdef CONFIG_USE_OPENSSL
#include "openssl.h"
INCLUDE(openssl)
#endif

#ifdef CONFIG_USE_LIBRESSL
#include "libressl.h"
INCLUDE(libressl)
#endif

#ifdef CONFIG_USE_BORINGSSL
#include "boringssl.h"
INCLUDE(boringssl)
#endif

#ifdef CONFIG_USE_WOLFSSL
#include "wolfssl.h"
INCLUDE(wolfssl)
#endif

#ifdef CONFIG_USE_MBEDTLS
#include "mbedtls.h"
INCLUDE(mbedtls)
#endif

#ifdef CONFIG_USE_GNUTLS
#include "gnutls.h"
INCLUDE(gnutls)
#endif


#define INIT_LIB(name, NAME) \
  if (!verify_cert_ ##name) { \
    verify_cert_ ##name = \
      (fp_t)get_interface_fn(h_ ##name, LIB_ ##NAME, FN_VERIFY_CERT); \
    fprintf(stderr, #name " %p\n", verify_cert_ ##name); \
    if (!verify_cert_ ##name) \
      DBG("ERROR resolving function from: %s\n", LIB_ ##NAME); \
  } \
  assert(verify_cert_ ##name != NULL); \
  total_libs++;

#define INIT_CERTS_DER(name) \
  cert_chain_sz_ ##name = cert_chain_sz_openssl; \
  cert_chain_ ##name = (uint8_t *)cert_chain_openssl;
#define INIT_CERTS_PEM(name) \
  cert_chain_sz_ ##name = cert_chain_sz_pem; \
  cert_chain_ ##name = cert_chain_pem;

#define FREE_LIB_CERTS(name) \
  FREE_PTR(cert_chain_ ##name)

#define VERIFY_ONE(name) \
  ret_ ##name = verify_cert_ ##name(cert_chain_ ##name, \
                                    cert_chain_sz_ ##name);


struct GlobalInitializer {
  GlobalInitializer() {

#ifdef CONFIG_USE_OPENSSL
    INIT_LIB(openssl, OPENSSL)
#endif
#ifdef CONFIG_USE_LIBRESSL
    INIT_LIB(libressl, LIBRESSL)
#endif
#ifdef CONFIG_USE_BORINGSSL
    INIT_LIB(boringssl, BORINGSSL)
#endif
#ifdef CONFIG_USE_WOLFSSL
    INIT_LIB(wolfssl, WOLFSSL)
#endif
#ifdef CONFIG_USE_MBEDTLS
    INIT_LIB(mbedtls, MBEDTLS)
#endif
#ifdef CONFIG_USE_GNUTLS
    INIT_LIB(gnutls, GNUTLS)
#endif

    // initialize all diff-based structures
    diff_init();
  }

    ~GlobalInitializer() { }
};

static GlobalInitializer g_initializer;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *cert_chain_openssl,
                                      size_t cert_chain_sz_openssl) {
#ifdef CONFIG_USE_OPENSSL
  //
  // OpenSSL will dump three files:
  // ca_chain.pem
  // leaf_cert.pem
  // full_pem_chain.pem
  //
  // We will always verify the leaf_cert against the ca_chain.
  //
  EXERCISE(openssl)
#endif
  
#ifdef CONFIG_USE_DER
  // allocate and do not free. There is a delete inside RunOne taking care of
  // this? strange bug ASAN does not report a memleak and things seem to run
  // properly
  cert_chain_sz_pem = read_file("full_pem_chain.pem", &cert_chain_pem_init);
  if (cert_chain_sz_pem == 0) {
    cert_chain_sz_pem = cert_chain_sz_openssl;
    cert_chain_pem = (uint8_t *)cert_chain_openssl;
  } else {
    cert_chain_pem = (uint8_t *)cert_chain_pem_init;
  }
#else
  // if we are in pem mode, use whatever works for openssl
  cert_chain_sz_pem = cert_chain_sz_openssl;
  cert_chain_pem = (uint8_t *)cert_chain_openssl;
#endif
  
#ifdef CONFIG_USE_LIBRESSL
  INIT_CERTS_DER(libressl)
  EXERCISE(libressl)
#endif
#ifdef CONFIG_USE_BORINGSSL
  INIT_CERTS_DER(boringssl)
  EXERCISE(boringssl)
#endif

#ifdef CONFIG_USE_WOLFSSL
  INIT_CERTS_PEM(wolfssl)
  EXERCISE(wolfssl)
#endif

#ifdef CONFIG_USE_MBEDTLS
  cert_chain_mbedtls = (uint8_t *) calloc(cert_chain_sz_pem + 1,
                                          sizeof(uint8_t));
  cert_chain_sz_mbedtls = cert_chain_sz_pem + 1;
  if (!cert_chain_mbedtls) {
    FREE_LIB_CERTS(mbedtls)
    return EXIT_FAILURE;
  }

  memcpy(cert_chain_mbedtls, cert_chain_pem, cert_chain_sz_pem);
  cert_chain_mbedtls[cert_chain_sz_pem] = '\0';
  cert_chain_sz_mbedtls = cert_chain_sz_pem + 1;
  
  EXERCISE(mbedtls)
  FREE_LIB_CERTS(mbedtls)
#endif

#ifdef CONFIG_USE_GNUTLS
  INIT_CERTS_PEM(gnutls)
  EXERCISE(gnutls)
#endif
  
  FREE_LIB_CERTS(pem_init)
  return 0;
}
