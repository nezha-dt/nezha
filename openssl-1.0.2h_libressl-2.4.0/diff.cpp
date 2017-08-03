#include <assert.h>
//#include <pthread.h>
#include <dlfcn.h>
#include <stdint.h>

#include "common.h"
#include "func.h"

int total_libs = 0;

// Use dynamic loading of independent libraries to accommodate libraries that
// use the same API names.
void *get_interface_fn(void *handle, const char *libpath, const char *fname) {
  void *generic_fp;
  char *error;

  handle = dlopen(libpath, RTLD_LAZY);
  if (!handle) {
    DBG("cannot load library: %s\n", dlerror());
    return NULL;
  }

  generic_fp = dlsym(handle, fname);
  if ((error = dlerror()) != NULL)  {
    DBG("cannot resolve function: %s\n", error);
    return NULL;
  }

  return generic_fp;
}

// include generic structures for diff-based fuzzing
// #include "diff.h"

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
  verify_cert_ ##name(cert_chain_ ##name, cert_chain_sz_ ##name);


struct GlobalInitializer {
  GlobalInitializer() {

#ifdef CONFIG_USE_OPENSSL
    INIT_LIB(openssl, OPENSSL)
#endif
#ifdef CONFIG_USE_LIBRESSL
    INIT_LIB(libressl, LIBRESSL)
#endif

    // initialize all diff-based structures
    // diff_init();
  }

    ~GlobalInitializer() { }
};

static GlobalInitializer g_initializer;


typedef int (*UserCallback)(const uint8_t *Data, size_t Size);
struct UserCallbacks {
  UserCallback *callbacks;
  int size;
} callback_cont = { NULL, 0 };

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *cert_chain_openssl,
                                      size_t cert_chain_sz_openssl) {
  //
  // OpenSSL will dump three files:
  // ca_chain.pem
  // leaf_cert.pem
  // full_pem_chain.pem
  //
  // We will always verify the leaf_cert against the ca_chain.
  //
  return VERIFY_ONE(openssl)
}

extern "C" int Callback2(const uint8_t *cert_chain_openssl,
                         size_t cert_chain_sz_openssl) {

#ifdef CONFIG_USE_DER
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
  INIT_CERTS_DER(libressl)
  int ret = VERIFY_ONE(libressl)
  FREE_LIB_CERTS(pem_init)
  return ret;
}

UserCallback gl_callbacks[2] = { LLVMFuzzerTestOneInput, Callback2 };
extern "C" UserCallbacks *LLVMFuzzerCustomCallbacks() {
  callback_cont.callbacks = gl_callbacks;
  callback_cont.size = 2;
  return &callback_cont;
}

