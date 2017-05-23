#include <assert.h>
#include <stdint.h>

// Nezha-specific header file
#include "nezha_diff.h"

// Generic interface to packages
typedef int (*fp_t)(const uint8_t *, uint32_t);

// Exported function name from SUT apps
#define FUNCNAME_VRFY_VER     "checkVer"

#ifndef CONFIG_USE_APP1
// just in case app1 is not in the build
int ret_app1 = FAILURE_INTERNAL;
#endif

#define INCLUDE(name) \
  static fp_t verify_ver_ ##name = NULL; \
  static void *h_ ##name = NULL; \
  int ret_ ##name = FAILURE_INTERNAL;

#ifdef CONFIG_USE_APP1
INCLUDE(app1)
const static char *LIB_APP1 = "lib/libapp1.so";
#endif

#ifdef CONFIG_USE_APP2
INCLUDE(app2)
const static char *LIB_APP2 = "lib/libapp2.so";
#endif

#define INIT_LIB(name, NAME) \
  if (!verify_ver_ ##name) { \
    verify_ver_ ##name = \
      (fp_t)get_interface_fn(h_ ##name, LIB_ ##NAME, FUNCNAME_VRFY_VER); \
    fprintf(stderr, #name " %p\n", verify_ver_ ##name); \
    if (!verify_ver_ ##name) { \
      printf("ERROR resolving function from: %s\n", LIB_ ##NAME); \
      exit(1); \
    } \
  } \
  assert(verify_ver_ ##name != NULL); \
  total_libs++;

#define VERIFY_ONE(name) \
  ret_ ##name = verify_ver_ ##name(data, size);


struct GlobalInitializer {
  GlobalInitializer() {

#ifdef CONFIG_USE_APP1
    INIT_LIB(app1, APP1)
#endif
#ifdef CONFIG_USE_APP2
    INIT_LIB(app2, APP2)
#endif

    // initialize all diff-based structures
    diff_init();
  }

    ~GlobalInitializer() { }
};

static GlobalInitializer g_initializer;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
#ifdef CONFIG_USE_APP1
  EXERCISE(app1)
#endif
#ifdef CONFIG_USE_APP2
  EXERCISE(app2)
#endif
  return 0;
}
