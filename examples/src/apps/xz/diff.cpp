#include <assert.h>
#include <stdint.h>
#include "common.h"

// include generic structures for diff-based fuzzing
#include "diff.h"


// just in case clamav is not in the build
#ifndef CONFIG_USE_CLAMAV
static int ret_clamav = FAILURE_INTERNAL;
#endif

#define INCLUDE(name) \
  static fp_t unpack_xz_ ##name = NULL; \
  static void *h_ ##name = NULL; \
  int ret_ ##name = FAILURE_INTERNAL; \
  int ret_raw_ ##name = FAILURE_INTERNAL;

#ifdef CONFIG_USE_CLAMAV
#include "clamav_arc.h"
INCLUDE(clamav)
#endif

#ifdef CONFIG_USE_XZUTILS
#include "xzutils_arc.h"
INCLUDE(xzutils)
#endif

#define INIT_LIB(name, NAME) \
  if (!unpack_xz_ ##name) { \
      unpack_xz_ ##name = \
        (fp_t)get_interface_fn(h_ ##name, LIB_ ##NAME, FN_UNPACK_XZ); \
      if (!unpack_xz_ ##name) \
          DBG("ERROR resolving function from: %s\n", LIB_ ##NAME); \
  } \
  assert(unpack_xz_ ##name != NULL); \
  total_libs++;

#define VERIFY_ONE(name) \
  ret_ ##name = unpack_xz_ ##name(data, sz);

// Global initializer to automatically clean up
struct GlobalInitializer {
  GlobalInitializer() {

#ifdef CONFIG_USE_CLAMAV
    INIT_LIB(clamav, CLAMAV)
#endif
#ifdef CONFIG_USE_XZUTILS
    INIT_LIB(xzutils, XZUTILS)
#endif

    // initialize all diff-based structures
    NEZHA_TestStart();
  }

  ~GlobalInitializer() {
    //printf("In ~GlobalInitializer(): freeing\n");
    //FREE_GLOBALS
  }
};

static GlobalInitializer g_initializer;



#define XZ_FILE_MIN_SIZE    24
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t sz)
{

  //////// Specific to XZ file format ////////
  if (sz < XZ_FILE_MIN_SIZE)
    return 0;
  ////////////////////////////////////////////


#ifdef CONFIG_USE_CLAMAV
  EXERCISE(clamav)
#endif
#ifdef CONFIG_USE_XZUTILS
  EXERCISE(xzutils)
#endif

  return 0;
}

