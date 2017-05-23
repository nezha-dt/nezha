#ifndef __DIFF_H__
#define __DIFF_H__

#include <dlfcn.h>

#if defined(__has_include)
#if __has_include(<sanitizer / coverage_interface.h>)
#include <sanitizer/coverage_interface.h>
#endif
#if __has_include(<sanitizer / lsan_interface.h>)
#include <sanitizer/lsan_interface.h>
#endif
#endif

#define NO_SANITIZE_MEMORY
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#undef NO_SANITIZE_MEMORY
#define NO_SANITIZE_MEMORY __attribute__((no_sanitize_memory))
#endif
#endif


// Re-declare some of the sanitizer functions as "weak" so that libFuzzer can be
// linked w/o the sanitizers and sanitizer-coverage (in which case it will
// complain at start-up time).
extern "C" {
__attribute__((weak)) size_t
  __sanitizer_get_total_unique_coverage();
__attribute__((weak)) void
  __sanitizer_reset_coverage();
__attribute__((weak)) uintptr_t
    __sanitizer_get_coverage_pc_buffer(uintptr_t **data);
__attribute__((weak)) uintptr_t
  __sanitizer_update_counter_bitset_and_clear_counters(uint8_t *bitset);
__attribute__((weak)) uintptr_t
  __sanitizer_get_number_of_counters();
}

#define FREE_GLOBALS \
  FREE_PTR(ret_vals) \
  FREE_PTR(cov_diff) \
  FREE_PTR(cov_buff_idx) \
  FREE_PTR(vcont_int.vals) \
  FREE_PTR(vcont_u64.vals) \
  FREE_PTR(bitset)

#define EXERCISE(name) \
  if (cur_lib == 0) \
    cov_buff_idx[cur_lib] = __sanitizer_get_total_unique_coverage(); \
  __sanitizer_update_counter_bitset_and_clear_counters(0); \
  VERIFY_ONE(name); \
  cov_buff_idx[cur_lib + 1] = __sanitizer_get_total_unique_coverage(); \
  ret_vals[cur_lib] = ret_ ##name; \
  memset(bitset_cur[cur_lib], 0, num_bitcounters); \
  __sanitizer_update_counter_bitset_and_clear_counters(bitset_cur[cur_lib]); \
  bitcounts[cur_lib] = \
    update_bitcount(bitset_cur[cur_lib], bitset_old[cur_lib], &ecnt[cur_lib]); \
  cur_lib = (cur_lib < total_libs - 1) ? cur_lib + 1 : 0;


// Let's just increase the number of libs upon includes to append them in-order
// into the array but this assumes that always the calls will happen in the same
// order inside the code because otherwise things will break!
int total_libs = 0;

// Current lib we are visiting.
int cur_lib = 0;

// Array holding return values.
int *ret_vals = NULL;

// Array holding indexes to the start of the global PC buffer (start, end).
// We use this to track the per-lib list of unique PCs executed.
uint64_t *cov_buff_idx = NULL;

// Array holding per-lib bitcounts.
int *bitcounts = NULL;

// Track coarse-grained edge count using libFuzzer 8-bit bitset. Like AFL, each
// per-edge count tracks the hit count in several buckets:
// 1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+
uint8_t **bitset_cur;
uint8_t **bitset_old;

// Track coarse-grained raw edge count converted from the bitset.
int *ecnt;

uint32_t num_bitcounters;

// TODO(atang): Refactor these int types to unsigned versions.
struct ValContainerInt {
  int *vals;
  int size;
} vcont_int = { NULL, 0 };

struct ValContainerU64 {
  uint64_t *vals;
  int size;
} vcont_u64 = { NULL, 0 };


extern "C" ValContainerInt *LLVMFuzzerNezhaOutputs() {
  if (!ret_vals)
    return NULL;
  vcont_int.vals = ret_vals;
  vcont_int.size = total_libs;
  return &vcont_int;
}

extern "C" ValContainerInt *LLVMFuzzerBitcounts() {
  if (!bitcounts)
    return NULL;
  vcont_int.vals = bitcounts;
  vcont_int.size = total_libs;
  return &vcont_int;
}

extern "C" ValContainerInt *LLVMFuzzerEdgecounts() {
  if (!ecnt)
    return NULL;
  vcont_int.vals = ecnt;
  vcont_int.size = total_libs;
  return &vcont_int;
}

extern "C" ValContainerU64 *LLVMFuzzerCovBuffers() {
  if (!cov_buff_idx)
    return NULL;
  vcont_u64.vals = cov_buff_idx;
  vcont_u64.size = total_libs + 1;
  return &vcont_u64;
}

void diff_init() {
  num_bitcounters = __sanitizer_get_number_of_counters();
  
  ret_vals = (int *) calloc(total_libs, sizeof(int));
  cov_buff_idx = (uint64_t *) calloc(total_libs + 1, sizeof(uint64_t));
  bitcounts = (int *) calloc(total_libs, sizeof(int));
  ecnt = (int *) calloc(total_libs, sizeof(int));
  
  bitset_cur = (uint8_t **) calloc(total_libs, sizeof(uint8_t *));
  assert(bitset_cur != NULL && "error allocating bitset_cur*");
  for (int i = 0; i < total_libs; i++) {
    bitset_cur[i] = (uint8_t *) calloc(num_bitcounters, sizeof(uint8_t));
    assert(bitset_cur[i] != NULL && "error allocating bitset_cur");
  }

  bitset_old = (uint8_t **) calloc(total_libs, sizeof(uint8_t *));
  assert(bitset_old != NULL && "error allocating bitset_old*");
  for (int i = 0; i < total_libs; i++) {
    bitset_old[i] = (uint8_t *) calloc(num_bitcounters, sizeof(uint8_t));
    assert(bitset_old[i] != NULL && "error allocating bitset_old");
  }
  
  assert(ret_vals != NULL && "error allocating ret_vals");
  assert(cov_buff_idx != NULL && "error allocating cov_buff_idx");
  assert(bitcounts != NULL && "error allocating bitcounts");
  assert(ecnt != NULL && "error allocating ecnt");
}

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

int update_bitcount(uint8_t *bitset, uint8_t *bitset_prev, int *ecnt) {
  uint32_t num_new_bits = 0;
  int raw_edge_count = 0;
  
  for (uint32_t i = 0; i < num_bitcounters; i++) {
    if (!bitset[i])
      continue;
    
    // Update bit counter only when the most recent execution results in a new
    // bit added to the existing bitset.
    //
    // This replicates the functionality of
    // __sanitizer_update_counter_bitset_and_clear_counters() because we are
    // reset the bitset before invoking this function to retrieve the raw edge
    // counts.
    if ((bitset_prev[i] & bitset[i]) ^ bitset[i]) {
      bitset_prev[i] |= bitset[i];
      num_new_bits++;
    }
    
    // Update raw edge counts using the upper limit of the bucket, with the
    // exception of the biggest bucket.
    /**/ if (bitset[i] & 0x01) raw_edge_count += 1;   // 1
    else if (bitset[i] & 0x02) raw_edge_count += 2;   // 2
    else if (bitset[i] & 0x04) raw_edge_count += 3;   // 3
    else if (bitset[i] & 0x08) raw_edge_count += 7;   // 4-7
    else if (bitset[i] & 0x10) raw_edge_count += 15;  // 8-15
    else if (bitset[i] & 0x20) raw_edge_count += 31;  // 16-31
    else if (bitset[i] & 0x40) raw_edge_count += 127; // 32-127
    else if (bitset[i] & 0x80) raw_edge_count += 255; // 128+
  }
  
  *ecnt = raw_edge_count;
  
  return num_new_bits;
}

#endif // __DIFF_H__
