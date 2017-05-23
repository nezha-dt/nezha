#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

#ifdef CONFIG_SUMMARY
#define DBG_S(...) do {printf(__VA_ARGS__); fflush(stdout);} while (0)
#else
#define DBG_S(...) do {} while (0)
#endif

#ifdef CONFIG_DEBUG
#define DBG(...) do {printf(__VA_ARGS__); fflush(stdout);} while (0)
#else
#define DBG(...) do {} while (0)
#endif


// Directives to enable desired functions to be exported
#if __GNUC__ >= 4
    #define LIB_EXPORT      __attribute__ ((visibility("default")))
#else
    #define LIB_EXPORT
#endif

// Generic interface to packages
typedef int (*fp_t)(const uint8_t *, uint32_t);

// Normalized error codes
#define RET_OK                  0   // decompression ok
#define RET_ARC_ERR             1   // decompression failed
#define RET_CRC_ERR             2   // crc failed
#define RET_UNK_ERR_BASE        100 // unknown err base
#define FAILURE_INTERNAL        11223344

#define FN_UNPACK_XZ           "unpack_xz_mem"


#define FREE_PTR(ptr) \
    if (ptr) { \
        free(ptr);\
        ptr = NULL;\
    }
#endif  //__COMMON_H__
