#ifndef __CLAMAV_ARC_H__
#define __CLAMAV_ARC_H__

#include "common.h"


const static char *LIB_CLAMAV = "lib/libclamav.so";

extern "C" int unpack_xz_mem(const uint8_t *data, uint32_t size);
extern "C" int unpack_xz_mem_clamav(const uint8_t *data, uint32_t size);


/**
 * Return codes from libclamav/clamav.h
 */
#define _CL_CLEAN       0
#define _CL_EFORMAT     26


#endif  //__CLAMAV_ARC_H__