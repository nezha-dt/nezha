#ifndef __COMMON_H__
#define __COMMON_H__

// Directives to enable desired functions to be exported
#if __GNUC__ >= 4
    #define LIB_EXPORT      __attribute__ ((visibility("default")))
#else
    #define LIB_EXPORT
#endif
#endif  //__COMMON_H__
