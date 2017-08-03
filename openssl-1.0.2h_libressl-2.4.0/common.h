#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <assert.h>

// Generic interface to packages
typedef int (*fp_t)(const uint8_t *, uint32_t);


/**
 * Default CApath
 */
const static char *CAPATH_DEFAULT1   = "/etc/ssl/certs";
const static char *CAPATH_DEFAULT2   = "certs/CApath";



/**
 * Since we are verifying a certificate chain, a wealth of information (such as
 * the depth where error occurs, raw error code, and whether the chain validates
 * successfully) is available.
 *
 * We combine these values together into a composite return value.
 *  - [0]:      1 if chain validates successfully
 *  - [3:1]:    Set to 0
 *  - [11:4]:   depth (leaf cert is always at depth 0)
 *  - [32:12]:  err code of the most recent error
 */
#define compositize_ret_val(raw_ret, depth, err) \
            ( (raw_ret) | \
              (depth << 4) | \
              (err << 12) )

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

// OpenSSL-variant common error codes
// (Description: https://www.ibm.com/support/knowledgecenter/SSB23S_1.1.0.13/gtpc2/cpp_ssl_get_verify_result.html)
#define         __LF_X509_V_OK                                     		0
#define         __LF_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT               2
#define         __LF_X509_V_ERR_UNABLE_TO_GET_CRL                       3
#define         __LF_X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE        4
#define         __LF_X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE         5
#define         __LF_X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY      6
#define         __LF_X509_V_ERR_CERT_SIGNATURE_FAILURE                  7
#define         __LF_X509_V_ERR_CRL_SIGNATURE_FAILURE                   8
#define         __LF_X509_V_ERR_CERT_NOT_YET_VALID                      9
#define         __LF_X509_V_ERR_CERT_HAS_EXPIRED                        10
#define         __LF_X509_V_ERR_CRL_NOT_YET_VALID                       11
#define         __LF_X509_V_ERR_CRL_HAS_EXPIRED                         12
#define         __LF_X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD          13
#define         __LF_X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD           14
#define         __LF_X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD          15
#define         __LF_X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD          16
#define         __LF_X509_V_ERR_OUT_OF_MEM                              17
#define         __LF_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT             18
#define         __LF_X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN               19
#define         __LF_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY       20
#define         __LF_X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE         21
#define         __LF_X509_V_ERR_CERT_CHAIN_TOO_LONG                     22
#define         __LF_X509_V_ERR_CERT_REVOKED                            23
#define         __LF_X509_V_ERR_INVALID_CA                              24
#define         __LF_X509_V_ERR_PATH_LENGTH_EXCEEDED                    25
#define         __LF_X509_V_ERR_INVALID_PURPOSE                         26
#define         __LF_X509_V_ERR_CERT_UNTRUSTED                          27
#define         __LF_X509_V_ERR_CERT_REJECTED                           28
#define         __LF_X509_V_ERR_SUBJECT_ISSUER_MISMATCH                 29
#define         __LF_X509_V_ERR_AKID_SKID_MISMATCH                      30
#define         __LF_X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH             31
#define         __LF_X509_V_ERR_KEYUSAGE_NO_CERTSIGN                    32
#define         __LF_X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER                33
#define         __LF_X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION            34
#define         __LF_X509_V_ERR_KEYUSAGE_NO_CRL_SIGN                    35
#define         __LF_X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION        36
#define         __LF_X509_V_ERR_INVALID_NON_CA                          37
#define         __LF_X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED              38
#define         __LF_X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE           39
#define         __LF_X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED          40
#define         __LF_X509_V_ERR_INVALID_EXTENSION                       41
#define         __LF_X509_V_ERR_INVALID_POLICY_EXTENSION                42
#define         __LF_X509_V_ERR_NO_EXPLICIT_POLICY                      43
#define         __LF_X509_V_ERR_DIFFERENT_CRL_SCOPE                     44
#define         __LF_X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE           45
#define         __LF_X509_V_ERR_UNNESTED_RESOURCE                       46
#define         __LF_X509_V_ERR_PERMITTED_VIOLATION                     47
#define         __LF_X509_V_ERR_EXCLUDED_VIOLATION                      48
#define         __LF_X509_V_ERR_SUBTREE_MINMAX                          49
#define         __LF_X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE             51
#define         __LF_X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX           52
#define         __LF_X509_V_ERR_UNSUPPORTED_NAME_SYNTAX                 53
#define         __LF_X509_V_ERR_CRL_PATH_VALIDATION_ERROR               54

// Normalized error codes
#define RET_CERT_OK             0
#define RET_CERT_ERR            1
#define RET_CERT_CANT_PARSE     0xFFFFFFF0
#define FAILURE_INTERNAL        0xFFFFFFFF

#define FN_VERIFY_CERT          "verify_cert_mem"


#define FREE_PTR(ptr) \
    if (ptr) { \
        free(ptr);\
        ptr = NULL;\
    }
#endif  //__COMMON_H__
