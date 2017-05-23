#include <assert.h>

#include "common.h"
#include "func.h"

#ifdef CONFIG_TEST_OPENSSL
#include "openssl.h"
#include <openssl/err.h>
#endif

#ifdef CONFIG_TEST_LIBRESSL
#include "libressl.h"
#endif

#ifdef CONFIG_TEST_BORINGSSL
#include "boringssl.h"
#endif

#ifdef CONFIG_TEST_WOLFSSL
#include "wolfssl.h"
#endif

#ifdef CONFIG_TEST_MBEDTLS
#include "mbedtls.h"
#endif

#ifdef CONFIG_TEST_GNUTLS
#include "gnutls.h"
#endif

#define VERIFY(name) \
    ret = verify_cert_mem_ ##name(cert_data, cert_sz);\

static void verify(char *cert)
{
    int ret = 0;

    uint8_t *cert_data = NULL;
    size_t cert_sz;

    if (!(cert_sz = read_file(cert, &cert_data))) {
        printf("ERROR reading file: %s\n", cert);
        goto end;
    }

#ifdef CONFIG_TEST_MBEDTLS
	cert_data = (unsigned char *)realloc(cert_data, ++cert_sz);
	if (!cert_data)
		goto end;
	cert_data[cert_sz - 1] = 0;
#endif

#ifdef CONFIG_TEST_OPENSSL
    VERIFY(openssl)
#endif

#ifdef CONFIG_TEST_LIBRESSL
    VERIFY(libressl)
#endif

#ifdef CONFIG_TEST_BORINGSSL
    VERIFY(boringssl)
#endif

#ifdef CONFIG_TEST_WOLFSSL
    VERIFY(wolfssl)
#endif

#ifdef CONFIG_TEST_MBEDTLS
    VERIFY(mbedtls)
#endif


#ifdef CONFIG_TEST_GNUTLS
    VERIFY(gnutls)
#endif

end:
    if (cert_data) {
      free(cert_data);
      cert_data = NULL;
    }
    return;
}


int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("usage: %s server_cert\n", argv[0]);
        exit(EXIT_SUCCESS);
    }

    verify(argv[1]);

    return EXIT_SUCCESS;
}
