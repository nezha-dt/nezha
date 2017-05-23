#include <assert.h>
#include <stdio.h>

#include "common.h"
#include "func.h"

#ifdef CONFIG_TEST_CLAMAV
#include "clamav_arc.h"
#endif

#ifdef CONFIG_TEST_XZUTILS
#include "xzutils_arc.h"
#endif

#define UNPACK(name) \
ret = unpack_xz_mem_ ##name(data, sz);\
// printf(#name " %d\n", ret);


static void verify(char *filefn)
{
    int ret;

    uint8_t *data = NULL;
    size_t sz;

    if ((sz = read_file(filefn, &data)) == -1)
        return;

#ifdef CONFIG_TEST_CLAMAV
    UNPACK(clamav)
#endif

#ifdef CONFIG_TEST_XZUTILS
    UNPACK(xzutils)
#endif

    FREE_PTR(data)
}


int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: %s testfile(.xz)\n", argv[0]);
        return EXIT_SUCCESS;
    }

    verify(argv[1]);

    return EXIT_SUCCESS;
}
