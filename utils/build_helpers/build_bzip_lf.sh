#!/bin/bash
CWD=`pwd`
INCL=${CWD}/utils/build_helpers/include.sh
source ${INCL}

BDIR_BZ=${BUILD_LIBS}/${BZIP}_lf

echo -e "\t * Building ASAN/SanitizerCoverage-instrumented BZIP2"
if [ ! -d ${BDIR} ]; then
    mkdir -p ${BDIR}
fi

LC="-g -fsanitize=address -fsanitize-coverage=edge,indirect-calls,8bit-counters"

function reset_bzip_dir {
    rm -rf ${SRC_LIBS}/$BZIP
    echo -e "\t\t - Downloading BZIP in ${SRC_LIBS}/bzip"
    wget -P ${SRC_LIBS} ${BZIP_ST} 2>/dev/null

    pushd ${SRC_LIBS} > /dev/null
        if [ -f bzip2-1.0.6.tar.gz ]; then
            tar xzf bzip2-1.0.6.tar.gz
            mv bzip2-1.0.6 ${BZIP}
        fi
        # cleanup
        rm -f *gz *tar
    popd > /dev/null
}

reset_bzip_dir

pushd ${SRC_LIBS}/${BZIP} >/dev/null
    echo -e "\t\t - Configuring BZIP2"
    # clean up just in case
    make -j10 clean > /dev/null 2>&1
    make -j10 distclean > /dev/null 2>&1
    make CC="clang-3.8" CXX="clang++-3.8" CFLAGS="$LC" \
> /dev/null 2>&1

    echo -e "\t\t - Adding dependencies"
    echo -e "\t\t - Compiling"
    make -j10 > /dev/null  2>&1
    echo -e "\t\t - Installing"
    make -j10 install PREFIX=${BDIR_BZ} > /dev/null 2>&1
    # clean up for next install
    make -j10 clean > /dev/null 2>&1
    make -j10 distclean > /dev/null 2>&1
    test=$(objdump -d ${BDIR_BZ}/bin/bzip2 2>/dev/null \
| grep "__sanitizer" | wc -l)
    if [ -f ${BDIR_BZ}/bin/bzip2 ] &&
        [ -f ${BDIR_BZ}/lib/libbz2.a ] &&
        [ $test -ne 0 ]; then
        echo -e "\t\t - Testing install..\033[0;32m OK\n"
    else
        echo -e "\t\t - Testing install..\033[0;31m FAILED\n"
    fi
    echo -en "\e[0m"
popd >/dev/null
