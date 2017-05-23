#!/bin/bash

CWD=`pwd`
INCL=${CWD}/utils/build_helpers/include.sh
source ${INCL}

GIT_COMMIT_VER=cacf7f1d4e3d44d871b605da3b647f07d718623f

BDIR=${BUILD_LIBS}/${ZLIB}_lf


echo -e "\t * Building ASAN/SanitizerCoverage-instrumented ZLIB"
if [ ! -d ${BDIR} ]; then
    echo "Creating dir ${BDIR}"
    mkdir -p ${BDIR}
fi

LC="-g -fsanitize=address -fsanitize-coverage=edge,indirect-calls,8bit-counters"

if ! [ -d ${SRC_LIBS}/${ZLIB}  ]; then
    echo -e "\t\t - Downloading ZLIB in ${SRC_LIBS}/zlib"
    git clone ${ZLIB_ST} ${SRC_LIBS}/zlib 2>/dev/null
fi

pushd ${SRC_LIBS}/${ZLIB} >/dev/null
    echo -e "\t\t - Configuring"
    # clean up just in case
    make -j10 clean > /dev/null 2>&1
    make -j10 distclean > /dev/null 2>&1
    git checkout ${GIT_COMMIT_VER} > /dev/null 2>&1
    prefix=${BDIR} CC="clang-3.8" CXX="clang++-3.8" CFLAGS="$LZ" ./configure > /dev/null 2>&1
    echo -e "\t\t - Adding dependencies"
    echo -e "\t\t - Compiling"
    make -j10 > /dev/null 2>&1
    echo -e "\t\t - Installing"
    make -j10 install > /dev/null 2>&1
    # clean up for next install
    make -j10 clean > /dev/null 2>&1
    make -j10 distclean > /dev/null 2>&1
    test=$( grep "__sanitizer" ${BDIR}/lib | wc -l)
    if [ -f ${BDIR}/lib/libz.a ] &&
        [ $test -ne 0 ]; then
        echo -e "\t\t - Testing install..\033[0;32m OK\n"
    else
        echo -e "\t\t - Testing install..\033[0;31m FAILED\n"
    fi
    echo -en "\e[0m"
popd >/dev/null
