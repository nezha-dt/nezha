CWD=`pwd`
INCL=${CWD}/utils/build_helpers/include.sh
source ${INCL}

PATCH=xzutils_5.2.2_xz.patch

GIT_COMMIT_VER=faf302137e54d605b44ecf0373cb51a6403a2de1
BDIR=${BUILD_LIBS}/${XZUTILS}_lf

echo -e "\t * Building ASAN/SanitizerCoverage-instrumented XZUtils"
if [ ! -d ${BDIR} ]; then
    mkdir -p ${BDIR}
fi

LC="-g -fsanitize=address -fsanitize-coverage=edge,indirect-calls,8bit-counters"

if ! [ -d ${SRC_LIBS}/${XZUTILS}  ]; then
    echo -e "\t\t - Downloading XZ-Utils in ${SRC_LIBS}/xzutils"
    git clone ${XZUTILS_ST} ${SRC_LIBS}/xzutils 2>/dev/null
fi

pushd ${SRC_LIBS}/${XZUTILS} >/dev/null
    echo -e "\t\t - Configuring"
    # clean up just in case
    make -j10 clean > /dev/null 2>&1
    make -j10 distclean > /dev/null 2>&1
    git checkout ${GIT_COMMIT_VER} > /dev/null 2>&1
    cp ../../../../utils/patches/${PATCH} .
    patch -p1 < ${PATCH} > /dev/null 2>&1
    bash autogen.sh > /dev/null 2>&1
    ./configure --disable-shared --with-pic --prefix=${BDIR} \
--exec-prefix=${BDIR} CC="clang-3.8" CXX="clang++-3.8" CFLAGS="$LC" \
>/dev/null 2>&1
    echo -e "\t\t - Adding dependencies"
    echo -e "\t\t - Compiling"
    make -j10 > /dev/null 2>&1
    echo -e "\t\t - Installing"
    make -j10 install > /dev/null 2>&1
    # clean up for next install
    make -j10 clean > /dev/null 2>&1
    make -j10 distclean > /dev/null 2>&1
    ${BDIR}/bin/xz --version 1> /tmp/ttest
    test=$(objdump -d ${BDIR}/bin/xz 2>/dev/null \
| grep "__sanitizer" | wc -l)
    if [ -f ${BDIR}/bin/xz ] &&
        [ -f ${BDIR}/lib/liblzma.a ] &&
        [ $(grep -i liblzma /tmp/ttest | wc -l) -ne 0 ] &&
        [ $test -ne 0 ]; then
        echo -e "\t\t - Testing install..\033[0;32m OK\n"
    else
        echo -e "\t\t - Testing install..\033[0;31m FAILED\n"
    fi
    echo -en "\e[0m"
popd >/dev/null
