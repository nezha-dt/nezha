CWD=`pwd`
INCL=${CWD}/utils/build_helpers/include.sh
source ${INCL}

PATCH=libressl_2.4.0_sign.patch
BDIR=${BUILD_LIBS}/${LIBRESSL}_lf

echo -e "\t * Building sancov-instrumented LibreSSL"
if [ ! -d ${BDIR} ]; then
    mkdir -p ${BDIR}
fi

LC="-g -fsanitize=address -fsanitize-recover=undefined,integer -fsanitize-coverage=edge,indirect-calls,8bit-counters"
DF="-DFUZZER_DISABLE_SIGNCHECK"

if ! [ -d ${SRC_LIBS}/${LIBRESSL}  ]; then
    echo -e "\t\t - LibreSSL was not downloaded properly"
    exit 1
fi

pushd ${SRC_LIBS}/${LIBRESSL} >/dev/null
    echo -e "\t\t - Configuring"
    # clean up just in case
    make -j10 clean > /dev/null 2>&1
    make -j10 distclean > /dev/null 2>&1
    # patch away the signature checking if we have not patched already
    cp ../../../../utils/patches/${PATCH} .
    # patch if we have not patched already
    patch -p1 -N --dry-run --silent < ${PATCH} >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "\t\t - Applying patch"
        patch -p1 < ${PATCH} >/dev/null 2>&1
    else
        echo -e "\t\t - Skipping patch - already applied"
    fi
    rm ${PATCH}
    ./configure --disable-shared --with-pic --prefix=${BDIR} \
--exec-prefix=${BDIR} CC="clang-3.8" CFLAGS="$LC $DF"> /dev/null  2>&1
    echo -e "\t\t - Adding dependencies"
    echo -e "\t\t - Compiling"
    make -j10 > /dev/null  2>&1
    echo -e "\t\t - Installing"
    make -j10 install > /dev/null 2>&1
    # clean up for next install
    make -j10 clean > /dev/null 2>&1
    make -j10 distclean > /dev/null 2>&1
    ${BDIR}/bin/openssl h 2> /tmp/ttest
    test=$(objdump -d ${BDIR}/bin/openssl 2>/dev/null \
| grep "__sanitizer" | wc -l)
    if [ -f ${BDIR}/bin/openssl ] &&
        [ -f ${BDIR}/lib/libssl.a ] &&
        [ $(wc -l /tmp/ttest | cut -d' ' -f1) -eq 37 ] &&
        [ $test -ne 0 ]; then
        echo -e "\t\t - Testing install..\033[0;32m OK\n"
    else
        echo -e "\t\t - Testing install..\033[0;31m FAILED\n"
    fi
    echo -en "\e[0m"
popd >/dev/null
