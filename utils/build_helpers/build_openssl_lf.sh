CWD=`pwd`
INCL=${CWD}/utils/build_helpers/include.sh
source ${INCL}

PATCH=openssl_1.0.2h_sign.patch

BDIR=${BUILD_LIBS}/${OPENSSL}_lf

echo -e "\t * Building sancov-instrumented OpenSSL"
if [ ! -d ${BDIR} ]; then
    mkdir -p ${BDIR}
fi

CF="-g -fsanitize=address -fsanitize-coverage=edge,indirect-calls,8bit-counters"
DF="-DFUZZER_DISABLE_SIGNCHECK"

if ! [ -d ${SRC_LIBS}/${OPENSSL}  ]; then
    echo -e "\t\t - Downloading OpenSSL in ${SRC_LIBS}/openssl"
    wget -P ${SRC_LIBS} ${OPENSSL_ST} 2>/dev/null
    pushd ${SRC_LIBS} >/dev/null
        if [ -f openssl-1.0.2h.tar.gz ]; then
            echo -e "\t\t - Extracting OpenSSL"
            tar xzf openssl-1.0.2h.tar.gz
            mv openssl-1.0.2h ${OPENSSL}
        fi
    popd >/dev/null
fi

pushd ${SRC_LIBS}/${OPENSSL} >/dev/null
    echo -e "\t\t - Configuring"
    # patch away the signature checking if we have not patched already
    cp ../../../../utils/patches/${PATCH} .
    patch -p1 -N --dry-run --silent < ${PATCH} >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "\t\t - Applying patch"
        patch -p1 < ${PATCH} >/dev/null 2>&1
    else
        echo -e "\t\t - Skipping patch - already applied"
    fi
    rm ${PATCH}
    CC="clang-3.8 $CF $DF" ./config no-shared -fPIC --prefix=${BDIR} \
        --openssldir=${BDIR}/openssl > /dev/null 2>&1
    echo -e "\t\t - Adding dependencies"
    # there is an issue with multiple builds in openssl
    make depend > /dev/null 2>&1
    echo -e "\t\t - Compiling"
    make > /dev/null  2>&1
    echo -e "\t\t - Installing"
    make install > /dev/null 2>&1
    ${BDIR}/bin/openssl test 2> /tmp/.opensslvtest
    test=$(objdump -d ${BDIR}/bin/openssl 2>/dev/null | grep \
"__sanitizer" | wc -l)
    if [ -f ${BDIR}/bin/openssl ] &&
        [ -f ${BDIR}/lib/libssl.a ] &&
        [ $(wc -l /tmp/.opensslvtest | cut -d' ' -f1) -eq 37 ] &&
        [ $test -ne 0 ]; then
        echo -e "\t\t - Testing install..\033[0;32m OK\n"
    else
        echo -e "\t\t - Testing install..\033[0;31m FAILED\n"
    fi
    echo -en "\e[0m"
popd >/dev/null
