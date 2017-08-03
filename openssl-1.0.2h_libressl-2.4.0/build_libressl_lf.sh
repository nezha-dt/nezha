#!/bin/bash
FUZZ_CXXFLAGS="-O2 -fno-omit-frame-pointer -g -fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div"
DF="-DFUZZER_DISABLE_SIGNCHECK"
NAME=libressl-2.4.0_diff
BDIR=BUILD/$NAME
PATCH=libressl_2.4.0_sign.patch
LIBRESSL_ST=http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.4.0.tar.gz

rm -rf $BDIR && mkdir -p BUILD SRC
if [ ! -d SRC/${NAME} ]; then
    echo -e "- Downloading LibreSSL in SRC"
    wget -P SRC ${LIBRESSL_ST} >/dev/null 2>&1
    pushd SRC >/dev/null
        if [ -f libressl-2.4.0.tar.gz ]; then
            tar xzf libressl-2.4.0.tar.gz
            mv libressl-2.4.0 ${NAME}
            rm libressl-2.4.0.tar.gz
        fi
    popd >/dev/null
fi

cp -rf SRC/$NAME BUILD
cp openssl-1.0.2h_libressl-2.4.0/$PATCH $BDIR

pushd $BDIR >/dev/null
    echo -e "- Building LibreSSL 2.4.0"
    FBDIR=`pwd`/../build_$NAME
    echo -e "\t\t - Configuring"
    # clean up just in case
    make -j10 clean > /dev/null 2>&1
    make -j10 distclean > /dev/null 2>&1
    # patch away the signature checking if we have not patched already
    # patch if we have not patched already
    patch -p1 -N --dry-run --silent < ${PATCH} >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "\t\t - Applying patch"
        patch -p1 < ${PATCH} >/dev/null 2>&1
    else
        echo -e "\t\t - Skipping patch - already applied"
    fi
    ./configure --disable-shared --with-pic --prefix=${FBDIR} \
--exec-prefix=${FBDIR} CC="clang" CFLAGS="$FUZZ_CXXFLAGS $DF">/dev/null 2>&1
    echo -e "\t\t - Adding dependencies"
    echo -e "\t\t - Compiling"
    make -j10 > /dev/null  2>&1
    echo -e "\t\t - Installing"
    make -j10 install > /dev/null 2>&1
    # clean up for next install
    make -j10 clean > /dev/null 2>&1
    make -j10 distclean > /dev/null 2>&1
    ${FBDIR}/bin/openssl h 2> /tmp/ttest
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
rm -rf $BDIR
