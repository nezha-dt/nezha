#!/bin/bash
FUZZ_CXXFLAGS="-O2 -fno-omit-frame-pointer -g -fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div"
DF="-DFUZZER_DISABLE_SIGNCHECK"
PATCH=openssl_1.0.2h_sign.patch
NAME=openssl-1.0.2h_diff
BDIR=BUILD/$NAME

OPENSSL_ST=https://www.openssl.org/source/openssl-1.0.2h.tar.gz
rm -rf $BDIR && mkdir -p BUILD SRC
if [ ! -d SRC/${NAME} ]; then
    wget -P SRC ${OPENSSL_ST} >/dev/null 2>&1
    echo -e "- Downloading OpenSSL in SRC"
    pushd SRC >/dev/null
        if [ -f openssl-1.0.2h.tar.gz ]; then
            echo -e "- Extracting OpenSSL"
            tar xzf openssl-1.0.2h.tar.gz
            mv openssl-1.0.2h ${NAME}
            rm openssl-1.0.2h.tar.gz
        fi
    popd >/dev/null
fi

cp -rf SRC/$NAME BUILD
cp openssl-1.0.2h_libressl-2.4.0/$PATCH $BDIR
pushd $BDIR >/dev/null
    # patch away the signature checking if we have not patched already
    echo -e "- Building OpenSSL 1.0.2h"
    patch -p1 -N --dry-run --silent < ${PATCH} >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "\t\t - Applying patch"
        patch -p1 < ${PATCH} >/dev/null 2>&1
    else
        echo -e "\t\t - Skipping patch - already applied"
    fi
    echo -e "\t\t - Configuring"
	CC="clang $FUZZ_CXXFLAGS $DF" ./config no-shared -fPIC \
		--prefix=`pwd`/../build_$NAME \
        --openssldir=`pwd`/../build_$NAME/openssl > /dev/null 2>&1
    # there is an issue with multiple builds in openssl
    make depend > /dev/null 2>&1
    echo -e "\t\t - Compiling"
    make > /dev/null 2>&1
    echo -e "\t\t - Installing"
	make install > /dev/null 2>&1
popd >/dev/null
rm -rf $BDIR
