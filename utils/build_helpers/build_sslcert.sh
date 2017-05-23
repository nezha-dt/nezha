#!/bin/bash

CWD=`pwd`
INCL=${CWD}/utils/build_helpers/include.sh

echo -e "#!/bin/bash
OPENSSL=openssl
LIBRESSL=libressl
BORINGSSL=boringssl
LIBFUZZER=libFuzzer

SSDEEP=ssdeep

CWD=${CWD}
BUILDS=${CWD}/examples/builds
BUILD_LIBS=${CWD}/examples/builds/libs
BUILD_APPS=${CWD}/examples/builds/apps
SRC_APPS=${CWD}/examples/src/apps
SRC_LIBS=${CWD}/examples/src/libs

SSDEEP_ST=https://github.com/DinoTools/python-ssdeep.git
OPENSSL_ST=https://www.openssl.org/source/openssl-1.0.2h.tar.gz
LIBRESSL_ST=http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.4.0.tar.gz
BORINGSSL_ST=https://boringssl.googlesource.com/boringssl
LF_ST=https://chromium.googlesource.com/chromium/llvm-project/llvm/lib/Fuzzer" > ${INCL}

source ${INCL}

if [ -d examples ] && [ -d utils ]; then
    mkdir -p ${SRC_LIBS} ${BUILD_LIBS} ${SRC_APPS} ${BUILD_APPS}
else
    echo "Please run this from the git root directory!"
    exit 1
fi



source ${CWD}/utils/build_helpers/include.sh

mkdir -p ${BUILDS}
# ignore everything in these directories
echo "*" > ${BUILDS}/.gitignore

if ! [ -f /usr/bin/clang-3.8 ]; then
    echo -e "\t\t -\033[0;31m Did not find clang-3.8";
    echo -en "\e[0m";
    exit 1;
fi

echo "[+] Downloading Libraries"
if ! [ -d ${SRC_LIBS}/${OPENSSL}  ]; then
    echo -e "\t\t - Downloading OpenSSL in ${SRC_LIBS}/openssl"
    wget -P ${SRC_LIBS} ${OPENSSL_ST} 2>/dev/null
fi
if ! [ -d ${SRC_LIBS}/${LIBRESSL}  ]; then
    echo -e "\t\t - Downloading LibreSSL in ${SRC_LIBS}/libressl"
    wget -P ${SRC_LIBS} ${LIBRESSL_ST} 2>/dev/null
fi
if ! [ -d ${SRC_LIBS}/${BORINGSSL}  ]; then
    echo -e "\t\t - Downloading boringSSL in ${SRC_LIBS}/boringssl"
    git clone ${BORINGSSL_ST} ${SRC_LIBS}/boringssl 2>/dev/null
fi
if ! [ -d ${SRC_LIBS}/${LIBFUZZER}  ]; then
    echo -e "\t\t - Downloading libFuzzer in ${SRC_LIBS}/libFuzzer"
    git clone ${LF_ST} ${SRC_LIBS}/libFuzzer 2>/dev/null
fi
if ! [ -d ${SRC_LIBS}/${SSDEEP}  ]; then
    echo -e "\t\t - Downloading ssdeep in ${SRC_LIBS}/ssdeep"
    git clone ${SSDEEP_ST} ${SRC_LIBS}/${SSDEEP} 2>/dev/null
fi


echo "[+] Extracting files"
pushd ${SRC_LIBS} >/dev/null
    if [ -f openssl-1.0.2h.tar.gz ]; then
        tar xzf openssl-1.0.2h.tar.gz
        mv openssl-1.0.2h ${OPENSSL}
    fi

    if [ -f libressl-2.4.0.tar.gz ]; then
        tar xzf libressl-2.4.0.tar.gz
        mv libressl-2.4.0 ${LIBRESSL}
    fi

    if (! [ -f libFuzzer/libFuzzer.a ]); then
        echo "[+] Installing libFuzzer"
        pushd libFuzzer >/dev/null
            clang++-3.8 -c -g -O2 -std=c++11 *.cpp -I. >/dev/null 2>&1
            ar ruv libFuzzer.a Fuzzer*.o >/dev/null 2>&1
            if [ -f libFuzzer.a ]; then
                echo -e "\t\t -\033[0;32m OK\n";
                echo -en "\e[0m";
            else
                echo -e "\t\t -\033[0;31m FAILED\n";
                echo -en "\e[0m";
                exit 1;
            fi
        popd >/dev/null
    fi
    
    # SSDEEP
    if [ -d ${SSDEEP} ]; then
        pushd ${SSDEEP}/src/ssdeep-lib >/dev/null
        sed -e 's/-${am__api_version}//g' configure > configure2
        chmod +x configure2
        ./configure2 --prefix=`pwd`/../../../../../builds/libs/ssdeep-lib \
                CC="clang-3.8" CXX="clang++-3.8" >/dev/null 2>&1
        make > /dev/null 2>&1
        automake --add-missing >/dev/null
        make > /dev/null 2>&1
        make install >/dev/null 2>&1
        popd >/dev/null
    fi
    
    # cleanup
    rm -f *gz *tar
popd >/dev/null


echo "[+] Building Libraries"
${CWD}/utils/build_helpers/build_openssl_lf.sh
${CWD}/utils/build_helpers/build_boringssl_lf.sh
${CWD}/utils/build_helpers/build_libressl_lf.sh