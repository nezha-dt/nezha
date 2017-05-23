CWD=`pwd`
INCL=${CWD}/utils/build_helpers/include.sh
BUILDS=${CWD}/examples/builds
BUILD_LIBS=${CWD}/examples/builds/libs
SRC_LIBS=${CWD}/examples/src/libs
SRC_APPS=${CWD}/examples/src/apps

echo -e "#!/bin/bash
LIBFUZZER=libFuzzer
CLAMAV=clamav
XZUTILS=xzutils
SSDEEP=ssdeep

OPENSSL=openssl
LIBRESSL=libressl
BORINGSSL=boringssl

CWD=${CWD}
BUILDS=${CWD}/examples/builds
BUILD_LIBS=${CWD}/examples/builds/libs
SRC_LIBS=${CWD}/examples/src/libs
SRC_APPS=${CWD}/examples/src/apps

CLAMAV_ST=https://www.clamav.net/downloads/production/clamav-0.99.2.tar.gz
XZUTILS_ST=https://github.com/xz-mirror/xz.git
OPENSSL_ST=https://www.openssl.org/source/openssl-1.0.2h.tar.gz
LIBRESSL_ST=http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.4.0.tar.gz
BORINGSSL_ST=https://boringssl.googlesource.com/boringssl
LF_ST=https://chromium.googlesource.com/chromium/llvm-project/llvm/lib/Fuzzer
SSDEEP_ST=https://github.com/DinoTools/python-ssdeep.git" > ${INCL}

if [ -d examples ] && [ -d utils ]; then
    mkdir -p ${SRC_LIBS} ${BUILD_LIBS} ${SRC_APPS}
else
    echo "Please run this from the git root directory!"
    exit 1
fi

source ${INCL}

${CWD}/utils/build_helpers/build_dependencies.sh || exit 1;

# echo "[+] Building Libraries"
${CWD}/utils/build_helpers/build_xzutils_lf.sh
${CWD}/utils/build_helpers/build_clamav_lf.sh
${CWD}/utils/build_helpers/build_openssl_lf.sh
${CWD}/utils/build_helpers/build_boringssl_lf.sh
${CWD}/utils/build_helpers/build_libressl_lf.sh
