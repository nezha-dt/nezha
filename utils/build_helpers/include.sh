#!/bin/bash
LIBFUZZER=libFuzzer
CLAMAV=clamav
XZUTILS=xzutils
SSDEEP=ssdeep

OPENSSL=openssl
LIBRESSL=libressl
BORINGSSL=boringssl

CWD=/home/test/nezha_tmp
BUILDS=/home/test/nezha_tmp/examples/builds
BUILD_LIBS=/home/test/nezha_tmp/examples/builds/libs
SRC_LIBS=/home/test/nezha_tmp/examples/src/libs
SRC_APPS=/home/test/nezha_tmp/examples/src/apps

CLAMAV_ST=https://www.clamav.net/downloads/production/clamav-0.99.2.tar.gz
XZUTILS_ST=https://github.com/xz-mirror/xz.git
OPENSSL_ST=https://www.openssl.org/source/openssl-1.0.2h.tar.gz
LIBRESSL_ST=http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.4.0.tar.gz
BORINGSSL_ST=https://boringssl.googlesource.com/boringssl
LF_ST=https://chromium.googlesource.com/chromium/llvm-project/llvm/lib/Fuzzer
SSDEEP_ST=https://github.com/DinoTools/python-ssdeep.git
