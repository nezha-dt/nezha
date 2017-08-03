#!/bin/bash
. $(dirname $0)/../common.sh
mkdir -p SRC BUILD
build_lib() {
    $SCRIPT_DIR/build_openssl_lf.sh
    $SCRIPT_DIR/build_libressl_lf.sh
}

build_lib
build_libfuzzer
pushd $SCRIPT_DIR > /dev/null 2>&1
    make clean
    ./make_all_tests.sh
popd > /dev/null 2>&1
