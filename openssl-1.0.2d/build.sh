#!/bin/bash
# Copyright 2016 Google Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
SCRIPT_DIR=$(dirname $0)
COMMON_DIR=${SCRIPT_DIR}/..
. $COMMON_DIR/common.sh

CC=clang
CXX=clang++

LIB_PATH=$COMMON_DIR/$LIB_FUZZING_ENGINE
INCLUDE_FLAGS=-I$COMMON_DIR/Fuzzer/include

build_lib() {
  rm -rf BUILD
  cp -rf SRC BUILD
  (cd BUILD && CC="$CC $CFLAGS" ./config && make clean && make -j $JOBS)
}

get_git_tag https://github.com/openssl/openssl.git OpenSSL_1_0_2d SRC
build_lib
build_fuzzer
set -x
$CXX $CXXFLAGS $SCRIPT_DIR/target.cc -DCERT_PATH=\"$SCRIPT_DIR/\"  BUILD/libssl.a BUILD/libcrypto.a $LIB_PATH $INCLUDE_FLAGS -lgcrypt -I BUILD/include -o $EXECUTABLE_NAME_BASE
$CXX $CXXFLAGS $SCRIPT_DIR/diff_target.cc -DCERT_PATH=\"$SCRIPT_DIR/\"  BUILD/libssl.a BUILD/libcrypto.a $LIB_PATH $INCLUDE_FLAGS -lgcrypt -I BUILD/include -o openssl-1.0.2d-diff
