CWD=`pwd`
INCL=${CWD}/utils/build_helpers/include.sh
source ${INCL}

PATCH=boringssl_f0451ca3_sign.patch

GIT_COMMIT_VER=f0451ca37d303eee6de5a328cb13c438d1cdea85
BDIR=${BUILD_LIBS}/${BORINGSSL}_lf

echo -e "\t * Building sancov-instrumented BoringSSL"
if [ ! -d ${BDIR} ]; then
    mkdir -p ${BDIR}
fi

if ! [ -d ${SRC_LIBS}/${BORINGSSL}  ]; then
    echo -e "\t\t - Downloading boringSSL in ${SRC_LIBS}/boringssl"
    git clone ${BORINGSSL_ST} ${SRC_LIBS}/${BORINGSSL} 2>/dev/null
fi

pushd ${SRC_LIBS}/${BORINGSSL} > /dev/null
    echo -e "\t\t - Configuring"
    # patch away the signature checking if we have not patched already
    git checkout ${GIT_COMMIT_VER} > /dev/null 2>&1
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
popd > /dev/null

echo -e "\t\t - Copying dir"
cp -r ${SRC_LIBS}/${BORINGSSL}/* ${BDIR}/
echo -e "\t\t - Copying libFuzzer.a"
cp -r ${SRC_LIBS}/${LIBFUZZER}/libFuzzer.a ${BDIR}/

pushd ${BDIR} >/dev/null
    echo -e "\t\t - Compiling"
    sed -i '6iset(CMAKE_POSITION_INDEPENDENT_CODE TRUE)' CMakeLists.txt
    sed -i '120i    add_definitions(-DFUZZER_DISABLE_SIGNCHECK)' CMakeLists.txt
    rm -rf build
    mkdir build
    pushd build > /dev/null
        cmake -DFUZZ=1 -DCMAKE_C_COMPILER=clang-3.8 \
            -DCMAKE_CXX_COMPILER=clang++-3.8 .. >/dev/null 2>&1
        make -j10 >/dev/null 2>&1
    popd >/dev/null
    test1=$(objdump -d ${BDIR}/build/ssl/ssl_test 2>/dev/null | grep \
"__sanitizer" | wc -l)
    if [ -f ${BDIR}/build/ssl/libssl.a ] &&
        [ $test1 -ne 0 ] &&
        [ "$(${BDIR}/build/ssl/ssl_test)" = "PASS" ]; then
        echo -e "\t\t - Testing install..\033[0;32m OK\n"
    else
        echo -e "\t\t - Testing install..\033[0;31m FAILED\n"
    fi
    echo -en "\e[0m"
popd >/dev/null
