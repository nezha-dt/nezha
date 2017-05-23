CWD=`pwd`
INCL=${CWD}/utils/build_helpers/include.sh
source ${INCL}

BDIR_XZ=${BUILD_LIBS}/${CLAMAV}_xz_lf
PATCH=clamav_0.99.2_xz.patch

echo -e "\t * Building ASAN/SanitizerCoverage-instrumented ClamAV"
if [ ! -d ${BDIR} ]; then
    mkdir -p ${BDIR}
fi

LC="-g -fsanitize=address -fsanitize-coverage=edge,indirect-calls,8bit-counters"

function reset_clamav_dir {
    rm -rf ${SRC_LIBS}/$CLAMAV
    echo -e "\t\t - Downloading Clam-AV in ${SRC_LIBS}/clamav"
    wget -P ${SRC_LIBS} ${CLAMAV_ST} 2>/dev/null

    pushd ${SRC_LIBS} > /dev/null
        if [ -f clamav-0.99.2.tar.gz ]; then
            tar xzf clamav-0.99.2.tar.gz
            mv clamav-0.99.2 ${CLAMAV}
        fi
        # cleanup
        rm -f *gz *tar
    popd > /dev/null
}

reset_clamav_dir

pushd ${SRC_LIBS}/${CLAMAV} >/dev/null
    echo -e "\t\t - Configuring ClamAV for XZ"
    # clean up just in case
    cp ../../../../utils/patches/${PATCH} .
    # patch if we have not patched already
    patch -p1 -N --dry-run --silent < ${PATCH} >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "\t\t - Applying patch for xz"
        patch -p1 < ${PATCH} >/dev/null 2>&1
    else
        echo -e "\t\t - Skipping patch - already applied"
    fi
    rm ${PATCH}

    /bin/cp -f ../../../../utils/patches/clamav_xzdec.c \
        ${SRC_LIBS}/${CLAMAV}/libclamav/7z/XzDec.c

    ./configure --disable-shared --with-pic --prefix=${BDIR_XZ} \
--exec-prefix=${BDIR_XZ} CC="clang-3.8" CXX="clang++-3.8" CFLAGS="$LC" \
> /dev/null  2>&1
    echo -e "\t\t - Adding dependencies"
    echo -e "\t\t - Compiling"
    make -j10 > /dev/null  2>&1
    echo -e "\t\t - Installing"
    make -j10 install > /dev/null 2>&1
    # clean up for next install
    make -j10 clean > /dev/null 2>&1
    make -j10 distclean > /dev/null 2>&1
    ${BDIR_XZ}/bin/clamscan --version 1> /tmp/ttest
    test=$(objdump -d ${BDIR_XZ}/bin/clamscan 2>/dev/null \
| grep "__sanitizer" | wc -l)
    if [ -f ${BDIR_XZ}/bin/clamscan ] &&
        [ -f ${BDIR_XZ}/lib/libclamav.a ] &&
        [ $(grep -i clam /tmp/ttest | wc -l) -ne 0 ] &&
        [ $test -ne 0 ]; then
        echo -e "\t\t - Testing install..\033[0;32m OK\n"
    else
        echo -e "\t\t - Testing install..\033[0;31m FAILED\n"
    fi
    echo -en "\e[0m"
popd >/dev/null
