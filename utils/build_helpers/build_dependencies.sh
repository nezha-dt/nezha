#!/bin/bash
CWD=`pwd`
source ${CWD}/utils/build_helpers/include.sh

mkdir -p ${BUILDS}
# ignore everything in these directories
echo "*" > ${BUILDS}/.gitignore

echo "[+] Installing examples dependencies (this might take a while)"
sudo apt-get -y install build-essential cmake llvm-3.8 clang-3.8 golang \
    libssl-dev autogen autopoint libtool autoconf automake >/dev/null 2>&1

if ! [ -f /usr/bin/clang-3.8 ]; then
    echo -e "\t\t -\033[0;31m Did not find clang-3.8";
    echo -e "\t\t -\033[0;31m This should not have happened :(";
    echo -e "\t\t -\033[0;31m Please attempt a manual installation or required packages through apt-get then rerun setup.sh";
    echo -en "\e[0m";
    exit 1;
fi

echo "[+] Downloading files"

if ! [ -d ${SRC_LIBS}/${OPENSSL}  ]; then
    echo -e "\t\t - Downloading OpenSSL in ${SRC_LIBS}/openssl"
    wget -P ${SRC_LIBS} ${OPENSSL_ST} 2>/dev/null
fi
if ! [ -d ${SRC_LIBS}/${LIBRESSL}  ]; then
    echo -e "\t\t - Downloading LibreSSL in ${SRC_LIBS}/libressl"
    wget -P ${SRC_LIBS} ${LIBRESSL_ST} 2>/dev/null
fi
if ! [ -d ${SRC_LIBS}/${BORINGSSL}  ]; then
    echo -e "\t\t - Downloading boringSSL in ${SRC_LIBS}/${BORINGSSL}"
    git clone ${BORINGSSL_ST} ${SRC_LIBS}/${BORINGSSL} 2>/dev/null
fi

if ! [ -d ${SRC_LIBS}/${CLAMAV}  ]; then
    echo -e "\t\t - Downloading Clam-AV in ${SRC_LIBS}/clamav"
    wget -P ${SRC_LIBS} ${CLAMAV_ST} 2>/dev/null
fi

if ! [ -d ${SRC_LIBS}/${XZUTILS}  ]; then
    echo -e "\t\t - Downloading XZ-Utils in ${SRC_LIBS}/xzutils"
    git clone ${XZUTILS_ST} ${SRC_LIBS}/xzutils 2>/dev/null
fi

if ! [ -d ${SRC_LIBS}/${SSDEEP}  ]; then
    echo -e "\t\t - Downloading ssdeep in ${SRC_LIBS}/ssdeep"
    git clone ${SSDEEP_ST} ${SRC_LIBS}/${SSDEEP} 2>/dev/null
fi

if ! [ -d ${SRC_LIBS}/${LIBFUZZER}  ]; then
    echo -e "\t\t - Downloading libFuzzer in ${SRC_LIBS}/libFuzzer"
    git clone ${LF_ST} ${SRC_LIBS}/libFuzzer 2>/dev/null
fi

echo "[+] Extracting & installing dependencies"
pushd ${SRC_LIBS} >/dev/null
    if [ -f openssl-1.0.2h.tar.gz ]; then
        echo -e "\t\t - Extracting OpenSSL"
        tar xzf openssl-1.0.2h.tar.gz
        mv openssl-1.0.2h ${OPENSSL}
    fi

    if [ -f libressl-2.4.0.tar.gz ]; then
        echo -e "\t\t - Extracting LibreSSL"
        tar xzf libressl-2.4.0.tar.gz
        mv libressl-2.4.0 ${LIBRESSL}
    fi

    if [ -f clamav-0.99.2.tar.gz ]; then
        echo -e "\t\t - Extracting clamav"
        tar xzf clamav-0.99.2.tar.gz
        mv clamav-0.99.2 ${CLAMAV}
    fi

	if (! [ -f libFuzzer/libFuzzer.a ]); then
        echo -e "\t\t - Installing libFuzzer"
		pushd libFuzzer >/dev/null
			clang++-3.8 -c -g -O2 -std=c++11 *.cpp -I. >/dev/null 2>&1
			ar ruv libFuzzer.a Fuzzer*.o >/dev/null 2>&1
			if [ -f libFuzzer.a ]; then
				echo -e "\t\t\t -\033[0;32m OK\n";
				echo -en "\e[0m";
			else
				echo -e "\t\t\t -\033[0;31m FAILED\n";
				echo -en "\e[0m";
				exit 1;
			fi
		popd >/dev/null
	fi

    echo -e "\t\t - Building ssdeep"
    if [ -d ${SSDEEP} ]; then
        pushd ${SSDEEP} >/dev/null
        git checkout 9ca00aa37f1ca4c2dcb12978ef61fa8d12186ca7 >/dev/null 2>&1
            pushd ssdeep-lib >/dev/null
            autoreconf >/dev/null 2>&1
            automake --add-missing >/dev/null 2>&1
            autoreconf >/dev/null 2>&1
            ./configure --prefix=`pwd`/../../../../builds/libs/ssdeep-lib \
                CC="clang-3.8" CXX="clang++-3.8" >/dev/null 2>&1
            make && make install >/dev/null 2>&1
            popd >/dev/null
        popd >/dev/null
    fi
    # cleanup
    rm -f *gz *tar
popd >/dev/null
