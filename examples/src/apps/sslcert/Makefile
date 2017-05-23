
#
# General
#
#
CC=clang-3.8
CXX=clang++-3.8

# Directories
SRC_DIR=../../../src/libs
LIBS_DIR=../../../builds/libs

CERT_DIR=certs
OUT_DIR=out
CORPUS_DIR=corpus_dir
BIG_CORPUS=~/Desktop/corpus
SMALL_CORPUS=corpus_dir
LIBDIR=lib

# LibFuzzer suffix
SUFFIX=_lf

# List of SSL libraries
OPENSSL=$(LIBS_DIR)/openssl$(SUFFIX)
BORINGSSL=$(LIBS_DIR)/boringssl$(SUFFIX)
LIBRESSL=$(LIBS_DIR)/libressl$(SUFFIX)


#
#
# Configuration
#
#

# All possible libs: do not remove from this list, just set the appropriate
# USE_LIB_XXX flag, if you want to include this lib in the build
ALL_LIBS = boringssl openssl libressl

USE_LIB_OPENSSL=1
# CONFIG: Select libraries to include
USE_LIB_BORINGSSL=1
USE_LIB_LIBRESSL=1

# populate based on selection above
LIBS =
CONFIG_USE_LIBS =

LIBS=$(foreach l, \
	 $(ALL_LIBS), \
	 $(if $(filter 1,$(USE_LIB_$(shell echo $l | tr a-z A-Z))),$l))

CONFIG_USE_LIBS=$(foreach l, \
				$(ALL_LIBS), \
				$(if $(filter 1,$(USE_LIB_$(shell echo $l | tr a-z A-Z))),\
				-DCONFIG_USE_$(shell echo $l | tr a-z A-Z)))

# CONFIG: Indicate if we are compiling with the main() function for testing
# (Do not set when compiling with libFuzzer)
DBG_MAIN=0
ifeq ($(DBG_MAIN), 1)
CONFIG_DBG_MAIN=-DCONFIG_DBG_MAIN
endif

NEZHA_SRC=../../../../nezha/
INC_NEZHA=-I../../../../NEZHA/
NEZHA=nezha
LD_SSDEEP=-L$(LIBS_DIR)/ssdeep-lib/lib -Wl,-static -lfuzzy -Wl,-Bdynamic
INC_SSDEEP=-I$(LIBS_DIR)/ssdeep-lib/include
CONFIG_USE_LF=-DCONFIG_USE_LF
NEZHA_LIB=$(NEZHA_SRC)/nezha.a

# this cannot be passed at runtime for the tests
# because they are created dynamically
USE_DER=1
ifeq ($(USE_DER), 1)
CONFIG_USE_DER=-DCONFIG_USE_DER
CA_FORMAT=der
BIN_SUFFIX=.der
else
CONFIG_USE_DER=-DCONFIG_USE_PEM
CA_FORMAT=pem
BIN_SUFFIX=.pem
endif

# CONFIG: Enable debugging logs
DBG_LOG=0
ifeq ($(DBG_LOG), 1)

CONFIG_DEBUG=-DCONFIG_DEBUG
ifeq ($(USE_DER), 1)
BIN_SUFFIX=.der.dbg
else
BIN_SUFFIX=.pem.dbg
endif
else
BIN_SUFFIX=.$(CA_FORMAT)
endif

SUM=0
ifeq ($(SUM), 1)
CONFIG_DEBUG=-DCONFIG_SUMMARY
endif

OPTIONS=$(CONFIG_DBG_MAIN) $(CONFIG_USE_DER) $(CONFIG_DEBUG)
DBGFLAGS=-g -ggdb3
CFLAGS=-O2 -Wall $(DBGFLAGS) $(OPTIONS)
CFLAGS_SHARED_O=-fPIC -fvisibility=hidden
CFLAGS_SHARED_LIB=$(CFLAGS_SHARED_O) -rdynamic -shared
COV_MAIN_FLAGS=-fsanitize=address -fsanitize-recover=undefined,integer
COV_FULL_FLAGS=-fsanitize-coverage=edge,indirect-calls,8bit-counters

#
#
# Flags
#
#
INC_BORINGSSL= -I$(BORINGSSL)/include
LD_BORINGSSL=-L$(BORINGSSL)/build/crypto -L$(BORINGSSL)/crypto -lcrypto -pthread \
			 -Wl,-static -lcrypto -Wl,-Bdynamic

INC_OPENSSL= -I$(OPENSSL)/include
LD_OPENSSL= -L$(OPENSSL)/lib -lcrypto

INC_LIBRESSL= -I$(LIBRESSL)/include
LD_LIBRESSL= -L$(LIBRESSL)/lib -lcrypto -Wl,-static -lcrypto -Wl,-Bdynamic

LD_MAIN=-ldl -lstdc++ -pthread
#
#
# Make Rules
#
#
TARGET=diff$(BIN_SUFFIX)

.PHONY:all
all: prelim $(TARGET)

.PHONY:prelim
prelim:
	mkdir -p $(LIBDIR) $(OUT_DIR)

define mk_libs
lib$1_$(CA_FORMAT).so: $1.cpp
	$(CXX) $(CFLAGS) $(CFLAGS_SHARED_O) $(INC_$(shell echo $1 | tr a-z A-Z)) \
		$(COV_MAIN_FLAGS) -c -o $1.o $1.cpp

	$(CXX) $(CFLAGS) $(CFLAGS_SHARED_LIB) $(COV_FULL_FLAGS) \
			-o lib$1_$(CA_FORMAT).so $1.o $(LD_$(shell echo $1 | tr a-z A-Z))
	mv lib$1_$(CA_FORMAT).so $(LIBDIR)
endef

$(foreach l, $(LIBS), \
  $(eval $(call mk_libs,$(l))) \
)

nezha:
	$(CXX) -c -g -O2 -std=c++11 ../../../../nezha/*.cpp -I../../../../nezha/ \
			$(INC_SSDEEP)
	ar rv ../../../../nezha/nezha.a Fuzzer*.o
	rm Fuzzer*.o
$(TARGET): diff.cpp $(foreach l, $(LIBS), lib$(l)_$(CA_FORMAT).so)
	$(CXX) $(CFLAGS) $(INC_NEZHA) \
			$(foreach l, $(LIBS), $(INC_$(shell echo $(l) | tr a-z A-Z)))  \
			$(COV_MAIN_FLAGS) $(CONFIG_USE_LIBS) $< $(NEZHA_LIB) \
			$(LD_SSDEEP) $(LD_MAIN) -o $@

afl: afl_target.cpp $(foreach l, $(LIBS), lib$(l)_$(CA_FORMAT).so)
	$(CXX) $(CFLAGS)  \
			$(foreach l, $(LIBS), $(INC_$(shell echo $(l) | tr a-z A-Z)))  \
			$(COV_MAIN_FLAGS) $(CONFIG_USE_LIBS) $< -o $@


#
#
# Test rules
#
#

TEST_CERT=test_cert.$(CA_FORMAT)
TEST_COMMON=main_test.cpp
# mbedTLS does not accept 1024!
KEY_SZ=2048

.PHONY: mk_all_tests
mk_all_tests: $(foreach l, $(LIBS), test_$(l))

.PHONY: run_all_tests
run_all_tests: $(foreach l, $(LIBS), run_test_$(l))

define mk_tests
test_$1:
	$(CXX) $(COV_MAIN_FLAGS) -DCONFIG_TEST_$(shell echo $1 | tr a-z A-Z) \
	-DCONFIG_DBG_MAIN $(CFLAGS) $(INC_$(shell echo $1 | tr a-z A-Z)) \
	$(TEST_COMMON) $1.cpp -o test_$1$(BIN_SUFFIX) \
	$(LD_$(shell echo $1 | tr a-z A-Z))
endef

$(foreach l, $(LIBS), \
  $(eval $(call mk_tests,$(l))) \
)

define mk_run_tests
run_test_$1:
	ASAN_OPTIONS=halt_on_error=0 ./test_$1$(BIN_SUFFIX) \
				 $(CERT_DIR)/$(TEST_CERT)
endef

$(foreach l, $(LIBS), \
  $(eval $(call mk_run_tests,$(l))) \
)

#
# Cert tests
#

define INT_CA_CONF_CONTENTS
[ ca ]
default_ca = myca

[ crl_ext ]
issuerAltName=issuer:copy
authorityKeyIdentifier=keyid:always

[ myca ]
dir = ./
new_certs_dir = $$dir
unique_subject = no
certificate = $$dir/intermediate.pem
database = $$dir/certindex
private_key = $$dir/intermediate.key
serial = $$dir/certserial
default_days = 365
default_md = sha1
policy = myca_policy
x509_extensions = myca_extensions
crlnumber = $$dir/crlnumber
default_crl_days = 365

[ myca_policy ]
commonName = supplied
stateOrProvinceName = supplied
countryName = optional
emailAddress = optional
organizationName = supplied
organizationalUnitName = optional

[ myca_extensions ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,any
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
crlDistributionPoints = @crl_section
subjectAltName  = @alt_names
authorityInfoAccess = @ocsp_section

[alt_names]
DNS.0 = fuzzing.com

[crl_section]
URI.0 = http://pki.columbia.ca.com/FuzzingIntermidiate1.crl

[ocsp_section]
caIssuers;URI.0 = http://pki.columbia.ca.edu/Fuzzingintermediate.crt
OCSP;URI.0 = http://pki.columbiaca.com/ocsp/
endef

define CA_CONF_CONTENTS
[ ca ]
default_ca = myca

[ crl_ext ]
issuerAltName=issuer:copy
authorityKeyIdentifier=keyid:always

[ myca ]
dir = ./
new_certs_dir = $$dir
unique_subject = no
certificate = $$dir/rootCA.pem
database = $$dir/certindex
private_key = $$dir/rootCA.key
serial = $$dir/certserial
default_days = 730
default_md = sha1
policy = myca_policy
x509_extensions = myca_extensions
crlnumber = $$dir/crlnumber
default_crl_days = 730

[ myca_policy ]
commonName = supplied
stateOrProvinceName = supplied
countryName = optional
emailAddress = optional
organizationName = supplied
organizationalUnitName = optional

[ myca_extensions ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,any
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
keyUsage = digitalSignature,keyEncipherment,cRLSign,keyCertSign
extendedKeyUsage = serverAuth
crlDistributionPoints = @crl_section
subjectAltName  = @alt_names
authorityInfoAccess = @ocsp_section

[ v3_ca ]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,any
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
keyUsage = digitalSignature,keyEncipherment,cRLSign,keyCertSign
extendedKeyUsage = serverAuth
crlDistributionPoints = @crl_section
subjectAltName  = @alt_names
authorityInfoAccess = @ocsp_section

[alt_names]
DNS.0 = Fuzzing Intermediate CA 1

[crl_section]
URI.0 = http://www.columbia.edu

[ocsp_section]
caIssuers;URI.0 = http://pki.columbia.ca.edu/FuzzingRoot.crt
OCSP;URI.0 = http://pki.columbia.ca.edu/ocsp/
endef

export CA_CONF_CONTENTS
export INT_CA_CONF_CONTENTS

CUR_DIR=`pwd`

.PHONY: certs
certs:
	#
	#
	# generate root CA
	#
	#
	mkdir -p $(CERT_DIR)/root
	# generate root CA key
	openssl genrsa -out $(CERT_DIR)/root/rootCA.key $(KEY_SZ)
	# generate root certificate
	openssl req -sha256 -x509 -new -key $(CERT_DIR)/root/rootCA.key -days 365 \
			-out $(CERT_DIR)/root/rootCA.der -outform DER
	# verify root certificate
	openssl x509 -noout -text -in $(CERT_DIR)/root/rootCA.der -inform DER
	# produce PEM certificate for CA
	openssl x509 -in $(CERT_DIR)/root/rootCA.der -inform DER \
			-out $(CERT_DIR)/root/rootCA.pem
	echo "$$CA_CONF_CONTENTS" > $(CERT_DIR)/root/ca.conf
	touch $(CERT_DIR)/root/certindex
	echo 1000000000 > $(CERT_DIR)/root/certserial
	echo 1000000000 > $(CERT_DIR)/root/crlnumber
	#
	#
	# generate intermediate CA
	#
	#
	# init dir
	mkdir -p $(CERT_DIR)/intermediate
	touch $(CERT_DIR)/intermediate/certindex
	echo 1000000000 > $(CERT_DIR)/intermediate/certserial
	echo 1000000000 > $(CERT_DIR)/intermediate/crlnumber
	echo "$$INT_CA_CONF_CONTENTS" > $(CERT_DIR)/intermediate/ca.conf
	# create key
	openssl genrsa -out $(CERT_DIR)/root/intermediate.key $(KEY_SZ)
	# generate csr for intermediate CA
	openssl req -new -sha256 -key $(CERT_DIR)/root/intermediate.key \
			-out $(CERT_DIR)/root/intermediate.csr
	# sign intermediate CA with root CA
	cd $(CERT_DIR)/root && openssl ca -batch -config ca.conf -notext -in \
		intermediate.csr -out intermediate.pem && cd ../../
	# produce DER for intermediate CA
	openssl x509 -in $(CERT_DIR)/root/intermediate.pem -inform PEM \
			-out $(CERT_DIR)/root/intermediate.der -outform DER
	/bin/cp -f $(CERT_DIR)/root/intermediate* $(CERT_DIR)/intermediate
	# generate CRLs
	cd $(CERT_DIR)/intermediate && openssl ca -config ca.conf -gencrl \
			-keyfile intermediate.key -cert intermediate.pem \
			-out intermediate.crl.pem && cd ../../
	openssl crl -inform PEM \
			-in $(CERT_DIR)/intermediate/intermediate.crl.pem -outform DER \
			-out $(CERT_DIR)/intermediate/intermediate.crl
	# verify intermediate CA
	openssl x509 -noout -text -in $(CERT_DIR)/root/intermediate.pem -inform PEM
	#
	#
	# generate test certificate key
	#
	#
	mkdir -p $(CERT_DIR)/endcerts
	openssl genrsa -out $(CERT_DIR)/endcerts/test_cert.key $(KEY_SZ)
	# generate a certificate signing request
	openssl req -new -sha256 -key $(CERT_DIR)/endcerts/test_cert.key \
			-out $(CERT_DIR)/endcerts/test_cert.csr
	# generate test certificate
	cd $(CERT_DIR)/intermediate && openssl ca -batch \
			-config ca.conf -notext \
			-in ../endcerts/test_cert.csr -out ../endcerts/test_cert.pem && \
			cd ../../
	# produce DER test_cert
	openssl x509 -in $(CERT_DIR)/endcerts/test_cert.pem -outform DER \
			-out $(CERT_DIR)/endcerts/test_cert.der
	# create chain
	cat $(CERT_DIR)/root/rootCA.key $(CERT_DIR)/root/rootCA.pem \
			> $(CERT_DIR)/rootCA.pem
	cp $(CERT_DIR)/endcerts/test_cert.der $(CERT_DIR)
	cp $(CERT_DIR)/endcerts/test_cert.pem $(CERT_DIR)
	# verify server certificate
	openssl verify -verbose -CAfile $(CERT_DIR)/rootCA.pem \
			$(CERT_DIR)/test_cert.pem
	mkdir $(CERT_DIR)/CApath
	cp $(CERT_DIR)/rootCA.pem \
			$(CERT_DIR)/CApath/`openssl x509 -noout -hash -in certs/rootCA.pem`.0
	sudo cp $(CERT_DIR)/CApath/* /etc/ssl/certs

# Trial-run of fuzzing with corpus with no mutation
.PHONY: fuzz_big
fuzz_big: $(BIG_CORPUS)
	./$(TARGET) $(BIG_CORPUS) -max_len=1500 -artifact_prefix=$(OUT_DIR)/ \
-print_final_stats=1 -runs=-1 -detect_leaks=0 -rss_limit_mb=4096

.PHONY: fuzz_small
fuzz_small: $(SMALL_CORPUS)
	./$(TARGET) $(SMALL_CORPUS) -max_len=1500 -artifact_prefix=$(OUT_DIR)/ \
-print_final_stats=1 -runs=-1 -detect_leaks=0 -rss_limit_mb=4096 -jobs=10 \
-workers=4

.PHONY: fuzz_test
fuzz_test: $(SMALL_CORPUS)
	ASAN_OPTIONS=coverage=1:html_cov_report=1:detect_leaks=0 \
	./$(TARGET) $(SMALL_CORPUS) -max_len=1500 -artifact_prefix=$(OUT_DIR)/ \
-print_final_stats=1 -runs=0 -detect_leaks=0 -jobs=1

# Test code coverage of corpus
.PHONY: cov
cov:
	ASAN_OPTIONS=coverage=1:html_cov_report=1:detect_leaks=0 \
./$(TARGET) $(CORPUS_DIR) -jobs=1 -workers=1 -runs=0


.PHONY: test
test:
	rm -rf corpus out/*
	cp -R sample_corpus corpus
	ASAN_OPTIONS=halt_on_error=0 ./diff.der corpus/ \
				 -artifact_prefix=out/ -diff_pdfine=1 \
				 -print_final_stats=1 -runs=100000 -detect_leaks=0

#
#
# Clean rules
#
#
.PHONY:clean
clean:
	rm -rf *.o *.a $(LIBDIR) diff.der* diff.pem* test_* \
			../../../../nezha/nezha.a fuzzdiff*
