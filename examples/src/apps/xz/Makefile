#
# General
#
CC=clang-3.8
CXX=clang++-3.8

# Directories
SRC_DIR=../../../src/libs
LIBS_DIR=../../../builds/libs

OUT_DIR=out
CORPUS_DIR=corpus_dir
LIBDIR=lib

# LibFuzzer suffix
SUFFIX=_lf

# List of ARCHIVING libraries
CLAMAV=$(LIBS_DIR)/clamav_xz$(SUFFIX)
XZUTILS=$(LIBS_DIR)/xzutils$(SUFFIX)

# NEZHA_LIB=../../../../nezha/nezha.a
# INC_NEZHA=-I../../../../nezha/
# NEZHA=nezha
# LD_SSDEEP=-L$(LIBS_DIR)/ssdeep-lib/lib -Wl,-static -lfuzzy -Wl,-Bdynamic
# INC_SSDEEP=-I$(LIBS_DIR)/ssdeep-lib/include


#
#
# Configuration
#
#

# All possible libs: do not remove from this list, just set the appropriate
# USE_LIB_XXX flag, if you want to include this lib in the build
ALL_LIBS = clamav xzutils

#
# CONFIG: Select libraries to include (do not remove the first one)
#
USE_LIB_CLAMAV=1
USE_LIB_XZUTILS=1

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

#
# CONFIG: Indicate if we are compiling with the main() function for testing
# (Do not set when compiling with libFuzzer)
#
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

#
# CONFIG: Enable debugging logs
#
DBG_LOG=0
ifeq ($(DBG_LOG), 1)
CONFIG_DEBUG=-DCONFIG_DEBUG
endif

SUM=0
ifeq ($(SUM), 1)
CONFIG_DEBUG=-DCONFIG_SUMMARY
endif

OPTIONS=$(CONFIG_DBG_MAIN) $(CONFIG_DEBUG) $(CONFIG_USE_LF)
DBGFLAGS=-g -ggdb
CFLAGS=-O2 -Wall $(DBGFLAGS) $(OPTIONS)
CFLAGS_SHARED_O=-fPIC -fvisibility=hidden
CFLAGS_SHARED_LIB=$(CFLAGS_SHARED_O) -rdynamic -shared
CXXFLAGS=-std=c++11
LD_MAIN=-ldl -lstdc++ -lgcrypt
COV_MAIN_FLAGS=-fsanitize=address
COV_FULL_FLAGS=-fsanitize-coverage=edge,indirect-calls,8bit-counters


#
#
# Flags
#
#
INC_CLAMAV= -I$(CLAMAV)/include
LD_CLAMAV=-L$(CLAMAV)/lib -Wl,-static -lclamav -lclamunrar -lclamunrar_iface \
		  -Wl,-Bdynamic -ldl -lm -lxml2 \
		  -lpthread -lcrypto -lssl -lz -lltdl -lpcre -lbz2

INC_XZUTILS= -I$(XZUTILS)/include
LD_XZUTILS=-L$(XZUTILS)/lib -Wl,-static -llzma -Wl,-Bdynamic -lpthread

#
#
# Make Rules
#
#
TARGET=diff

.PHONY:all
all: prelim $(TARGET)

.PHONY:prelim
prelim:
	mkdir -p $(LIBDIR) $(OUT_DIR)

define mk_libs
lib$1.so: $1_arc.cpp
	$(CXX) $(CFLAGS) $(CFLAGS_SHARED_O) $(INC_$(shell echo $1 | tr a-z A-Z)) \
	$(COV_MAIN_FLAGS) -c -o $1.o $1_arc.cpp

	$(CXX) $(CFLAGS) $(CFLAGS_SHARED_LIB) $(COV_FULL_FLAGS) -o lib$1.so $1.o \
			$(LD_$(shell echo $1 | tr a-z A-Z))
	mv lib$1.so $(LIBDIR)
endef

$(foreach l, $(LIBS), \
  $(eval $(call mk_libs,$(l))) \
)

nezha:
	$(CXX) -c -g -O2 -std=c++11 ../../../../nezha/*.cpp -I../../../../nezha/ \
			$(INC_SSDEEP)
	ar rv ../../../../nezha/nezha.a Fuzzer*.o
	rm Fuzzer*.o

$(TARGET): $(TARGET).cpp $(foreach l, $(LIBS), lib$(l).so)
	$(CXX) $(CFLAGS) $(CXXFLAGS) $(INC_NEZHA) \
			$(foreach l, $(LIBS), $(INC_$(shell echo $(l) | tr a-z A-Z)))  \
			$(COV_MAIN_FLAGS) $(CONFIG_USE_LIBS) $< $(NEZHA_LIB) \
			$(LD_SSDEEP) $(LD_MAIN) -o $@


#
#
# Test rules
#
#

TEST_ARC=testfile.xz
TEST_COMMON=main_test.cpp

.PHONY: mk_all_tests
mk_all_tests: $(foreach l, $(LIBS), test_$(l))

.PHONY: run_all_tests
run_all_tests: $(foreach l, $(LIBS), run_test_$(l))

define mk_tests
test_$1:
	$(CXX) $(COV_MAIN_FLAGS) $(COV_FULL_FLAGS) -DCONFIG_TEST_$(shell echo $1 | tr a-z A-Z) \
	-DCONFIG_DBG_MAIN $(CFLAGS) $(INC_$(shell echo $1 | tr a-z A-Z)) \
	$(TEST_COMMON) $1_arc.cpp -o test_$1 $(LD_$(shell echo $1 | tr a-z A-Z))
endef

$(foreach l, $(LIBS), \
  $(eval $(call mk_tests,$(l))) \
)

define mk_run_tests
run_test_$1:
	./test_$1 $(CORPUS_DIR)/$(TEST_ARC)
endef

$(foreach l, $(LIBS), \
  $(eval $(call mk_run_tests,$(l))) \
)

# Test code coverage of corpus
.PHONY: cov
cov:
	ASAN_OPTIONS=coverage=1:html_cov_report=1 \
./$(TARGET) $(CORPUS_DIR) -jobs=1 -workers=1 -runs=0

test:
	rm -rf corpus out && mkdir -p out
	cp -r sample_corpus corpus && ASAN_OPTIONS=halt_on_error=0 ./diff corpus \
	-artifact_prefix=out/ -runs=100000 -diff_pdfine=1

# Trial-run of fuzzing with corpus with no mutation
.PHONY: fuzz_test
fuzz_test:
	./$(TARGET) $(CORPUS_DIR) -artifact_prefix=$(OUT_DIR)/ \
-print_final_stats=1 -runs=0




#
#
# Clean rules
#
#
.PHONY:clean
clean:
	rm -rf *.o *.a *.log *.sancov $(LIBDIR) $(TARGET) test_* \
../../../../nezha/nezha.a
