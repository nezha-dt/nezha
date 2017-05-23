
#
# General
#
#
CC=clang-3.8
CXX=clang++-3.8

# Directories/Files
OUT_DIR=out
CORPUS_DIR=corpus_dir
LIBDIR=lib
LIBS_DIR=../../../builds/libs
NEZHA_MAIN=nezha_main

# Nezha runtime
NEZHA_SRC=../../../../nezha
NEZHA_LIB=$(NEZHA_SRC)/nezha.a
LD_SSDEEP=-L$(LIBS_DIR)/ssdeep-lib/lib -Wl,-static -lfuzzy -Wl,-Bdynamic
INC_SSDEEP=-I$(LIBS_DIR)/ssdeep-lib/include

# Flags
CFLAGS=-O2 -Wall
CFLAGS_SHARED_O=-fPIC -fvisibility=hidden
CFLAGS_SHARED_LIB=$(CFLAGS_SHARED_O) -rdynamic -shared
COV_MAIN_FLAGS=-fsanitize=address -fsanitize-recover=undefined,integer
COV_FULL_FLAGS=-fsanitize-coverage=edge,indirect-calls,8bit-counters
LD_MAIN=-ldl -lstdc++ -pthread


#
#
# Configuration
#
#

# All possible libs: do not remove from this list, just set the appropriate
# USE_LIB_XXX flag, if you want to include this lib in the build
ALL_LIBS = app1 app2

USE_LIB_APP1=1
# CONFIG: Select libraries to include
USE_LIB_APP2=1

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
# Nezha Main Executable
#
.PHONY:all
all: prelim $(NEZHA_MAIN)

.PHONY:prelim
prelim:
	mkdir -p $(LIBDIR) $(OUT_DIR)

define mk_libs
lib$1.so: $1.cpp
	$(CXX) $(CFLAGS) $(CFLAGS_SHARED_O) $(COV_MAIN_FLAGS) -c -o $1.o $1.cpp
	$(CXX) $(CFLAGS) $(CFLAGS_SHARED_LIB) $(COV_FULL_FLAGS) \
			-o lib$1.so $1.o $(LD_$(shell echo $1 | tr a-z A-Z))
	mv lib$1.so $(LIBDIR)
endef

$(foreach l, $(LIBS), \
	$(eval $(call mk_libs,$(l))) \
)

$(NEZHA_MAIN): $(NEZHA_MAIN).cpp $(foreach l, $(LIBS), lib$(l).so)
	$(CXX) $(CFLAGS) $(INC_NEZHA) \
			$(foreach l, $(LIBS), $(INC_$(shell echo $(l) | tr a-z A-Z)))  \
			$(COV_MAIN_FLAGS) $(CONFIG_USE_LIBS) $< $(NEZHA_LIB) \
			$(LD_SSDEEP) $(LD_MAIN) -o $@

#
# Nezha Runtime
#
.PHONY:nezha
nezha:
	$(CXX) -c -g -O2 -std=c++11 $(NEZHA_SRC)/*.cpp -I$(NEZHA_SRC)/nezha/ \
			$(INC_SSDEEP)
	ar rv $(NEZHA_SRC)/nezha.a Fuzzer*.o
	rm Fuzzer*.o


#
# Compile SUT apps as test executables
#
.PHONY: mk_all_tests
mk_all_tests: $(foreach l, $(LIBS), test_$(l))

define mk_tests
test_$1:
	$(CXX) -DCONFIG_DBG_MAIN $1.cpp -o test_$1
endef

$(foreach l, $(LIBS), \
	$(eval $(call mk_tests,$(l))) \
)


#
# Clean rules
#
.PHONY:clean
clean:
	rm -rf *.o *.a $(LIBDIR) $(OUT_DIR) nezha_main test_* \
			$(NEZHA_SRC)/nezha.a