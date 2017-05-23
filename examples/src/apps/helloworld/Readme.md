# "Hello world" example - `checkVer`
In this example, we will apply differential testing to the verification behavior
of two simple toy programs.

Consider two programs that implement a version string verification functionality.
Both programs feature a similar checking logic, but there is a subtle difference
in the return values for certain inputs.

App1 code:
```
int checkVer(const uint8_t *data_ver_str, uint32_t size_str)
{
  if (size_str != 3)
    return -3;
  if (data_ver_str[2] % 2 != 0)
    return -1;
  if (data_ver_str[2] < 1 || data_ver_str[2] > 7)
    return -2;
  return 0;
}
```

App2 code:
```
int checkVer(const uint8_t *data_ver_str, uint32_t size_str)
{
  if (size_str != 3)
    return -3;
  if (data_ver_str[2] < 3 || data_ver_str[2] > 7)
    return -2;
  if (data_ver_str[2] % 2 != 0)
    return -1;
  return 0;
}
```

## The discrepancy
The output of the two programs is different for the input string `"\x00\x00\x02"`,
where the 3rd character is `"\x02"`.

To show this, we first compile and two programs as executables and run them 
separately.
```
$ make mk_all_tests
$ ./test_app1
INPUT[1]:-3
INPUT[2]:-3
INPUT[3]:0
INPUT[4]:-1
INPUT[5]:0
$ ./test_app2
...
INPUT[5]:-2
```

Notice for input 5, `app1` returns 0, while `app2` returns -2.


## Using Nezha for differential testing
Here we do a brief walkthrough of using Nezha to uncover this discrepancy in
the two toy apps. The following components are encapsulated in the main Nezha
test harness file `nezha_main.cpp`.

### Nezha header file
Include the Nezha-specific header file within the main Nezha test harness. This 
header file contains the core code that maintains the book-keeping information 
for the delta-diversity guidance engines.
```
// Nezha-specific header file
#include "nezha_diff.h"
```

### Compile apps as shared libraries
Notice that the names of the function (to be tested) within the two apps are 
identical. Compiling both the `app1` and `app2` code statically into the test
harness can be messy as a result. This is not unlike close software forks like
OpenSSL and LibreSSL.

A workaround is to compile each app as a shared library that will be loaded 
dynamically. 
```
// Exported function name from SUT apps
#define FUNCNAME_VRFY_VER     "checkVer"

// Generic interface to packages
typedef int (*fp_t)(const uint8_t *, uint32_t);

#define INCLUDE(name) \
  static fp_t verify_ver_ ##name = NULL; \
  static void *h_ ##name = NULL; \
  int ret_ ##name = FAILURE_INTERNAL;

#ifdef CONFIG_USE_APP1
INCLUDE(app1)
const static char *LIB_APP1 = "lib/libapp1.so";
#endif

#ifdef CONFIG_USE_APP2
INCLUDE(app2)
const static char *LIB_APP2 = "lib/libapp2.so";
#endif
```

### Exercise each app for each test input
We pre-configure macros to exercise each of the apps within the libFuzzer-specific
function, `LLVMFuzzerTestOneInput`.
```
#define VERIFY_ONE(name) \
  ret_ ##name = verify_ver_ ##name(data, size);

#define EXERCISE(name) \
  if (cur_lib == 0) \
    cov_buff_idx[cur_lib] = __sanitizer_get_total_unique_coverage(); \
  __sanitizer_update_counter_bitset_and_clear_counters(0); \
  VERIFY_ONE(name); \
  cov_buff_idx[cur_lib + 1] = __sanitizer_get_total_unique_coverage(); \
  ret_vals[cur_lib] = ret_ ##name; \
  memset(bitset_cur[cur_lib], 0, num_bitcounters); \
  __sanitizer_update_counter_bitset_and_clear_counters(bitset_cur[cur_lib]); \
  bitcounts[cur_lib] = \
    update_bitcount(bitset_cur[cur_lib], bitset_old[cur_lib], &ecnt[cur_lib]); \
  cur_lib = (cur_lib < total_libs - 1) ? cur_lib + 1 : 0;

...
#ifdef CONFIG_USE_APP1
  EXERCISE(app1)
#endif
#ifdef CONFIG_USE_APP2
  EXERCISE(app2)
#endif
```

## Building the test harness
Compile the Nezha runtime and test harness `nezha_main` executable.
```
$ make nezha
$ make
```

## Testing with Global Coverage
First, we run `nezha_main` using the default differential testing mode, the
union (global) coverage mode. Recall that this mode only adds inputs that 
exercise new edges by tracking the combined coverage from both `app1` and 
`app2`.

```
$ ./nezha_main -help=1
...
 log_unique           	1	[NEW] Log only unique differences.
 diff_union           	1	[NEW] FITNESS: Union (global) coverage.
...
```

We'll start with an empty corpus, and run the default global coverage mode.
This will take a while...
```
$ ./nezha_main out
app1 0x7f6a45afe790
app2 0x7f6a458fc790
INFO: Seed: 112837427
INFO: DiffMode: | Global Coverage
INFO: -max_len is not provided, using 64
INFO: A corpus is not provided, starting from an empty corpus
#0	READ   units: 1 exec/s: 0
#1	INITED units: 1 exec/s: 0
#65536	pulse  units: 1 exec/s: 32768
...
```

## Testing with Output Diversity
Instead of using the global coverage guidance engine, we will now use the 
Output Diversity guidance engine geared towards multi-app differential testing.
```
$ ./nezha_main -diff_od=1 out
app1 0x7f5bc1cfe790
app2 0x7f5bc1afc790
INFO: Seed: 2180994877
INFO: DiffMode: | Output Diversity
INFO: -max_len is not provided, using 64
INFO: A corpus is not provided, starting from an empty corpus
#1	NEW    units: 2 exec/s: 0 L: 64 MS: 0
#324	NEW    units: 3 exec/s: 0 L: 3 MS: 4 CrossOver-InsertByte-ShuffleBytes-InsertByte-
#341	NEW    units: 4 exec/s: 0 L: 3 MS: 1 ShuffleBytes-
#551	NEW    units: 5 exec/s: 0 L: 3 MS: 1 ChangeByte-
artifact_prefix='./'; Test unit written to ./0_fffffffe_da39a_da39a_661_fb2f6377e45abece254cb00faac01e401888f87a
...
```

The discrepancy is found within seconds, after roughly 551 test inputs. Notice
that the test input that causes the discrepancy has `"\x02"` as the third 
character, as expected.
```
$ xxd -g1 0_fffffffe_da39a_da39a_661_fb2f6377e45abece254cb00faac01e401888f87a
00000000: 83 28 02                                         .(.
```
