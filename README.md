# NEZHA
NEZHA is an efficient and domain-independent differential
fuzzer developed at Columbia University. NEZHA exploits the
behavioral asymmetries between multiple test programs to focus on inputs that
are more likely to trigger logic bugs.

## What?
NEZHA features several runtime diversity-promoting metrics used to generate
inputs for multi-app differential testing. These metrics are described in
detail in the 2017 IEEE Symposium on Security and Privacy (Oakland) paper -
[NEZHA: Efficient Domain-Independent Differential Testing](https://www.ieee-security.org/TC/SP2017/papers/390.pdf).

# Getting Started
The current code is a WIP to port NEZHA to the latest libFuzzer and is non-tested.
Users who wish to access the code used in the NEZHA paper and the respective
examples should access [v-0.1](https://github.com/nezha-dt/nezha/tree/v0.1).

This repo follows the format of libFuzzer's [fuzzer-test-suite](https://github.com/google/fuzzer-test-suite).
For a simple example on how to perform differential testing using the NEZHA
port of libFuzzer see [differential_fuzzing_tutorial](https://github.com/nezha-dt/nezha/tree/master/differential_fuzzing_tutorial).

# Support
We welcome issues and pull requests with new fuzzing targets.
