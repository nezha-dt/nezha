# Differential Fuzzing with libFuzzer - Tutorial
## Setup

To setup libFuzzer, follow the instructions at the main [tutorial](https://github.com/google/fuzzer-test-suite/tree/master/tutorial)

## Example differential fuzzing invocation
Inside `nezhaplus/test-suite/`, run:
```shell
clang++ -g -fsanitize=address -fsanitize-coverage=trace-pc-guard differential_fuzzing_tutorial/diff_fuzz_me.cc Fuzzer/libFuzzer.a
mkdir -p out && ./a.out -diff_mode=1 -artifact_prefix=out/
```

## 'Hello world' differential fuzzing driver
To perform differential fuzzing with libFuzzer, `-diff_mode=1` has to be passed
to the fuzzer. In addition to the default `LLVMFuzzerTestOneInput` routine,
users can declare an arbitrary number of functions to be called sequentially by
libFuzzer, however each of the functions needs to have the same template as
`LLVMFuzzerTestOneInput`. During execution, the same `Data` buffer of size `Size`
will be passed to all the functions.

Users need to declare what functions should be called by the fuzzer via the
callback `LLVMFuzzerCustomCallbacks()`. For instance, if in addition to
`LLVMFuzzerTestOneInput` the user needs to also call a second callback named
`Callback2`, the following needs to be declared:

```c
extern "C" int Callback2(const uint8_t *Data, size_t Size) {
  return DoSomethingElseWithData(Data, Size);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    return DoSomethingWithData(Data, Size);
}

UserCallback gl_callbacks[2] = { LLVMFuzzerTestOneInput, Callback2 };
extern "C" UserCallbacks *LLVMFuzzerCustomCallbacks() {
  callback_cont.callbacks = gl_callbacks;
  callback_cont.size = 2;
  return &callback_cont;
}
```

Notice that, contrary to standard invocation of `LLVMFuzzerTestOneInput` which
always ends with a `return 0`, in differential fuzzing, the return values
of all callbacks are compared with each other. In case at least one callback
returns 0 whereas another callback returns a non-zero value, a difference is
logged. The format for the logged differences is
`diff_<return_value_of_callback0>_<return_value_of_callback1>_..._<input_hash>`.
Moreover, in case a difference is observed after a Mutation, the respective
input before the mutation is logged as well. For instance, for the above example,
once fuzzing is finished the contents of `out/` may be as follows:

```
418228556282275e55df9c7bc6dfbafacfd59f50_BeforeMutationWas_c12d8b31ce7921765eac8e369a5b1d659575b04a
crash-0eb8e4ed029b774d80f2b66408203801cb982a60
diff_1_0_418228556282275e55df9c7bc6dfbafacfd59f50
```
This denotes that the input with hash 418228556282275e55df9c7bc6dfbafacfd59f50,
saved as `diff_1_0_418228556282275e55df9c7bc6dfbafacfd59f50`, caused the first
callback declared in `gl_callbacks` to return 1, and the second callback to
return 0 after its last mutation. The same input before its last mutation has a
hash c12d8b31ce7921765eac8e369a5b1d659575b04a and is saved as
`418228556282275e55df9c7bc6dfbafacfd59f50_BeforeMutationWas_c12d8b31ce7921765eac8e369a5b1d659575b04a`.

By comparing return values of the respective callbacks, we can compare expected
behavior of routines that are supposed to behave identically, (i.e. always return
the same value on the same input). As such, if we construct our callbacks appropriately,
we can find semantic bugs. One such example is shown in the directory `openssl-1.0.2h_libressl-2.4.0`,
finding a parsing bug in libreSSL 2.4.0.
