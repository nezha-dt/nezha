# NEZHA
NEZHA is an evolutionary-based efficient and domain-independent differential
testing framework developed at Columbia University. NEZHA exploits the
behavioral asymmetries between multiple test programs to focus on inputs that
are more likely to trigger semantic bugs.

## What?
NEZHA features several runtime diversity-promoting metrics used to generate
inputs for multi-app differential testing. These metrics are described in
detail in the 2017 IEEE Symposium on Security and Privacy (Oakland) paper -
[NEZHA: Efficient Domain-Independent Differential Testing](https://www.ieee-security.org/TC/SP2017/papers/390.pdf).

# Getting Started
These examples are tested on Ubuntu 16.04.

Install all dependencies and build NEZHA and the respective examples by invoking
```
        ./utils/build_helpers/setup.sh
```

This should create the appropriate files under examples/

Please refer to the domain-specific examples:

* [Quick Start](examples/src/apps/helloworld)
* [Example 1 - SSL/TLS](examples/src/apps/sslcert)
* [Example 2 - XZ archive parsing](examples/src/apps/xz)

# Bug Examples
Examples of some of the bugs we found with Nezha are listed [here](examples/bugs).

# Writing your own tests / extending NEZHA
Please refer to the [Wiki](https://github.com/nezha-dt/nezha/wiki) for more
information on NEZHA's internals.
