# Differential testing of XZ parsers
In this example, we focus the differential testing the xz parser of ClamAV
antivirus as well as the xz utility

# Build Instructions

Normally all dependencies should have been installed if you run the setup.sh
script under build_helpers. If so, just type

```
make nezha
make
```

### NEZHA run options
```
$ ./diff -help=1
...
    fhash_min            	80	[NEW] Minimum threshold for difference bucketing (ssdeep-based fuzzy hash).
    log_unique           	1	[NEW] Log only unique differences.
    diff_union           	1	[NEW] FITNESS: Union (global) coverage.
    diff_pdcoarse        	0	[NEW] FITNESS: Path diversity (coarse).
    diff_pdfine          	0	[NEW] FITNESS: Path Diversity (fine).
    diff_od              	0	[NEW] FITNESS: Output diversity (return values).
...
```

# Sample run
To give NEZHA a try, simply run

```
make test
```

You should be seeing outputs in out/

In particular, for an output
```
0_9_91da0_12f0c_594_60a8f2dac2955af35e77f49e28d62fbff922c8a9
```
the first two numbers separated by underscores are the return values
for each of the parsers for this input and the following two numbers are
prefixes of the respective
fuzzy hashes for the coverage of this input on each application. The final hash
is the hash of the input itself. Using that hash, one can see what was the
input before the mutation that triggered the discrepancy
```
60a8f2dac2955af35e77f49e28d62fbff922c8a9_BeforeMutationWas_cf4799e2cac14db5dce72c36c4375f5b74333fd3
```
so that an analyst can perform delta-debugging using these inputs
