make USE_DER=0
make USE_DER=0 SUM=1 mk_all_tests
make USE_DER=0 DBG_LOG=1 mk_all_tests
make USE_DER=1 diff.der
make USE_DER=1 SUM=1 mk_all_tests
make USE_DER=1 DBG_LOG=1 mk_all_tests
