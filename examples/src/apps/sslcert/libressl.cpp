#include "libressl.h"

#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>



struct GlobalState {
    GlobalState()
    : caStore(InitCaStore()){
        OpenSSL_add_all_algorithms();
    }

    ~GlobalState() {
        X509_STORE_free(caStore);
        EVP_cleanup();
    }

    X509_STORE *InitCaStore() {
        X509_STORE *store = NULL;
        X509_LOOKUP *lookup = NULL;
        int rc;

        store = X509_STORE_new();
        assert(store != NULL);

        lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
        assert(lookup != NULL);
        rc = X509_LOOKUP_add_dir(lookup, CAPATH_DEFAULT1, X509_FILETYPE_PEM);
        assert(rc);

        lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
        assert(lookup != NULL);
        rc = X509_LOOKUP_add_dir(lookup, CAPATH_DEFAULT2, X509_FILETYPE_PEM);
        assert(rc);

        return store;
    }

    // Global CA store
    X509_STORE *caStore;
};



/**
 * Assume that the leaf certificate is the first certificate within the
 * certificate chain buffer. This is typical of how certificate chains are
 * transferred during the Server Hello message during the TLS session setup.
 *
 * This function returns the leaf certificate via param @leaf and returns the
 * rest of the certificates within the chain using a X509 certificate stack.
 */
static STACK_OF(X509) *load_cert_chain_from_mem(X509 **leaf,
                                                const uint8_t *data,
                                                uint32_t size)
{
    STACK_OF(X509) *certs;
    BIO *bio;
    X509 *x;
    int certnum = 0;
#ifdef CONFIG_DEBUG
    BUF_MEM *bptr;
#endif

    if ((bio = BIO_new_mem_buf((uint8_t *)data, size)) == NULL)
        return NULL;

    if ((certs = sk_X509_new_null()) == NULL) {
        BIO_free(bio);
        return NULL;
    }

    ERR_set_mark();
    do {
        certnum++;

#ifdef CONFIG_DEBUG
        BIO_get_mem_ptr(bio, &bptr);
        DBG("- cert offset[%d]: %ld\n", certnum, size - bptr->length);
#endif

#ifdef CONFIG_USE_DER
        x = d2i_X509_bio(bio, NULL);
#else
        x = PEM_read_bio_X509(bio, NULL, 0, NULL);
#endif

        // Extract the first certificate as the leaf cert to be verified
        if (certnum == 1) {
            if (x != NULL) {
                *leaf = x;
                continue;
            }
#ifdef CONFIG_DEBUG
            else {
                ERR_print_errors_fp(stderr);
            }
#endif
        }

        // Push subsequent certificate into a stack struct to be returned.
        if (x != NULL && !sk_X509_push(certs, x)) {
            sk_X509_pop_free(certs, X509_free);
            BIO_free(bio);
            return NULL;

        } else if (x == NULL) {
            // Probably just ran out of certs, so ignore any errors generated
            ERR_pop_to_mark();
        }

    } while (x != NULL);

    BIO_free(bio);
    return certs;
}


extern "C"
LIB_EXPORT
int verify_cert_mem(const uint8_t *data_cert, uint32_t size_cert)
{
    // Global state initializer
    static GlobalState g_state;

    int depth = 0;
    int composite_ret = FAILURE_INTERNAL;
    int raw_ret = FAILURE_INTERNAL;
    int err = FAILURE_INTERNAL;
    X509 *leaf = NULL;
    STACK_OF(X509) *untrusted = NULL;
    X509_STORE_CTX *sctx = NULL;


    ERR_clear_error();
    untrusted = load_cert_chain_from_mem(&leaf, data_cert, size_cert);

    // It's possible after mutation, we cannot even parse the certificate.
    if (leaf == NULL) {
        raw_ret = RET_CERT_CANT_PARSE;
        composite_ret = RET_CERT_CANT_PARSE;
        err = RET_CERT_CANT_PARSE;
        goto exit1;
    }

    if ((sctx = X509_STORE_CTX_new()) == NULL) {
        DBG("ERROR: X.509 store context allocation failed\n");
        goto exit;
    }

    if (!X509_STORE_CTX_init(sctx, g_state.caStore, leaf, untrusted))
        goto exit;

exit:
    raw_ret = X509_verify_cert(sctx);
    err = X509_STORE_CTX_get_error(sctx);
    depth = X509_STORE_CTX_get_error_depth(sctx);


exit1:
#ifdef CONFIG_DEBUG
    DBG("[LSSL] [cert:%p  sz:%u] ret=%d  depth=%d  err=%x\n",
        data_cert,
        size_cert,
        raw_ret,
        depth,
        err);

    if (raw_ret != 1)
        ERR_print_errors_fp(stderr);
#endif
    composite_ret = compositize_ret_val(raw_ret, depth, err);

    X509_STORE_CTX_free(sctx);
    X509_free(leaf);
    sk_X509_pop_free(untrusted, X509_free);


    if (composite_ret != 1) {
      if (raw_ret == FAILURE_INTERNAL)
        DBG_S("libressl:%x:FAILURE_INTERNAL\n", FAILURE_INTERNAL);
      else if (raw_ret == RET_CERT_CANT_PARSE)
        DBG_S("libressl:%x:RET_CERT_CANT_PARSE\n", RET_CERT_CANT_PARSE);
      else
        DBG_S("libressl:%x:%s\n",
              composite_ret,
              X509_verify_cert_error_string(err));
    } else {
      DBG_S("libressl:0:OK\n");
    }

    if (composite_ret == 1)
      return 0;
    else
      return composite_ret;
}

extern "C"
LIB_EXPORT
int verify_cert_mem_libressl(const uint8_t *data_cert, uint32_t size_cert)
{
    return verify_cert_mem(data_cert, size_cert);
}
