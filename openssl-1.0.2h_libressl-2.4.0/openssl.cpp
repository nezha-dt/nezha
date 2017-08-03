#include "openssl.h"

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

#ifdef CONFIG_USE_DER
    FILE *full_pem_chain = NULL;
    FILE *ca_chain  = NULL;
    FILE *leaf_cert = NULL;

	// remove any previous files
    remove("full_pem_chain.pem");
    remove("ca_chain.pem");
#endif

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

#ifdef CONFIG_USE_DER
        full_pem_chain = fopen("full_pem_chain.pem", "a");
        if (!full_pem_chain) {
          perror("Could not open pem_chain file for writing");
        }
        if (x != NULL) {
            PEM_write_X509(full_pem_chain, x);
        }

        if (full_pem_chain) {
          fclose(full_pem_chain);
          full_pem_chain = NULL;
        }
#endif
        // Extract the first certificate as the leaf cert to be verified
        if (certnum == 1) {
            if (x != NULL) {
                *leaf = x;
#ifdef CONFIG_USE_DER
                leaf_cert = fopen("leaf_cert.pem", "w");
                if (!leaf_cert) {
                  perror("Could not open leaf cert file for writing");
                }
                PEM_write_X509(leaf_cert, x);
                if (leaf_cert) {
                  fclose(leaf_cert);
                  leaf_cert = NULL;
                }
#endif
                continue;
            }
            else {
#ifdef CONFIG_DEBUG
                ERR_print_errors_fp(stderr);
#endif
            }
        } else {
          if (x != NULL) {
#ifdef CONFIG_USE_DER
                ca_chain = fopen("ca_chain.pem", "a");
                if (!ca_chain) {
                  perror("Could not open ca_chain file for writing");
                }
                PEM_write_X509(ca_chain, x);
                if (ca_chain) {
                  fclose(ca_chain);
                  ca_chain = NULL;
                }
#else
          ;
#endif
          }
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

    int composite_ret = FAILURE_INTERNAL;
    int raw_ret = FAILURE_INTERNAL;
    int err = FAILURE_INTERNAL;
    int depth = 0;
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
    DBG("[OSSL] [cert:%p  sz:%u] ret=%d  depth=%d  err=%x\n",
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
        DBG_S("openssl:%x:FAILURE_INTERNAL\n", FAILURE_INTERNAL);
      else if (raw_ret == RET_CERT_CANT_PARSE)
        DBG_S("openssl:%x:RET_CERT_CANT_PARSE\n", RET_CERT_CANT_PARSE);
      else
        DBG_S("openssl:%x:%s\n",
              composite_ret,
              X509_verify_cert_error_string(err));
    } else {
      DBG_S("openssl:0:OK\n");
    }

    if (composite_ret == 1)
      return 0;
    else
      return composite_ret;
}

extern "C"
LIB_EXPORT
int verify_cert_mem_openssl(const uint8_t *data_cert, uint32_t size_cert)
{
    return verify_cert_mem(data_cert, size_cert);
}
