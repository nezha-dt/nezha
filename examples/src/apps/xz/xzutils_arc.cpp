#include "xzutils_arc.h"

#include <assert.h>
#include <lzma.h>

#define OUTPUT_BUF_SIZE       (1024 * 1024 << 5)

#define ACTION_RUN          LZMA_RUN
#define ACTION_FIN          LZMA_FINISH


struct GlobalState {
    GlobalState()
    : outbuf(InitOutBuf()) { }

    ~GlobalState() {
        free(outbuf);
    }

    unsigned char *InitOutBuf() {
        unsigned char *tmpbuf = (unsigned char *)malloc(OUTPUT_BUF_SIZE);
        assert(tmpbuf != NULL);
        return tmpbuf;
    }

    unsigned char *const outbuf;
};


void print_err(int rc)
{
    switch (rc) {
        case LZMA_MEM_ERROR:
            DBG_S("Memory error\n");
            break;
            
        case LZMA_FORMAT_ERROR:
            DBG_S("File format not recognized\n");
            break;
            
        case LZMA_OPTIONS_ERROR:
            DBG_S("Unsupported compression options\n");
            break;
            
        case LZMA_DATA_ERROR:
            DBG_S("File is corrupt\n");
            break;
            
        case LZMA_BUF_ERROR:
            DBG_S("Unexpected end of input\n");
            break;
            
        default:
            DBG_S("Internal error (bug)\n");
    }
}



/**
 * Deprecated: Only handle one chunk
 */
LIB_EXPORT
extern "C" int unpack_xz_mem_1(const uint8_t *data, uint32_t size)
{
    static GlobalState g_state;
    int rc;
    
    lzma_ret ret;
    lzma_stream strm = LZMA_STREAM_INIT;
    
    assert(lzma_stream_decoder(&strm, UINT64_MAX, LZMA_CONCATENATED) == LZMA_OK);
    
    strm.next_in = data;
    strm.avail_in = size;
    strm.next_out = g_state.outbuf;
    strm.avail_out = OUTPUT_BUF_SIZE;
    
    ret = lzma_code(&strm, ACTION_RUN);
    
    lzma_end(&strm);
    
    rc = ((ret == LZMA_OK_) ||
          (ret == LZMA_STREAM_END_)) ? RET_OK : ret;
    
    if (rc)
        DBG_S("xzutils:%d:%s\n", rc, strerror(rc));
    else
        DBG_S("xzutils:0:OK\n");
    
    return rc;
}


LIB_EXPORT
extern "C" int unpack_xz_mem(const uint8_t *data, uint32_t size)
{
    static GlobalState g_state;
    int rc;
    int nread = 0;
    lzma_action action = LZMA_RUN;
    
    lzma_ret ret;
    lzma_stream strm = LZMA_STREAM_INIT;
    
    assert(lzma_stream_decoder(&strm, UINT64_MAX, LZMA_CONCATENATED) == LZMA_OK);
    
    strm.avail_in = 0;
    strm.next_out = g_state.outbuf;
    strm.avail_out = OUTPUT_BUF_SIZE;

    while (true) {
        
        if (strm.avail_in == 0) {
            strm.next_in = data + nread;
            strm.avail_in = size - nread > BUFSIZ ? BUFSIZ : size - nread;
            
            nread += strm.avail_in;
            
            // When using LZMA_CONCATENATED, we need to tell
            // liblzma when it has got all the input.
            if (nread >= size)
                action = LZMA_FINISH;
        }

        ret = lzma_code(&strm, action);
     
        // Simulate write:
        // As much data as possible gets written to stdout even if decoder
        // detected an error.
        if (strm.avail_out == 0 || ret != LZMA_OK) {
            strm.next_out = g_state.outbuf;
            strm.avail_out = OUTPUT_BUF_SIZE;
        }
        
        if (ret != LZMA_OK)
            goto _exit;
    }
    
_exit:
    lzma_end(&strm);
    
    rc = ((ret == LZMA_OK_) ||
          (ret == LZMA_STREAM_END_)) ? RET_OK : ret;
    
    if (rc) {
        DBG_S("xzutils:%d: ", rc);
        print_err(rc);
    } else {
        DBG_S("xzutils:0:OK\n");
    }
    
    return rc;
}


LIB_EXPORT
extern "C" int unpack_xz_mem_xzutils(const uint8_t *data, uint32_t size)
{
    return unpack_xz_mem(data, size);
}
