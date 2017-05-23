#include "clamav_arc.h"

#include <assert.h>
#include <clamav.h>

struct GlobalState {
    GlobalState()
    : ctx(InitCtx()) {
        cl_init(CL_INIT_DEFAULT);
    }

    ~GlobalState() {
        cl_cleanup_crypto();
        assert(CUSTOM_xz_destroy(ctx) == 0);
    }

    void *InitCtx() {
        void *tmpctx;
        assert(CUSTOM_xz_init(&tmpctx) == 0);
        return tmpctx;
    }

    void *const ctx;
};



LIB_EXPORT
extern "C" int unpack_xz_mem(const uint8_t *data, uint32_t size)
{
    static GlobalState g_state;
    int ret = CUSTOM_xz_parse(g_state.ctx, data, size);
    int rc = (ret == _CL_CLEAN) ? RET_OK : ret;
    if (rc)
      DBG_S("clamav:%d:%s\n", rc, cl_strerror(rc));
    else
      DBG_S("clamav:0:OK\n");
    return rc;
}

LIB_EXPORT
extern "C" int unpack_xz_mem_clamav(const uint8_t *data, uint32_t size)
{
    return unpack_xz_mem(data, size);
}
