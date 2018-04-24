/* Copyright (C) 2017 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"

#include "detect-smb-share.h"
#ifdef HAVE_RUST
#include "rust.h"
#include "rust-smb-detect-gen.h"

#define BUFFER_NAME "smb_named_pipe"
#define KEYWORD_NAME BUFFER_NAME
#define KEYWORD_ID DETECT_SMB_NAMED_PIPE

static int g_smb_named_pipe_buffer_id = 0;

static int DetectSmbNamedPipeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    int r = DetectBufferSetActiveList(s, g_smb_named_pipe_buffer_id);
    s->alproto = ALPROTO_SMB;
    return r;
}

static InspectionBuffer *GetNamedPipeData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t _flow_flags,
        void *txv, const int list_id)
{
    BUG_ON(det_ctx->inspect_buffers == NULL);
    InspectionBuffer *buffer = &det_ctx->inspect_buffers[list_id];

    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        uint8_t *b = NULL;

        if (rs_smb_tx_get_named_pipe(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

void DetectSmbNamedPipeRegister(void)
{
    sigmatch_table[KEYWORD_ID].name = KEYWORD_NAME;
    sigmatch_table[KEYWORD_ID].Setup = DetectSmbNamedPipeSetup;
    sigmatch_table[KEYWORD_ID].flags |= SIGMATCH_NOOPT;
    sigmatch_table[KEYWORD_ID].desc = "sticky buffer to match on SMB named pipe in tree connect";

    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOSERVER, 2,
            PrefilterGenericMpmRegister, GetNamedPipeData,
            ALPROTO_SMB, 1);

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME,
            ALPROTO_SMB, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetNamedPipeData);

    g_smb_named_pipe_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}

#undef BUFFER_NAME
#undef KEYWORD_NAME
#undef KEYWORD_ID

#else /* NO RUST */
void DetectSmbNamedPipeRegister(void) {}
#endif

#ifdef HAVE_RUST
#define BUFFER_NAME "smb_share"
#define KEYWORD_NAME BUFFER_NAME
#define KEYWORD_ID DETECT_SMB_SHARE

static int g_smb_share_buffer_id = 0;

static int DetectSmbShareSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    int r = DetectBufferSetActiveList(s, g_smb_share_buffer_id);
    s->alproto = ALPROTO_SMB;
    return r;
}

static InspectionBuffer *GetShareData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t _flow_flags,
        void *txv, const int list_id)
{
    BUG_ON(det_ctx->inspect_buffers == NULL);
    InspectionBuffer *buffer = &det_ctx->inspect_buffers[list_id];

    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        uint8_t *b = NULL;

        if (rs_smb_tx_get_share(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

void DetectSmbShareRegister(void)
{
    sigmatch_table[KEYWORD_ID].name = KEYWORD_NAME;
    sigmatch_table[KEYWORD_ID].Setup = DetectSmbShareSetup;
    sigmatch_table[KEYWORD_ID].flags |= SIGMATCH_NOOPT;
    sigmatch_table[KEYWORD_ID].desc = "sticky buffer to match on SMB share name in tree connect";

    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOSERVER, 2,
            PrefilterGenericMpmRegister, GetShareData,
            ALPROTO_SMB, 1);

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME,
            ALPROTO_SMB, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetShareData);

    g_smb_share_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}
#else
void DetectSmbShareRegister(void) {}
#endif
