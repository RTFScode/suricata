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

/** \file
 *
 * \author Giuseppe Longo <giuseppe@glongo.it>
 *
 */


#include "suricata.h"
#include "suricata-common.h"

#include "app-layer-htp.h"

#include "util-file-decompression.h"
#include "util-file-swf-decompression.h"
#include "util-misc.h"
#include "util-print.h"

#include <zlib.h>

#ifdef HAVE_LIBLZMA
#include <lzma.h>
#endif

#define MAX_SWF_DECOMPRESSED_LEN 50000000
/*
 * Return uncompressed file length
 * in little-endian order
 */
uint32_t FileGetSwfDecompressedLen(const uint8_t *buffer,
                                   const uint32_t buffer_len)
{
    if (buffer_len < 8) {
        return 0;
    }

    int a = buffer[4];
    int b = buffer[5];
    int c = buffer[6];
    int d = buffer[7];

    uint32_t value = (((a & 0xff) << 24) | ((b & 0xff) << 16) | ((c & 0xff) << 8) | (d & 0xff));

    uint32_t len = (((value >> 24) & 0x000000FF) | ((value >> 8) & 0x0000FF00) |
                   ((value << 8) & 0x00FF0000) | ((value << 24) & 0xFF000000));

    return MIN(MAX_SWF_DECOMPRESSED_LEN, len);
}

uint8_t FileGetSwfVersion(const uint8_t *buffer, const uint32_t buffer_len)
{
    if (buffer_len > 3)
        return buffer[3];

    return 0;
}

/* CWS format */
/*
 * | 4 bytes         | 4 bytes    | n bytes         |
 * | 'CWS' + version | script len | compressed data |
 */
int FileSwfZlibDecompression(DetectEngineThreadCtx *det_ctx,
                             uint8_t *compressed_data, uint32_t compressed_data_len,
                             uint8_t *decompressed_data, uint32_t decompressed_data_len)
{
    int ret = 1;
    z_stream infstream;
    infstream.zalloc = Z_NULL;
    infstream.zfree = Z_NULL;
    infstream.opaque = Z_NULL;

    infstream.avail_in = (uInt)compressed_data_len;
    infstream.next_in = (Bytef *)compressed_data;
    infstream.avail_out = (uInt)decompressed_data_len;
    infstream.next_out = (Bytef *)decompressed_data;

    inflateInit(&infstream);
    int result = inflate(&infstream, Z_NO_FLUSH);
    switch(result) {
        case Z_STREAM_END:
            break;
        case Z_OK:
            break;
        case Z_DATA_ERROR:
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_Z_DATA_ERROR);
            ret = 0;
            break;
        case Z_STREAM_ERROR:
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_Z_STREAM_ERROR);
            ret = 0;
            break;
        case Z_BUF_ERROR:
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_Z_BUF_ERROR);
            ret = 0;
            break;
        default:
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_Z_UNKNOWN_ERROR);
            ret = 0;
            break;
    }
    inflateEnd(&infstream);

    return ret;
}

/* ZWS format */
/*
 * | 4 bytes         | 4 bytes    | 4 bytes        | 5 bytes    | n bytes   | 6 bytes         |
 * | 'ZWS' + version | script len | compressed len | LZMA props | LZMA data | LZMA end marker |
 */
#ifdef HAVE_LIBLZMA
int FileSwfLzmaDecompression(DetectEngineThreadCtx *det_ctx,
                             uint8_t *compressed_data, uint32_t compressed_data_len,
                             uint8_t *decompressed_data, uint32_t decompressed_data_len)
{
    int ret = 1;
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret result = lzma_alone_decoder(&strm, UINT64_MAX /* memlimit */);
    if (result != LZMA_OK) {
        DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_LZMA_DECODER_ERROR);
        return 0;
    }

    strm.avail_in = compressed_data_len;
    strm.next_in = compressed_data;
    strm.avail_out = decompressed_data_len;
    strm.next_out = decompressed_data;

    result = lzma_code(&strm, LZMA_RUN);
    switch(result) {
        case LZMA_STREAM_END:
            break;
        case LZMA_OK:
            break;
        case LZMA_MEMLIMIT_ERROR:
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_LZMA_MEMLIMIT_ERROR);
            ret = 0;
            break;
        case LZMA_OPTIONS_ERROR:
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_LZMA_OPTIONS_ERROR);
            ret = 0;
            break;
        case LZMA_FORMAT_ERROR:
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_LZMA_FORMAT_ERROR);
            ret = 0;
            break;
        case LZMA_DATA_ERROR:
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_LZMA_DATA_ERROR);
            ret = 0;
            break;
        case LZMA_BUF_ERROR:
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_LZMA_BUF_ERROR);
            ret = 0;
            break;
        default:
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_LZMA_UNKNOWN_ERROR);
            ret = 0;
            break;
    }

    lzma_end(&strm);
    return ret;
}
#endif /* HAVE_LIBLZMA */
