/* Copyright (C) 2012-2017 Open Information Security Foundation
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
- * \author nPulse Technologies, LLC.
- * \author Matt Keeler <mk@npulsetech.com>
 *  *
 * Support for NAPATECH adapter with the 3GD Driver/API.
 * Requires libntapi from Napatech A/S.
 *
 */
#include "suricata-common.h"
#include "suricata.h"
#include "threadvars.h"
#include "util-optimize.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "tm-modules.h"
#include "util-privs.h"
#include "tmqh-packetpool.h"
#include "util-napatech.h"
#include "source-napatech.h"

#ifndef HAVE_NAPATECH

TmEcode NoNapatechSupportExit(ThreadVars *, const void *, void **);

void TmModuleNapatechStreamRegister(void) {
    tmm_modules[TMM_RECEIVENAPATECH].name = "NapatechStream";
    tmm_modules[TMM_RECEIVENAPATECH].ThreadInit = NoNapatechSupportExit;
    tmm_modules[TMM_RECEIVENAPATECH].Func = NULL;
    tmm_modules[TMM_RECEIVENAPATECH].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVENAPATECH].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVENAPATECH].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVENAPATECH].cap_flags = SC_CAP_NET_ADMIN;
}

void TmModuleNapatechDecodeRegister(void) {
    tmm_modules[TMM_DECODENAPATECH].name = "NapatechDecode";
    tmm_modules[TMM_DECODENAPATECH].ThreadInit = NoNapatechSupportExit;
    tmm_modules[TMM_DECODENAPATECH].Func = NULL;
    tmm_modules[TMM_DECODENAPATECH].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENAPATECH].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODENAPATECH].RegisterTests = NULL;
    tmm_modules[TMM_DECODENAPATECH].cap_flags = 0;
    tmm_modules[TMM_DECODENAPATECH].flags = TM_FLAG_DECODE_TM;
}

TmEcode NoNapatechSupportExit(ThreadVars *tv, const void *initdata, void **data) {
    SCLogError(SC_ERR_NAPATECH_NOSUPPORT,
            "Error creating thread %s: you do not have support for Napatech adapter "
            "enabled please recompile with --enable-napatech", tv->name);
    exit(EXIT_FAILURE);
}

#else /* Implied we do have NAPATECH support */


#include <nt.h>

#define MAX_STREAMS 256

extern int max_pending_packets;

typedef struct NapatechThreadVars_ {
    ThreadVars *tv;
    NtNetStreamRx_t rx_stream;
    uint16_t stream_id;
    int hba;
    TmSlot *slot;
} NapatechThreadVars;


TmEcode NapatechStreamThreadInit(ThreadVars *, const void *, void **);
void NapatechStreamThreadExitStats(ThreadVars *, void *);
TmEcode NapatechPacketLoopZC(ThreadVars *tv, void *data, void *slot);

TmEcode NapatechDecodeThreadInit(ThreadVars *, const void *, void **);
TmEcode NapatechDecodeThreadDeinit(ThreadVars *tv, void *data);
TmEcode NapatechDecode(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

/* These are used as the threads are exiting to get a comprehensive count of
 * all the packets received and dropped.
 */
SC_ATOMIC_DECLARE(uint64_t, total_packets);
SC_ATOMIC_DECLARE(uint64_t, total_drops);
SC_ATOMIC_DECLARE(uint16_t, total_tallied);

/**
 * \brief Register the Napatech  receiver (reader) module.
 */
void TmModuleNapatechStreamRegister(void)
{
    tmm_modules[TMM_RECEIVENAPATECH].name = "NapatechStream";
    tmm_modules[TMM_RECEIVENAPATECH].ThreadInit = NapatechStreamThreadInit;
    tmm_modules[TMM_RECEIVENAPATECH].Func = NULL;
    tmm_modules[TMM_RECEIVENAPATECH].PktAcqLoop = NapatechPacketLoopZC;
    tmm_modules[TMM_RECEIVENAPATECH].PktAcqBreakLoop = NULL;
    tmm_modules[TMM_RECEIVENAPATECH].ThreadExitPrintStats = NapatechStreamThreadExitStats;
    tmm_modules[TMM_RECEIVENAPATECH].ThreadDeinit = NapatechStreamThreadDeinit;
    tmm_modules[TMM_RECEIVENAPATECH].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVENAPATECH].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVENAPATECH].flags = TM_FLAG_RECEIVE_TM;

    SC_ATOMIC_INIT(total_packets);
    SC_ATOMIC_INIT(total_drops);
    SC_ATOMIC_INIT(total_tallied);
}

/**
 * \brief Register the Napatech decoder module.
 */
void TmModuleNapatechDecodeRegister(void)
{
    tmm_modules[TMM_DECODENAPATECH].name = "NapatechDecode";
    tmm_modules[TMM_DECODENAPATECH].ThreadInit = NapatechDecodeThreadInit;
    tmm_modules[TMM_DECODENAPATECH].Func = NapatechDecode;
    tmm_modules[TMM_DECODENAPATECH].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENAPATECH].ThreadDeinit = NapatechDecodeThreadDeinit;
    tmm_modules[TMM_DECODENAPATECH].RegisterTests = NULL;
    tmm_modules[TMM_DECODENAPATECH].cap_flags = 0;
    tmm_modules[TMM_DECODENAPATECH].flags = TM_FLAG_DECODE_TM;
}

/*
 *-----------------------------------------------------------------------------
 *-----------------------------------------------------------------------------
 * Statistics code
 *-----------------------------------------------------------------------------
*/

/**
 * \brief   Initialize the Napatech receiver thread, generate a single
 *          NapatechThreadVar structure for each thread, this will
 *          contain a NtNetStreamRx_t stream handle which is used when the
 *          thread executes to acquire the packets.
 *
 * \param tv        Thread variable to ThreadVars
 * \param initdata  Initial data to the adapter passed from the user,
 *                  this is processed by the user.
 *
 *                  For now, we assume that we have only a single name for the NAPATECH
 *                  adapter.
 *
 * \param data      data pointer gets populated with
 *
 */
TmEcode NapatechStreamThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    struct NapatechStreamDevConf *conf = (struct NapatechStreamDevConf *) initdata;
    uint16_t stream_id = conf->stream_id;
    *data = NULL;

    NapatechThreadVars *ntv = SCCalloc(1, sizeof (NapatechThreadVars));
    if (unlikely(ntv == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for NAPATECH  thread vars.");
        exit(EXIT_FAILURE);
    }

    memset(ntv, 0, sizeof (NapatechThreadVars));
    ntv->stream_id = stream_id;
    ntv->tv = tv;
    ntv->hba = conf->hba;
    SCLogDebug("Started processing packets from NAPATECH  Stream: %lu", ntv->stream_id);

    *data = (void *) ntv;
    SCReturnInt(TM_ECODE_OK);
}

static PacketQueue packets_to_release[MAX_STREAMS];

static void NapatechReleasePacket(struct Packet_ *p)
{
    PacketFreeOrRelease(p);
    PacketEnqueue(&packets_to_release[p->ntpv.stream_id], p);
}

TmEcode NapatechPacketLoopZC(ThreadVars *tv, void *data, void *slot)
{
    int32_t status;
    char error_buffer[100];
    uint64_t pkt_ts;
    NtNetBuf_t packet_buffer;
    NapatechThreadVars *ntv = (NapatechThreadVars *) data;
    uint64_t hba_pkt_drops = 0;
    uint64_t hba_byte_drops = 0;
    uint16_t hba_pkt = 0;

    /* This just keeps the startup output more orderly. */
    usleep(200000 * ntv->stream_id);

    if (ntv->hba > 0) {
        char *s_hbad_pkt = SCCalloc(1, 32);
        if (unlikely(s_hbad_pkt == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for NAPATECH stream counter.");
            exit(EXIT_FAILURE);
        }
        snprintf(s_hbad_pkt, 32, "nt%d.hba_drop", ntv->stream_id);
        hba_pkt = StatsRegisterCounter(s_hbad_pkt, tv);
        StatsSetupPrivate(tv);
        StatsSetUI64(tv, hba_pkt, 0);
    }
    SCLogDebug("Opening NAPATECH Stream: %lu for processing", ntv->stream_id);

    if ((status = NT_NetRxOpen(&(ntv->rx_stream), "SuricataStream", NT_NET_INTERFACE_PACKET, ntv->stream_id, ntv->hba)) != NT_SUCCESS) {
        NT_ExplainError(status, error_buffer, sizeof (error_buffer));
        SCLogError(SC_ERR_NAPATECH_OPEN_FAILED, "Failed to open NAPATECH Stream: %u - %s", ntv->stream_id, error_buffer);
        SCFree(ntv);
        SCReturnInt(TM_ECODE_FAILED);
    }

#if defined(__linux__)
    SCLogInfo("Napatech Packet Loop Started - cpu: %3d,    stream: %3u (numa: %u)",
            sched_getcpu(), ntv->stream_id, NapatechGetNumaNode(ntv->stream_id));
#else
    SCLogInfo("Napatech Packet Loop Started -  stream: %lu ", ntv->stream_id);
#endif

    TmSlot *s = (TmSlot *) slot;
    ntv->slot = s->slot_next;

    while (!(suricata_ctl_flags & SURICATA_STOP)) {
        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        PacketPoolWait();

        /* Napatech returns packets 1 at a time */
        status = NT_NetRxGet(ntv->rx_stream, &packet_buffer, 1000);
        if (unlikely(status == NT_STATUS_TIMEOUT || status == NT_STATUS_TRYAGAIN)) {
            continue;
        } else if (unlikely(status != NT_SUCCESS)) {
            NT_ExplainError(status, error_buffer, sizeof (error_buffer) - 1);

            SCLogInfo("Failed to read from Napatech Stream%d: %s",
                    ntv->stream_id, error_buffer);
            SCReturnInt(TM_ECODE_FAILED);
        }

        Packet *p = PacketGetFromQueueOrAlloc();
        if (unlikely(p == NULL)) {
            NT_NetRxRelease(ntv->rx_stream, packet_buffer);
            SCReturnInt(TM_ECODE_FAILED);
        }

        pkt_ts = NT_NET_GET_PKT_TIMESTAMP(packet_buffer);

        /*
         * Handle the different timestamp forms that the napatech cards could use
         *   - NT_TIMESTAMP_TYPE_NATIVE is not supported due to having an base of 0 as opposed to NATIVE_UNIX which has a base of 1/1/1970
         */
        switch (NT_NET_GET_PKT_TIMESTAMP_TYPE(packet_buffer)) {
            case NT_TIMESTAMP_TYPE_NATIVE_UNIX:
                p->ts.tv_sec = pkt_ts / 100000000;
                p->ts.tv_usec = ((pkt_ts % 100000000) / 100) + (pkt_ts % 100) > 50 ? 1 : 0;
                break;
            case NT_TIMESTAMP_TYPE_PCAP:
                p->ts.tv_sec = pkt_ts >> 32;
                p->ts.tv_usec = pkt_ts & 0xFFFFFFFF;
                break;
            case NT_TIMESTAMP_TYPE_PCAP_NANOTIME:
                p->ts.tv_sec = pkt_ts >> 32;
                p->ts.tv_usec = ((pkt_ts & 0xFFFFFFFF) / 1000) + (pkt_ts % 1000) > 500 ? 1 : 0;
                break;
            case NT_TIMESTAMP_TYPE_NATIVE_NDIS:
                /* number of seconds between 1/1/1601 and 1/1/1970 */
                p->ts.tv_sec = (pkt_ts / 100000000) - 11644473600;
                p->ts.tv_usec = ((pkt_ts % 100000000) / 100) + (pkt_ts % 100) > 50 ? 1 : 0;
                break;
            default:
                SCLogError(SC_ERR_NAPATECH_TIMESTAMP_TYPE_NOT_SUPPORTED,
                        "Packet from Napatech Stream: %u does not have a supported timestamp format",
                        ntv->stream_id);
                NT_NetRxRelease(ntv->rx_stream, packet_buffer);
                SCReturnInt(TM_ECODE_FAILED);
        }

        if (unlikely(ntv->hba > 0)) {
            NtNetRx_t stat_cmd;
            stat_cmd.cmd = NT_NETRX_READ_CMD_STREAM_DROP;
            // Update drop counter
            if (unlikely((status = NT_NetRxRead(ntv->rx_stream, &stat_cmd)) != NT_SUCCESS)) {
                NT_ExplainError(status, error_buffer, sizeof (error_buffer));
                SCLogInfo("Couldn't retrieve drop statistics from the RX stream: %u - %s",
                        ntv->stream_id, error_buffer);
            } else {
                hba_pkt_drops = stat_cmd.u.streamDrop.pktsDropped;

                StatsSetUI64(tv, hba_pkt, hba_pkt_drops);
            }
            StatsSyncCountersIfSignalled(tv);
        }

        p->ReleasePacket = NapatechReleasePacket;
        p->ntpv.nt_packet_buf = packet_buffer;
        p->ntpv.stream_id = ntv->stream_id;
        p->datalink = LINKTYPE_ETHERNET;

        if (unlikely(PacketSetData(p, (uint8_t *)NT_NET_GET_PKT_L2_PTR(packet_buffer), NT_NET_GET_PKT_WIRE_LENGTH(packet_buffer)))) {
            TmqhOutputPacketpool(ntv->tv, p);
            NT_NetRxRelease(ntv->rx_stream, packet_buffer);
            SCReturnInt(TM_ECODE_FAILED);
        }

        if (unlikely(TmThreadsSlotProcessPkt(ntv->tv, ntv->slot, p) != TM_ECODE_OK)) {
            TmqhOutputPacketpool(ntv->tv, p);
            NT_NetRxRelease(ntv->rx_stream, packet_buffer);
            SCReturnInt(TM_ECODE_FAILED);
        }

        /* Release any packets that were returned by the callback function */
        Packet *rel_pkt = PacketDequeue(&packets_to_release[ntv->stream_id]);
        while (rel_pkt != NULL) {
            NT_NetRxRelease(ntv->rx_stream, rel_pkt->ntpv.nt_packet_buf);
            rel_pkt = PacketDequeue(&packets_to_release[ntv->stream_id]);
        }
        StatsSyncCountersIfSignalled(tv);
    }

    if (unlikely(ntv->hba > 0)) {
        SCLogInfo("Host Buffer Allowance Drops - pkts: %ld,  bytes: %ld", hba_pkt_drops, hba_byte_drops);
    }

    SCReturnInt(TM_ECODE_OK);
}


/**
 * \brief Print some stats to the log at program exit.
 *
 * \param tv Pointer to ThreadVars.
 * \param data Pointer to data, ErfFileThreadVars.
 */
void NapatechStreamThreadExitStats(ThreadVars *tv, void *data)
{
    NapatechThreadVars *ntv = (NapatechThreadVars *) data;
    NapatechCurrentStats stat = NapatechGetCurrentStats(ntv->stream_id);

    double percent = 0;
    if (stat.current_drops > 0)
        percent = (((double) stat.current_drops)
                  / (stat.current_packets + stat.current_drops)) * 100;

    SCLogInfo("nt%lu - pkts: %lu; drop: %lu (%5.2f%%); bytes: %lu",
                 (uint64_t) ntv->stream_id, stat.current_packets,
                  stat.current_drops, percent, stat.current_bytes);

    SC_ATOMIC_ADD(total_packets, stat.current_packets);
    SC_ATOMIC_ADD(total_drops, stat.current_drops);
    SC_ATOMIC_ADD(total_tallied, 1);

    if (SC_ATOMIC_GET(total_tallied) == GetNumConfiguredStreams()) {
        if (SC_ATOMIC_GET(total_drops) > 0)
            percent = (((double) SC_ATOMIC_GET(total_drops)) / (SC_ATOMIC_GET(total_packets)
                         + SC_ATOMIC_GET(total_drops))) * 100;

        SCLogInfo(" ");
        SCLogInfo("--- Total Packets: %ld  Total Dropped: %ld (%5.2f%%)",
                  SC_ATOMIC_GET(total_packets), SC_ATOMIC_GET(total_drops), percent);
    }
}

/**
 * \brief   Deinitializes the NAPATECH card.
 * \param   tv pointer to ThreadVars
 * \param   data pointer that gets cast into PcapThreadVars for ptv
 */
TmEcode NapatechStreamThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();
    NapatechThreadVars *ntv = (NapatechThreadVars *) data;
    SCLogDebug("Closing Napatech Stream: %d", ntv->stream_id);
    NT_NetRxClose(ntv->rx_stream);
    SCReturnInt(TM_ECODE_OK);
}

/** Decode Napatech */

/**
 * \brief   This function passes off to link type decoders.
 *
 * NapatechDecode reads packets from the PacketQueue and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into PcapThreadVars for ptv
 * \param pq pointer to the current PacketQueue
 */
TmEcode NapatechDecode(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
        PacketQueue *postpq)
{
    SCEnter();

    DecodeThreadVars *dtv = (DecodeThreadVars *) data;

    /* XXX HACK: flow timeout can call us for injected pseudo packets
     *           see bug: https://redmine.openinfosecfoundation.org/issues/1107 */
    if (p->flags & PKT_PSEUDO_STREAM_END)
        return TM_ECODE_OK;

    // update counters
    DecodeUpdatePacketCounters(tv, dtv, p);

    switch (p->datalink) {
        case LINKTYPE_ETHERNET:
            DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        default:
            SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED,
                    "Error: datalink type %" PRId32 " not yet supported in module NapatechDecode",
                    p->datalink);
            break;
    }

    PacketDecodeFinalize(tv, dtv, p);
    SCReturnInt(TM_ECODE_OK);
}

TmEcode NapatechDecodeThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;
    dtv = DecodeThreadVarsAlloc(tv);
    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);
    *data = (void *) dtv;
    SCReturnInt(TM_ECODE_OK);
}

TmEcode NapatechDecodeThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);    }

#endif /* HAVE_NAPATECH */
