/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Tom DeCanio <td@npulsetech.com>
 *
 * Implements JSON DNS logging portion of the engine.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"
#include "util-mem.h"
#include "app-layer-parser.h"
#include "output.h"
#include "app-layer-dns-udp.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"

#include "output-json.h"
#include "output-json-dns.h"

#ifdef HAVE_LIBJANSSON

#ifdef HAVE_RUST
#include "rust-dns-log-gen.h"
#endif

/* we can do query logging as well, but it's disabled for now as the
 * TX id handling doesn't expect it */
#define QUERY 0

#define LOG_QUERIES    BIT_U64(0)
#define LOG_ANSWERS    BIT_U64(1)

#define LOG_A          BIT_U64(2)
#define LOG_NS         BIT_U64(3)
#define LOG_MD         BIT_U64(4)
#define LOG_MF         BIT_U64(5)
#define LOG_CNAME      BIT_U64(6)
#define LOG_SOA        BIT_U64(7)
#define LOG_MB         BIT_U64(8)
#define LOG_MG         BIT_U64(9)
#define LOG_MR         BIT_U64(10)
#define LOG_NULL       BIT_U64(11)
#define LOG_WKS        BIT_U64(12)
#define LOG_PTR        BIT_U64(13)
#define LOG_HINFO      BIT_U64(14)
#define LOG_MINFO      BIT_U64(15)
#define LOG_MX         BIT_U64(16)
#define LOG_TXT        BIT_U64(17)
#define LOG_RP         BIT_U64(18)
#define LOG_AFSDB      BIT_U64(19)
#define LOG_X25        BIT_U64(20)
#define LOG_ISDN       BIT_U64(21)
#define LOG_RT         BIT_U64(22)
#define LOG_NSAP       BIT_U64(23)
#define LOG_NSAPPTR    BIT_U64(24)
#define LOG_SIG        BIT_U64(25)
#define LOG_KEY        BIT_U64(26)
#define LOG_PX         BIT_U64(27)
#define LOG_GPOS       BIT_U64(28)
#define LOG_AAAA       BIT_U64(29)
#define LOG_LOC        BIT_U64(30)
#define LOG_NXT        BIT_U64(31)
#define LOG_SRV        BIT_U64(32)
#define LOG_ATMA       BIT_U64(33)
#define LOG_NAPTR      BIT_U64(34)
#define LOG_KX         BIT_U64(35)
#define LOG_CERT       BIT_U64(36)
#define LOG_A6         BIT_U64(37)
#define LOG_DNAME      BIT_U64(38)
#define LOG_OPT        BIT_U64(39)
#define LOG_APL        BIT_U64(40)
#define LOG_DS         BIT_U64(41)
#define LOG_SSHFP      BIT_U64(42)
#define LOG_IPSECKEY   BIT_U64(43)
#define LOG_RRSIG      BIT_U64(44)
#define LOG_NSEC       BIT_U64(45)
#define LOG_DNSKEY     BIT_U64(46)
#define LOG_DHCID      BIT_U64(47)
#define LOG_NSEC3      BIT_U64(48)
#define LOG_NSEC3PARAM BIT_U64(49)
#define LOG_TLSA       BIT_U64(50)
#define LOG_HIP        BIT_U64(51)
#define LOG_CDS        BIT_U64(52)
#define LOG_CDNSKEY    BIT_U64(53)
#define LOG_SPF        BIT_U64(54)
#define LOG_TKEY       BIT_U64(55)
#define LOG_TSIG       BIT_U64(56)
#define LOG_MAILA      BIT_U64(57)
#define LOG_ANY        BIT_U64(58)
#define LOG_URI        BIT_U64(59)

#define LOG_FORMAT_GROUPED     BIT_U64(60)
#define LOG_FORMAT_DETAILED    BIT_U64(61)

#define LOG_FORMAT_ALL (LOG_FORMAT_GROUPED|LOG_FORMAT_DETAILED)
#define LOG_ALL_RRTYPES (~(uint64_t)(LOG_QUERIES|LOG_ANSWERS|LOG_FORMAT_DETAILED|LOG_FORMAT_GROUPED))

typedef enum {
    DNS_RRTYPE_A = 0,
    DNS_RRTYPE_NS,
    DNS_RRTYPE_MD,
    DNS_RRTYPE_MF,
    DNS_RRTYPE_CNAME,
    DNS_RRTYPE_SOA,
    DNS_RRTYPE_MB,
    DNS_RRTYPE_MG,
    DNS_RRTYPE_MR,
    DNS_RRTYPE_NULL,
    DNS_RRTYPE_WKS,
    DNS_RRTYPE_PTR,
    DNS_RRTYPE_HINFO,
    DNS_RRTYPE_MINFO,
    DNS_RRTYPE_MX,
    DNS_RRTYPE_TXT,
    DNS_RRTYPE_RP,
    DNS_RRTYPE_AFSDB,
    DNS_RRTYPE_X25,
    DNS_RRTYPE_ISDN,
    DNS_RRTYPE_RT,
    DNS_RRTYPE_NSAP,
    DNS_RRTYPE_NSAPPTR,
    DNS_RRTYPE_SIG,
    DNS_RRTYPE_KEY,
    DNS_RRTYPE_PX,
    DNS_RRTYPE_GPOS,
    DNS_RRTYPE_AAAA,
    DNS_RRTYPE_LOC,
    DNS_RRTYPE_NXT,
    DNS_RRTYPE_SRV,
    DNS_RRTYPE_ATMA,
    DNS_RRTYPE_NAPTR,
    DNS_RRTYPE_KX,
    DNS_RRTYPE_CERT,
    DNS_RRTYPE_A6,
    DNS_RRTYPE_DNAME,
    DNS_RRTYPE_OPT,
    DNS_RRTYPE_APL,
    DNS_RRTYPE_DS,
    DNS_RRTYPE_SSHFP,
    DNS_RRTYPE_IPSECKEY,
    DNS_RRTYPE_RRSIG,
    DNS_RRTYPE_NSEC,
    DNS_RRTYPE_DNSKEY,
    DNS_RRTYPE_DHCID,
    DNS_RRTYPE_NSEC3,
    DNS_RRTYPE_NSEC3PARAM,
    DNS_RRTYPE_TLSA,
    DNS_RRTYPE_HIP,
    DNS_RRTYPE_CDS,
    DNS_RRTYPE_CDNSKEY,
    DNS_RRTYPE_SPF,
    DNS_RRTYPE_TKEY,
    DNS_RRTYPE_TSIG,
    DNS_RRTYPE_MAILA,
    DNS_RRTYPE_ANY,
    DNS_RRTYPE_URI,
    DNS_RRTYPE_MAX,
} DnsRRTypes;

typedef enum {
    DNS_VERSION_1 = 1,
    DNS_VERSION_2
} DnsVersion;

#ifdef HAVE_RUST
#define DNS_VERSION_DEFAULT DNS_VERSION_2
#else
#define DNS_VERSION_DEFAULT DNS_VERSION_1
#endif

static struct {
    const char *config_rrtype;
    uint64_t flags;
} dns_rrtype_fields[] = {
   { "a", LOG_A },
   { "ns", LOG_NS },
   { "md", LOG_MD },
   { "mf", LOG_MF },
   { "cname", LOG_CNAME },
   { "soa", LOG_SOA },
   { "mb", LOG_MB },
   { "mg", LOG_MG },
   { "mr", LOG_MR },
   { "null", LOG_NULL },
   { "wks", LOG_WKS },
   { "ptr", LOG_PTR },
   { "hinfo", LOG_HINFO },
   { "minfo", LOG_MINFO },
   { "mx", LOG_MX },
   { "txt", LOG_TXT },
   { "rp", LOG_RP },
   { "afsdb", LOG_AFSDB },
   { "x25", LOG_X25 },
   { "isdn", LOG_ISDN },
   { "rt", LOG_RT },
   { "nsap", LOG_NSAP },
   { "nsapptr", LOG_NSAPPTR },
   { "sig", LOG_SIG },
   { "key", LOG_KEY },
   { "px", LOG_PX },
   { "gpos", LOG_GPOS },
   { "aaaa", LOG_AAAA },
   { "loc", LOG_LOC },
   { "nxt", LOG_NXT },
   { "srv", LOG_SRV },
   { "atma", LOG_ATMA },
   { "naptr", LOG_NAPTR },
   { "kx", LOG_KX },
   { "cert", LOG_CERT },
   { "a6", LOG_A6 },
   { "dname", LOG_DNAME },
   { "opt", LOG_OPT },
   { "apl", LOG_APL },
   { "ds", LOG_DS },
   { "sshfp", LOG_SSHFP },
   { "ipseckey", LOG_IPSECKEY },
   { "rrsig", LOG_RRSIG },
   { "nsec", LOG_NSEC },
   { "dnskey", LOG_DNSKEY },
   { "dhcid", LOG_DHCID },
   { "nsec3", LOG_NSEC3 },
   { "nsec3param", LOG_NSEC3PARAM },
   { "tlsa", LOG_TLSA },
   { "hip", LOG_HIP },
   { "cds", LOG_CDS },
   { "cdnskey", LOG_CDNSKEY },
   { "spf", LOG_SPF },
   { "tkey", LOG_TKEY },
   { "tsig", LOG_TSIG },
   { "maila", LOG_MAILA },
   { "any", LOG_ANY },
   { "uri", LOG_URI }
};

typedef struct LogDnsFileCtx_ {
    LogFileCtx *file_ctx;
    uint64_t flags; /** Store mode */
    bool include_metadata;
    DnsVersion version;
} LogDnsFileCtx;

typedef struct LogDnsLogThread_ {
    LogDnsFileCtx *dnslog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t dns_cnt;

    MemBuffer *buffer;
} LogDnsLogThread;

#ifndef HAVE_RUST
static int DNSRRTypeEnabled(uint16_t type, uint64_t flags)
{
    if (likely(flags == ~0UL)) {
        return 1;
    }

    switch (type) {
        case DNS_RECORD_TYPE_A:
            return ((flags & LOG_A) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NS:
            return ((flags & LOG_NS) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_MD:
            return ((flags & LOG_MD) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_MF:
            return ((flags & LOG_MF) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_CNAME:
            return ((flags & LOG_CNAME) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_SOA:
            return ((flags & LOG_SOA) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_MB:
            return ((flags & LOG_MB) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_MG:
            return ((flags & LOG_MG) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_MR:
            return ((flags & LOG_MR) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NULL:
            return ((flags & LOG_NULL) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_WKS:
            return ((flags & LOG_WKS) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_PTR:
            return ((flags & LOG_PTR) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_HINFO:
            return ((flags & LOG_HINFO) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_MINFO:
            return ((flags & LOG_MINFO) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_MX:
            return ((flags & LOG_MX) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_TXT:
            return ((flags & LOG_TXT) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_RP:
            return ((flags & LOG_RP) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_AFSDB:
            return ((flags & LOG_AFSDB) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_X25:
            return ((flags & LOG_X25) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_ISDN:
            return ((flags & LOG_ISDN) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_RT:
            return ((flags & LOG_RT) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NSAP:
            return ((flags & LOG_NSAP) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NSAPPTR:
            return ((flags & LOG_NSAPPTR) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_SIG:
            return ((flags & LOG_SIG) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_KEY:
            return ((flags & LOG_KEY) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_PX:
            return ((flags & LOG_PX) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_GPOS:
            return ((flags & LOG_GPOS) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_AAAA:
            return ((flags & LOG_AAAA) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_LOC:
            return ((flags & LOG_LOC) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NXT:
            return ((flags & LOG_NXT) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_SRV:
            return ((flags & LOG_SRV) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_ATMA:
            return ((flags & LOG_ATMA) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NAPTR:
            return ((flags & LOG_NAPTR) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_KX:
            return ((flags & LOG_KX) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_CERT:
            return ((flags & LOG_CERT) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_A6:
            return ((flags & LOG_A6) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_DNAME:
            return ((flags & LOG_DNAME) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_OPT:
            return ((flags & LOG_OPT) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_APL:
            return ((flags & LOG_APL) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_DS:
            return ((flags & LOG_DS) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_SSHFP:
            return ((flags & LOG_SSHFP) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_IPSECKEY:
            return ((flags & LOG_IPSECKEY) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_RRSIG:
            return ((flags & LOG_RRSIG) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NSEC:
            return ((flags & LOG_NSEC) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_DNSKEY:
            return ((flags & LOG_DNSKEY) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_DHCID:
            return ((flags & LOG_DHCID) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NSEC3:
            return ((flags & LOG_NSEC3) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NSEC3PARAM:
            return ((flags & LOG_NSEC3PARAM) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_TLSA:
            return ((flags & LOG_TLSA) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_HIP:
            return ((flags & LOG_HIP) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_CDS:
            return ((flags & LOG_CDS) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_CDNSKEY:
            return ((flags & LOG_CDNSKEY) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_SPF:
            return ((flags & LOG_SPF) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_TKEY:
            return ((flags & LOG_TKEY) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_TSIG:
            return ((flags & LOG_TSIG) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_MAILA:
            return ((flags & LOG_MAILA) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_ANY:
            return ((flags & LOG_ANY) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_URI:
            return ((flags & LOG_URI) != 0) ? 1 : 0;
        default:
            return 0;
    }
}
#endif

#ifndef HAVE_RUST
static json_t *OutputQuery(DNSTransaction *tx, uint64_t tx_id, DNSQueryEntry *entry)
{
    json_t *djs = json_object();
    if (djs == NULL) {
        return NULL;
    }

    /* type */
    json_object_set_new(djs, "type", json_string("query"));

    /* id */
    json_object_set_new(djs, "id", json_integer(tx->tx_id));

    /* query */
    char *c;
    c = BytesToString((uint8_t *)((uint8_t *)entry + sizeof(DNSQueryEntry)), entry->len);
    if (c != NULL) {
        json_object_set_new(djs, "rrname", json_string(c));
        SCFree(c);
    }

    /* name */
    char record[16] = "";
    DNSCreateTypeString(entry->type, record, sizeof(record));
    json_object_set_new(djs, "rrtype", json_string(record));

    /* tx id (tx counter) */
    json_object_set_new(djs, "tx_id", json_integer(tx_id));

    return djs;
}

json_t *JsonDNSLogQuery(DNSTransaction *tx, uint64_t tx_id)
{
    DNSQueryEntry *entry = NULL;
    json_t *queryjs = json_array();
    if (queryjs == NULL)
        return NULL;

    TAILQ_FOREACH(entry, &tx->query_list, next) {
        json_t *qjs = OutputQuery(tx, tx_id, entry);
        if (qjs != NULL) {
            json_array_append_new(queryjs, qjs);
        }
    }

    return queryjs;
}

static void LogQuery(LogDnsLogThread *aft, json_t *js, DNSTransaction *tx,
        uint64_t tx_id, DNSQueryEntry *entry)
{
    SCLogDebug("got a DNS request and now logging !!");

    if (!DNSRRTypeEnabled(entry->type, aft->dnslog_ctx->flags)) {
        return;
    }

    json_t *djs = OutputQuery(tx, tx_id, entry);
    if (djs == NULL) {
        return;
    }

    /* reset */
    MemBufferReset(aft->buffer);

    /* dns */
    json_object_set_new(js, "dns", djs);
    OutputJSONBuffer(js, aft->dnslog_ctx->file_ctx, &aft->buffer);
    json_object_del(js, "dns");
}
#endif

#ifndef HAVE_RUST

static json_t *DnsParseSshFpType(DNSAnswerEntry *entry, uint8_t *ptr)
{
    /* get algo and type */
    uint8_t algo = *ptr;
    uint8_t fptype = *(ptr+1);

    /* turn fp raw buffer into a nice :-separate hex string */
    uint16_t fp_len = (entry->data_len - 2);
    uint8_t *dptr = ptr+2;

    /* c-string for ':' separated hex and trailing \0. */
    uint32_t output_len = fp_len * 3 + 1;
    char hexstring[output_len];
    memset(hexstring, 0x00, output_len);

    uint16_t x;
    for (x = 0; x < fp_len; x++) {
        char one[4];
        snprintf(one, sizeof(one), x == fp_len - 1 ? "%02x" : "%02x:", dptr[x]);
        strlcat(hexstring, one, output_len);
    }

    /* wrap the whole thing in it's own structure */
    json_t *hjs = json_object();
    if (hjs == NULL) {
        return NULL;
    }

    json_object_set_new(hjs, "fingerprint", json_string(hexstring));
    json_object_set_new(hjs, "algo", json_integer(algo));
    json_object_set_new(hjs, "type", json_integer(fptype));

    return hjs;
}

static void OutputAnswerDetailed(DNSAnswerEntry *entry, json_t *js,
        uint64_t flags)
{
    do {
        json_t *jdata = json_object();
        if (jdata == NULL) {
            return;
        }

        /* query */
        if (entry->fqdn_len > 0) {
            char *c;
            c = BytesToString((uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry)),
                    entry->fqdn_len);
            if (c != NULL) {
                json_object_set_new(jdata, "rrname", json_string(c));
                SCFree(c);
            }
        }

        /* name */
        char record[16] = "";
        DNSCreateTypeString(entry->type, record, sizeof(record));
        json_object_set_new(jdata, "rrtype", json_string(record));

        /* ttl */
        json_object_set_new(jdata, "ttl", json_integer(entry->ttl));

        uint8_t *ptr = (uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry)+ entry->fqdn_len);
        if (entry->type == DNS_RECORD_TYPE_A && entry->data_len == 4) {
            char a[16] = "";
            PrintInet(AF_INET, (const void *)ptr, a, sizeof(a));
            json_object_set_new(jdata, "rdata", json_string(a));
        } else if (entry->type == DNS_RECORD_TYPE_AAAA && entry->data_len == 16) {
            char a[46] = "";
            PrintInet(AF_INET6, (const void *)ptr, a, sizeof(a));
            json_object_set_new(jdata, "rdata", json_string(a));
        } else if (entry->data_len == 0) {
            json_object_set_new(jdata, "rdata", json_string(""));
        } else if (entry->type == DNS_RECORD_TYPE_TXT || entry->type == DNS_RECORD_TYPE_CNAME ||
                entry->type == DNS_RECORD_TYPE_MX || entry->type == DNS_RECORD_TYPE_PTR ||
                entry->type == DNS_RECORD_TYPE_NS) {
            if (entry->data_len != 0) {
                char buffer[256] = "";
                uint16_t copy_len = entry->data_len < (sizeof(buffer) - 1) ?
                    entry->data_len : sizeof(buffer) - 1;
                memcpy(buffer, ptr, copy_len);
                buffer[copy_len] = '\0';
                json_object_set_new(jdata, "rdata", json_string(buffer));
            } else {
                json_object_set_new(jdata, "rdata", json_string(""));
            }
        } else if (entry->type == DNS_RECORD_TYPE_SSHFP) {
            if (entry->data_len > 2) {
                json_t *hjs = DnsParseSshFpType(entry, ptr);
                if (hjs != NULL) {
                   json_object_set_new(jdata, "sshfp", hjs);
                }
            }
        }
        json_array_append_new(js, jdata);
    } while ((entry = TAILQ_NEXT(entry, next)));
}

static void OutputAnswerGrouped(DNSAnswerEntry *entry, json_t *js)
{
    struct {
        #define ENTRY_TYPE_A        0
        #define ENTRY_TYPE_AAAA     1
        #define ENTRY_TYPE_TXT      2
        #define ENTRY_TYPE_CNAME    3
        #define ENTRY_TYPE_MX       4
        #define ENTRY_TYPE_PTR      5
        #define ENTRY_TYPE_NS       6
        #define ENTRY_TYPE_SSHFP    7
        #define ENTRY_TYPE_MAX      8
        const char *name;
        json_t *value;
    } dns_rtypes[] = {
        { "A",      NULL },
        { "AAAA",   NULL },
        { "TXT",    NULL },
        { "CNAME",  NULL },
        { "MX",     NULL },
        { "PTR",    NULL },
        { "NS",     NULL },
        { "SSHFP",  NULL }
    };

    int i;
    json_t *jrdata = json_object();
    if (jrdata == NULL) {
        return;
    }

    do {
        uint8_t *ptr = (uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry)+ entry->fqdn_len);
        if (entry->type == DNS_RECORD_TYPE_A && entry->data_len == 4) {
            char a[16] = "";
            if (dns_rtypes[ENTRY_TYPE_A].value == NULL) {
                dns_rtypes[ENTRY_TYPE_A].value = json_array();
                if (dns_rtypes[ENTRY_TYPE_A].value == NULL) {
                    goto out;
                }
            }
            PrintInet(AF_INET, (const void *)ptr, a, sizeof(a));
            json_array_append_new(dns_rtypes[ENTRY_TYPE_A].value, json_string(a));
        } else if (entry->type == DNS_RECORD_TYPE_AAAA && entry->data_len == 16) {
            char a[46] = "";
            if (dns_rtypes[ENTRY_TYPE_AAAA].value == NULL) {
                dns_rtypes[ENTRY_TYPE_AAAA].value = json_array();
                if (dns_rtypes[ENTRY_TYPE_AAAA].value == NULL) {
                    goto out;
                }
            }
            PrintInet(AF_INET6, (const void *)ptr, a, sizeof(a));
            json_array_append_new(dns_rtypes[ENTRY_TYPE_AAAA].value, json_string(a));
        } else if (entry->data_len == 0) {
            json_object_set_new(js, "rdata", json_string(""));
        } else if (entry->type == DNS_RECORD_TYPE_TXT || entry->type == DNS_RECORD_TYPE_CNAME ||
                entry->type == DNS_RECORD_TYPE_MX || entry->type == DNS_RECORD_TYPE_PTR ||
                entry->type == DNS_RECORD_TYPE_NS) {
            if (entry->data_len != 0) {
                char buffer[256] = "";
                uint16_t copy_len = entry->data_len < (sizeof(buffer) - 1) ?
                    entry->data_len : sizeof(buffer) - 1;
                memcpy(buffer, ptr, copy_len);
                buffer[copy_len] = '\0';

                if (entry->type == DNS_RECORD_TYPE_TXT) {
                    if (dns_rtypes[ENTRY_TYPE_TXT].value == NULL) {
                        dns_rtypes[ENTRY_TYPE_TXT].value = json_array();
                        if (dns_rtypes[ENTRY_TYPE_TXT].value == NULL) {
                            goto out;
                        }
                    }
                    json_array_append_new(dns_rtypes[ENTRY_TYPE_TXT].value, json_string(buffer));
                } else if (entry->type == DNS_RECORD_TYPE_CNAME) {
                    if (dns_rtypes[ENTRY_TYPE_CNAME].value == NULL) {
                        dns_rtypes[ENTRY_TYPE_CNAME].value = json_array();
                        if (dns_rtypes[ENTRY_TYPE_CNAME].value == NULL) {
                            goto out;
                        }
                    }
                    json_array_append_new(dns_rtypes[ENTRY_TYPE_CNAME].value, json_string(buffer));
                } else if (entry->type == DNS_RECORD_TYPE_MX) {
                    if (dns_rtypes[ENTRY_TYPE_MX].value == NULL) {
                        dns_rtypes[ENTRY_TYPE_MX].value = json_array();
                        if (dns_rtypes[ENTRY_TYPE_MX].value == NULL) {
                            goto out;
                        }
                    }
                    json_array_append_new(dns_rtypes[ENTRY_TYPE_MX].value, json_string(buffer));
                } else if (entry->type == DNS_RECORD_TYPE_PTR) {
                    if (dns_rtypes[ENTRY_TYPE_PTR].value == NULL) {
                        dns_rtypes[ENTRY_TYPE_PTR].value = json_array();
                        if (dns_rtypes[ENTRY_TYPE_PTR].value == NULL) {
                            goto out;
                        }
                    }
                    json_array_append_new(dns_rtypes[ENTRY_TYPE_PTR].value, json_string(buffer));
                } else if (entry->type == DNS_RECORD_TYPE_NS) {
                    if (dns_rtypes[ENTRY_TYPE_NS].value == NULL) {
                        dns_rtypes[ENTRY_TYPE_NS].value = json_array();
                        if (dns_rtypes[ENTRY_TYPE_NS].value == NULL) {
                            goto out;
                        }
                    }
                    json_array_append_new(dns_rtypes[ENTRY_TYPE_NS].value, json_string(buffer));
                }
            } else {
                json_object_set_new(js, "rdata", json_string(""));
            }
        } else if (entry->type == DNS_RECORD_TYPE_SSHFP) {
            if (entry->data_len > 2) {
                json_t *hjs = DnsParseSshFpType(entry, ptr);
                if (hjs != NULL) {
                    if (dns_rtypes[ENTRY_TYPE_SSHFP].value == NULL) {
                        dns_rtypes[ENTRY_TYPE_SSHFP].value = json_array();
                        if (dns_rtypes[ENTRY_TYPE_SSHFP].value == NULL) {
                            goto out;
                        }
                    }
                    json_array_append_new(dns_rtypes[ENTRY_TYPE_SSHFP].value, hjs);
                }
            }
        }
    } while ((entry = TAILQ_NEXT(entry, next)));

out:
    for (i = 0; i < ENTRY_TYPE_MAX; i++) {
        if (dns_rtypes[i].value != NULL) {
            json_object_set_new(jrdata, dns_rtypes[i].name, dns_rtypes[i].value);
            dns_rtypes[i].value = NULL;
        }
    }

    json_object_set_new(js, "grouped", jrdata);
}

static void OutputAnswerV1(LogDnsLogThread *aft, json_t *djs,
        DNSTransaction *tx, DNSAnswerEntry *entry)
{
    if (!DNSRRTypeEnabled(entry->type, aft->dnslog_ctx->flags)) {
        return;
    }

    json_t *js = json_object();
    if (js == NULL)
        return;

    /* type */
    json_object_set_new(js, "type", json_string("answer"));

    /* id */
    json_object_set_new(js, "id", json_integer(tx->tx_id));

    /* dns */
    char flags[7] = "";
    snprintf(flags, sizeof(flags), "%4x", tx->flags);
    json_object_set_new(js, "flags", json_string(flags));
    if (tx->flags & 0x8000)
        json_object_set_new(js, "qr", json_true());
    if (tx->flags & 0x0400)
        json_object_set_new(js, "aa", json_true());
    if (tx->flags & 0x0200)
        json_object_set_new(js, "tc", json_true());
    if (tx->flags & 0x0100)
        json_object_set_new(js, "rd", json_true());
    if (tx->flags & 0x0080)
        json_object_set_new(js, "ra", json_true());


    /* rcode */
    char rcode[16] = "";
    DNSCreateRcodeString(tx->rcode, rcode, sizeof(rcode));
    json_object_set_new(js, "rcode", json_string(rcode));

    /* query */
    if (entry->fqdn_len > 0) {
        char *c;
        c = BytesToString((uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry)),
                entry->fqdn_len);
        if (c != NULL) {
            json_object_set_new(js, "rrname", json_string(c));
            SCFree(c);
        }
    }

    /* name */
    char record[16] = "";
    DNSCreateTypeString(entry->type, record, sizeof(record));
    json_object_set_new(js, "rrtype", json_string(record));

    /* ttl */
    json_object_set_new(js, "ttl", json_integer(entry->ttl));

    uint8_t *ptr = (uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry)+ entry->fqdn_len);
    if (entry->type == DNS_RECORD_TYPE_A && entry->data_len == 4) {
        char a[16] = "";
        PrintInet(AF_INET, (const void *)ptr, a, sizeof(a));
        json_object_set_new(js, "rdata", json_string(a));
    } else if (entry->type == DNS_RECORD_TYPE_AAAA && entry->data_len == 16) {
        char a[46] = "";
        PrintInet(AF_INET6, (const void *)ptr, a, sizeof(a));
        json_object_set_new(js, "rdata", json_string(a));
    } else if (entry->data_len == 0) {
        json_object_set_new(js, "rdata", json_string(""));
    } else if (entry->type == DNS_RECORD_TYPE_TXT || entry->type == DNS_RECORD_TYPE_CNAME ||
            entry->type == DNS_RECORD_TYPE_MX || entry->type == DNS_RECORD_TYPE_PTR ||
            entry->type == DNS_RECORD_TYPE_NS) {
        if (entry->data_len != 0) {
            char buffer[256] = "";
            uint16_t copy_len = entry->data_len < (sizeof(buffer) - 1) ?
                entry->data_len : sizeof(buffer) - 1;
            memcpy(buffer, ptr, copy_len);
            buffer[copy_len] = '\0';
            json_object_set_new(js, "rdata", json_string(buffer));
        } else {
            json_object_set_new(js, "rdata", json_string(""));
        }
    } else if (entry->type == DNS_RECORD_TYPE_SSHFP) {
        if (entry->data_len > 2) {
            json_t *hjs = DnsParseSshFpType(entry, ptr);
            if (hjs != NULL) {
                json_object_set_new(js, "sshfp", hjs);
            }
        }
    }

    /* reset */
    MemBufferReset(aft->buffer);
    json_object_set_new(djs, "dns", js);
    OutputJSONBuffer(djs, aft->dnslog_ctx->file_ctx, &aft->buffer);
    json_object_del(djs, "dns");

    return;
}

static json_t *BuildAnswer(DNSTransaction *tx, uint64_t tx_id, uint64_t flags,
                           DnsVersion version)
{
    json_t *js = json_object();
    if (js == NULL)
        return NULL;

    /* version */
    if (version == DNS_VERSION_2) {
        json_object_set_new(js, "version", json_integer(DNS_VERSION_2));
    } else {
        json_object_set_new(js, "version", json_integer(DNS_VERSION_1));
    }

    /* type */
    json_object_set_new(js, "type", json_string("answer"));

    /* id */
    json_object_set_new(js, "id", json_integer(tx->tx_id));

    /* flags */
    char dns_flags[7] = "";
    snprintf(dns_flags, sizeof(dns_flags), "%4x", tx->flags);
    json_object_set_new(js, "flags", json_string(dns_flags));
    if (tx->flags & 0x8000)
        json_object_set_new(js, "qr", json_true());
    if (tx->flags & 0x0400)
        json_object_set_new(js, "aa", json_true());
    if (tx->flags & 0x0200)
        json_object_set_new(js, "tc", json_true());
    if (tx->flags & 0x0100)
        json_object_set_new(js, "rd", json_true());
    if (tx->flags & 0x0080)
        json_object_set_new(js, "ra", json_true());

    /* rcode */
    char rcode[16] = "";
    DNSCreateRcodeString(tx->rcode, rcode, sizeof(rcode));
    json_object_set_new(js, "rcode", json_string(rcode));

    /* Log the query rrname. Mostly useful on error, but still
     * useful. */
    DNSQueryEntry *query = TAILQ_FIRST(&tx->query_list);
    if (query != NULL) {
        char *c;
        c = BytesToString((uint8_t *)((uint8_t *)query + sizeof(DNSQueryEntry)),
                query->len);
        if (c != NULL) {
            json_object_set_new(js, "rrname", json_string(c));
            SCFree(c);
        }
    }

    if (flags & LOG_FORMAT_DETAILED) {
        if (!TAILQ_EMPTY(&tx->answer_list)) {
            json_t *jarray = json_array();
            if (jarray == NULL) {
                json_decref(js);
                return NULL;
            }
            OutputAnswerDetailed(TAILQ_FIRST(&tx->answer_list), jarray, flags);
            json_object_set_new(js, "answers", jarray);
        }

        if (!TAILQ_EMPTY(&tx->authority_list)) {
            json_t *js_authorities = json_array();
            if (likely(js_authorities != NULL)) {
                OutputAnswerDetailed(TAILQ_FIRST(&tx->authority_list),
                        js_authorities, flags);
                json_object_set_new(js, "authorities", js_authorities);
            }
        }
    }

    if (!TAILQ_EMPTY(&tx->answer_list) && (flags & LOG_FORMAT_GROUPED)) {
        OutputAnswerGrouped(TAILQ_FIRST(&tx->answer_list), js);
    }

    return js;
}

static void OutputAnswerV2(LogDnsLogThread *aft, json_t *djs,
        DNSTransaction *tx)
{
    json_t *dnsjs = BuildAnswer(tx, tx->tx_id, aft->dnslog_ctx->flags,
                                aft->dnslog_ctx->version);
    if (dnsjs != NULL) {
        /* reset */
        MemBufferReset(aft->buffer);
        json_object_set_new(djs, "dns", dnsjs);
        OutputJSONBuffer(djs, aft->dnslog_ctx->file_ctx, &aft->buffer);
    }
}

json_t *JsonDNSLogAnswer(DNSTransaction *tx, uint64_t tx_id)
{
    DNSAnswerEntry *entry = TAILQ_FIRST(&tx->answer_list);
    json_t *js = NULL;

    if (entry) {
        js = BuildAnswer(tx, tx_id, LOG_FORMAT_DETAILED, DNS_VERSION_2);
    }

    return js;
}

#endif

#ifndef HAVE_RUST
static void OutputFailure(LogDnsLogThread *aft, json_t *djs,
        DNSTransaction *tx, DNSQueryEntry *entry) __attribute__((nonnull));

static void OutputFailure(LogDnsLogThread *aft, json_t *djs,
        DNSTransaction *tx, DNSQueryEntry *entry)
{
    if (!DNSRRTypeEnabled(entry->type, aft->dnslog_ctx->flags)) {
        return;
    }

    json_t *js = json_object();
    if (js == NULL)
        return;

    /* type */
    json_object_set_new(js, "type", json_string("answer"));

    /* id */
    json_object_set_new(js, "id", json_integer(tx->tx_id));

    /* rcode */
    char rcode[16] = "";
    DNSCreateRcodeString(tx->rcode, rcode, sizeof(rcode));
    json_object_set_new(js, "rcode", json_string(rcode));

    /* no answer RRs, use query for rname */
    char *c;
    c = BytesToString((uint8_t *)((uint8_t *)entry + sizeof(DNSQueryEntry)), entry->len);
    if (c != NULL) {
        json_object_set_new(js, "rrname", json_string(c));
        SCFree(c);
    }

    /* reset */
    MemBufferReset(aft->buffer);
    json_object_set_new(djs, "dns", js);
    OutputJSONBuffer(djs, aft->dnslog_ctx->file_ctx, &aft->buffer);
    json_object_del(djs, "dns");

    return;
}
#endif

#ifndef HAVE_RUST
static void LogAnswers(LogDnsLogThread *aft, json_t *js, DNSTransaction *tx, uint64_t tx_id)
{

    SCLogDebug("got a DNS response and now logging !!");

    if (aft->dnslog_ctx->version == DNS_VERSION_2) {
        DNSQueryEntry *query = TAILQ_FIRST(&tx->query_list);
        if (query && !DNSRRTypeEnabled(query->type, aft->dnslog_ctx->flags)) {
            return;
        }
        OutputAnswerV2(aft, js, tx);
    } else {
        DNSAnswerEntry *entry = NULL;

        /* rcode != noerror */
        if (tx->rcode) {
            /* Most DNS servers do not support multiple queries because
             * the rcode in response is not per-query.  Multiple queries
             * are likely to lead to FORMERR, so log this. */
            DNSQueryEntry *query = NULL;
            TAILQ_FOREACH(query, &tx->query_list, next) {
                OutputFailure(aft, js, tx, query);
            }
        }

        TAILQ_FOREACH(entry, &tx->answer_list, next) {
            OutputAnswerV1(aft, js, tx, entry);
        }
        TAILQ_FOREACH(entry, &tx->authority_list, next) {
            OutputAnswerV1(aft, js, tx, entry);
        }
    }

}
#endif

static int JsonDnsLoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *alstate, void *txptr, uint64_t tx_id)
{
    SCEnter();

    LogDnsLogThread *td = (LogDnsLogThread *)thread_data;
    LogDnsFileCtx *dnslog_ctx = td->dnslog_ctx;
    json_t *js;

    if (unlikely(dnslog_ctx->flags & LOG_QUERIES) == 0) {
        return TM_ECODE_OK;
    }

#ifdef HAVE_RUST
    for (uint16_t i = 0; i < 0xffff; i++) {
        js = CreateJSONHeader(p, LOG_DIR_PACKET, "dns");
        if (unlikely(js == NULL)) {
            return TM_ECODE_OK;
        }
        if (dnslog_ctx->include_metadata) {
            JsonAddMetadata(p, f, js);
        }
        json_t *dns = rs_dns_log_json_query(txptr, i, td->dnslog_ctx->flags);
        if (unlikely(dns == NULL)) {
            json_decref(js);
            break;
        }
        json_object_set_new(js, "dns", dns);
        MemBufferReset(td->buffer);
        OutputJSONBuffer(js, td->dnslog_ctx->file_ctx, &td->buffer);
        json_decref(js);
    }
#else
    DNSTransaction *tx = txptr;
    DNSQueryEntry *query = NULL;
    TAILQ_FOREACH(query, &tx->query_list, next) {
        js = CreateJSONHeader(p, LOG_DIR_PACKET, "dns");
        if (unlikely(js == NULL))
            return TM_ECODE_OK;
        if (dnslog_ctx->include_metadata) {
            JsonAddMetadata(p, f, js);
        }

        LogQuery(td, js, tx, tx_id, query);

        json_decref(js);
    }
#endif

    SCReturnInt(TM_ECODE_OK);
}

static int JsonDnsLoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *alstate, void *txptr, uint64_t tx_id)
{
    SCEnter();

    LogDnsLogThread *td = (LogDnsLogThread *)thread_data;
    LogDnsFileCtx *dnslog_ctx = td->dnslog_ctx;

    if (unlikely(dnslog_ctx->flags & LOG_ANSWERS) == 0) {
        return TM_ECODE_OK;
    }

    json_t *js = CreateJSONHeader(p, LOG_DIR_PACKET, "dns");
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    if (dnslog_ctx->include_metadata) {
        JsonAddMetadata(p, f, js);
    }

#if HAVE_RUST
    if (td->dnslog_ctx->version == DNS_VERSION_2) {
        json_t *answer = rs_dns_log_json_answer(txptr,
                td->dnslog_ctx->flags);
        if (answer != NULL) {
            json_object_set_new(js, "dns", answer);
            MemBufferReset(td->buffer);
            OutputJSONBuffer(js, td->dnslog_ctx->file_ctx, &td->buffer);
        }
    }
#else
    DNSTransaction *tx = txptr;

    LogAnswers(td, js, tx, tx_id);
#endif

    json_decref(js);

    SCReturnInt(TM_ECODE_OK);
}

#define OUTPUT_BUFFER_SIZE 65536
static TmEcode LogDnsLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogDnsLogThread *aft = SCMalloc(sizeof(LogDnsLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogDnsLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogDNS.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->dnslog_ctx= ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode LogDnsLogThreadDeinit(ThreadVars *t, void *data)
{
    LogDnsLogThread *aft = (LogDnsLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(LogDnsLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void LogDnsLogDeInitCtx(OutputCtx *output_ctx)
{
    LogDnsFileCtx *dnslog_ctx = (LogDnsFileCtx *)output_ctx->data;
    LogFileFreeCtx(dnslog_ctx->file_ctx);
    SCFree(dnslog_ctx);
    SCFree(output_ctx);
}

static void LogDnsLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogDnsFileCtx *dnslog_ctx = (LogDnsFileCtx *)output_ctx->data;
    SCFree(dnslog_ctx);
    SCFree(output_ctx);
}

static void JsonDnsLogParseConfig(LogDnsFileCtx *dnslog_ctx, ConfNode *conf,
                                  const char *query_key, const char *answer_key,
                                  const char *answer_types_key)
{
    const char *query = ConfNodeLookupChildValue(conf, query_key);
    if (query != NULL) {
        if (ConfValIsTrue(query)) {
            dnslog_ctx->flags |= LOG_QUERIES;
        } else {
            dnslog_ctx->flags &= ~LOG_QUERIES;
        }
    } else {
        if (dnslog_ctx->version == DNS_VERSION_2) {
            dnslog_ctx->flags |= LOG_QUERIES;
        }
    }

    const char *response = ConfNodeLookupChildValue(conf, answer_key);
    if (response != NULL) {
        if (ConfValIsTrue(response)) {
            dnslog_ctx->flags |= LOG_ANSWERS;
        } else {
            dnslog_ctx->flags &= ~LOG_ANSWERS;
        }
    } else {
        if (dnslog_ctx->version == DNS_VERSION_2) {
            dnslog_ctx->flags |= LOG_ANSWERS;
        }
    }

    ConfNode *custom;
    if ((custom = ConfNodeLookupChild(conf, answer_types_key)) != NULL) {
        dnslog_ctx->flags &= ~LOG_ALL_RRTYPES;
        ConfNode *field;
        TAILQ_FOREACH(field, &custom->head, next)
        {
            if (field != NULL)
            {
                DnsRRTypes f;
                for (f = DNS_RRTYPE_A; f < DNS_RRTYPE_MAX; f++)
                {
                    if (strcasecmp(dns_rrtype_fields[f].config_rrtype,
                                   field->val) == 0)
                    {
                        dnslog_ctx->flags |= dns_rrtype_fields[f].flags;
                        break;
                    }
                }
            }
        }
    } else {
        if (dnslog_ctx->version == DNS_VERSION_2) {
            dnslog_ctx->flags |= LOG_ALL_RRTYPES;
        }
    }
}

static DnsVersion JsonDnsParseVersion(ConfNode *conf)
{
    if (conf == NULL) {
        return DNS_VERSION_DEFAULT;
    }

    DnsVersion version = DNS_VERSION_DEFAULT;
    intmax_t config_version;
    if (ConfGetChildValueInt(conf, "version", &config_version)) {
        switch(config_version) {
            case 1:
                version = DNS_VERSION_1;
                break;
            case 2:
                version = DNS_VERSION_2;
                break;
            default:
                SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                        "invalid eve-log dns version option: %"PRIuMAX", "
                        "forcing it to version %u",
                        config_version, DNS_VERSION_DEFAULT);
                version = DNS_VERSION_DEFAULT;
                break;
        }
    } else {
        SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                "version not found, forcing it to version %u",
                DNS_VERSION_DEFAULT);
        version = DNS_VERSION_DEFAULT;
    }
#ifdef HAVE_RUST
    if (version != DNS_VERSION_2) {
        FatalError(SC_ERR_NOT_SUPPORTED, "EVE/DNS version %d not support with "
                "by Rust builds.", version);
    }
#endif
    return version;
}

static void JsonDnsLogInitFilters(LogDnsFileCtx *dnslog_ctx, ConfNode *conf)
{
    dnslog_ctx->flags = ~0UL;

    if (conf) {
        if (dnslog_ctx->version == DNS_VERSION_1) {
            JsonDnsLogParseConfig(dnslog_ctx, conf, "query", "answer", "custom");
        } else {
            JsonDnsLogParseConfig(dnslog_ctx, conf, "requests", "responses", "types");

            if (dnslog_ctx->flags & LOG_ANSWERS) {
                ConfNode *format;
                if ((format = ConfNodeLookupChild(conf, "formats")) != NULL) {
                    dnslog_ctx->flags &= ~LOG_FORMAT_ALL;
                    ConfNode *field;
                    TAILQ_FOREACH(field, &format->head, next) {
                        if (strcasecmp(field->val, "detailed") == 0) {
                            dnslog_ctx->flags |= LOG_FORMAT_DETAILED;
                        } else if (strcasecmp(field->val, "grouped") == 0) {
                            dnslog_ctx->flags |= LOG_FORMAT_GROUPED;
                        }
                    }
                } else {
                    dnslog_ctx->flags |= LOG_FORMAT_ALL;
                }
            }
        }
    }
}

static OutputInitResult JsonDnsLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    const char *enabled = ConfNodeLookupChildValue(conf, "enabled");
    if (enabled != NULL && !ConfValIsTrue(enabled)) {
        result.ok = true;
        return result;
    }

    DnsVersion version = JsonDnsParseVersion(conf);

    OutputJsonCtx *ojc = parent_ctx->data;

    LogDnsFileCtx *dnslog_ctx = SCMalloc(sizeof(LogDnsFileCtx));
    if (unlikely(dnslog_ctx == NULL)) {
        return result;
    }
    memset(dnslog_ctx, 0x00, sizeof(LogDnsFileCtx));

    dnslog_ctx->file_ctx = ojc->file_ctx;
    dnslog_ctx->include_metadata = ojc->include_metadata;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(dnslog_ctx);
        return result;
    }

    output_ctx->data = dnslog_ctx;
    output_ctx->DeInit = LogDnsLogDeInitCtxSub;

    dnslog_ctx->version = version;
    JsonDnsLogInitFilters(dnslog_ctx, conf);

    SCLogDebug("DNS log sub-module initialized");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DNS);
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DNS);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

#define DEFAULT_LOG_FILENAME "dns.json"
/** \brief Create a new dns log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
static OutputInitResult JsonDnsLogInitCtx(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    const char *enabled = ConfNodeLookupChildValue(conf, "enabled");
    if (enabled != NULL && !ConfValIsTrue(enabled)) {
        return result;
    }

    DnsVersion version = JsonDnsParseVersion(conf);
#ifdef HAVE_RUST
    if (version != 2) {
        SCLogError(SC_ERR_NOT_SUPPORTED, "EVE/DNS version %d not support with "
                "by Rust builds.", version);
        exit(1);
    }
#endif

    LogFileCtx *file_ctx = LogFileNewCtx();

    if(file_ctx == NULL) {
        SCLogError(SC_ERR_DNS_LOG_GENERIC, "couldn't create new file_ctx");
        return result;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return result;
    }

    LogDnsFileCtx *dnslog_ctx = SCMalloc(sizeof(LogDnsFileCtx));
    if (unlikely(dnslog_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return result;
    }
    memset(dnslog_ctx, 0x00, sizeof(LogDnsFileCtx));

    dnslog_ctx->file_ctx = file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(dnslog_ctx);
        return result;
    }

    output_ctx->data = dnslog_ctx;
    output_ctx->DeInit = LogDnsLogDeInitCtx;

    dnslog_ctx->version = version;
    JsonDnsLogInitFilters(dnslog_ctx, conf);

    SCLogDebug("DNS log output initialized");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DNS);
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DNS);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}


#define MODULE_NAME "JsonDnsLog"
void JsonDnsLogRegister (void)
{
    /* Logger for requests. */
    OutputRegisterTxModuleWithProgress(LOGGER_JSON_DNS_TS, MODULE_NAME,
        "dns-json-log", JsonDnsLogInitCtx, ALPROTO_DNS, JsonDnsLoggerToServer,
        0, 1, LogDnsLogThreadInit, LogDnsLogThreadDeinit, NULL);

    /* Logger for replies. */
    OutputRegisterTxModuleWithProgress(LOGGER_JSON_DNS_TC, MODULE_NAME,
        "dns-json-log", JsonDnsLogInitCtx, ALPROTO_DNS, JsonDnsLoggerToClient,
        1, 1, LogDnsLogThreadInit, LogDnsLogThreadDeinit, NULL);

    /* Sub-logger for requests. */
    OutputRegisterTxSubModuleWithProgress(LOGGER_JSON_DNS_TS, "eve-log",
        MODULE_NAME, "eve-log.dns", JsonDnsLogInitCtxSub, ALPROTO_DNS,
        JsonDnsLoggerToServer, 0, 1, LogDnsLogThreadInit,
        LogDnsLogThreadDeinit, NULL);

    /* Sub-logger for replies. */
    OutputRegisterTxSubModuleWithProgress(LOGGER_JSON_DNS_TC, "eve-log",
        MODULE_NAME, "eve-log.dns", JsonDnsLogInitCtxSub, ALPROTO_DNS,
        JsonDnsLoggerToClient, 1, 1, LogDnsLogThreadInit, LogDnsLogThreadDeinit,
        NULL);
}

#else

void JsonDnsLogRegister (void)
{
}

#endif
