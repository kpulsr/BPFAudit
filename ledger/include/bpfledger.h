/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPFAudit Ledger - Shared Record Structure
 * Used by: kernel module
 */

#ifndef _BPFLEDGER_H
#define _BPFLEDGER_H

#ifndef __BPF__
#include <linux/types.h>
#endif
/* Event sources */
#define AUDIT_SOURCE_FPROBE 1
#define AUDIT_SOURCE_KPROBE 2

/* Event types */
#define AUDIT_EVENT_LOAD    0
#define AUDIT_EVENT_ATTACH  1
#define AUDIT_EVENT_PIN     2
#define AUDIT_EVENT_DETACH  3
#define AUDIT_EVENT_CLOSE   4
#define AUDIT_EVENT_FREE    5
#define AUDIT_EVENT_BATCH_ANCHOR 6  
#define AUDIT_EVENT_CBPF_LOAD_ATTACH  7
#define AUDIT_EVENT_CBPF_FREE         8
#define AUDIT_EVENT_HEARTBEAT 10

/* TAG AND COMM SIZE */
#define AUDIT_PROG_TAG_SIZE 8
#define AUDIT_COMM_SIZE 16


/*
 * audit_record - one eBPF lifecycle event
 *
 * seq and hashes are filled by the kernel module
 */

struct audit_record {
    /*--- common header (24bytes) ---*/
    u64 seq; 
    u64 timestamp_ns; 

    u8 event_type; 
    u8 source; 
    u8 _hdr_pad[6]; 

    /*--- per-type payload (128bytes) ---*/
    union {
        struct {
            u32 pid; 
            u32 tgid; 
            u32 uid; 
            u32 gid; /* 16 */

            u64 cgroup_id; 
            u64 pid_ns_id; /* 32 */

            u32 prog_id; 
            u32 prog_type; /* 40 */

            u8 prog_tag[AUDIT_PROG_TAG_SIZE]; /* 48 */
            char comm[AUDIT_COMM_SIZE]; /* 64 */
            char path[64];   /* 128 */
        }ev; 

        struct {
            u64 end_seq;
            u8   batch_hash[32]; /* SHA-256 of batch   */
            u8   batch_hmac[32];       /* HMAC-SHA256 of hash */ 
            u8   _pad[56]; 
        } anr;

        u8 _raw[128]; /*heartbeat ... no payload*/
    }u; 
}__attribute__((packed)); 


#ifndef __BPF__
_Static_assert(sizeof(struct audit_record) == 152,
               "audit_record size changed — update ABI docs");
_Static_assert(sizeof(((struct audit_record *)0)->u.ev)     == 128, "ev arm size");
_Static_assert(sizeof(((struct audit_record *)0)->u.anr) == 128, "anchor arm size");
#endif
#define AUDIT_RECORD_SIZE sizeof(struct audit_record)
#endif /* _BPFLEDGER_H */
