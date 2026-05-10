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

/* TAG AND COMM SIZE */
#define AUDIT_PROG_TAG_SIZE 8
#define AUDIT_COMM_SIZE 16


/*
 * audit_record - one eBPF lifecycle event
 *
 * seq and hashes are filled by the kernel module
 */
struct audit_record {
  u64 seq;
  u64 timestamp_ns;
  u64 prev_hash;
  u64 curr_hash;

  u32 pid;
  u32 tgid;
  u32 uid;
  u32 gid;

  u64 cgroup_id;
  u64 pid_ns_id;

  u32 prog_id;
  u32 prog_type;

  u8 event_type;
  u8 source;
  u8  _pad[6];

  u8 prog_tag[8];
  char comm[16];

  char path[64];
}__attribute__((packed)); 

#define AUDIT_RECORD_SIZE sizeof(struct audit_record)

#endif /* _BPFLEDGER_H */
