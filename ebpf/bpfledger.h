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
#define AUDIT_SOURCE_LSM 0 
#define AUDIT_SOURCE_LSM_FREE 1
#define AUDIT_SOURCE_LSM_BPF  2 



/* Event types */
#define AUDIT_EVENT_LOAD    0  
#define AUDIT_EVENT_FREE    1
#define AUDIT_EVENT_PIN     2
#define AUDIT_EVENT_GET     3
#define AUDIT_EVENT_ATTACH  4
#define AUDIT_EVENT_DETACH  5
#define AUDIT_SOURCE_KPROBE 6
#define AUDIT_SOURCE_PIN    7 
#define AUDIT_SOURCE_LINK   8
#define AUDIT_EVENT_INTENT  9 

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
  u64 reserved_pad;
  u64 pid_ns_id;

  u32 prog_id;
  u32 prog_type;

  u8 event_type;
  u8 source;
  u8 pad[6];

  u8 prog_tag[8];
  char comm[16];
  u8 bytecode_hash[32];

  union {
    char path[64];
    u32 prog_fd;
    u8 raw[64];
  } extra;
};

#define AUDIT_RECORD_SIZE sizeof(struct audit_record)

#endif /* _BPFLEDGER_H */
