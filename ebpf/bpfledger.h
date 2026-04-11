/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPFAudit Ledger - Shared Record Structure
 * Used by: kernel module, BPF program (via vmlinux/BTF), userspace daemon
 */

#ifndef _BPFLEDGER_H
#define _BPFLEDGER_H

#ifndef __BPF__
#include <linux/types.h>
#endif
/* Event sources */
#define AUDIT_SOURCE_LSM    0   /* Came from BPF LSM hook     */
#define AUDIT_SOURCE_KPROBE 1   /* Came from kprobe/fentry    */

/* Event types */
#define AUDIT_EVENT_LOAD    1
#define AUDIT_EVENT_UNLOAD  2

#define AUDIT_PROG_TAG_SIZE 8
#define AUDIT_COMM_SIZE     16

/*
 * audit_record - one eBPF lifecycle event
 *
 * seq and hashes are filled by the kernel module, not the BPF program.
 * The BPF program fills everything else before calling bpfaudit_submit_event().
 */
struct audit_record {
	/* Filled by kernel module (ledger side) */
	__u64 seq;                          /* monotonic counter, set in module  */
	__u64 timestamp_ns;                 /* ktime_get_ns(), set in module     */
	__u8  prev_hash[32];                /* SHA-256 of previous record        */
	__u8  curr_hash[32];                /* SHA-256 of this record            */

	/* Filled by BPF program (hook side) */
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	__u32 gid;
	__u64 cgroup_id;
	__u32 prog_id;
	__u32 prog_type;
	__u8  event_type;                   /* AUDIT_EVENT_LOAD / UNLOAD         */
	__u8  source;                       /* AUDIT_SOURCE_LSM / KPROBE         */
	__u8  prog_tag[AUDIT_PROG_TAG_SIZE];
	char  comm[AUDIT_COMM_SIZE];

	/* Padding to 128-byte cache-line multiple */
	__u8  __pad[2];
};

#define AUDIT_RECORD_SIZE sizeof(struct audit_record)

#endif /* _BPFLEDGER_H */
