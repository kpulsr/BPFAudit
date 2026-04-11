// SPDX-License-Identifier: GPL-2.0
/*
 * BPFAudit — BPF-side hooks
 *
 * Two independent paths, both calling bpfaudit_submit_event() kfunc
 * which lives in bpfledger.ko:
 *
 *   Path A: LSM hook  lsm/bpf_prog_load    — synchronous, gets full prog info
 *   Path B: kprobe    bpf_prog_load        — independent, cross-validation
 *
 * The kfunc call is the ONLY write path into the kernel-side ledger
 * Userspace cannot write to /dev/bpfledger at all
 */

#include "bpfledger.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* ── kfunc declaration ─────────────────────────────────────────────────── */

/*
 * kfunc exported by bpfledger.ko
 */
extern void bpfaudit_submit_event(struct audit_record *rec,
                                  __u32 rec__sz) __ksym;

/* ── BPF maps ──────────────────────────────────────────────────────────── */

/* Cross-validation counters — read by userspace daemon to detect path mismatch
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} lsm_counter SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} kprobe_counter SEC(".maps");

/* ── Helpers ───────────────────────────────────────────────────────────── */

static __always_inline void fill_process_ctx(struct audit_record *rec) {
  __u64 pidtgid = bpf_get_current_pid_tgid();
  __u64 uidgid = bpf_get_current_uid_gid();

  rec->pid = (__u32)(pidtgid & 0xffffffff);
  rec->tgid = (__u32)(pidtgid >> 32);
  rec->uid = (__u32)(uidgid & 0xffffffff);
  rec->gid = (__u32)(uidgid >> 32);

  rec->cgroup_id = bpf_get_current_cgroup_id();
  bpf_get_current_comm(rec->comm, sizeof(rec->comm));
}

static __always_inline void inc_counter(void *map) {
  __u32 key = 0;
  __u64 *val = bpf_map_lookup_elem(map, &key);
  if (val)
    __sync_fetch_and_add(val, 1);
}

/* ── Path A: LSM hook ──────────────────────────────────────────────────── */

/*
 * Fires synchronously when any BPF program passes the verifier and is about
 * to be loaded
 * Returns 0... currently only audit no enforcement
 */
SEC("lsm/bpf_prog_load")
int BPF_PROG(audit_lsm_prog_load, struct bpf_prog *prog, union bpf_attr *attr,
             struct bpf_token *token) {
  struct audit_record rec = {};

  fill_process_ctx(&rec);

  rec.event_type = AUDIT_EVENT_LOAD;
  rec.source = AUDIT_SOURCE_LSM;

  if (prog) {
    rec.prog_type = BPF_CORE_READ(prog, type);
    rec.prog_id = BPF_CORE_READ(prog, aux, id);
    __builtin_memcpy(rec.prog_tag, BPF_CORE_READ(prog, tag),
                     AUDIT_PROG_TAG_SIZE);
  }

  inc_counter(&lsm_counter);
  bpfaudit_submit_event(&rec, sizeof(rec));

  return 0; /* audit only */
}

SEC("lsm/bpf_prog_free")
void BPF_PROG(audit_lsm_prog_free, struct bpf_prog *prog) {
  struct audit_record rec = {};

  if (!prog)
    return;

  fill_process_ctx(&rec);

  rec.event_type = AUDIT_EVENT_UNLOAD;
  rec.source = AUDIT_SOURCE_LSM;
  rec.prog_type = BPF_CORE_READ(prog, type);
  rec.prog_id = BPF_CORE_READ(prog, aux, id);
  __builtin_memcpy(rec.prog_tag, BPF_CORE_READ(prog, tag), AUDIT_PROG_TAG_SIZE);

  inc_counter(&lsm_counter);
  bpfaudit_submit_event(&rec, sizeof(rec));
}

/* ── Path B: kprobe — independent cross-validation ─────────────────────── */

/*
 * Attaches to the kernel's bpf_prog_load() function via kprobe
 * so we record minimal context. Sufficient for counting/cross-validation.
 */
SEC("kprobe/bpf_prog_load")
int BPF_KPROBE(audit_kprobe_prog_load) {
  struct audit_record rec = {};

  fill_process_ctx(&rec);

  rec.event_type = AUDIT_EVENT_LOAD;
  rec.source = AUDIT_SOURCE_KPROBE;
  /* prog_type/prog_id not available at kprobe entry left zero */

  inc_counter(&kprobe_counter);
  bpfaudit_submit_event(&rec, sizeof(rec));

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
