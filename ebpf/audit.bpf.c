// SPDX-License-Identifier: GPL-2.0
/*
 * BPFAudit — BPF-side hooks
 *
 * Single path calling bpfaudit_submit_event() kfunc
 * which lives in bpfledger.ko:
 *
 *   LSM hook  lsm/bpf_prog    — synchronous, gets full prog info
 *   LSM hook  lsm/bpf_prog_free - synchronous, gets full prog info 
 *   LSM hook  lsm/bpf     check program PIN, ATTACH, DETTACH, UNPIN 
 *
 * The kfunc call is the ONLY write path into the kernel-side ring buffer
 * Userspace cannot write to /dev/bpfledger at all
 */

#include "vmlinux.h"
#include "bpfledger.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* ── kfunc declaration ─────────────────────────────────────────────────── */

/*
 * kfunc exported by bpfledger.ko
 */

extern void bpfaudit_submit_event(struct audit_record *rec,
                                  __u32 rec__sz, struct bpf_prog *prog) __ksym;

extern void bpfaudit_submit_event_noprog(struct audit_record *rec,
                                          __u32 rec__sz) __ksym;

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

/* ── LSM bpf_prog hook ──────────────────────────────────────────────────── */

/*
 * Fires synchronously when any BPF program passes the verifier and is about
 * to be loaded
 * Returns 0... currently only audit no enforcement
 */
SEC("lsm/bpf_prog")
int BPF_PROG(audit_lsm_prog, struct bpf_prog *prog) {

  /* skip kernel threads — they have no mm */
  if (bpf_get_current_task_btf()->mm == NULL)
      return 0;


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

  //inc_counter(&lsm_counter);
  bpfaudit_submit_event(&rec, sizeof(rec),prog);

  return 0; /* audit only */
}



/* ── LSM bpf hook ──────────────────────────────────────────────────── */
/*
 * Fires synchronously on every bpf() syscall command.
 * Filters PIN, GET, LINK_CREATE, LINK_DETACH only.
 * Audit only — no enforcement.
 */
SEC("lsm/bpf")
int BPF_PROG(audit_lsm_bpf, int cmd, union bpf_attr *attr, unsigned int size, bool kernel)
{
    if (kernel) 
        return 0;

    struct audit_record rec = {};

    switch (cmd) {
    case BPF_OBJ_PIN:
        rec.event_type = AUDIT_EVENT_PIN;
        break;
    case BPF_OBJ_GET:
        rec.event_type = AUDIT_EVENT_GET;
        break;
    case BPF_LINK_CREATE:
        rec.event_type = AUDIT_EVENT_ATTACH;
        break;
    case BPF_LINK_DETACH:
        rec.event_type = AUDIT_EVENT_DETACH;
        break;
    default:
        return 0;   /* ignore everything else */
    }

    fill_process_ctx(&rec);
    rec.source = AUDIT_SOURCE_LSM_BPF;

    /* capture path for PIN/GET, prog_fd for ATTACH/DETACH */
    if (attr) {
        if (cmd == BPF_OBJ_PIN || cmd == BPF_OBJ_GET)
            bpf_probe_read_user_str(rec.extra.path, sizeof(rec.extra.path),
                        (void *)(unsigned long)attr->pathname);
        else
            rec.extra.prog_fd = (__u32)BPF_CORE_READ(attr, link_create.prog_fd);
    }

    bpfaudit_submit_event_noprog(&rec, sizeof(rec));
    return 0;
}



/* ── LSM bpf_prog_free hook ──────────────────────────────────────────────────── */
/* Fires synchronously before a BPF program is freed/unloaded*/
SEC("lsm/bpf_prog_free")
void BPF_PROG(audit_lsm_prog_free, struct bpf_prog *prog)
{
    /* skip kernel threads — they have no mm */
    if (bpf_get_current_task_btf()->mm == NULL)
        return;

    struct audit_record rec = {};

    fill_process_ctx(&rec);

    rec.event_type = AUDIT_EVENT_FREE;
    rec.source     = AUDIT_SOURCE_LSM_FREE;

    bpfaudit_submit_event_noprog(&rec, sizeof(rec));
}

char LICENSE[] SEC("license") = "GPL";
