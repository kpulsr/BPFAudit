// SPDX-License-Identifier: GPL-2.0
/*
 * bpfledger.c — Native LKM append-only eBPF lifecycle ledger
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "bpfledger.h"
#include "bpfaudit_emit.h"
#include <linux/bpf.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fprobe.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/poll.h>
#include <linux/ptrace.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/uidgid.h>
#include <linux/wait.h>
#include <linux/cgroup.h>
#include <linux/sysfs.h>
#include <linux/perf_event.h>
#include <linux/hex.h>
#include <net/sock.h>
#include <linux/filter.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Meriah Ibrahim Abderrahim");
MODULE_DESCRIPTION("Native BPF Ledger (Cryptographic, Container-Aware)");
MODULE_VERSION("6.0-FINAL");

/* --------------------------- Ring Buffer -------------------------*/
#define RING_SIZE 65536
#define RING_MASK (RING_SIZE - 1)
#define BATCH_SIZE 16
#define ANCHOR_FIFO_SIZE 64
#define ANCHOR_FIFO_MASK (ANCHOR_FIFO_SIZE - 1)
/* --------------------------- Global Variables ----------------------------*/
static struct audit_record ring[RING_SIZE];
static u64 ring_head = 0;
static DEFINE_SPINLOCK(ring_lock);
static DECLARE_WAIT_QUEUE_HEAD(ring_wq);

static struct audit_record tpm_batch[BATCH_SIZE];
static struct audit_record flush_batch[BATCH_SIZE];
static unsigned int batch_count = 0;

static struct audit_record anchor_fifo[ANCHOR_FIFO_SIZE]; 
static unsigned anchor_head = 0;
static unsigned anchor_tail = 0;
static DEFINE_SPINLOCK(anchor_lock);

static struct audit_record hb_slot;
static atomic_t hb_avail = ATOMIC_INIT(0);

static void flush_partial_batch(void);
static struct bpf_ring_ctx hb_ctx = { &hb_slot, &hb_avail, &ring_wq, flush_partial_batch};

static struct device *bpfaudit_dev;
/* ----------------------------- Helpers -----------------------------------*/
/**
 * extract all possible data of the current process
 * responsible for LOAD, ATTACH, DETTACH and FREE / PIN
 * namespace is for containers env
 */
static void fill_process_ctx(struct audit_record *rec) {
  struct css_set *css; 

  rec->u.ev.pid = (u32)current->pid;
  rec->u.ev.tgid = (u32)current->tgid;
  rec->u.ev.uid = from_kuid(&init_user_ns, current_uid());
  rec->u.ev.gid = from_kgid(&init_user_ns, current_gid());

  if (task_active_pid_ns(current))
    rec->u.ev.pid_ns_id = task_active_pid_ns(current)->ns.inum;

  css = task_css_set(current);
  if (css && css->dfl_cgrp)
      rec->u.ev.cgroup_id = (u64)cgroup_ino(css->dfl_cgrp); 
  else
      rec->u.ev.cgroup_id = 0; 
}

/**
 * submit a full recoded event to a ringbuffer
 * fill the current hash and put the old current to be previous
 * to build a full chained sequence
 */
static void native_submit_event(struct audit_record *rec) {
  unsigned long flags;
  u64 seq;

  spin_lock_irqsave(&ring_lock, flags);
  bool do_flush = false; 	

  seq = ring_head++;
  rec->seq = seq;
  rec->timestamp_ns = ktime_get_ns();

  memcpy(&ring[seq & RING_MASK], rec, sizeof(*rec));
   
  if (rec->event_type != AUDIT_EVENT_HEARTBEAT) {
    tpm_batch[batch_count++] = *rec;
    if (batch_count == BATCH_SIZE) {
		memcpy(flush_batch, tpm_batch, sizeof(flush_batch));
	 	do_flush = true;
		batch_count = 0;
    }
  }
  spin_unlock_irqrestore(&ring_lock, flags);

  if (do_flush) {
    struct batch_crypto_record * recc = batch_hash_sign(flush_batch, BATCH_SIZE);
    if (!IS_ERR(recc)) {
        struct audit_record anchor;
        unsigned long aflags;
        u64 end_seq = flush_batch[BATCH_SIZE - 1].seq;
        memset(&anchor, 0, sizeof(anchor));
        anchor.event_type   = AUDIT_EVENT_BATCH_ANCHOR;
        anchor.timestamp_ns = ktime_get_ns();

        anchor.u.anr.end_seq = end_seq;

        memcpy(anchor.u.anr.batch_hash,      recc->hash,      32);
        memcpy(anchor.u.anr.batch_hmac, recc->signature, 32);
        kfree(recc);

        spin_lock_irqsave(&anchor_lock, aflags);
        anchor_fifo[anchor_head & ANCHOR_FIFO_MASK] = anchor;
        anchor_head++;
        spin_unlock_irqrestore(&anchor_lock, aflags);
    } else {
        pr_warn("bach_hash_store failed\n");
    }
  }
  wake_up_interruptible(&ring_wq);
  return;
}



static void flush_partial_batch(void)
{
    unsigned long flags;
    unsigned int count;
    struct audit_record *batch_copy;
    unsigned long aflags;

    spin_lock_irqsave(&ring_lock, flags);
    if (batch_count == 0) {
        spin_unlock_irqrestore(&ring_lock, flags);
        return;
    }
    count = batch_count;

    batch_copy = kmalloc(count * sizeof(struct audit_record), GFP_ATOMIC);
    if (!batch_copy) {
        spin_unlock_irqrestore(&ring_lock, flags);
        pr_warn("flush_partial: alloc failed\n");
        return;
    }

    memcpy(batch_copy, tpm_batch, count * sizeof(struct audit_record));
    batch_count = 0;
    spin_unlock_irqrestore(&ring_lock, flags);

    struct batch_crypto_record *recc = batch_hash_sign(batch_copy, count);
    u64 end_seq = batch_copy[count - 1].seq;
    kfree(batch_copy);

    if (!IS_ERR(recc)) {
        struct audit_record anchor;

        memset(&anchor, 0, sizeof(anchor));
        anchor.event_type   = AUDIT_EVENT_BATCH_ANCHOR;
        anchor.timestamp_ns = ktime_get_ns();
        anchor.u.anr.end_seq = end_seq; 
        memcpy(anchor.u.anr.batch_hash,      recc->hash,      32);
        memcpy(anchor.u.anr.batch_hmac, recc->signature, 32);
        kfree(recc);

        spin_lock_irqsave(&anchor_lock, aflags);
        anchor_fifo[anchor_head & ANCHOR_FIFO_MASK] = anchor;
        anchor_head++;
        spin_unlock_irqrestore(&anchor_lock, aflags);
        wake_up_interruptible(&ring_wq);
    } else {
        pr_warn("flush_partial: batch_hash_store failed\n");
    }
}

/**
 * is_feature_probe - Stateless detection of BPF feature probe programs
 * probes have hardcoded instruction patterns from the canonical sources:
 *   - libbpf/src/libbpf_probes.c  [prog-type, helper, map probes]
 *   - bpftool/src/feature.c       [misc: loops, ISA, limit probes]
 *
 * Returns: true if this program is a known feature probe pattern
 */
static bool is_feature_probe(struct bpf_prog *prog)
{
    struct bpf_insn *insn;


    if(!prog || !prog->aux)
        return false; 

   /* pr_info("bpfledger probe_check: id=%u type=%u len=%u map_cnt=%u\n",
            prog->aux->id, prog->type, prog->len, prog->aux->used_map_cnt); */

    /* programs using 2+ maps are real programs ! not probes based on search in 
     * libbpf 
     * bpftrace 
     * bpftool 
     * */

    if (prog->aux->used_map_cnt >= 2)
        return false;

    /* The few map-using probes (global_data, prog_bind_map, ldimm64_off)
     * are all short SOCKET_FILTER programs with exactly 1 map.
     */

    if (prog->aux->used_map_cnt == 1) {
        if (prog->type != BPF_PROG_TYPE_SOCKET_FILTER)
            return false;
        if (prog->len > 5)
            return false;
        return true;
    }

    /* 2-instruction probes: prog-type & helper
     * libbpf_probe_bpf_prog_type():  mov r0, 0; exit
     * libbpf_probe_bpf_helper():     call helper; exit
     * bpftool probe_prog_type_ifindex(): mov r0, 2; exit
     */
    if (prog->len <= 2)
        return true;

    /* libbpf probe_kern_probe_read_kernel: 6 insns, TRACEPOINT
     *   r1 = r10; r1 += -8; r2 = 8; r3 = 0; call probe_read_kernel; exit
     */

    if (prog->len == 6 && prog->type == BPF_PROG_TYPE_TRACEPOINT) {
        insn = prog->insnsi;
        if (insn[0].code == (BPF_ALU64 | BPF_MOV | BPF_X) &&
            insn[0].dst_reg == BPF_REG_1 && insn[0].src_reg == BPF_REG_10 &&
            insn[1].code == (BPF_ALU64 | BPF_ADD | BPF_K) &&
            insn[1].dst_reg == BPF_REG_1 && insn[1].imm == -8 &&
            insn[2].code == (BPF_ALU64 | BPF_MOV | BPF_K) &&
            insn[2].dst_reg == BPF_REG_2 && insn[2].imm == 8 &&
            insn[3].code == (BPF_ALU64 | BPF_MOV | BPF_K) &&
            insn[3].dst_reg == BPF_REG_3 && insn[3].imm == 0 &&
            insn[4].code == (BPF_JMP | BPF_CALL) &&
            insn[4].dst_reg == 0 && insn[4].src_reg == 0 &&
            insn[5].code == (BPF_JMP | BPF_EXIT))
            return true;
    }

    /* libbpf probe_kern_arg_ctx_tag: 4 insns, KPROBE
     *   call_rel(+1); exit; call get_func_ip; exit
     */
    if (prog->len == 4 && prog->type == BPF_PROG_TYPE_KPROBE) {
        insn = prog->insnsi;
        if (insn[0].code == (BPF_JMP | BPF_CALL) &&
            insn[0].src_reg == BPF_PSEUDO_CALL &&
            insn[1].code == (BPF_JMP | BPF_EXIT) &&
            insn[2].code == (BPF_JMP | BPF_CALL) &&
            insn[2].src_reg == 0 &&
            insn[3].code == (BPF_JMP | BPF_EXIT))
            return true;
    }

    /* libbpf probe_kern_arg_ctx_tag: 3 insns, KPROBE
     *   call_rel(+1); exit; exit
     */
    if (prog->len == 3 && prog->type == BPF_PROG_TYPE_KPROBE) {
        insn = prog->insnsi;
        if (insn[0].code == (BPF_JMP | BPF_CALL) &&
            insn[0].src_reg == BPF_PSEUDO_CALL &&
            insn[1].code == (BPF_JMP | BPF_EXIT) &&
            insn[2].code == (BPF_JMP | BPF_EXIT))
            return true;
    }

    /* 4-instruction probes: loops, ISA v2/v3
     * probe_bounded_loops():         mov r0,10; sub r0,1; jne r0,0,-2; exit
     * probe_v2_isa_extension():      mov r0,0; jlt r0,0,1; mov r0,1; exit
     * probe_v3_isa_extension():      mov r0,0; jlt32 r0,0,1; mov r0,1; exit
     */
    if (prog->len == 4 && prog->type == BPF_PROG_TYPE_SOCKET_FILTER) {
        insn = prog->insnsi;
        if (!insn)
            return false;

        if ((insn[0].code == 0xb7 && insn[0].imm == 10 &&
             insn[1].code == 0x07 && insn[1].dst_reg == 0 && insn[1].imm == 1 &&
             insn[2].code == 0x15 && insn[2].dst_reg == 0 && insn[2].off == -2 &&
             insn[3].code == 0x95) ||                                   /* loop */

            (insn[0].code == 0xb7 && insn[0].dst_reg == 0 && insn[0].imm == 0 &&
             insn[1].code == 0xa5 && insn[1].dst_reg == 0 && insn[1].off == 1 &&
             insn[2].code == 0xb7 && insn[2].dst_reg == 0 && insn[2].imm == 1 &&
             insn[3].code == 0x95) ||                                   /* v2 */

            (insn[0].code == 0xb7 && insn[0].dst_reg == 0 && insn[0].imm == 0 &&
             insn[1].code == 0xb5 && insn[1].dst_reg == 0 && insn[1].off == 1 &&
             insn[2].code == 0xb7 && insn[2].dst_reg == 0 && insn[2].imm == 1 &&
             insn[3].code == 0x95))                                     /* v3 */
            return true;
    }

    /* 5-instruction probe: ISA v4
     * probe_v4_isa_extension():      mov r0,0; jeq32 r0,1,1; ja 1; mov r0,1; exit
     */
    if (prog->len == 5 && prog->type == BPF_PROG_TYPE_SOCKET_FILTER) {
        insn = prog->insnsi;
        if (!insn)
            return false;

        if (insn[0].code == 0xb7 && insn[0].dst_reg == 0 && insn[0].imm == 0 &&
            insn[1].code == 0x35 && insn[1].dst_reg == 0 && insn[1].imm == 1 && insn[1].off == 1 &&
            insn[2].code == 0x06 && insn[2].off == 1 &&                   /* BPF_JMP32 | BPF_JA */
            insn[3].code == 0xb7 && insn[3].dst_reg == 0 && insn[3].imm == 1 &&
            insn[4].code == 0x95)
            return true;
    }

    /* bpftool large_insn_limit probe */
    if (prog->len == 4097 && prog->type == BPF_PROG_TYPE_SOCKET_FILTER)
        return true;

    if (prog->len <= 6) {
        insn = prog->insnsi;
        if (insn[prog->len - 1].code == (BPF_JMP | BPF_EXIT))
            return true;
    }

    pr_info("bpfledger probe_check: id=%u type=%u len=%u map_cnt=%u\n",
                 prog->aux->id, prog->type, prog->len, prog->aux->used_map_cnt);
    return false;
}


static void emit_prog_event(struct bpf_prog *prog, u8 event_type, u8 source)
{
  struct audit_record rec;
  memset(&rec, 0, sizeof(rec));
  get_task_comm(rec.u.ev.comm, current);
  fill_process_ctx(&rec);
  rec.event_type = event_type;
  rec.source     = source;
  rec.u.ev.prog_id    = prog->aux->id ? prog->aux->id : 0;
  rec.u.ev.prog_type  = prog->type;
  memcpy(rec.u.ev.prog_tag, prog->tag, 8);
  native_submit_event(&rec);
}


/* ----------------------------  Fprobe  --------------------------*/
/* BPF program lifecycle hooks... Full Chain
 * Execution order (chronological):
 * LOAD:
 *   1. bpf_prog_new_fd        — post-verifier, FD created, prog live in kernel
 *
 * ATTACH (one of, depending on path):
 *   2a. bpf_link_settle       — BPF_LINK_CREATE path (fentry/fexit/LSM/XDP/TC/cgroup-link/...)
 *   2b. perf_event_set_bpf_prog — perf ioctl path (kprobe/uprobe/tracepoint via ioctl)
 *   2c. __cgroup_bpf_attach   — BPF_PROG_ATTACH legacy path (cgroup types)
 *   2d. bpf_probe_register    — BPF_RAW_TRACEPOINT_OPEN path (raw_tp programs)
 *
 * PIN (optional):
 *   3.  bpf_obj_pin_user      — program pinned to /sys/fs/bpf/ for persistence
 *
 * DETACH (mirrors attach path):
 *   4a. bpf_link_free         — BPF_LINK_CREATE path (skips PERF_EVENT type)
 *   4b. perf_event_detach_bpf_prog — perf path (both ioctl and link flavor)
 *   4c. __cgroup_bpf_detach   — BPF_PROG_ATTACH legacy path
 *   4d. bpf_probe_unregister  — BPF_RAW_TRACEPOINT_OPEN path
 *
 * CLOSE:
 *   5.  bpf_prog_release      — prog FD closed, still in process context
 *
 * FREE:
 *   6.  bpf_prog_put_deferred — refcount zero, runs in kworker, memory about to be released
 *
 * Covers: LOAD -> ATTACH -> (PIN) -> DETACH -> CLOSE -> MEMFREE
 *
 * Known limitations (future work):
 *   - BPF_PROG_ATTACH sockmap path  (sock_map_prog_update)
 *   - BPF_PROG_ATTACH flow dissector (skb_flow_dissector_bpf_prog_attach)
 *   - setsockopt SO_ATTACH_BPF      (sk_attach_bpf)
 *   - netlink TC/XDP/LWT attach     (cls_bpf_change / dev_change_xdp_fd / bpf_build_state)
 */


/**
 * once verifier finished, new id allocated
 * bpf_prog_new_fd called to create a new fd to the loaded program
 * call in kernel : /linux/kernel/bpf/syscall.c under bpf_prog_load call
 *
 * extraced info : comm, prog_id, prog_type, prog_tag and process info
 */
static int fp_bpf_prog_new_fd(struct fprobe *fp, unsigned long ip, unsigned long ret_ip,
        struct ftrace_regs *fregs, void * data) {

  struct bpf_prog *prog = (struct bpf_prog *)ftrace_regs_get_argument(fregs,0);
  if (prog && prog->aux && prog->aux->id > 0) {
    if (is_feature_probe(prog)) return 0;
    emit_prog_event(prog, AUDIT_EVENT_LOAD, AUDIT_SOURCE_FPROBE);
  }
  return 0;
}
static struct fprobe fps_bpf_prog_new_fd = {.entry_handler = fp_bpf_prog_new_fd};


/**
 * fp_bpf_link_settle - capture BPF program attachment via modern link API
 * Hooks bpf_link_settle(), the final commit of bpf_link_create()
 * Fires only after successful attach, if attach fails, cleanup runs instead
 * Extracts prog metadata from primer->link->prog and emits AUDIT_EVENT_ATTACH.
 */
static int fp_bpf_link_settle(struct fprobe *fp, unsigned long ip,
    unsigned long ret_ip, struct ftrace_regs *fregs, void *data) {

  struct bpf_link_primer *primer =
        (struct bpf_link_primer *)ftrace_regs_get_argument(fregs, 0);

  if(!primer)
      return 0; 

  struct bpf_prog *prog; 
  if (!primer->link || !primer->link->prog || !primer->link->prog->aux)
     return 0; 

  prog = primer->link->prog;
  emit_prog_event(prog, AUDIT_EVENT_ATTACH, AUDIT_SOURCE_FPROBE);
  return 0;
}
static struct fprobe fps_bpf_link_settle = {
    .entry_handler = fp_bpf_link_settle,
};


/**
 * fp_bpf_link_free, Capture DETACH for non-perf link types
 * Skips BPF_LINK_TYPE_PERF_EVENT because bpf_perf_link_release()
 * internally calls perf_event_detach_bpf_prog(), which we hook
 * separately to avoid double-logging the same detach
 */
static int fp_bpf_link_free(struct fprobe *fp, unsigned long ip,
    unsigned long ret_ip, struct ftrace_regs *fregs, void *data)
{
  struct bpf_link *link = (struct bpf_link *)ftrace_regs_get_argument(fregs, 0);
 
  if (link->type == BPF_LINK_TYPE_PERF_EVENT)
    return 0;
 
  if (link && link->prog && link->prog->aux) {
    emit_prog_event(link->prog, AUDIT_EVENT_DETACH, AUDIT_SOURCE_FPROBE);
  }
  return 0;
}

static struct fprobe fps_bpf_link_free = {.entry_handler = fp_bpf_link_free};


/**
 * captures BPF program attachment to perf events
 * Prog passed as second argument (index 1)
 */
static int fp_perf_event_set_bpf(struct fprobe *fp, unsigned long ip,
    unsigned long ret_ip, struct ftrace_regs *fregs, void *data) {

  struct bpf_prog *prog = (struct bpf_prog *)ftrace_regs_get_argument(fregs, 1);
  if (prog && prog->aux && prog->aux->id > 0) {
    emit_prog_event(prog, AUDIT_EVENT_ATTACH, AUDIT_SOURCE_FPROBE);
  }
  return 0;
}
static struct fprobe fps_perf_event_set = {.entry_handler = fp_perf_event_set_bpf};


/**
 * fp_perf_event_detach_bpf_prog, Capture DETACH for perf events
 *
 * Covers both legacy perf attach (PERF_EVENT_IOC_SET_BPF ioctl,
 * no bpf_link) and modern perf attach (BPF_LINK_TYPE_PERF_EVENT,
 * via bpf_perf_link_release -> perf_event_free_bpf_prog)
 */
static int kp_perf_event_detach_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct perf_event *event = (struct perf_event *)regs_get_kernel_argument(regs, 0);
    
    if (!event || !event->prog || !event->prog->aux)
        return 0;

    struct bpf_prog *prog = event->prog;

    struct audit_record rec;
    memset(&rec, 0, sizeof(rec));
    get_task_comm(rec.u.ev.comm, current);
    fill_process_ctx(&rec);
    rec.event_type = AUDIT_EVENT_DETACH;
    rec.source = AUDIT_SOURCE_KPROBE;
    rec.u.ev.prog_id = prog->aux->id;
    rec.u.ev.prog_type = prog->type;
    memcpy(rec.u.ev.prog_tag, prog->tag, 8);
    native_submit_event(&rec);
    return 0;
}

static struct kprobe kp_perf_event_detach = {
    .symbol_name = "perf_event_detach_bpf_prog",
    .pre_handler = kp_perf_event_detach_handler,
};


/**
 * captures BPF object pinning to filesystem
 * Logs PIN event before kernel
 * creates persistent reference in /sys/fs/bpf/
 */
static int fp_bpf_obj_pin_user(struct fprobe *fp, unsigned long ip,
    unsigned long ret_ip, struct ftrace_regs *fregs, void *data) {
  char __user *pathname;
  struct audit_record rec;
  long ret;

  memset(&rec, 0, sizeof(rec));
  get_task_comm(rec.u.ev.comm, current);
  fill_process_ctx(&rec);
  rec.event_type = AUDIT_EVENT_PIN;
  rec.source = AUDIT_SOURCE_FPROBE;

  pathname = (char __user *)ftrace_regs_get_argument(fregs, 1);
  ret = strncpy_from_user(rec.u.ev.path, pathname, sizeof(rec.u.ev.path) - 1);
  if (ret < 0)
     rec.u.ev.path[0] = '\0'; 

  native_submit_event(&rec);
  return 0;
}
static struct fprobe fps_bpf_obj_pin_user = {.entry_handler = fp_bpf_obj_pin_user};


/**/
static int fp_cgroup_bpf_attach(struct fprobe *fp, unsigned long ip,
    unsigned long ret_ip, struct ftrace_regs *fregs, void *data)
{
    /* __cgroup_bpf_attach(cgrp, prog, replace_prog, link, type, flags)
     * prog is argument index 1 */
    struct bpf_prog *prog = (struct bpf_prog *)ftrace_regs_get_argument(fregs, 1);
    if (!prog || !prog->aux || !prog->aux->id) return 0;
    if (is_feature_probe(prog)) return 0;

    emit_prog_event(prog, AUDIT_EVENT_ATTACH, AUDIT_SOURCE_FPROBE);
    return 0;
}
static struct fprobe fps_cgroup_bpf_attach = {.entry_handler = fp_cgroup_bpf_attach};


/**/
static int fp_cgroup_bpf_detach(struct fprobe *fp, unsigned long ip,
    unsigned long ret_ip, struct ftrace_regs *fregs, void *data)
{
    /* __cgroup_bpf_detach(cgrp, prog, link, type)
     * prog is argument index 1 */
    struct bpf_prog *prog = (struct bpf_prog *)ftrace_regs_get_argument(fregs, 1);
    if (!prog || !prog->aux || !prog->aux->id) return 0;

    emit_prog_event(prog, AUDIT_EVENT_DETACH, AUDIT_SOURCE_FPROBE);
    return 0;
}
static struct fprobe fps_cgroup_bpf_detach = {.entry_handler = fp_cgroup_bpf_detach};


/**
 * kp_bpf_probe_register - capture RAW_TRACEPOINT program attach
 * Hooks bpf_probe_register(), called by bpf_raw_tracepoint_open()
 * when a BPF_RAW_TRACEPOINT_OPEN cmd activates a raw_tp program.
 */
static int kp_bpf_probe_register_handler(struct kprobe *p, struct pt_regs *regs)
{
  struct bpf_prog *prog = (struct bpf_prog *)regs_get_kernel_argument(regs, 1);
  if (!prog || !prog->aux || !prog->aux->id) return 0;
  if (is_feature_probe(prog)) return 0;
  emit_prog_event(prog, AUDIT_EVENT_ATTACH, AUDIT_SOURCE_KPROBE);
  return 0;
}
static struct kprobe kp_bpf_probe_register = {
  .symbol_name = "bpf_probe_register",
  .pre_handler = kp_bpf_probe_register_handler,
};


/**
 * kp_bpf_probe_unregister - capture RAW_TRACEPOINT program detach
 * Hooks bpf_probe_unregister(), called when the anonymous raw_tp fd
 * is closed
 */
static int kp_bpf_probe_unregister_handler(struct kprobe *p, struct pt_regs *regs)
{
  struct bpf_prog *prog = (struct bpf_prog *)regs_get_kernel_argument(regs, 1);
  if (!prog || !prog->aux || !prog->aux->id) return 0;
  emit_prog_event(prog, AUDIT_EVENT_DETACH,AUDIT_SOURCE_KPROBE);
  return 0;
}
static struct kprobe kp_bpf_probe_unregister = {
  .symbol_name = "bpf_probe_unregister",
  .pre_handler = kp_bpf_probe_unregister_handler,
};


/*
 * put_deferred runs in a kworker context so we never know who realy closed the FD 
 * this runs before deferred work, still inside the real process
 * */
static int fp_bpf_prog_release(struct fprobe *fp, unsigned long ip,
    unsigned long ret_ip, struct ftrace_regs *fregs, void *data) {

  struct file *filp = (struct file *)ftrace_regs_get_argument(fregs, 1);
  if (!filp || !filp->private_data) return 0;

  struct bpf_prog *prog = (struct bpf_prog *)filp->private_data;
  if (!prog || !prog->aux || !prog->aux->id) return 0;

  if (is_feature_probe(prog)) return 0;
  emit_prog_event(prog, AUDIT_EVENT_CLOSE, AUDIT_SOURCE_FPROBE);
  return 0;
}
static struct fprobe fps_bpf_prog_release = {
  .entry_handler = fp_bpf_prog_release,
};


/**
 * captures BPF program final destruction
 * called when reference count hits zero and deferred work runs
 * extracts prog from work_struct via container_of,
 * logs FREE before memory released.
 */
static int fp_bpf_prog_put_deferred(struct fprobe *fp, unsigned long ip,
    unsigned long ret_ip, struct ftrace_regs *fregs, void *data) {

  struct work_struct *work = 
      (struct work_struct *)ftrace_regs_get_argument(fregs, 0);
  struct bpf_prog_aux *aux = container_of(work, struct bpf_prog_aux, work);
  struct bpf_prog *prog = aux->prog;

  if (!prog || !aux->id)
    return 0; /* not yet zeroed... zeroed in bpf_prog_free_id */

  if (is_feature_probe(prog)) return 0;
  emit_prog_event(prog, AUDIT_EVENT_FREE,AUDIT_SOURCE_FPROBE);
  return 0;
}

static struct fprobe fps_bpf_prog_put_deferred = {.entry_handler = fp_bpf_prog_put_deferred};


/*============================================================================*/
/*===============================CLASSIC BPF==================================*/


struct cbpf_load_data {
    struct sock *sk;   /* save socket at entry, read filter at return */
};

static int krp_cbpf_entry(struct kretprobe_instance *ri,
                           struct pt_regs *regs)
{
    struct cbpf_load_data *d = (struct cbpf_load_data *)ri->data;
    /* sk_attach_filter(struct sock_fprog *fprog, struct sock *sk)
     * sk is second argument */
    d->sk = (struct sock *)regs_get_kernel_argument(regs, 1);
    pr_info("cbpf sk_attach_filter ENTRY sk=%px\n", d->sk);
    return 0;
}

static int krp_cbpf_ret(struct kretprobe_instance *ri,
                         struct pt_regs *regs)
{
    struct cbpf_load_data *d = (struct cbpf_load_data *)ri->data;
    long retval = regs_return_value(regs);
    struct sk_filter *f;
    struct bpf_prog *prog;

    pr_info("cbpf sk_attach_filter RET retval=%ld sk=%px\n", retval, d->sk);

    if (retval != 0 || !d->sk)
        return 0;

    rcu_read_lock();
    f = rcu_dereference(d->sk->sk_filter);
    if (!f || !f->prog) {
        rcu_read_unlock();
        return 0;
    }
    prog = f->prog;
    pr_info("cbpf LOAD+ATTACH: prog=%px type=%u\n", prog, prog->type);
    emit_prog_event(prog, AUDIT_EVENT_LOAD, AUDIT_SOURCE_KPROBE);
    emit_prog_event(prog, AUDIT_EVENT_ATTACH, AUDIT_SOURCE_KPROBE);
    rcu_read_unlock();
    return 0;
}

static struct kretprobe krp_cbpf_create = {
    .handler       = krp_cbpf_ret,
    .entry_handler = krp_cbpf_entry,
    .data_size     = sizeof(struct cbpf_load_data),
    .maxactive     = 32,
    .kp.symbol_name = "sk_attach_filter",  /* ← direct SO_ATTACH_FILTER path */
};
/*===========================================================================*/

static int kp_sk_filter_release_rcu_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct rcu_head *rcu = (struct rcu_head *)regs_get_kernel_argument(regs, 0);
    struct sk_filter *fp;
    struct bpf_prog *prog;

    if (!rcu) return 0;

    fp = container_of(rcu, struct sk_filter, rcu);
    if (!fp || !fp->prog) return 0;

    prog = fp->prog;
    pr_info("cbpf FREE via release_rcu: prog=%px type=%u\n", prog, prog->type);
    emit_prog_event(prog, AUDIT_EVENT_DETACH,AUDIT_SOURCE_KPROBE);
    emit_prog_event(prog, AUDIT_EVENT_FREE, AUDIT_SOURCE_KPROBE);
    return 0;
}

static struct kprobe kp_cbpf_destroy = {
    .symbol_name = "sk_filter_release_rcu",  // ← was sk_detach_filter
    .pre_handler = kp_sk_filter_release_rcu_handler,
};

/* ------------------------- Character Device -------------------------------*/

#define DEVICE_NAME "bpfaudit"
#define CLASS_NAME "bpfaudit"

static int g_major;
static struct cdev g_cdev;
struct reader_state {
  u64 pos;
};

static struct class bpfledger_class = {
    .name = CLASS_NAME,
};

static int bpfledger_open(struct inode *inode, struct file *file) {
  struct reader_state *rs = kzalloc(sizeof(*rs), GFP_KERNEL);
  if (!rs)
    return -ENOMEM;
  spin_lock_irq(&ring_lock);
  rs->pos = ring_head > RING_SIZE ? ring_head - RING_SIZE : 0;
  spin_unlock_irq(&ring_lock);
  file->private_data = rs;
  return 0;
}

static int bpfledger_release(struct inode *inode, struct file *file) {
  kfree(file->private_data);
  return 0;
}

static ssize_t bpfledger_read(struct file *file, char __user *buf,
                               size_t count, loff_t *offset)
{
    struct reader_state *rs = file->private_data;
    struct audit_record anchor;
    struct audit_record rec;
    unsigned long aflags;
    u64 head, pos_before;
    int ret;

    if (count < sizeof(struct audit_record))
        return -EINVAL;

    /* Priority 1: heartbeat — always urgent */
    if (atomic_read(&hb_avail)) {
        if (copy_to_user(buf, &hb_slot, sizeof(hb_slot)))
            return -EFAULT;
        atomic_set(&hb_avail, 0);
        return sizeof(hb_slot);
    }

    /* Priority 2: ring records — drain ring BEFORE delivering anchor
     * This guarantees all batch records reach daemon before anchor fires */
    spin_lock_irq(&ring_lock);
    head = ring_head;
    spin_unlock_irq(&ring_lock);

    if (rs->pos < head) {
        spin_lock_irq(&ring_lock);
        if (ring_head - rs->pos > RING_SIZE)
            rs->pos = ring_head - RING_SIZE;
        pos_before = rs->pos;
        memcpy(&rec, &ring[pos_before & RING_MASK], sizeof(rec));
        if (ring_head - pos_before > RING_SIZE) {
            spin_unlock_irq(&ring_lock);
            return -EOVERFLOW;
        }
        spin_unlock_irq(&ring_lock);
        if (copy_to_user(buf, &rec, sizeof(rec)))
            return -EFAULT;
        rs->pos++;
        return sizeof(rec);
    }

    /* Priority 3: anchor — only when ring is fully drained
     * At this point rs->pos == ring_head: all records read, safe to deliver anchor */
    spin_lock_irqsave(&anchor_lock, aflags);
    if (anchor_head != anchor_tail) {
        anchor = anchor_fifo[anchor_tail & ANCHOR_FIFO_MASK];
        anchor_tail++;
        spin_unlock_irqrestore(&anchor_lock, aflags);
        if (copy_to_user(buf, &anchor, sizeof(anchor)))
            return -EFAULT;
        return sizeof(anchor);
    }
    spin_unlock_irqrestore(&anchor_lock, aflags);

    /* Nothing available — sleep */
    if (file->f_flags & O_NONBLOCK)
        return -EAGAIN;

    ret = wait_event_interruptible(ring_wq,
            ring_head > rs->pos ||
            atomic_read(&hb_avail) ||
            anchor_head != anchor_tail);
    if (ret)
        return ret;

    /* Recurse via re-entry — re-evaluate priorities from top */
    return bpfledger_read(file, buf, count, offset);
}

static __poll_t bpfledger_poll(struct file *file, poll_table *wait) {
  struct reader_state *rs = file->private_data;
  poll_wait(file, &ring_wq, wait);


 if (atomic_read(&hb_avail))
     return EPOLLIN | EPOLLRDNORM;


  spin_lock_irq(&ring_lock);
  if (rs->pos < ring_head) {
    spin_unlock_irq(&ring_lock);
    return EPOLLIN | EPOLLRDNORM;
  }
  spin_unlock_irq(&ring_lock);
  return 0;
}

static const struct file_operations bpfledger_fops = {
    .owner = THIS_MODULE,
    .open = bpfledger_open,
    .release = bpfledger_release,
    .read = bpfledger_read,
    .poll = bpfledger_poll,
};

/* ----------------------------- init/exit -----------------------------------*/

static int __init bpfledger_init(void) {
  int ret;
  dev_t dev;

  ret = bpfaudit_heartbeat_init(&hb_ctx);
  if (ret < 0)
    return ret;

  ret = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
  if (ret < 0)
    goto err_heartbeat;

  g_major = MAJOR(dev);

  /* cdev */
  cdev_init(&g_cdev, &bpfledger_fops);
  g_cdev.owner = THIS_MODULE;
  if ((ret = cdev_add(&g_cdev, dev, 1)))
    goto err_cdev;

  /* Class registration*/
  if ((ret = class_register(&bpfledger_class)))
    goto err_class;

  bpfaudit_dev  = device_create(&bpfledger_class, NULL, dev, NULL, DEVICE_NAME);
  if (IS_ERR(bpfaudit_dev)) {
    ret = -ENOMEM;
    goto err_device;
  }

  //register_kprobe(&kp_bpf_check);
  register_fprobe(&fps_bpf_prog_new_fd,"bpf_prog_new_fd",NULL);
  register_fprobe(&fps_bpf_link_settle,"bpf_link_settle", NULL);
  register_fprobe(&fps_bpf_link_free,"bpf_link_free", NULL);
  register_kprobe(&kp_bpf_probe_register);
  register_kprobe(&kp_bpf_probe_unregister);
  ret = register_kprobe(&kp_perf_event_detach);
  if (ret) {
    pr_err("bpfledger: perf_event_detach_bpf_prog fprobe failed: %d\n", ret);
    goto err_fprobes;
  } 
  ret = register_fprobe(&fps_perf_event_set,"perf_event_set_bpf_prog", NULL);
  if (ret) {
    pr_err("bpfledger: perf_event_set_bpf_prog fprobe failed: %d\n", ret);
    goto err_fprobes;
  }
  ret = register_kretprobe(&krp_cbpf_create);
  if (ret)
    pr_err("bpfledger: bpf_prog_create_from_user kretprobe failed: %d\n", ret);

  ret = register_kprobe(&kp_cbpf_destroy);
  if (ret)
    pr_err("bpfledger: bpf_prog_destroy kprobe failed: %d\n", ret);
  register_fprobe(&fps_cgroup_bpf_attach, "__cgroup_bpf_attach", NULL);
  register_fprobe(&fps_cgroup_bpf_detach, "__cgroup_bpf_detach", NULL);
  register_fprobe(&fps_bpf_obj_pin_user,"bpf_obj_pin_user", NULL);
  register_fprobe(&fps_bpf_prog_release, "bpf_prog_release", NULL);
  register_fprobe(&fps_bpf_prog_put_deferred, "bpf_prog_put_deferred",NULL);

  return 0;

err_fprobes:
    unregister_fprobe(&fps_bpf_link_free);
    unregister_fprobe(&fps_bpf_link_settle);
    unregister_fprobe(&fps_bpf_prog_new_fd);
err_device:
  class_unregister(&bpfledger_class);
err_class:
  cdev_del(&g_cdev);
err_cdev:
  unregister_chrdev_region(dev, 1);
  bpfaudit_heartbeat_exit();    
  return ret;
err_heartbeat:
  bpfaudit_heartbeat_exit();
  return ret;
}

static void __exit bpfledger_exit(void) {
  dev_t dev = MKDEV(g_major, 0);
 
  bpfaudit_heartbeat_exit();
  unregister_fprobe(&fps_bpf_prog_put_deferred);
  unregister_fprobe(&fps_bpf_prog_release); 
  unregister_fprobe(&fps_bpf_obj_pin_user);
  unregister_fprobe(&fps_cgroup_bpf_attach);
  unregister_fprobe(&fps_cgroup_bpf_detach);
  unregister_kretprobe(&krp_cbpf_create);
  unregister_kprobe(&kp_cbpf_destroy);
  unregister_fprobe(&fps_perf_event_set);
  unregister_kprobe(&kp_perf_event_detach);
  unregister_kprobe(&kp_bpf_probe_register); 
  unregister_kprobe(&kp_bpf_probe_unregister);
  unregister_fprobe(&fps_bpf_link_free);
  unregister_fprobe(&fps_bpf_link_settle);
  unregister_fprobe(&fps_bpf_prog_new_fd);
  //unregister_kprobe(&kp_bpf_check);

  device_destroy(&bpfledger_class, dev);
  class_unregister(&bpfledger_class);
  cdev_del(&g_cdev);
  unregister_chrdev_region(dev, 1);
}
module_init(bpfledger_init);
module_exit(bpfledger_exit);
