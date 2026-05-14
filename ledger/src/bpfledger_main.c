// SPDX-License-Identifier: GPL-2.0
/*
 * bpfledger.c — Native LKM append-only eBPF lifecycle ledger
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "bpfledger.h"
#include "bpfaudit_heartbeat.h"
#include "bpfledger_ring.h"
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


/* --------------------------- Init Flags ----------------------------------*/
/*
 * bpfledger_cleanup() checks these to know what needs to be torn down,
 * used by both the error path in init and by __exit.
 */
#define FLAG_RING                BIT(0)
#define FLAG_HEARTBEAT           BIT(1)
#define FLAG_CHRDEV              BIT(2)
#define FLAG_CDEV                BIT(3)
#define FLAG_CLASS               BIT(4)
#define FLAG_DEVICE              BIT(5)
#define FLAG_PROBE_NEW_FD        BIT(6)
#define FLAG_PROBE_LINK_SETTLE   BIT(7)
#define FLAG_PROBE_LINK_FREE     BIT(8)
#define FLAG_PROBE_REG           BIT(9)
#define FLAG_PROBE_UNREG         BIT(10)
#define FLAG_PROBE_PERF_DETACH   BIT(11)
#define FLAG_PROBE_PERF_SET      BIT(12)
#define FLAG_PROBE_CBPF_CREATE   BIT(13)
#define FLAG_PROBE_CBPF_DESTROY  BIT(14)
#define FLAG_PROBE_CGROUP_ATTACH BIT(15)
#define FLAG_PROBE_CGROUP_DETACH BIT(16)
#define FLAG_PROBE_PIN           BIT(17)
#define FLAG_PROBE_RELEASE       BIT(18)
#define FLAG_PROBE_PUT_DEFERRED  BIT(19)

static unsigned long init_flags;


/* --------------------------- Global Variables ----------------------------*/
static struct device *bpfaudit_dev;
static struct bpf_ring_ctx hb_ctx = {
    .hb_slot      = &hb_slot,
    .hb_avail     = &hb_avail,
    .ring_wq      = &ring_wq,
    .flush_partial = flush_partial_batch,
};
/* ----------------------------- Helpers -----------------------------------*/
/**
* fill_process_ctx - populate process and namespace identity fields in an audit record.
* Captures pid, tgid, uid, gid, pid namespace inode, and cgroup id from current.
* Called by emit_prog_event() for every lifecycle event.
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


/**
 * fp_cgroup_bpf_attach - capture cgroup BPF program attachment
 * Hooks __cgroup_bpf_attach(), the legacy BPF_PROG_ATTACH path for cgroup types.
 */
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


/**
 * fp_cgroup_bpf_detach - capture cgroup BPF program detachment
 * Hooks __cgroup_bpf_detach(), the legacy BPF_PROG_DETACH path for cgroup types.
 */
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


// after:
/* bpf_prog_release runs before deferred work, still in the real process context.
 * Captures the closing process identity before bpf_prog_put_deferred() runs
 * in a kworker where the original caller is no longer available. */
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
    .kp.symbol_name = "sk_attach_filter", 
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
    .symbol_name = "sk_filter_release_rcu", 
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
retry: 
    /* Priority 1: heartbeat — always urgent */
    if (atomic_read(&hb_avail)) {
        smp_rmb();
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
            READ_ONCE(anchor_head) != READ_ONCE(anchor_tail));
    if (ret)
        return ret;

    goto retry; 
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

static void bpfledger_cleanup(void)
{
    dev_t dev = MKDEV(g_major, 0);

    if (init_flags & FLAG_PROBE_PUT_DEFERRED)
        unregister_fprobe(&fps_bpf_prog_put_deferred);
    if (init_flags & FLAG_PROBE_RELEASE)
        unregister_fprobe(&fps_bpf_prog_release);
    if (init_flags & FLAG_PROBE_PIN)
        unregister_fprobe(&fps_bpf_obj_pin_user);
    if (init_flags & FLAG_PROBE_CGROUP_DETACH)
        unregister_fprobe(&fps_cgroup_bpf_detach);
    if (init_flags & FLAG_PROBE_CGROUP_ATTACH)
        unregister_fprobe(&fps_cgroup_bpf_attach);
    if (init_flags & FLAG_PROBE_CBPF_DESTROY)
        unregister_kprobe(&kp_cbpf_destroy);
    if (init_flags & FLAG_PROBE_CBPF_CREATE)
        unregister_kretprobe(&krp_cbpf_create);
    if (init_flags & FLAG_PROBE_PERF_SET)
        unregister_fprobe(&fps_perf_event_set);
    if (init_flags & FLAG_PROBE_PERF_DETACH)
        unregister_kprobe(&kp_perf_event_detach);
    if (init_flags & FLAG_PROBE_UNREG)
        unregister_kprobe(&kp_bpf_probe_unregister);
    if (init_flags & FLAG_PROBE_REG)
        unregister_kprobe(&kp_bpf_probe_register);
    if (init_flags & FLAG_PROBE_LINK_FREE)
        unregister_fprobe(&fps_bpf_link_free);
    if (init_flags & FLAG_PROBE_LINK_SETTLE)
        unregister_fprobe(&fps_bpf_link_settle);
    if (init_flags & FLAG_PROBE_NEW_FD)
        unregister_fprobe(&fps_bpf_prog_new_fd);

    if (init_flags & FLAG_DEVICE)
        device_destroy(&bpfledger_class, dev);
    if (init_flags & FLAG_CLASS)
        class_unregister(&bpfledger_class);
    if (init_flags & FLAG_CDEV)
        cdev_del(&g_cdev);
    if (init_flags & FLAG_CHRDEV)
        unregister_chrdev_region(dev, 1);

    if (init_flags & FLAG_HEARTBEAT)
        bpfaudit_heartbeat_exit();
    if (init_flags & FLAG_RING)
        bpfledger_ring_exit();

    init_flags = 0;
}

static int __init bpfledger_init(void)
{
    int ret;
    dev_t dev;

    if (bpfledger_ring_init()) {
        pr_err("ring buffer alloc failed\n");
        return -ENOMEM;
    }
    init_flags |= FLAG_RING;

    ret = bpfaudit_heartbeat_init(&hb_ctx);
    if (ret < 0) {
        pr_err("heartbeat init failed: %d\n", ret);
        goto fail;
    }
    init_flags |= FLAG_HEARTBEAT;

    ret = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        pr_err("alloc_chrdev_region failed: %d\n", ret);
        goto fail;
    }
    init_flags |= FLAG_CHRDEV;
    g_major = MAJOR(dev);

    cdev_init(&g_cdev, &bpfledger_fops);
    g_cdev.owner = THIS_MODULE;
    ret = cdev_add(&g_cdev, dev, 1);
    if (ret) {
        pr_err("cdev_add failed: %d\n", ret);
        goto fail;
    }
    init_flags |= FLAG_CDEV;

    ret = class_register(&bpfledger_class);
    if (ret) {
        pr_err("class_register failed: %d\n", ret);
        goto fail;
    }
    init_flags |= FLAG_CLASS;

    bpfaudit_dev = device_create(&bpfledger_class, NULL, dev, NULL, DEVICE_NAME);
    if (IS_ERR(bpfaudit_dev)) {
        ret = PTR_ERR(bpfaudit_dev);
        pr_err("device_create failed: %d\n", ret);
        goto fail;
    }
    init_flags |= FLAG_DEVICE;

    ret = register_fprobe(&fps_bpf_prog_new_fd, "bpf_prog_new_fd", NULL);
    if (ret) { pr_err("fprobe bpf_prog_new_fd failed: %d\n", ret); goto fail; }
    init_flags |= FLAG_PROBE_NEW_FD;

    ret = register_fprobe(&fps_bpf_link_settle, "bpf_link_settle", NULL);
    if (ret) { pr_err("fprobe bpf_link_settle failed: %d\n", ret); goto fail; }
    init_flags |= FLAG_PROBE_LINK_SETTLE;

    ret = register_fprobe(&fps_bpf_link_free, "bpf_link_free", NULL);
    if (ret) { pr_err("fprobe bpf_link_free failed: %d\n", ret); goto fail; }
    init_flags |= FLAG_PROBE_LINK_FREE;

    ret = register_kprobe(&kp_bpf_probe_register);
    if (ret) { pr_err("kprobe bpf_probe_register failed: %d\n", ret); goto fail; }
    init_flags |= FLAG_PROBE_REG;

    ret = register_kprobe(&kp_bpf_probe_unregister);
    if (ret) { pr_err("kprobe bpf_probe_unregister failed: %d\n", ret); goto fail; }
    init_flags |= FLAG_PROBE_UNREG;

    ret = register_kprobe(&kp_perf_event_detach);
    if (ret) { pr_err("kprobe perf_event_detach failed: %d\n", ret); goto fail; }
    init_flags |= FLAG_PROBE_PERF_DETACH;

    ret = register_fprobe(&fps_perf_event_set, "perf_event_set_bpf_prog", NULL);
    if (ret) { pr_err("fprobe perf_event_set failed: %d\n", ret); goto fail; }
    init_flags |= FLAG_PROBE_PERF_SET;

    ret = register_kretprobe(&krp_cbpf_create);
    if (ret) { pr_err("kretprobe cbpf_create failed: %d\n", ret); goto fail; }
    init_flags |= FLAG_PROBE_CBPF_CREATE;

    ret = register_kprobe(&kp_cbpf_destroy);
    if (ret) { pr_err("kprobe cbpf_destroy failed: %d\n", ret); goto fail; }
    init_flags |= FLAG_PROBE_CBPF_DESTROY;

    ret = register_fprobe(&fps_cgroup_bpf_attach, "__cgroup_bpf_attach", NULL);
    if (ret) { pr_err("fprobe cgroup_bpf_attach failed: %d\n", ret); goto fail; }
    init_flags |= FLAG_PROBE_CGROUP_ATTACH;

    ret = register_fprobe(&fps_cgroup_bpf_detach, "__cgroup_bpf_detach", NULL);
    if (ret) { pr_err("fprobe cgroup_bpf_detach failed: %d\n", ret); goto fail; }
    init_flags |= FLAG_PROBE_CGROUP_DETACH;

    ret = register_fprobe(&fps_bpf_obj_pin_user, "bpf_obj_pin_user", NULL);
    if (ret) { pr_err("fprobe bpf_obj_pin_user failed: %d\n", ret); goto fail; }
    init_flags |= FLAG_PROBE_PIN;

    ret = register_fprobe(&fps_bpf_prog_release, "bpf_prog_release", NULL);
    if (ret) { pr_err("fprobe bpf_prog_release failed: %d\n", ret); goto fail; }
    init_flags |= FLAG_PROBE_RELEASE;

    ret = register_fprobe(&fps_bpf_prog_put_deferred, "bpf_prog_put_deferred", NULL);
    if (ret) { pr_err("fprobe bpf_prog_put_deferred failed: %d\n", ret); goto fail; }
    init_flags |= FLAG_PROBE_PUT_DEFERRED;

    pr_info("loaded successfully\n");
    return 0;

fail:
    bpfledger_cleanup();
    return ret;
}

static void __exit bpfledger_exit(void)
{
    bpfledger_cleanup();
}

module_init(bpfledger_init);
module_exit(bpfledger_exit);
