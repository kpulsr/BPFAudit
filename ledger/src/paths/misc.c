#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "bpfledger.h"
#include "bpfledger_ring.h"
#include <linux/bpf.h>
#include <linux/fprobe.h>
#include <linux/kprobes.h>
#include <linux/perf_event.h>
#include <linux/slab.h>
#include <linux/wait.h>

/**
 * fp_perf_event_detach_bpf_prog, Capture DETACH for perf events
 *
 * Covers both legacy perf attach (PERF_EVENT_IOC_SET_BPF ioctl,
 * no bpf_link) and modern perf attach (BPF_LINK_TYPE_PERF_EVENT,
 * via bpf_perf_link_release -> perf_event_free_bpf_prog)
 */
static int kp_perf_event_detach_handler(struct kprobe *p,
                                        struct pt_regs *regs) {
  struct perf_event *event =
      (struct perf_event *)regs_get_kernel_argument(regs, 0);
  if (unlikely(!event || !event->prog || !event->prog->aux))
    return 0;
  emit_prog_event(event->prog, AUDIT_EVENT_DETACH, AUDIT_SOURCE_KPROBE);
  return 0;
}

static struct kprobe kp_perf_event_detach = {
    .symbol_name = "perf_event_detach_bpf_prog",
    .pre_handler = kp_perf_event_detach_handler,
};


