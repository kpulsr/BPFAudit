#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "attach_paths.h"
#include "bpfledger_ring.h"
#include <linux/bpf.h>
#include <linux/fprobe.h>
#include <linux/slab.h>
#include <linux/wait.h>

/**
 * fp_bpf_link_settle - capture BPF program attachment via modern link API
 * Hooks bpf_link_settle(), the final commit of bpf_link_create()
 * Fires only after successful attach, if attach fails, cleanup runs instead
 * Extracts prog metadata from primer->link->prog and emits AUDIT_EVENT_ATTACH.
 */
static int fp_bpf_link_settle(struct fprobe *fp, unsigned long ip,
                              unsigned long ret_ip, struct ftrace_regs *fregs,
                              void *data) {

  struct bpf_link_primer *primer =
      (struct bpf_link_primer *)ftrace_regs_get_argument(fregs, 0);

  if (unlikely(!primer))
    return 0;

  struct bpf_prog *prog;
  if (unlikely(!primer->link || !primer->link->prog ||
               !primer->link->prog->aux))
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
                            unsigned long ret_ip, struct ftrace_regs *fregs,
                            void *data) {
  struct bpf_link *link = (struct bpf_link *)ftrace_regs_get_argument(fregs, 0);

  if (likely(link && link->prog && link->prog->aux)) {
    if (link->type == BPF_LINK_TYPE_PERF_EVENT)
      return 0;
    if (link->type == BPF_LINK_TYPE_RAW_TRACEPOINT)
      return 0;
    emit_prog_event(link->prog, AUDIT_EVENT_DETACH, AUDIT_SOURCE_FPROBE);
  }
  return 0;
}

static struct fprobe fps_bpf_link_free = {.entry_handler = fp_bpf_link_free};

//============================================================================

static int registered;

int link_init(void) {
  int ret;

  ret = register_fprobe(&fps_bpf_link_settle, "bpf_link_settle", NULL);
  if (ret)
    goto fail;
  registered++;

  ret = register_fprobe(&fps_bpf_link_free, "bpf_link_free", NULL);
  if (ret)
    goto fail;
  registered++;

  return 0;

fail:
  link_exit();
  return ret;
}

void link_exit(void) {
  switch (registered) {
  case 2:
    unregister_fprobe(&fps_bpf_link_free);
    fallthrough;
  case 1:
    unregister_fprobe(&fps_bpf_link_settle);
    fallthrough;
  default:
    break;
  }

  registered = 0;
}