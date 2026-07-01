
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "attach_paths.h"
#include "bpfledger_ring.h"
#include <linux/bpf.h>
#include <linux/fprobe.h>
#include <linux/slab.h>
#include <linux/wait.h>
/**
 * fp_cgroup_bpf_attach - capture cgroup BPF program attachment
 * Hooks __cgroup_bpf_attach(), the legacy BPF_PROG_ATTACH path for cgroup
 * types.
 */
static int fp_cgroup_bpf_attach(struct fprobe *fp, unsigned long ip,
                                unsigned long ret_ip, struct ftrace_regs *fregs,
                                void *data) {
  /* __cgroup_bpf_attach(cgrp, prog, replace_prog, link, type, flags)
   * prog is argument index 1 */
  struct bpf_prog *prog = (struct bpf_prog *)ftrace_regs_get_argument(fregs, 1);
  if (unlikely(!prog || !prog->aux || !prog->aux->id))
    return 0;
  if (is_feature_probe(prog))
    return 0;

  emit_prog_event(prog, AUDIT_EVENT_ATTACH, AUDIT_SOURCE_FPROBE);
  return 0;
}
static struct fprobe fps_cgroup_bpf_attach = {.entry_handler =
                                                  fp_cgroup_bpf_attach};

/**
 * fp_cgroup_bpf_detach - capture cgroup BPF program detachment
 * Hooks __cgroup_bpf_detach(), the legacy BPF_PROG_DETACH path for cgroup
 * types.
 */
static int fp_cgroup_bpf_detach(struct fprobe *fp, unsigned long ip,
                                unsigned long ret_ip, struct ftrace_regs *fregs,
                                void *data) {
  /* __cgroup_bpf_detach(cgrp, prog, link, type)
   * prog is argument index 1 */
  struct bpf_prog *prog = (struct bpf_prog *)ftrace_regs_get_argument(fregs, 1);
  if (unlikely(!prog || !prog->aux || !prog->aux->id))
    return 0;

  emit_prog_event(prog, AUDIT_EVENT_DETACH, AUDIT_SOURCE_FPROBE);
  return 0;
}
static struct fprobe fps_cgroup_bpf_detach = {.entry_handler =
                                                  fp_cgroup_bpf_detach};

//=================================================================================

static int cgroup_registered;

int prog_attach_init(void) {
  int ret;

  ret = register_fprobe(&fps_cgroup_bpf_attach, "__cgroup_bpf_attach", NULL);
  if (ret)
    goto fail;
  cgroup_registered++;

  ret = register_fprobe(&fps_cgroup_bpf_detach, "__cgroup_bpf_detach", NULL);
  if (ret)
    goto fail;
  cgroup_registered++;

  return 0;

fail:
  prog_attach_exit();
  return ret;
}

void prog_attach_exit(void) {
  switch (cgroup_registered) {
  case 2:
    unregister_fprobe(&fps_cgroup_bpf_detach);
    fallthrough;
  case 1:
    unregister_fprobe(&fps_cgroup_bpf_attach);
    fallthrough;
  default:
    break;
  }

  cgroup_registered = 0;
}