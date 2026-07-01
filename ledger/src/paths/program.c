
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "attach_paths.h"
#include "bpfledger_ring.h"
#include <linux/bpf.h>
#include <linux/fprobe.h>
#include <linux/slab.h>
#include <linux/wait.h>
/**
 * once verifier finished, new id allocated
 * bpf_prog_new_fd called to create a new fd to the loaded program
 * call in kernel : /linux/kernel/bpf/syscall.c under bpf_prog_load call
 *
 * extraced info : comm, prog_id, prog_type, prog_tag and process info
 */
static int fp_bpf_prog_new_fd(struct fprobe *fp, unsigned long ip,
                              unsigned long ret_ip, struct ftrace_regs *fregs,
                              void *data) {

  struct bpf_prog *prog = (struct bpf_prog *)ftrace_regs_get_argument(fregs, 0);
  if (likely(prog && prog->aux && prog->aux->id > 0)) {
    if (is_feature_probe(prog))
      return 0;
    emit_prog_event(prog, AUDIT_EVENT_LOAD, AUDIT_SOURCE_FPROBE);
  }
  return 0;
}
static struct fprobe fps_bpf_prog_new_fd = {.entry_handler =
                                                fp_bpf_prog_new_fd};

/**
 * captures BPF object pinning to filesystem
 * Logs PIN event before kernel
 * creates persistent reference in /sys/fs/bpf/
 */
static int fp_bpf_obj_pin_user(struct fprobe *fp, unsigned long ip,
                               unsigned long ret_ip, struct ftrace_regs *fregs,
                               void *data) {
  char __user *pathname;
  struct audit_record rec;
  struct bpf_prog *prog;
  struct file *f;
  u32 ufd;
  long ret;

  memset(&rec, 0, sizeof(rec));
  get_task_comm(rec.u.ev.comm, current);
  fill_process_ctx(&rec);
  rec.event_type = AUDIT_EVENT_PIN;
  rec.source = AUDIT_SOURCE_FPROBE;

  ufd = (u32)ftrace_regs_get_argument(fregs, 0);

  f = fget(ufd);
  if (f) {
    prog = (struct bpf_prog *)f->private_data;
    if (prog) {
      rec.u.ev.prog_id = prog->aux->id;
      rec.u.ev.prog_type = prog->type;
      memcpy(rec.u.ev.prog_tag, prog->tag, AUDIT_PROG_TAG_SIZE);
    }
    fput(f);
  }

  pathname = (char __user *)ftrace_regs_get_argument(fregs, 2);
  ret = strncpy_from_user(rec.u.ev.path, pathname, sizeof(rec.u.ev.path) - 1);
  if (unlikely(ret < 0))
    rec.u.ev.path[0] = '\0';

  native_submit_event(&rec);
  pr_debug("event: prog_id=%u type=%u event=%u source=%u pid=%u path=%s\n",
           rec.u.ev.prog_id, rec.u.ev.prog_type, rec.event_type, rec.source,
           current->pid, rec.u.ev.path);
  return 0;
}
static struct fprobe fps_bpf_obj_pin_user = {.entry_handler =
                                                 fp_bpf_obj_pin_user};

/* bpf_prog_release runs before deferred work, still in the real process
 * context. Captures the closing process identity before bpf_prog_put_deferred()
 * runs in a kworker where the original caller is no longer available. */
static int fp_bpf_prog_release(struct fprobe *fp, unsigned long ip,
                               unsigned long ret_ip, struct ftrace_regs *fregs,
                               void *data) {

  struct file *filp = (struct file *)ftrace_regs_get_argument(fregs, 1);
  if (unlikely(!filp || !filp->private_data))
    return 0;

  struct bpf_prog *prog = (struct bpf_prog *)filp->private_data;
  if (unlikely(!prog || !prog->aux || !prog->aux->id))
    return 0;

  if (is_feature_probe(prog))
    return 0;
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
                                    unsigned long ret_ip,
                                    struct ftrace_regs *fregs, void *data) {

  struct work_struct *work =
      (struct work_struct *)ftrace_regs_get_argument(fregs, 0);
  struct bpf_prog_aux *aux = container_of(work, struct bpf_prog_aux, work);
  struct bpf_prog *prog = aux->prog;

  if (unlikely(!prog || !aux->id))
    return 0; /* not yet zeroed... zeroed in bpf_prog_free_id */

  if (is_feature_probe(prog))
    return 0;
  emit_prog_event(prog, AUDIT_EVENT_FREE, AUDIT_SOURCE_FPROBE);
  return 0;
}

static struct fprobe fps_bpf_prog_put_deferred = {.entry_handler =
                                                      fp_bpf_prog_put_deferred};

//============================================================================
static int registered;

int prog__init(void) {
  int ret;

  ret = register_fprobe(&fps_bpf_prog_new_fd, "bpf_prog_new_fd", NULL);
  if (ret)
    goto fail;
  registered++;

  ret = register_fprobe(&fps_bpf_obj_pin_user, "bpf_obj_pin_user", NULL);
  if (ret)
    goto fail;
  registered++;

  ret = register_fprobe(&fps_bpf_prog_release, "bpf_prog_release", NULL);
  if (ret)
    goto fail;
  registered++;

  ret = register_fprobe(&fps_bpf_prog_put_deferred, "bpf_prog_put_deferred",
                        NULL);
  if (ret)
    goto fail;
  registered++;

  return 0;

fail:
  prog__exit();
  return ret;
}

void prog__exit(void) {
  switch (registered) {
  case 4:
    unregister_fprobe(&fps_bpf_prog_put_deferred);
    fallthrough;
  case 3:
    unregister_fprobe(&fps_bpf_prog_release);
    fallthrough;
  case 2:
    unregister_fprobe(&fps_bpf_obj_pin_user);
    fallthrough;
  case 1:
    unregister_fprobe(&fps_bpf_prog_new_fd);
    fallthrough;
  default:
    break;
  }

  registered = 0;
}