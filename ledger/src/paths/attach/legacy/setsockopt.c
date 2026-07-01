#include "attach_paths.h"
#include "bpfledger_ring.h"
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/kprobes.h>
#include <net/sock.h>
/*============================================================================*/
/*===============================CLASSIC BPF==================================*/

struct cbpf_load_data {
  struct sock *sk; /* save socket at entry, read filter at return */
};

static int krp_cbpf_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct cbpf_load_data *d = (struct cbpf_load_data *)ri->data;
  /* sk_attach_filter(struct sock_fprog *fprog, struct sock *sk)
   * sk is second argument */
  d->sk = (struct sock *)regs_get_kernel_argument(regs, 1);
  return 0;
}

static int krp_cbpf_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct cbpf_load_data *d = (struct cbpf_load_data *)ri->data;
  long retval = regs_return_value(regs);
  struct sk_filter *f;
  struct bpf_prog *prog;

  if (unlikely(retval != 0 || !d->sk))
    return 0;

  rcu_read_lock();
  f = rcu_dereference(d->sk->sk_filter);
  if (!f || !f->prog) {
    rcu_read_unlock();
    return 0;
  }
  prog = f->prog;
  emit_prog_event(prog, AUDIT_EVENT_LOAD, AUDIT_SOURCE_KPROBE);
  emit_prog_event(prog, AUDIT_EVENT_ATTACH, AUDIT_SOURCE_KPROBE);
  rcu_read_unlock();
  return 0;
}

static struct kretprobe krp_cbpf_create = {
    .handler = krp_cbpf_ret,
    .entry_handler = krp_cbpf_entry,
    .data_size = sizeof(struct cbpf_load_data),
    .maxactive = 32,
    .kp.symbol_name = "sk_attach_filter",
};
/*===========================================================================*/

static int kp_sk_filter_release_rcu_handler(struct kprobe *p,
                                            struct pt_regs *regs) {
  struct rcu_head *rcu = (struct rcu_head *)regs_get_kernel_argument(regs, 0);
  struct sk_filter *fp;
  struct bpf_prog *prog;

  if (!rcu)
    return 0;

  fp = container_of(rcu, struct sk_filter, rcu);
  if (unlikely(!fp || !fp->prog))
    return 0;

  prog = fp->prog;
  emit_prog_event(prog, AUDIT_EVENT_DETACH, AUDIT_SOURCE_KPROBE);
  emit_prog_event(prog, AUDIT_EVENT_FREE, AUDIT_SOURCE_KPROBE);
  return 0;
}

static struct kprobe kp_cbpf_destroy = {
    .symbol_name = "sk_filter_release_rcu",
    .pre_handler = kp_sk_filter_release_rcu_handler,
};

//==============================================================================
static int setsockopt_registered;

int setsockopt_init(void) {
  int ret;

  ret = register_kretprobe(&krp_cbpf_create);
  if (ret)
    goto fail;
  setsockopt_registered++;

  ret = register_kprobe(&kp_cbpf_destroy);
  if (ret)
    goto fail;
  setsockopt_registered++;

  return 0;

fail:
  setsockopt_exit();
  return ret;
}

void setsockopt_exit(void) {
  switch (setsockopt_registered) {
  case 2:
    unregister_kprobe(&kp_cbpf_destroy);
    fallthrough;
  case 1:
    unregister_kretprobe(&krp_cbpf_create);
    fallthrough;
  default:
    break;
  }

  setsockopt_registered = 0;
}