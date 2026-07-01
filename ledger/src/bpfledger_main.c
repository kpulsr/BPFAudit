// SPDX-License-Identifier: GPL-2.0
/*
 * bpfledger.c — Native LKM append-only eBPF lifecycle ledger
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "attach_paths.h"
#include "bpfaudit_heartbeat.h"
#include "bpfledger_ring.h"
#include <linux/cdev.h>
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Meriah Ibrahim Abderrahim");
MODULE_DESCRIPTION(
    "bpfledger: cryptographic eBPF lifecycle auditing with container context");
MODULE_VERSION("0.1.0");

/* --------------------------- Init Flags ----------------------------------*/
/*
 * bpfledger_cleanup() checks these to know what needs to be torn down,
 * used by both the error path in init and by __exit.
 */
#define FLAG_RING BIT(0)
#define FLAG_HEARTBEAT BIT(1)
#define FLAG_CHRDEV BIT(2)
#define FLAG_CDEV BIT(3)
#define FLAG_CLASS BIT(4)
#define FLAG_DEVICE BIT(5)

static unsigned long init_flags;

/* --------------------------- Global Variables ----------------------------*/
static struct device *bpfaudit_dev;
static struct bpf_ring_ctx hb_ctx = {
    .hb_slot = &hb_slot,
    .hb_avail = &hb_avail,
    .ring_wq = &ring_wq,
    .flush_partial = flush_partial_batch,
};

/* ----------------------------  Fprobe  --------------------------*/
/* BPF program lifecycle hooks... Full Chain
 * Execution order (chronological):
 * LOAD:
 *   1. bpf_prog_new_fd        — post-verifier, FD created, prog live in kernel
 *
 * ATTACH (one of, depending on path):
 *   2a. bpf_link_settle       — BPF_LINK_CREATE path
 * (fentry/fexit/LSM/XDP/TC/cgroup-link/...) 2b. perf_event_set_bpf_prog — perf
 * ioctl path (kprobe/uprobe/tracepoint via ioctl) 2c. __cgroup_bpf_attach   —
 * BPF_PROG_ATTACH legacy path (cgroup types) 2d. bpf_probe_register    —
 * BPF_RAW_TRACEPOINT_OPEN path (raw_tp programs)
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
 *   6.  bpf_prog_put_deferred — refcount zero, runs in kworker, memory about to
 * be released
 *
 * Covers: LOAD -> ATTACH -> (PIN) -> DETACH -> CLOSE -> MEMFREE
 *
 * Known limitations (future work):
 *   - BPF_PROG_ATTACH sockmap path  (sock_map_prog_update)
 *   - BPF_PROG_ATTACH flow dissector (skb_flow_dissector_bpf_prog_attach)
 *   - setsockopt SO_ATTACH_BPF      (sk_attach_bpf)
 *   - netlink TC/XDP/LWT attach     (cls_bpf_change / dev_change_xdp_fd /
 * bpf_build_state)
 */

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
  if (unlikely(!rs))
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

static ssize_t bpfledger_read(struct file *file, char __user *buf, size_t count,
                              loff_t *offset) {
  struct reader_state *rs = file->private_data;
  struct audit_record anchor;
  struct audit_record rec;
  unsigned long aflags;
  u64 head, pos_before;
  int ret;

  if (unlikely(count < sizeof(struct audit_record)))
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
   * At this point rs->pos == ring_head: all records read, safe to deliver
   * anchor */
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

  ret = wait_event_interruptible(
      ring_wq, ring_head > rs->pos || atomic_read(&hb_avail) ||
                   READ_ONCE(anchor_head) != READ_ONCE(anchor_tail));
  if (ret)
    return ret;

  goto retry;
}

static const struct file_operations bpfledger_fops = {
    .owner = THIS_MODULE,
    .open = bpfledger_open,
    .release = bpfledger_release,
    .read = bpfledger_read,
};

/* ----------------------------- init/exit -----------------------------------*/
static void bpfledger_cleanup(void) {
  dev_t dev = MKDEV(g_major, 0);

  /* Probe subsystems */
  setsockopt_exit();
  prog_attach_exit();
  link_exit();
  prog__exit();

  /* Core resources */
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

static int __init bpfledger_init(void) {
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

  ret = prog__init();
  if (ret)
    goto fail;

  ret = link_init();
  if (ret)
    goto fail;

  ret = prog_attach_init();
  if (ret)
    goto fail;

  ret = setsockopt_init();
  if (ret)
    goto fail;

  return 0;

fail:
  bpfledger_cleanup();
  return ret;
}

static void __exit bpfledger_exit(void) { bpfledger_cleanup(); }

module_init(bpfledger_init);
module_exit(bpfledger_exit);
