// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/ktime.h>
#include <linux/poll.h>
#include <linux/siphash.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <crypto/blake2b.h>

#include "bpfledger.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Meriah Ibrahim Abderrahim");
MODULE_DESCRIPTION("Append-only eBPF lifecycle ledger with ring buffer");
MODULE_VERSION("1.0");

/* ───────────────────────────── Ring buffer ──────────────────────────────── */

#define RING_SIZE 4096 /* must be power of 2 */
#define RING_MASK (RING_SIZE - 1)

static struct audit_record ring[RING_SIZE];
static u64 ring_head; /* next write slot, ever-increasing */
static DEFINE_SPINLOCK(ring_lock);
static DECLARE_WAIT_QUEUE_HEAD(ring_wq);

static u64 g_prev_hash;             /* protected by ring_lock */
static siphash_key_t g_siphash_key; /* hashing key */

/* ───────────────────────────── SipHashing & hash * ──────────────────────────────── */

static void chain_hash(struct audit_record *rec) {

  struct {
    u64 prev;
    u64 seq;
    u64 ts;
    u32 pid;
    u8 tag[AUDIT_PROG_TAG_SIZE];
  } input;
  u64 h;

  rec->prev_hash = g_prev_hash;

  input.prev = g_prev_hash;
  input.seq = rec->seq;
  input.ts = rec->timestamp_ns;
  input.pid = rec->pid;
  memcpy(input.tag, rec->prog_tag, AUDIT_PROG_TAG_SIZE);

  h = siphash(&input, sizeof(input), &g_siphash_key);

  rec->curr_hash = h;
  g_prev_hash = h;
}

static void prog_hash(struct audit_record *ar, struct bpf_prog *prog)
{
    size_t size;

    if (!prog || !prog->len)
        return;

    if (prog->len > 4096) {
        pr_warn("prog_hash: prog too large (%u insns), skipping\n", prog->len);
        return;
    }

    size = (size_t)prog->len * sizeof(struct bpf_insn);

    blake2b(NULL, 0,
            (u8 *)prog->insnsi, size,
            ar->bytecode_hash, 32);
}

/* ───────────────────────────── kfunc ────────────────────────────────────── */

__bpf_kfunc void bpfaudit_submit_event(struct audit_record *rec, __u32 rec__sz,
                                       struct bpf_prog *prog);

__bpf_kfunc void bpfaudit_submit_event_noprog(struct audit_record *rec, __u32 rec__sz); 


__bpf_kfunc void bpfaudit_submit_event(struct audit_record *rec, __u32 rec__sz,
                                       struct bpf_prog *prog) {
  struct audit_record *slot;
  unsigned long flags;
  u64 seq;

  pr_info("submit_event: rec=%p sz=%u\n", rec, rec__sz);

  if (!rec || rec__sz < sizeof(struct audit_record)) {
    pr_warn("submit_event: invalid args, dropping\n");
    return;
  }

  spin_lock_irqsave(&ring_lock, flags);

  seq = ring_head++;
  slot = &ring[seq & RING_MASK];

  memcpy(slot, rec, sizeof(*rec));
  slot->seq = seq;
  slot->timestamp_ns = ktime_get_ns();
  prog_hash(slot, prog);
  chain_hash(slot);
  spin_unlock_irqrestore(&ring_lock, flags);

  pr_info("submit_event: seq=%llu written, waking readers\n",
          (unsigned long long)seq);

  wake_up_interruptible(&ring_wq);
}

__bpf_kfunc void bpfaudit_submit_event_noprog(struct audit_record *rec, __u32 rec__sz)
{
    bpfaudit_submit_event(rec, rec__sz, NULL);
}

EXPORT_SYMBOL_GPL(bpfaudit_submit_event);
EXPORT_SYMBOL_GPL(bpfaudit_submit_event_noprog);

BTF_KFUNCS_START(bpfaudit_kfunc_ids)
BTF_ID_FLAGS(func, bpfaudit_submit_event, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpfaudit_submit_event_noprog, KF_TRUSTED_ARGS)
BTF_KFUNCS_END(bpfaudit_kfunc_ids)

static const struct btf_kfunc_id_set bpfaudit_lsm_kfunc_set = {
    .owner = THIS_MODULE,
    .set = &bpfaudit_kfunc_ids,
};

/* ───────────────────────── Char device ──────────────────────────────────── */

#define DEVICE_NAME "bpfledger"
#define CLASS_NAME "bpfledger"

static int g_major;
static struct class *g_class;
static struct cdev g_cdev;

struct reader_state {
  u64 pos; /* next seq to read */
};

static int bpfledger_open(struct inode *inode, struct file *file) {
  struct reader_state *rs;

  rs = kzalloc(sizeof(*rs), GFP_KERNEL);
  if (!rs)
    return -ENOMEM;

  spin_lock_irq(&ring_lock);
  rs->pos = ring_head > RING_SIZE ? ring_head - RING_SIZE : 0;
  spin_unlock_irq(&ring_lock);

  file->private_data = rs;
  pr_info("open: reader starting at seq=%llu\n", (unsigned long long)rs->pos);
  return 0;
}

static int bpfledger_release(struct inode *inode, struct file *file) {
  kfree(file->private_data);
  return 0;
}

static ssize_t bpfledger_read(struct file *file, char __user *buf, size_t count,
                              loff_t *offset) {
  struct reader_state *rs = file->private_data;
  struct audit_record rec;
  u64 head;
  int ret;

  if (count < sizeof(struct audit_record))
    return -EINVAL;

retry:
  spin_lock_irq(&ring_lock);
  head = ring_head;
  spin_unlock_irq(&ring_lock);

  if (rs->pos >= head) {
    if (file->f_flags & O_NONBLOCK)
      return -EAGAIN;

    pr_info("read: caught up at seq=%llu, blocking\n",
            (unsigned long long)rs->pos);

    ret = wait_event_interruptible(ring_wq, ring_head > rs->pos);
    if (ret)
      return ret;

    goto retry;
  }

  spin_lock_irq(&ring_lock);
  if (ring_head - rs->pos > RING_SIZE) {
    pr_warn("read: reader too slow, skipping to seq=%llu\n",
            (unsigned long long)(ring_head - RING_SIZE));
    rs->pos = ring_head - RING_SIZE;
  }
  memcpy(&rec, &ring[rs->pos & RING_MASK], sizeof(rec));
  spin_unlock_irq(&ring_lock);

  pr_info("read: delivering seq=%llu pid=%u\n", (unsigned long long)rec.seq,
          rec.pid);

  if (copy_to_user(buf, &rec, sizeof(rec)))
    return -EFAULT;

  rs->pos++;
  return sizeof(rec);
}

static __poll_t bpfledger_poll(struct file *file, poll_table *wait) {
  struct reader_state *rs = file->private_data;

  poll_wait(file, &ring_wq, wait);

  spin_lock_irq(&ring_lock);
  if (rs->pos < ring_head) {
    spin_unlock_irq(&ring_lock);
    return POLLIN | POLLRDNORM;
  }
  spin_unlock_irq(&ring_lock);
  return 0;
}

static long bpfledger_ioctl(struct file *file, unsigned int cmd,
                            unsigned long arg) {
  u64 count;

  switch (cmd) {
  case 0xEB00:
    spin_lock_irq(&ring_lock);
    count = ring_head;
    spin_unlock_irq(&ring_lock);
    if (put_user(count, (u64 __user *)arg))
      return -EFAULT;
    return 0;
  default:
    return -ENOTTY;
  }
}

static const struct file_operations bpfledger_fops = {
    .owner = THIS_MODULE,
    .open = bpfledger_open,
    .release = bpfledger_release,
    .read = bpfledger_read,
    .poll = bpfledger_poll,
    .unlocked_ioctl = bpfledger_ioctl,
    .llseek = noop_llseek,
};

/* ───────────────────────── Init / Exit ──────────────────────────────────── */

static int init_chardev(void) {
  dev_t dev;
  int ret;
  struct device *dev_ret;

  ret = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
  if (ret < 0)
    return ret;
  g_major = MAJOR(dev);

  cdev_init(&g_cdev, &bpfledger_fops);
  g_cdev.owner = THIS_MODULE;

  ret = cdev_add(&g_cdev, dev, 1);
  if (ret)
    goto err_cdev;

  g_class = class_create(CLASS_NAME);
  if (IS_ERR(g_class)) {
    ret = PTR_ERR(g_class);
    goto err_class;
  }

  dev_ret = device_create(g_class, NULL, dev, NULL, DEVICE_NAME);
  if (IS_ERR(dev_ret)) {
    ret = PTR_ERR(dev_ret);
    goto err_device;
  }

  pr_info("char device ready: /dev/%s major=%d\n", DEVICE_NAME, g_major);
  return 0;

err_device:
  class_destroy(g_class);
err_class:
  cdev_del(&g_cdev);
err_cdev:
  unregister_chrdev_region(dev, 1);
  return ret;
}

static void cleanup_chardev(void) {
  dev_t dev = MKDEV(g_major, 0);
  device_destroy(g_class, dev);
  class_destroy(g_class);
  cdev_del(&g_cdev);
  unregister_chrdev_region(dev, 1);
}

static int __init bpfledger_init(void) {
  int ret;

  get_random_bytes(&g_siphash_key, sizeof(g_siphash_key));

  memset(ring, 0, sizeof(ring));
  ring_head = 0;
  g_prev_hash = 0;

  ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM, &bpfaudit_lsm_kfunc_set);
  if (ret) {
    pr_err("kfunc register LSM failed: %d\n", ret);
    return ret;
  }

  ret =
      register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpfaudit_lsm_kfunc_set);
  if (ret) {
    pr_err("kfunc register kprobe failed: %d\n", ret);
    return ret;
  }

  ret = init_chardev();
  if (ret) {
    pr_err("chardev init failed: %d\n", ret);
    return ret;
  }

  pr_info("ready: ring buffer %d slots, /dev/%s open\n", RING_SIZE,
          DEVICE_NAME);
  return 0;
}

static void __exit bpfledger_exit(void) {
  cleanup_chardev();
  pr_info("unloaded: %llu events recorded\n", (unsigned long long)ring_head);
}

module_init(bpfledger_init);
module_exit(bpfledger_exit);
