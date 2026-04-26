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
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/poll.h>
#include <linux/ptrace.h>
#include <linux/random.h>
#include <linux/siphash.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uidgid.h>
#include <linux/wait.h>
#include <linux/cgroup.h>
#include <linux/sysfs.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Meriah Ibrahim Abderrahim");
MODULE_DESCRIPTION("Native BPF Ledger (Cryptographic, Container-Aware)");
MODULE_VERSION("6.0-FINAL");

/* --------------------------- Ring Buffer -------------------------*/
#define RING_SIZE 65536
#define RING_MASK (RING_SIZE - 1)
#define BATCH_SIZE 32

/* --------------------------- Global Variables ----------------------------*/
static struct audit_record ring[RING_SIZE];
static u64 ring_head = 0;
static u64 g_prev_hash = 0;
static siphash_key_t siphash_key;

static DEFINE_SPINLOCK(ring_lock);
static DECLARE_WAIT_QUEUE_HEAD(ring_wq);
static struct audit_record tpm_batch[BATCH_SIZE];
static unsigned int tpm_batch_count = 0;


static struct audit_record hb_slot;
static atomic_t hb_avail = ATOMIC_INIT(0);
static struct bpf_ring_ctx hb_ctx = { &hb_slot, &hb_avail, &ring_wq};
extern u8 last_batch_hash[32];
static struct device *bpfaudit_dev;


#define HASH_FIFO_SIZE 64
#define HASH_FIFO_MASK (HASH_FIFO_SIZE - 1)

static u8        hash_fifo[HASH_FIFO_SIZE][32];
static unsigned  hash_fifo_head = 0;   /* next write slot */
static unsigned  hash_fifo_tail = 0;   /* next read  slot */
static DEFINE_SPINLOCK(hash_fifo_lock);
/* ----------------------------- Helpers -----------------------------------*/

static ssize_t batch_hash_show(struct device *dev,
                               struct device_attribute *attr, char *buf)
{
    u8 hash[32];
    spin_lock(&hash_fifo_lock);
    if (hash_fifo_head == hash_fifo_tail) {
        spin_unlock(&hash_fifo_lock);
        return sprintf(buf, "\n");   /* empty — daemon will retry */
    }
    memcpy(hash, hash_fifo[hash_fifo_tail & HASH_FIFO_MASK], 32);
    hash_fifo_tail++;
    spin_unlock(&hash_fifo_lock);
    return sprintf(buf, "%*phN\n", 32, hash);
}
static DEVICE_ATTR(batch_hash, 0444, batch_hash_show, NULL);

/**
 * extract all possible data of the current process
 * responsible for LOAD, ATTACH, DETTACH and FREE / PIN
 * namespace is for containers env
 */
static void fill_process_ctx(struct audit_record *rec) {
  struct css_set *css; 

  rec->pid = (u32)current->pid;
  rec->tgid = (u32)current->tgid;
  rec->uid = from_kuid(&init_user_ns, current_uid());
  rec->gid = from_kgid(&init_user_ns, current_gid());

  if (task_active_pid_ns(current))
    rec->pid_ns_id = task_active_pid_ns(current)->ns.inum;

  css = task_css_set(current);
  if (css && css->dfl_cgrp)
      rec->cgroup_id = (u64)cgroup_ino(css->dfl_cgrp); 
  else
      rec->cgroup_id = 0; 
}

/**
 * submit a full recoded event to a ringbuffer
 * fill the current hash and put the old current to be previous
 * to build a full chained sequence
 */
static void native_submit_event(struct audit_record *rec) {
  unsigned long flags;
  u64 seq;

  struct audit_record flush_batch[BATCH_SIZE];

  spin_lock_irqsave(&ring_lock, flags);
  bool do_flush = false; 	

  seq = ring_head++;
  rec->seq = seq;
  rec->timestamp_ns = ktime_get_ns();
  rec->prev_hash = g_prev_hash;
  rec->curr_hash = 0;

  // hashing full data not partial hashing
  rec->curr_hash = siphash(rec, sizeof(*rec), &siphash_key);
  g_prev_hash = rec->curr_hash;

  memcpy(&ring[seq & RING_MASK], rec, sizeof(*rec));
   
  if (rec->event_type != AUDIT_EVENT_HEARTBEAT) {
    tpm_batch[tpm_batch_count++] = *rec;
    if (tpm_batch_count == BATCH_SIZE) {
		memcpy(flush_batch, tpm_batch, sizeof(flush_batch));
	 	do_flush = true;
		tpm_batch_count = 0;
    }
  }
  spin_unlock_irqrestore(&ring_lock, flags);
// wake_up_interruptible(&ring_wq);

  if (do_flush) {
    int hash_ret = tpm_store_batch(flush_batch, BATCH_SIZE);
    if (hash_ret == 0) {
        spin_lock_irqsave(&hash_fifo_lock, flags);
        if ((hash_fifo_head - hash_fifo_tail) < HASH_FIFO_SIZE) {
            memcpy(hash_fifo[hash_fifo_head & HASH_FIFO_MASK],
                   last_batch_hash, 32);
            hash_fifo_head++;
        } else {
            pr_warn("hash_fifo overflow — increase HASH_FIFO_SIZE\n");
        }
        spin_unlock_irqrestore(&hash_fifo_lock, flags);
    } else {
        pr_warn("tpm_store_batch failed (%d), skipping hash push\n", hash_ret);
    }
  }

  wake_up_interruptible(&ring_wq);
  return;
}

/* ----------------------- Kprobes / Kretprobe * --------------------------*/
/* BPF program lifecycle hooks... Full Chain
 * Execution order (chronological):
 *      1. bpf_check: Post-verification, pre-load: program validated, not yet
 * active
 *      2. bpf_prog_new_fd: Post-load, pre-attach: FD created, program exists in
 * kernel
 *      3. bpf_link_init: Pre-attach: link structure initializing
 *      4. perf_event_set_bpf_prog: Post-attach: program hooked to perf
 * event/trigger
 *      5. bpf_obj_pin_user: Optional post-attach: program pinned to FS for
 * persistence
 *      6. bpf_link_free: Pre-detach: link tearing down, program deactivating
 *      7. bpf_prog_put_deferred: Post-detach, pre-free: reference dropped
 * Covers: VALIDATION → LOAD → ATTACH → (PIN) → DETACH → DESTROY
 */

/**
 * triggers INTENT event
 * bpf_check runs under "bpf_prog_load"
 *     and runs the eBPF verifier,
 *     used for early detection at the verifier entry point
 * call in kernel : /linux/kernel/bpf/syscall.c
 */
static int pre_bpf_check(struct kprobe *p, struct pt_regs *regs) {
  struct audit_record rec;
  memset(&rec, 0, sizeof(rec));
  get_task_comm(rec.comm, current);
  fill_process_ctx(&rec);
  rec.event_type = AUDIT_EVENT_INTENT;
  rec.source = AUDIT_SOURCE_KPROBE;
  native_submit_event(&rec);
  return 0;
}
static struct kprobe kp_bpf_check = {.symbol_name = "bpf_check",
                                     .pre_handler = pre_bpf_check};

/**
 * once verifier finished, new id allocated
 * bpf_prog_new_fd called to create a new fd to the loaded program
 * call in kernel : /linux/kernel/bpf/syscall.c under bpf_prog_load call
 *
 * extraced info : comm, prog_id, prog_type, prog_tag and process info
 */
static int pre_bpf_prog_new_fd(struct kprobe *p, struct pt_regs *regs) {
  struct bpf_prog *prog = (struct bpf_prog *)regs_get_kernel_argument(regs, 0);
  if (prog && prog->aux && prog->aux->id > 0) {
    struct audit_record rec;
    memset(&rec, 0, sizeof(rec));
    get_task_comm(rec.comm, current);
    fill_process_ctx(&rec);
    rec.event_type = AUDIT_EVENT_LOAD;
    rec.source = AUDIT_SOURCE_KPROBE;
    rec.prog_id = prog->aux->id;
    rec.prog_type = prog->type;
    memcpy(rec.prog_tag, prog->tag, 8);
    native_submit_event(&rec);
  }
  return 0;
}
static struct kprobe kp_bpf_prog_new_fd = {.symbol_name = "bpf_prog_new_fd",
                                           .pre_handler = pre_bpf_prog_new_fd};

/**
 * captures BPF program attachment via link abstraction
 * Entry: grab link pointer from function args before init runs
 * Return: link is initialized, extract prog from it and log attachment
 *  we MUST save link pointer at entry to access it at return.
 *  Without entry_handler, ret_handler sees only: RAX = error code, link pointer
 * LOST
 */
static int entry_bpf_link_init(struct kretprobe_instance *ri,
                               struct pt_regs *regs) {
  struct bpf_link **data = (struct bpf_link **)ri->data;
  *data = (struct bpf_link *)regs_get_kernel_argument(regs, 0);
  return 0;
}
static int ret_bpf_link_init(struct kretprobe_instance *ri,
                             struct pt_regs *regs) {
  struct bpf_link **data = (struct bpf_link **)ri->data;
  struct bpf_link *link = *data;

  if (link && link->prog && link->prog->aux) {
    struct audit_record rec;
    memset(&rec, 0, sizeof(rec));
    get_task_comm(rec.comm, current);
    fill_process_ctx(&rec);
    rec.event_type = AUDIT_EVENT_ATTACH;
    rec.source = AUDIT_SOURCE_LINK;
    rec.prog_id = link->prog->aux->id;
    rec.prog_type = link->prog->type;
    memcpy(rec.prog_tag, link->prog->tag, 8);
    native_submit_event(&rec);
  }
  return 0;
}
static struct kretprobe krp_bpf_link_init = {
    .kp.symbol_name = "bpf_link_init",
    .handler = ret_bpf_link_init,
    .entry_handler = entry_bpf_link_init,
    .data_size = sizeof(struct bpf_link *)};

/**
 * captures BPF program detachment before link destruction
 * called when link is being torn down,
 * prog still accessible for audit logging
 */
static int pre_bpf_link_free(struct kprobe *p, struct pt_regs *regs) {
  struct bpf_link *link = (struct bpf_link *)regs_get_kernel_argument(regs, 0);
  if (link && link->prog && link->prog->aux) {
    struct audit_record rec;
    memset(&rec, 0, sizeof(rec));
    get_task_comm(rec.comm, current);
    fill_process_ctx(&rec);
    rec.event_type = AUDIT_EVENT_DETACH;
    rec.source = AUDIT_SOURCE_LINK;
    rec.prog_id = link->prog->aux->id;
    rec.prog_type = link->prog->type;
    memcpy(rec.prog_tag, link->prog->tag, 8);
    native_submit_event(&rec);
  }
  return 0;
}
static struct kprobe kp_bpf_link_free = {.symbol_name = "bpf_link_free",
                                         .pre_handler = pre_bpf_link_free};

/**
 * captures BPF program attachment to perf events
 * Prog passed as second argument (index 1)
 */
static int pre_perf_event_set_bpf(struct kprobe *p, struct pt_regs *regs) {
  struct bpf_prog *prog = (struct bpf_prog *)regs_get_kernel_argument(regs, 1);
  if (prog && prog->aux && prog->aux->id > 0) {
    struct audit_record rec;
    memset(&rec, 0, sizeof(rec));
    get_task_comm(rec.comm, current);
    fill_process_ctx(&rec);
    rec.event_type = AUDIT_EVENT_ATTACH;
    rec.source = AUDIT_SOURCE_KPROBE;
    rec.prog_id = prog->aux->id;
    rec.prog_type = prog->type;
    memcpy(rec.prog_tag, prog->tag, 8);
    native_submit_event(&rec);
  }
  return 0;
}
static struct kprobe kp_perf_event_set = {
    .symbol_name = "perf_event_set_bpf_prog",
    .pre_handler = pre_perf_event_set_bpf};

/**
 * captures BPF object pinning to filesystem
 * Logs PIN event before kernel
 * creates persistent reference in /sys/fs/bpf/
 */
static int pre_bpf_obj_pin_user(struct kprobe *p, struct pt_regs *regs) {
  char __user *pathname;
  struct audit_record rec;
  long ret;

  memset(&rec, 0, sizeof(rec));
  get_task_comm(rec.comm, current);
  fill_process_ctx(&rec);
  rec.event_type = AUDIT_EVENT_PIN;
  rec.source = AUDIT_SOURCE_PIN;

  pathname = (char __user *)regs->si;
  ret = strncpy_from_user(rec.path, pathname, sizeof(rec.path) - 1);
  if (ret < 0)
     rec.path[0] = '\0'; 

  native_submit_event(&rec);
  return 0;
}
static struct kprobe kp_bpf_obj_pin_user = {
    .symbol_name = "bpf_obj_pin_user", .pre_handler = pre_bpf_obj_pin_user};

/**
 * captures BPF program final destruction
 * called when reference count hits zero and deferred work runs
 * extracts prog from work_struct via container_of,
 * logs FREE before memory released.
 */
static int pre_bpf_prog_put_deferred(struct kprobe *p, struct pt_regs *regs) {
  struct work_struct *work =
      (struct work_struct *)regs_get_kernel_argument(regs, 0);
  struct bpf_prog_aux *aux = container_of(work, struct bpf_prog_aux, work);
  struct bpf_prog *prog = aux->prog;

  pr_info("bpfledger: kp_bpf_prog_put_deferred fired: prog=%p aux=%p id=%u\n",
          prog, prog ? prog->aux : NULL,
          (prog && prog->aux) ? prog->aux->id : 0);

  if (!prog || !aux->id)
    return 0; /* not yet zeroed... zeroed in bpf_prog_free_id */

  struct audit_record rec;
  memset(&rec, 0, sizeof(rec));
  get_task_comm(rec.comm, current);
  fill_process_ctx(&rec);
  rec.event_type = AUDIT_EVENT_FREE;
  rec.source = AUDIT_SOURCE_KPROBE;
  rec.prog_id = aux->id;
  rec.prog_type = prog->type;
  memcpy(rec.prog_tag, prog->tag, 8);
  native_submit_event(&rec);
  return 0;
}

static struct kprobe kp_bpf_prog_put_deferred = {
    .symbol_name = "bpf_prog_put_deferred",
    .pre_handler = pre_bpf_prog_put_deferred,
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

static ssize_t bpfledger_read(struct file *file, char __user *buf, size_t count,
                              loff_t *offset) {
hb:
   if (atomic_read(&hb_avail)) {
	if (copy_to_user(buf, &hb_slot, sizeof(hb_slot)))
		return -EFAULT;
	atomic_set(&hb_avail, 0);
	return sizeof(hb_slot);
   }


  struct reader_state *rs = file->private_data;
  struct audit_record rec;
  u64 head, pos_before;
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
    ret = wait_event_interruptible(ring_wq, ring_head > rs->pos || atomic_read(&hb_avail));
    if (ret)
      return ret;
    if (atomic_read(&hb_avail))
      goto hb;
    goto retry;
  }

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
  get_random_bytes(&siphash_key, sizeof(siphash_key));

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

  bpfaudit_dev = device_create(&bpfledger_class, NULL, dev, NULL, DEVICE_NAME);
  if (IS_ERR(bpfaudit_dev)) {
    ret = -ENOMEM;
    goto err_device;
  }

  ret = device_create_file(bpfaudit_dev, &dev_attr_batch_hash);
  if (ret)
     pr_err("sysfs batch_hash create field: %d\n", ret); 

  register_kprobe(&kp_bpf_check);
  register_kprobe(&kp_bpf_prog_new_fd);
  register_kretprobe(&krp_bpf_link_init);
  register_kprobe(&kp_bpf_link_free);
  register_kprobe(&kp_perf_event_set);
  register_kprobe(&kp_bpf_obj_pin_user);
  ret = register_kprobe(&kp_bpf_prog_put_deferred);
  if (ret < 0)
    pr_err("bpfledger: FAILED to register kp_bpf_prog_put_deferred: %d\n", ret);
  /*} else {
    pr_info("bpfledger: kp_bpf_prog_put_deferred kprobe registered OK\n");
  }*/

  return 0;

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
  unregister_kprobe(&kp_bpf_prog_put_deferred);
  unregister_kprobe(&kp_bpf_obj_pin_user);
  unregister_kprobe(&kp_perf_event_set);
  unregister_kprobe(&kp_bpf_link_free);
  unregister_kretprobe(&krp_bpf_link_init);
  unregister_kprobe(&kp_bpf_prog_new_fd);
  unregister_kprobe(&kp_bpf_check);


  device_remove_file(bpfaudit_dev, &dev_attr_batch_hash);
  device_destroy(&bpfledger_class, dev);
  class_unregister(&bpfledger_class);
  cdev_del(&g_cdev);
  unregister_chrdev_region(dev, 1);
}
module_init(bpfledger_init);
module_exit(bpfledger_exit);
