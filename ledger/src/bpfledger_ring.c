// SPDX-License-Identifier: GPL-2.0
#include "linux/compiler.h"
#define pr_fmt(fmt) KBUILD_MODNAME "/ring: " fmt

#include "bpfledger_ring.h"
#include <linux/err.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>

/* ----------------------------- Ring State --------------------------------*/

struct audit_record *ring;
u64 ring_head = 0;
DEFINE_SPINLOCK(ring_lock);
DECLARE_WAIT_QUEUE_HEAD(ring_wq);

static struct audit_record events_batch[BATCH_SIZE];
static struct audit_record flush_batch[BATCH_SIZE];
static unsigned int batch_count = 0;

struct audit_record anchor_fifo[ANCHOR_FIFO_SIZE];
unsigned anchor_head = 0;
unsigned anchor_tail = 0;
DEFINE_SPINLOCK(anchor_lock);

struct audit_record hb_slot;
atomic_t hb_avail = ATOMIC_INIT(0);

/* ----------------------------- Init / Exit ------------------------------*/

int bpfledger_ring_init(void) {
  ring = vzalloc(RING_SIZE * sizeof(struct audit_record));
  if (unlikely(!ring))
    return -ENOMEM;
  return 0;
}

void bpfledger_ring_exit(void) { vfree(ring); }

/* ----------------------------- Core Logic --------------------------------*/

void native_submit_event(struct audit_record *rec) {
  unsigned long flags;
  bool do_flush = false;
  u64 seq;

  spin_lock_irqsave(&ring_lock, flags);

  seq = ring_head++;
  rec->seq = seq;
  rec->timestamp_ns = ktime_get_ns();

  memcpy(&ring[seq & RING_MASK], rec, sizeof(*rec));

  if (likely(rec->event_type != AUDIT_EVENT_HEARTBEAT)) {
    events_batch[batch_count++] = *rec;
    if (batch_count == BATCH_SIZE) {
      memcpy(flush_batch, events_batch, sizeof(flush_batch));
      do_flush = true;
      batch_count = 0;
    }
  }
  spin_unlock_irqrestore(&ring_lock, flags);

  if (do_flush) {
    struct batch_crypto_record *recc = batch_hash_sign(flush_batch, BATCH_SIZE);
    if (likely(!IS_ERR(recc))) {
      struct audit_record anchor;
      unsigned long aflags;
      u64 end_seq = flush_batch[BATCH_SIZE - 1].seq;
      memset(&anchor, 0, sizeof(anchor));
      anchor.event_type = AUDIT_EVENT_BATCH_ANCHOR;
      anchor.timestamp_ns = ktime_get_ns();

      anchor.u.anr.end_seq = end_seq;

      memcpy(anchor.u.anr.batch_hash, recc->hash, 32);
      memcpy(anchor.u.anr.batch_hmac, recc->signature, 32);
      kfree(recc);

      spin_lock_irqsave(&anchor_lock, aflags);
      anchor_fifo[anchor_head & ANCHOR_FIFO_MASK] = anchor;
      anchor_head++;
      spin_unlock_irqrestore(&anchor_lock, aflags);
    } else {
      pr_warn("batch_hash_sign failed: %ld\n", PTR_ERR(recc));
    }
  }
  wake_up_interruptible(&ring_wq);
}

void flush_partial_batch(void) {
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
  if (unlikely(!batch_copy)) {
    spin_unlock_irqrestore(&ring_lock, flags);
    pr_warn("flush_partial: alloc failed\n");
    return;
  }

  memcpy(batch_copy, events_batch, count * sizeof(struct audit_record));
  batch_count = 0;
  spin_unlock_irqrestore(&ring_lock, flags);

  struct batch_crypto_record *recc = batch_hash_sign(batch_copy, count);
  u64 end_seq = batch_copy[count - 1].seq;
  kfree(batch_copy);

  if (likely(!IS_ERR(recc))) {
    struct audit_record anchor;

    memset(&anchor, 0, sizeof(anchor));
    anchor.event_type = AUDIT_EVENT_BATCH_ANCHOR;
    anchor.timestamp_ns = ktime_get_ns();
    anchor.u.anr.end_seq = end_seq;
    memcpy(anchor.u.anr.batch_hash, recc->hash, 32);
    memcpy(anchor.u.anr.batch_hmac, recc->signature, 32);
    kfree(recc);

    spin_lock_irqsave(&anchor_lock, aflags);
    anchor_fifo[anchor_head & ANCHOR_FIFO_MASK] = anchor;
    anchor_head++;
    spin_unlock_irqrestore(&anchor_lock, aflags);
    wake_up_interruptible(&ring_wq);
  } else {
    pr_warn("flush_partial: batch_hash_sign failed: %ld\n", PTR_ERR(recc));
  }
}
