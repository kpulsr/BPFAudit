/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _BPFLEDGER_RING_H
#define _BPFLEDGER_RING_H

#include <linux/types.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include "bpfledger.h"
#include "bpfaudit_crypto.h"

#define RING_SIZE        65536
#define RING_MASK        (RING_SIZE - 1)
#define BATCH_SIZE       16
#define ANCHOR_FIFO_SIZE 64
#define ANCHOR_FIFO_MASK (ANCHOR_FIFO_SIZE - 1)

extern struct audit_record  *ring;
extern u64                   ring_head;
extern spinlock_t            ring_lock;
extern wait_queue_head_t     ring_wq;
extern struct audit_record   anchor_fifo[ANCHOR_FIFO_SIZE];
extern unsigned              anchor_head;
extern unsigned              anchor_tail;
extern spinlock_t            anchor_lock;
extern struct audit_record   hb_slot;
extern atomic_t              hb_avail;

/*
 * bpfledger_ring_init - allocate the ring buffer via vmalloc
 */
int bpfledger_ring_init(void);

/*
 * bpfledger_ring_exit - free the ring buffer
 */
void bpfledger_ring_exit(void);

/*
 * native_submit_event - write a fully populated audit_record into the ring
 * Assigns seq and timestamp_ns, copies into ring[seq & RING_MASK],
 * accumulates into the batch, and triggers a flush + anchor when full.
 * Called from every probe handler in bpfledger_main.c.
 */
void native_submit_event(struct audit_record *rec);

/*
 * flush_partial_batch - sign and anchor any incomplete batch
 * Called by the heartbeat timer before each heartbeat fires,
 * ensuring no events are stranded in the accumulation buffer.
 * Passed as a function pointer via bpf_ring_ctx.
 */
void flush_partial_batch(void);

#endif /* _BPFLEDGER_RING_H */
