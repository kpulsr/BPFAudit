/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _BPFAUDIT_HEARTBEAT_H
#define _BPFAUDIT_HEARTBEAT_H

#include <linux/atomic.h>
#include <linux/wait.h>
#include <linux/types.h>
#include "bpfledger.h"

/*
 * bpf_ring_ctx - heartbeat communication context
 *
 * Passed by bpfledger_main at init time. The heartbeat timer uses it to
 * write the heartbeat record and wake the reader, and to trigger a
 * partial-batch flush before each heartbeat fires.
 *
 * @hb_slot:      pointer to the dedicated heartbeat audit_record slot
 * @hb_avail:     atomic flag; set to 1 by timer, cleared to 0 after read
 * @ring_wq:      wait queue to wake the userspace reader
 * @flush_partial: callback to flush any incomplete batch before heartbeat
 */
struct bpf_ring_ctx {
    struct audit_record  *hb_slot;
    atomic_t             *hb_avail;
    wait_queue_head_t    *ring_wq;
    void                (*flush_partial)(void);
};

/*
 * bpfaudit_heartbeat_init - start the heartbeat timer and fetch the HMAC key
 * @ctx: fully populated bpf_ring_ctx; all fields must be non-NULL.
 */
int bpfaudit_heartbeat_init(struct bpf_ring_ctx *ctx);

void bpfaudit_heartbeat_exit(void);

#endif /* _BPFAUDIT_HEARTBEAT_H */
