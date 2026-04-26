/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/spinlock.h> 
#include <linux/wait.h>
#ifndef _BPFAUDIT_EMIT_H
#define _BPFAUDIT_EMIT_H
#include "bpfledger.h"



#define AUDIT_EVENT_HEARTBEAT 10
#define RING_SIZE 65536
#define RING_MASK (RING_SIZE - 1)


struct bpf_ring_ctx {
//    struct audit_record *ring;
//    u64 *ring_head;
    struct audit_record *hb_slot;
    atomic_t *hb_avail; 
//    spinlock_t *ring_lock;
    wait_queue_head_t *ring_wq;
};

// tpm PCR 
int tpm_store_batch(struct audit_record *batch, unsigned int count);

/* Start/stop 30s liveness heartbeat (dual-channel) */
int bpfaudit_heartbeat_init(struct bpf_ring_ctx *ctx);
void bpfaudit_heartbeat_exit(void);

#endif
