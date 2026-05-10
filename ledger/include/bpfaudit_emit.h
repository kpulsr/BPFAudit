/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BPFAUDIT_EMIT_H
#define _BPFAUDIT_EMIT_H
#include <linux/wait.h>
#include <linux/spinlock.h> 
#include "bpfledger.h"



#define AUDIT_EVENT_HEARTBEAT 10
#define RING_SIZE 65536
#define RING_MASK (RING_SIZE - 1)


#define BATCH_HASH_SIZE 32     
#define HMAC_OUT_LEN 32


struct batch_crypto_record {
    u8  hash[BATCH_HASH_SIZE];
    u8  signature[HMAC_OUT_LEN];
};

int bpfaudit_set_hmac_key(const u8 *key, size_t len);

struct bpf_ring_ctx {
//    struct audit_record *ring;
//    u64 *ring_head;
    struct audit_record *hb_slot;
    atomic_t *hb_avail; 
//    spinlock_t *ring_lock;
    wait_queue_head_t *ring_wq;
    void  (*flush_partial)(void);
};

// tpm PCR 
struct batch_crypto_record * batch_hash_sign(struct audit_record *batch, unsigned int count);

/* Start/stop 30s liveness heartbeat (dual-channel) */
int bpfaudit_heartbeat_init(struct bpf_ring_ctx *ctx);
void bpfaudit_heartbeat_exit(void);

#endif
