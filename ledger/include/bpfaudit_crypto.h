/* SPDX-License-Identifier: GPL-2.0 */
/*
 * bpfaudit_crypto.h — HMAC key management and batch signing interface
 */
#ifndef _BPFAUDIT_CRYPTO_H
#define _BPFAUDIT_CRYPTO_H

#include <linux/types.h>
#include "bpfledger.h"

#define BATCH_HASH_SIZE 32
#define HMAC_KEY_SIZE   32
#define HMAC_OUT_LEN    32


struct batch_crypto_record {
    u8 hash[BATCH_HASH_SIZE];
    u8 signature[HMAC_OUT_LEN];
};

/*
 * bpfaudit_set_hmac_key - provision the HMAC key from external source
 * Called by fetch_hmac_key() in bpfaudit_heartbeat.c after reading
 * the key from the kernel keyring. @key must be exactly HMAC_KEY_SIZE bytes.
 *
 * Returns 0 on success, -EINVAL if len is wrong.
 */
int bpfaudit_set_hmac_key(const u8 *key, size_t len);

/*
 * bpfaudit_crypto_zeroize - wipe the in-memory HMAC key and mark not ready
 */
void bpfaudit_crypto_zeroize(void);

/*
 * batch_hash_sign - hash a batch of audit records and sign the digest
 *
 * Computes SHA-256 over @count records in @batch, then HMAC-SHA256 of
 * the digest under the current key, then ratchets the key forward.
 *
 * Returns a heap-allocated batch_crypto_record on success.
 */
struct batch_crypto_record *batch_hash_sign(struct audit_record *batch,
                                            unsigned int count);

int bpfaudit_fetch_hmac_key(void);
#endif /* _BPFAUDIT_CRYPTO_H */
