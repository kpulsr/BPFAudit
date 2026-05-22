// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME "/crypto: " fmt

#include "bpfaudit_crypto.h"
#include <crypto/hash.h>
#include <keys/user-type.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/key.h>
#include <linux/keyctl.h>
#include <linux/slab.h>
#include <linux/string.h>

/* ----------------------------- Key State ---------------------------------*/

static u8 K_current[HMAC_KEY_SIZE];
static bool K_ready = false;
static DEFINE_SPINLOCK(key_lock);

static struct crypto_shash *tfm_hmac;
static struct crypto_shash *tfm_sha256;
/* ----------------------------- Key Management ----------------------------*/

/*
 * fetch_hmac_key - read HMAC key from the kernel keyring
 * Looks up the "bpfaudit:hmac" logon key and calls bpfaudit_set_hmac_key().
 */
int bpfaudit_fetch_hmac_key(void) {
  struct key *k;
  const struct user_key_payload *ukp;
  int ret = 0;

  k = request_key(&key_type_logon, "bpfaudit:hmac", NULL);
  if (unlikely(IS_ERR(k)))
    return PTR_ERR(k);

  rcu_read_lock();
  ukp = user_key_payload_rcu(k);
  if (unlikely(!ukp || ukp->datalen != HMAC_KEY_SIZE)) {
    pr_err("fetch_hmac_key: key missing or wrong size (got %u, want %u)\n",
           ukp ? ukp->datalen : 0, HMAC_KEY_SIZE);
    ret = -EINVAL;
    goto out;
  }
  ret = bpfaudit_set_hmac_key(ukp->data, ukp->datalen);
out:
  rcu_read_unlock();
  key_put(k);
  return ret;
}

int bpfaudit_set_hmac_key(const u8 *key, size_t len) {
  unsigned long flags;

  if (unlikely(len != HMAC_KEY_SIZE))
    return -EINVAL;

  /* allocate TFMs once if not yet done */
  if (!tfm_hmac) {
    tfm_hmac = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(tfm_hmac)) {
      tfm_hmac = NULL;
      return PTR_ERR(tfm_hmac);
    }
  }
  if (!tfm_sha256) {
    tfm_sha256 = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm_sha256)) {
      tfm_sha256 = NULL;
      return PTR_ERR(tfm_sha256);
    }
  }

  spin_lock_irqsave(&key_lock, flags);
  memcpy(K_current, key, HMAC_KEY_SIZE);
  K_ready = true;
  spin_unlock_irqrestore(&key_lock, flags);
  pr_info("HMAC key provisioned\n");
  return crypto_shash_setkey(tfm_hmac, key, HMAC_KEY_SIZE);
}

void bpfaudit_crypto_zeroize(void) {
  unsigned long flags;
  spin_lock_irqsave(&key_lock, flags);
  memzero_explicit(K_current, HMAC_KEY_SIZE);
  K_ready = false;
  spin_unlock_irqrestore(&key_lock, flags);
  if (tfm_hmac) {
    crypto_free_shash(tfm_hmac);
    tfm_hmac = NULL;
  }
  if (tfm_sha256) {
    crypto_free_shash(tfm_sha256);
    tfm_sha256 = NULL;
  }
}

/* ----------------------------- Signing -----------------------------------*/

/*
 * ratchet_key - derive next key from current via SHA-256, replace in place
 * Keeps forward secrecy: compromise of K_n does not reveal K_{n-1} batches.
 */
static int ratchet_key(void) {
  u8 K_next[HMAC_KEY_SIZE];
  int ret;

  ret = crypto_shash_tfm_digest(tfm_sha256, K_current, HMAC_KEY_SIZE, K_next);
  if (unlikely(ret)) {
    pr_err("ratchet: key derivation failed: %d — keeping old key\n", ret);
    memzero_explicit(K_next, HMAC_KEY_SIZE);
    return ret;
  }

  memzero_explicit(K_current, HMAC_KEY_SIZE);
  memcpy(K_current, K_next, HMAC_KEY_SIZE);
  memzero_explicit(K_next, HMAC_KEY_SIZE);

  /* resync tfm_hmac to the new key */
  ret = crypto_shash_setkey(tfm_hmac, K_current, HMAC_KEY_SIZE);
  if (unlikely(ret))
    pr_err("ratchet: setkey failed: %d\n", ret);
  pr_info("key ratcheted\n");
  return ret;
}

/*
 * compute_hmac - HMAC-SHA256 of @data under K_current into @hmac_out
 * Returns -ENOKEY if no key has been provisioned yet.
 */
static int compute_hmac(const u8 *data, size_t len, u8 *hmac_out) {
  struct shash_desc *desc;
  unsigned long flags;
  int ret;

  spin_lock_irqsave(&key_lock, flags);
  if (unlikely(!K_ready)) {
    spin_unlock_irqrestore(&key_lock, flags);
    return -ENOKEY;
  }
  spin_unlock_irqrestore(&key_lock, flags);

  desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm_hmac), GFP_ATOMIC);
  if (unlikely(!desc))
    return -ENOMEM;

  desc->tfm = tfm_hmac;

  ret = crypto_shash_init(desc);
  if (unlikely(ret))
    goto out;
  ret = crypto_shash_update(desc, data, len);
  if (unlikely(ret))
    goto out;
  ret = crypto_shash_final(desc, hmac_out);
out:
  kfree(desc);
  return ret;
}

struct batch_crypto_record *batch_hash_sign(struct audit_record *batch,
                                            unsigned int count) {
  struct shash_desc *desc;
  u8 digest[BATCH_HASH_SIZE];
  int ret, i;

  struct batch_crypto_record *rec = kmalloc(sizeof(*rec), GFP_ATOMIC);
  if (unlikely(!rec))
    return ERR_PTR(-ENOMEM);

  desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm_sha256), GFP_ATOMIC);
  if (unlikely(!desc)) {
    ret = -ENOMEM;
    goto err_free_rec;
  }
  desc->tfm = tfm_sha256;

  ret = crypto_shash_init(desc);
  if (unlikely(ret))
    goto err_free_desc;

  for (i = 0; i < count; i++) {
    ret = crypto_shash_update(desc, (u8 *)&batch[i], sizeof(*batch));
    if (unlikely(ret))
      goto err_free_desc;
  }

  ret = crypto_shash_final(desc, digest);
  if (unlikely(ret)) {
    pr_err("batch_hash_sign: sha256 final failed: %d\n", ret);
    goto err_free_desc;
  }

  memcpy(rec->hash, digest, BATCH_HASH_SIZE);

  ret = compute_hmac(digest, BATCH_HASH_SIZE, rec->signature);
  if (unlikely(ret)) {
    pr_err("batch_hash_sign: HMAC failed: %d\n", ret);
    goto err_free_desc;
  }

  ret = ratchet_key();
  if (unlikely(ret))
    pr_warn(
        "batch_hash_sign: key ratchet failed, next batch uses old key: %d\n",
        ret);

  kfree(desc);
  return rec;

err_free_desc:
  kfree(desc);
err_free_rec:
  kfree(rec);
  return ERR_PTR(ret);
}
