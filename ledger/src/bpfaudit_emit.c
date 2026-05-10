/* SPDX-License-Identifier: GPL-2.0 */
#define pr_fmt(fmt) KBUILD_MODNAME "/emit: " fmt
#include "bpfaudit_emit.h"
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/key.h>
#include <linux/keyctl.h>
#include <keys/user-type.h>

#define BATCH_HASH_SIZE 32
#define HMAC_KEY_SIZE 32
#define HEARTBEAT_INTERVAL_S 30

static struct bpf_ring_ctx *g_ctx;
static struct hrtimer hb_timer;

static u8  K_current[HMAC_KEY_SIZE];
static bool K_ready = false;

/* --- HMAC key --- */
static int fetch_hmac_key(void)
{
    struct key *k;
    const struct user_key_payload *ukp;
    int ret = 0;

    k = request_key(&key_type_logon, "bpfaudit:hmac", NULL);
    if (IS_ERR(k))
        return PTR_ERR(k);

    rcu_read_lock();
    ukp = user_key_payload_rcu(k);
    if (!ukp || ukp->datalen != HMAC_KEY_SIZE) {
        ret = -EINVAL;
        goto out;
    }
    bpfaudit_set_hmac_key(ukp->data, ukp->datalen);
out:
    rcu_read_unlock();
    key_put(k);
    return ret;
}

/* --- HAMC signing --- */

static void ratchet_key(void)
{
    struct crypto_shash *tfm;
    u8 K_next[HMAC_KEY_SIZE];

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("ratchet: sha256 alloc failed\n");
        return;
    }
    crypto_shash_tfm_digest(tfm, K_current, HMAC_KEY_SIZE, K_next);
    crypto_free_shash(tfm);
    memzero_explicit(K_current, HMAC_KEY_SIZE);
    memcpy(K_current, K_next, HMAC_KEY_SIZE);
    memzero_explicit(K_next, HMAC_KEY_SIZE);
    pr_info("key ratcheted\n");
}

int bpfaudit_set_hmac_key(const u8 *key, size_t len)
{
    if (len != HMAC_KEY_SIZE)
        return -EINVAL;
    memcpy(K_current, key, HMAC_KEY_SIZE);
    K_ready = true;
    pr_info("HMAC key provisioned\n");
    return 0;
}


static int compute_hmac(const u8 *data, size_t len, u8 *hmac_out)
{
    struct crypto_shash *tfm;
    struct shash_desc   *desc;
    int ret;

    if (!K_ready)
        return -ENOKEY;

    tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);

    ret = crypto_shash_setkey(tfm, K_current, HMAC_KEY_SIZE);
    if (ret)
        goto out_free_tfm;

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_ATOMIC);
    if (!desc) {
        ret = -ENOMEM;
        goto out_free_tfm;
    }
    desc->tfm = tfm;

    ret = crypto_shash_init(desc);
    if (ret)
        goto out_free_desc;

    ret = crypto_shash_update(desc, data, len);
    if (ret)
        goto out_free_desc;

    ret = crypto_shash_final(desc, hmac_out);
    if (ret == 0)
        pr_info("compute_hmac OK: %*phN\n", 32, hmac_out);

out_free_desc:
    kfree(desc);
out_free_tfm:
    crypto_free_shash(tfm);
    return ret;
}


struct batch_crypto_record * batch_hash_sign(struct audit_record *batch, unsigned int count)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    u8 digest[BATCH_HASH_SIZE];
    int ret, i;
    struct batch_crypto_record *rec = kmalloc(sizeof(*rec), GFP_ATOMIC);
    if (!rec) return ERR_PTR(-ENOMEM);

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) { ret = PTR_ERR(tfm); goto err_free_rec; }

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_ATOMIC);
    if (!desc) { ret = -ENOMEM; goto err_free_tfm; }
    desc->tfm = tfm;

    ret = crypto_shash_init(desc);
    if (ret) goto err_free_desc;

    for (i = 0; i < count; i++) {
        ret = crypto_shash_update(desc, (u8 *)&batch[i], sizeof(*batch));
        if (ret) goto err_free_desc;
    }
    ret = crypto_shash_final(desc, digest);
    if (ret) goto err_free_desc;

    memcpy(rec->hash, digest, BATCH_HASH_SIZE);

    ret = compute_hmac(digest, BATCH_HASH_SIZE, rec->signature);
    if (ret) goto err_free_desc;

    ratchet_key();

    kfree(desc); crypto_free_shash(tfm);
    return rec;

err_free_desc: kfree(desc);
err_free_tfm:  crypto_free_shash(tfm);
err_free_rec:  kfree(rec);
    return ERR_PTR(ret);
}


/* Heartbeat fires every 30s into both channels */
static enum hrtimer_restart hb_fn(struct hrtimer *timer) {
   
   struct audit_record rec = {0};     
   if (g_ctx->flush_partial)
        g_ctx->flush_partial();

    rec.event_type = AUDIT_EVENT_HEARTBEAT;
    rec.timestamp_ns = ktime_get_ns();

    *g_ctx->hb_slot = rec;
    smp_wmb();
    atomic_set(g_ctx->hb_avail, 1);
    wake_up_interruptible(g_ctx->ring_wq);

    hrtimer_forward_now(timer, ktime_set(HEARTBEAT_INTERVAL_S, 0));
    return HRTIMER_RESTART;
}

int bpfaudit_heartbeat_init(struct bpf_ring_ctx *ctx) {
  int ret; 
  g_ctx = ctx;

  hrtimer_setup(&hb_timer, hb_fn, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
  hrtimer_start(&hb_timer, ktime_set(HEARTBEAT_INTERVAL_S, 0),
                HRTIMER_MODE_REL);
  pr_info("heartbeat started (interval=%ds)\n", HEARTBEAT_INTERVAL_S);

  ret = fetch_hmac_key();
  if (ret) {
    pr_err("failed to fetch HMAC key from keyring: %d\n", ret);
    return ret;
  }  

  return 0;    
}

void bpfaudit_heartbeat_exit(void) {
  hrtimer_cancel(&hb_timer);
  memzero_explicit(K_current, HMAC_KEY_SIZE);
  K_ready = false;
}
