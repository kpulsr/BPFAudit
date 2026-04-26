/* SPDX-License-Identifier: GPL-2.0 */
#define pr_fmt(fmt) KBUILD_MODNAME "/emit: " fmt
#include "bpfaudit_emit.h"
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/slab.h>
#include <linux/tpm.h>
#include <linux/workqueue.h>


struct tpm_work {
    struct work_struct work;
    u8 hash[32];
};

#define BATCH_HASH_SIZE 32
#define PCR_INDEX 16
#define HEARTBEAT_INTERVAL_S 30
static struct bpf_ring_ctx *g_ctx;
static struct hrtimer hb_timer;
static struct workqueue_struct *tpm_wq;

u8 last_batch_hash[32] = {0};


static void tpm_extend_work(struct work_struct *work)
{
    struct tpm_work *w = container_of(work, struct tpm_work, work);
    struct tpm_chip *chip;
    struct tpm_digest digests[2];
    int i;

    chip = tpm_default_chip();
    if (!chip)
        goto out;

    for (i = 0; i < chip->nr_allocated_banks; i++) {
        digests[i].alg_id = chip->allocated_banks[i].alg_id;
        if (digests[i].alg_id == TPM_ALG_SHA256)
            memcpy(digests[i].digest, w->hash, 32);
        else if (digests[i].alg_id == TPM_ALG_SHA1)
            memcpy(digests[i].digest, w->hash, 20);
        else
            memset(digests[i].digest, 0, chip->allocated_banks[i].digest_size);
    }

    tpm_pcr_extend(chip, PCR_INDEX, digests);
    put_device(&chip->dev);
out:
    kfree(w);
}


// tpm batch hash 
int tpm_store_batch(struct audit_record *batch, unsigned int count)
{
        struct crypto_shash *tfm;
        struct shash_desc *desc;
        u8 digest[BATCH_HASH_SIZE];
        struct tpm_digest *digests;   /* dynamic allocation */
        struct tpm_chip *chip;
        int ret, i;

        tfm = crypto_alloc_shash("sha256", 0, 0);
        if (IS_ERR(tfm))
                return PTR_ERR(tfm);

        desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_ATOMIC);
        if (!desc) {
                ret = -ENOMEM;
                goto err_free_tfm;
        }
        desc->tfm = tfm;

        ret = crypto_shash_init(desc);
        if (ret)
                goto err_free_desc;

        for (i = 0; i < count; i++) {
                ret = crypto_shash_update(desc, (u8 *)&batch[i], sizeof(*batch));
                if (ret)
                        goto err_free_desc;
        }

        ret = crypto_shash_final(desc, digest);
        if (ret)
                goto err_free_desc;

        memcpy(last_batch_hash, digest, 32);
        pr_info("batch %u hash=%*phN\n", count, BATCH_HASH_SIZE, digest);

        chip = tpm_default_chip();
        if (chip) {
                struct tpm_work *w = kmalloc(sizeof(*w), GFP_ATOMIC);
                if (w) {
                        memcpy(w->hash, digest, 32);
                        INIT_WORK(&w->work, tpm_extend_work);
                        queue_work(tpm_wq, &w->work); 
                }
                put_device(&chip->dev);
        } else {
                pr_warn("No TPM, skipping extend\n");
        }

err_free_desc:
        kfree(desc);
err_free_tfm:
        crypto_free_shash(tfm);
        return ret;
}


/* Heartbeat fires every 30s into both channels */
static enum hrtimer_restart hb_fn(struct hrtimer *timer) {
    struct audit_record rec = {0};
    unsigned long flags;

    rec.event_type = AUDIT_EVENT_HEARTBEAT;
    rec.timestamp_ns = ktime_get_ns();
    // no seq, no hash — just raw marker

    *g_ctx->hb_slot = rec;
    smp_wmb();
    atomic_set(g_ctx->hb_avail, 1);
    wake_up_interruptible(g_ctx->ring_wq);

    hrtimer_forward_now(timer, ktime_set(HEARTBEAT_INTERVAL_S, 0));
    return HRTIMER_RESTART;
}

int bpfaudit_heartbeat_init(struct bpf_ring_ctx *ctx) {	
  g_ctx = ctx;
    
  tpm_wq = alloc_ordered_workqueue("bpfaudit_tpm", WQ_MEM_RECLAIM);
  if (!tpm_wq)
      return -ENOMEM;
  hrtimer_setup(&hb_timer, hb_fn, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
  hrtimer_start(&hb_timer, ktime_set(HEARTBEAT_INTERVAL_S, 0),
                HRTIMER_MODE_REL);
  pr_info("heartbeat started (interval=%ds)\n", HEARTBEAT_INTERVAL_S);
  return 0;
}

void bpfaudit_heartbeat_exit(void) {
  hrtimer_cancel(&hb_timer);
  if (tpm_wq) {
     flush_workqueue(tpm_wq);   
     destroy_workqueue(tpm_wq);
  }
}
