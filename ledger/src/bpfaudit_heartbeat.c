// SPDX-License-Identifier: GPL-2.0

#include "linux/compiler.h"
#include "linux/init.h"
#define pr_fmt(fmt) KBUILD_MODNAME "/heartbeat: " fmt

#include "bpfaudit_crypto.h"
#include "bpfaudit_heartbeat.h"
#include <linux/err.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#define HEARTBEAT_INTERVAL_S 30

/* ----------------------------- State ------------------------------------*/

static struct bpf_ring_ctx *g_ctx;
static struct hrtimer hb_timer;

/* ----------------------------- Timer ------------------------------------*/

/*
 * hb_fn - hrtimer callback, runs in softirq context
 *
 * Order matters:
 *   1. Flush partial batch first — ensures all pending events are
 *      cryptographically anchored before the heartbeat record lands.
 *   2. Write heartbeat record to hb_slot.
 *   3. smp_wmb() — ensure hb_slot write is visible before hb_avail is set.
 *   4. Set hb_avail and wake the reader.
 */
static enum hrtimer_restart hb_fn(struct hrtimer *timer) {
  struct audit_record rec = {0};

  if (likely(g_ctx->flush_partial))
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

/* ----------------------------- Init / Exit ------------------------------*/

int __init bpfaudit_heartbeat_init(struct bpf_ring_ctx *ctx) {
  int ret;

  if (unlikely(!ctx || !ctx->hb_slot || !ctx->hb_avail || !ctx->ring_wq ||
               !ctx->flush_partial)) {
    pr_err("heartbeat_init: invalid context — all fields must be non-NULL\n");
    return -EINVAL;
  }
  g_ctx = ctx;

  ret = bpfaudit_fetch_hmac_key();
  if (unlikely(ret)) {
    pr_err("heartbeat_init: failed to fetch HMAC key from keyring: %d\n", ret);
    return ret;
  }

  hrtimer_setup(&hb_timer, hb_fn, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
  hrtimer_start(&hb_timer, ktime_set(HEARTBEAT_INTERVAL_S, 0),
                HRTIMER_MODE_REL);

  pr_info("started (interval=%ds)\n", HEARTBEAT_INTERVAL_S);
  return 0;
}

void __exit bpfaudit_heartbeat_exit(void) {
  hrtimer_cancel(&hb_timer);
  bpfaudit_crypto_zeroize();
  pr_info("stopped, HMAC key zeroized\n");
}
