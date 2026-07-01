#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include "bpfledger.h"
#include "bpfledger_ring.h"
#include <linux/bpf.h>

void emit_prog_event(struct bpf_prog *prog, u8 event_type, u8 source) {
  pr_debug("event: prog_id=%u type=%u event=%u source=%u pid=%u\n",
           prog->aux->id, prog->type, event_type, source, current->pid);

  struct audit_record rec;
  memset(&rec, 0, sizeof(rec));
  get_task_comm(rec.u.ev.comm, current);
  fill_process_ctx(&rec);
  rec.event_type = event_type;
  rec.source = source;
  rec.u.ev.prog_id = prog->aux->id ? prog->aux->id : 0;
  rec.u.ev.prog_type = prog->type;
  memcpy(rec.u.ev.prog_tag, prog->tag, 8);
  native_submit_event(&rec);
}