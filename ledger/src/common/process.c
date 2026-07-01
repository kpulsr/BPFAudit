#include "bpfledger.h"
#include <linux/cgroup.h>
#include <linux/pid_namespace.h>
#include <linux/uidgid.h>

/**
 * fill_process_ctx - populate process and namespace identity fields in an audit
 * record. Captures pid, tgid, uid, gid, pid namespace inode, and cgroup id from
 * current. Called by emit_prog_event() for every lifecycle event.
 */
void fill_process_ctx(struct audit_record *rec) {
  struct css_set *css;

  rec->u.ev.pid = (u32)current->pid;
  rec->u.ev.tgid = (u32)current->tgid;
  rec->u.ev.uid = from_kuid(&init_user_ns, current_uid());
  rec->u.ev.gid = from_kgid(&init_user_ns, current_gid());

  if (likely(task_active_pid_ns(current)))
    rec->u.ev.pid_ns_id = task_active_pid_ns(current)->ns.inum;

  css = task_css_set(current);
  if (css && css->dfl_cgrp)
    rec->u.ev.cgroup_id = (u64)cgroup_ino(css->dfl_cgrp);
  else
    rec->u.ev.cgroup_id = 0;
}