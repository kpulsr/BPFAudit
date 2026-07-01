#include "bpfledger.h"
#include <linux/bpf.h>

/**
 * is_feature_probe - Stateless detection of BPF feature probe programs
 * probes have hardcoded instruction patterns from the canonical sources:
 *   - libbpf/src/libbpf_probes.c  [prog-type, helper, map probes]
 *   - bpftool/src/feature.c       [misc: loops, ISA, limit probes]
 *
 * Returns: true if this program is a known feature probe pattern
 */
bool is_feature_probe(struct bpf_prog *prog) {
  struct bpf_insn *insn;

  if (unlikely(!prog || !prog->aux))
    return false;

  /* programs using 2+ maps are real programs ! not probes based on search in
   * libbpf
   * bpftrace
   * bpftool
   * */

  if (prog->aux->used_map_cnt >= 2)
    return false;

  /* The few map-using probes (global_data, prog_bind_map, ldimm64_off)
   * are all short SOCKET_FILTER programs with exactly 1 map.
   */

  if (prog->aux->used_map_cnt == 1) {
    if (prog->type != BPF_PROG_TYPE_SOCKET_FILTER)
      return false;
    if (prog->len > 5)
      return false;
    return true;
  }

  /* 2-instruction probes: prog-type & helper
   * libbpf_probe_bpf_prog_type():  mov r0, 0; exit
   * libbpf_probe_bpf_helper():     call helper; exit
   * bpftool probe_prog_type_ifindex(): mov r0, 2; exit
   */
  if (prog->len <= 2)
    return true;

  /* libbpf probe_kern_probe_read_kernel: 6 insns, TRACEPOINT
   *   r1 = r10; r1 += -8; r2 = 8; r3 = 0; call probe_read_kernel; exit
   */

  if (prog->len == 6 && prog->type == BPF_PROG_TYPE_TRACEPOINT) {
    insn = prog->insnsi;
    if (insn[0].code == (BPF_ALU64 | BPF_MOV | BPF_X) &&
        insn[0].dst_reg == BPF_REG_1 && insn[0].src_reg == BPF_REG_10 &&
        insn[1].code == (BPF_ALU64 | BPF_ADD | BPF_K) &&
        insn[1].dst_reg == BPF_REG_1 && insn[1].imm == -8 &&
        insn[2].code == (BPF_ALU64 | BPF_MOV | BPF_K) &&
        insn[2].dst_reg == BPF_REG_2 && insn[2].imm == 8 &&
        insn[3].code == (BPF_ALU64 | BPF_MOV | BPF_K) &&
        insn[3].dst_reg == BPF_REG_3 && insn[3].imm == 0 &&
        insn[4].code == (BPF_JMP | BPF_CALL) && insn[4].dst_reg == 0 &&
        insn[4].src_reg == 0 && insn[5].code == (BPF_JMP | BPF_EXIT))
      return true;
  }

  /* libbpf probe_kern_arg_ctx_tag: 4 insns, KPROBE
   *   call_rel(+1); exit; call get_func_ip; exit
   */
  if (prog->len == 4 && prog->type == BPF_PROG_TYPE_KPROBE) {
    insn = prog->insnsi;
    if (insn[0].code == (BPF_JMP | BPF_CALL) &&
        insn[0].src_reg == BPF_PSEUDO_CALL &&
        insn[1].code == (BPF_JMP | BPF_EXIT) &&
        insn[2].code == (BPF_JMP | BPF_CALL) && insn[2].src_reg == 0 &&
        insn[3].code == (BPF_JMP | BPF_EXIT))
      return true;
  }

  /* libbpf probe_kern_arg_ctx_tag: 3 insns, KPROBE
   *   call_rel(+1); exit; exit
   */
  if (prog->len == 3 && prog->type == BPF_PROG_TYPE_KPROBE) {
    insn = prog->insnsi;
    if (insn[0].code == (BPF_JMP | BPF_CALL) &&
        insn[0].src_reg == BPF_PSEUDO_CALL &&
        insn[1].code == (BPF_JMP | BPF_EXIT) &&
        insn[2].code == (BPF_JMP | BPF_EXIT))
      return true;
  }

  /* 4-instruction probes: loops, ISA v2/v3
   * probe_bounded_loops():         mov r0,10; sub r0,1; jne r0,0,-2; exit
   * probe_v2_isa_extension():      mov r0,0; jlt r0,0,1; mov r0,1; exit
   * probe_v3_isa_extension():      mov r0,0; jlt32 r0,0,1; mov r0,1; exit
   */
  if (prog->len == 4 && prog->type == BPF_PROG_TYPE_SOCKET_FILTER) {
    insn = prog->insnsi;
    if (!insn)
      return false;

    if ((insn[0].code == 0xb7 && insn[0].imm == 10 && insn[1].code == 0x07 &&
         insn[1].dst_reg == 0 && insn[1].imm == 1 && insn[2].code == 0x15 &&
         insn[2].dst_reg == 0 && insn[2].off == -2 &&
         insn[3].code == 0x95) || /* loop */

        (insn[0].code == 0xb7 && insn[0].dst_reg == 0 && insn[0].imm == 0 &&
         insn[1].code == 0xa5 && insn[1].dst_reg == 0 && insn[1].off == 1 &&
         insn[2].code == 0xb7 && insn[2].dst_reg == 0 && insn[2].imm == 1 &&
         insn[3].code == 0x95) || /* v2 */

        (insn[0].code == 0xb7 && insn[0].dst_reg == 0 && insn[0].imm == 0 &&
         insn[1].code == 0xb5 && insn[1].dst_reg == 0 && insn[1].off == 1 &&
         insn[2].code == 0xb7 && insn[2].dst_reg == 0 && insn[2].imm == 1 &&
         insn[3].code == 0x95)) /* v3 */
      return true;
  }

  /* 5-instruction probe: ISA v4
   * probe_v4_isa_extension():      mov r0,0; jeq32 r0,1,1; ja 1; mov r0,1; exit
   */
  if (prog->len == 5 && prog->type == BPF_PROG_TYPE_SOCKET_FILTER) {
    insn = prog->insnsi;
    if (!insn)
      return false;

    if (insn[0].code == 0xb7 && insn[0].dst_reg == 0 && insn[0].imm == 0 &&
        insn[1].code == 0x35 && insn[1].dst_reg == 0 && insn[1].imm == 1 &&
        insn[1].off == 1 && insn[2].code == 0x06 &&
        insn[2].off == 1 && /* BPF_JMP32 | BPF_JA */
        insn[3].code == 0xb7 && insn[3].dst_reg == 0 && insn[3].imm == 1 &&
        insn[4].code == 0x95)
      return true;
  }

  /* bpftool large_insn_limit probe */
  if (prog->len == 4097 && prog->type == BPF_PROG_TYPE_SOCKET_FILTER)
    return true;

  if (prog->len <= 6) {
    insn = prog->insnsi;
    if (insn[prog->len - 1].code == (BPF_JMP | BPF_EXIT))
      return true;
  }

  return false;
}
