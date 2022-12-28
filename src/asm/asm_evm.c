#include "asm/asm_evm.h"

RzAsmPlugin rz_asm_plugin_evm = {.name = "evm",
                                 .license = "LGPL3",
                                 .desc = "Ethereum Virtual Machine",
                                 .arch = "evm",
                                 .bits = 256,
                                 .endian = RZ_SYS_ENDIAN_LITTLE,
                                 .disassemble = &disassemble};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
    .type = RZ_LIB_TYPE_ASM, .data = &rz_asm_plugin_evm, .version = RZ_VERSION};
#endif

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
  if (len <= 0) {
    return -1;
  }

  op->size = 1;
  ut8 opcode = buf[0];

  const char *name = opnames[opcode];
  if (name) {
    rz_strbuf_setf(&op->buf_asm, "%s", name);
  } else if (EVM_OP_PUSH1 <= opcode && opcode <= EVM_OP_PUSH32) {

    int dlen = opcode - EVM_OP_PUSH1 + 1;
    op->size = dlen + 1;
    if (len < op->size) {
      return -1;
    }

    char *hexbuf = malloc(dlen * 2 + 1);
    if (!hexbuf) {
      return -1;
    }

    rz_hex_bin2str(buf + 1, dlen, hexbuf);
    rz_strbuf_setf(&op->buf_asm, "push%d 0x%s", dlen, hexbuf);
  } else if (EVM_OP_DUP1 <= opcode && opcode <= EVM_OP_DUP16) {
    rz_strbuf_setf(&op->buf_asm, "dup%d", opcode - EVM_OP_DUP1 + 1);
  } else if (EVM_OP_SWAP1 <= opcode && opcode <= EVM_OP_SWAP16) {
    rz_strbuf_setf(&op->buf_asm, "swap%d", opcode - EVM_OP_SWAP1 + 1);
  } else if (EVM_OP_LOG0 <= opcode && opcode <= EVM_OP_LOG4) {
    rz_strbuf_setf(&op->buf_asm, "log%d", opcode - EVM_OP_LOG0);
  } else {
    rz_strbuf_setf(&op->buf_asm, "unassigned");
  }

  return op->size;
}
