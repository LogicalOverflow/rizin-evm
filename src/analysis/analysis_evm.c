#include "analysis/analysis_evm.h"

RzAnalysisPlugin rz_analysis_plugin_evm = {
    .name = "evm",
    .desc = "Ethereum Virtual Machine analysis plugin",
    .license = "LGPL3",
    .arch = "evm",
    .bits = 256,
    .init = evm_analysis_init,
    .fini = evm_analysis_fini,
    .op = &evm_anop,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {.type = RZ_LIB_TYPE_ANALYSIS,
                                   .data = &rz_analysis_plugin_evm,
                                   .version = RZ_VERSION};
#endif

struct evm_analysis_info {
  ut64 last_push;
  bool push_valid;
};

static struct evm_analysis_info *evm_ai = NULL;

// These constants based on from anal_evm.c in radare2-extras (LGPL3 licensed)
static unsigned opcodes_types[] = {
    [EVM_OP_STOP] = RZ_ANALYSIS_OP_TYPE_RET,
    [EVM_OP_ADD] = RZ_ANALYSIS_OP_TYPE_ADD,
    [EVM_OP_MUL] = RZ_ANALYSIS_OP_TYPE_MUL,
    [EVM_OP_SUB] = RZ_ANALYSIS_OP_TYPE_SUB,
    [EVM_OP_DIV] = RZ_ANALYSIS_OP_TYPE_DIV,
    [EVM_OP_SDIV] = RZ_ANALYSIS_OP_TYPE_DIV,
    [EVM_OP_MOD] = RZ_ANALYSIS_OP_TYPE_MOD,
    [EVM_OP_SMOD] = RZ_ANALYSIS_OP_TYPE_MOD,
    [EVM_OP_ADDMOD] = RZ_ANALYSIS_OP_TYPE_ADD,
    [EVM_OP_MULMOD] = RZ_ANALYSIS_OP_TYPE_MUL,
    [EVM_OP_EXP] = RZ_ANALYSIS_OP_TYPE_MUL,
    [EVM_OP_SIGNEXTEND] = RZ_ANALYSIS_OP_TYPE_CAST,
    [EVM_OP_LT] = RZ_ANALYSIS_OP_TYPE_COND,
    [EVM_OP_GT] = RZ_ANALYSIS_OP_TYPE_COND,
    [EVM_OP_SLT] = RZ_ANALYSIS_OP_TYPE_COND,
    [EVM_OP_SGT] = RZ_ANALYSIS_OP_TYPE_COND,

    [EVM_OP_EQ] = RZ_ANALYSIS_OP_TYPE_CMP,
    [EVM_OP_ISZERO] = RZ_ANALYSIS_OP_TYPE_CMP,
    [EVM_OP_AND] = RZ_ANALYSIS_OP_TYPE_AND,
    [EVM_OP_OR] = RZ_ANALYSIS_OP_TYPE_OR,
    [EVM_OP_XOR] = RZ_ANALYSIS_OP_TYPE_XOR,
    [EVM_OP_NOT] = RZ_ANALYSIS_OP_TYPE_NOT,
    [EVM_OP_BYTE] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_SHA3] = RZ_ANALYSIS_OP_TYPE_CRYPTO,

    [EVM_OP_ADDRESS] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_BALANCE] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_ORIGIN] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_CALLER] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_CALLVALUE] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_CALLDATALOAD] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_CALLDATASIZE] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_CALLDATACOPY] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_CODESIZE] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_CODECOPY] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_GASPRICE] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_EXTCODESIZE] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_EXTCODECOPY] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_RETURNDATASIZE] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_RETURNDATACOPY] = RZ_ANALYSIS_OP_TYPE_STORE,

    [EVM_OP_BLOCKHASH] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_COINBASE] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_TIMESTAMP] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_NUMBER] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_DIFFICULTY] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_GASLIMIT] = RZ_ANALYSIS_OP_TYPE_CRYPTO,

    [EVM_OP_POP] = RZ_ANALYSIS_OP_TYPE_POP,
    [EVM_OP_MLOAD] = RZ_ANALYSIS_OP_TYPE_LOAD,
    [EVM_OP_MSTORE] = RZ_ANALYSIS_OP_TYPE_STORE,
    [EVM_OP_MSTORE8] = RZ_ANALYSIS_OP_TYPE_STORE,
    [EVM_OP_SLOAD] = RZ_ANALYSIS_OP_TYPE_LOAD,
    [EVM_OP_SSTORE] = RZ_ANALYSIS_OP_TYPE_STORE,
    [EVM_OP_JUMP] = RZ_ANALYSIS_OP_TYPE_JMP,
    [EVM_OP_JUMPI] = RZ_ANALYSIS_OP_TYPE_CJMP,
    [EVM_OP_PC] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_MSIZE] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_GAS] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_JUMPDEST] = RZ_ANALYSIS_OP_TYPE_NOP,

    [EVM_OP_PUSH1] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH2] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH3] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH4] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH5] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH6] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH7] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH8] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH9] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH10] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH11] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH12] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH13] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH14] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH15] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH16] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH17] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH18] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH19] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH20] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH21] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH22] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH23] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH24] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH25] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH26] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH27] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH28] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH29] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH30] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH31] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_PUSH32] = RZ_ANALYSIS_OP_TYPE_PUSH,
    [EVM_OP_DUP1] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_DUP2] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_DUP3] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_DUP4] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_DUP5] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_DUP6] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_DUP7] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_DUP8] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_DUP9] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_DUP10] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_DUP11] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_DUP12] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_DUP13] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_DUP14] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_DUP15] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_DUP16] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_SWAP1] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_SWAP2] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_SWAP3] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_SWAP4] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_SWAP5] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_SWAP6] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_SWAP7] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_SWAP8] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_SWAP9] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_SWAP10] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_SWAP11] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_SWAP12] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_SWAP13] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_SWAP14] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_SWAP15] = RZ_ANALYSIS_OP_TYPE_MOV,
    [EVM_OP_SWAP16] = RZ_ANALYSIS_OP_TYPE_MOV,

    [EVM_OP_LOG0] = RZ_ANALYSIS_OP_TYPE_TRAP,
    [EVM_OP_LOG1] = RZ_ANALYSIS_OP_TYPE_TRAP,
    [EVM_OP_LOG2] = RZ_ANALYSIS_OP_TYPE_TRAP,
    [EVM_OP_LOG3] = RZ_ANALYSIS_OP_TYPE_TRAP,
    [EVM_OP_LOG4] = RZ_ANALYSIS_OP_TYPE_TRAP,

    [EVM_OP_CREATE] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_CALL] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_CALLCODE] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_RETURN] = RZ_ANALYSIS_OP_TYPE_RET,
    [EVM_OP_DELEGATECALL] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
    [EVM_OP_REVERT] = RZ_ANALYSIS_OP_TYPE_RET,
    [EVM_OP_SELFDESTRUCT] = RZ_ANALYSIS_OP_TYPE_CRYPTO,
};

static int evm_op_get_size(const ut8 opcode) {
  if (EVM_OP_PUSH1 <= opcode && opcode <= EVM_OP_PUSH32) {
    return opcode - EVM_OP_PUSH1 + 2;
  }
  return 1;
}

static int evm_anop(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
                    const ut8 *data, int len, RzAnalysisOpMask mask) {
  if (len <= 0) {
    return 0;
  }

  ut8 opcode = data[0];
  int size = evm_op_get_size(opcode);
  if (len <= size) {
    return 0;
  }

  memset(op, '\0', sizeof(RzAnalysisOp));
  op->size = size;
  op->addr = addr;

  op->type = opcodes_types[opcode];
  if (!op->type) {
    op->type = RZ_ANALYSIS_OP_TYPE_UNK;
  }
  op->jump = -1;
  op->fail = -1;
  op->ptr = -1;
  op->val = -1;
  switch (opcode) {
  case EVM_OP_JUMP:
  case EVM_OP_JUMPI:

    op->fail = addr + 1;

    if (evm_ai->push_valid) {
      op->jump = evm_ai->last_push;
    } else {
      bool is_cond = EVM_OP_JUMPI == opcode;
      op->type = is_cond ? RZ_ANALYSIS_OP_TYPE_UCJMP : RZ_ANALYSIS_OP_TYPE_UJMP;
    }
    break;
  case EVM_OP_MLOAD:
  case EVM_OP_MSTORE:
  case EVM_OP_MSTORE8:
    if (evm_ai->push_valid) {
      op->ptr = evm_ai->last_push;
    }
    break;
  default:
    break;
  }

  if (EVM_OP_PUSH1 <= opcode && opcode <= EVM_OP_PUSH8) {
    // ut8 buf[8];
    // memset(buf, 0, 8);
    // memcpy(buf + 9 - size, data + 1, size - 1);

    const int bits = 8 * (size - 1);
    evm_ai->last_push = rz_read_be64(data+1) >> (64 - bits);
    evm_ai->push_valid = true;
  } else if (opcode != EVM_OP_JUMPDEST) {
    evm_ai->push_valid = false;
  }

  return op->size;
}

static bool evm_analysis_init(void **user) {
  evm_ai = RZ_NEW0(struct evm_analysis_info);
  if (evm_ai == NULL) {
    return false;
  }

  evm_ai->last_push = 0;
  evm_ai->push_valid = false;

  *user = evm_ai;
  return true;
}

static bool evm_analysis_fini(void *user) {
  rz_return_val_if_fail(user, false);
  free(user);
  evm_ai = NULL;
  return true;
}
