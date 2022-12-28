#ifndef ASM_EVM_H
#define ASM_EVM_H

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>
#include "evm_consts.h"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len);

#endif /* ASM_EVM_H */
