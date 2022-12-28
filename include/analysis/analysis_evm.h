#ifndef ANALYSIS_EVM_H
#define ANALYSIS_EVM_H

#include <rz_analysis.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include <rz_types.h>
#include <rz_util.h>
#include <string.h>
#include "evm_consts.h"

static int evm_anop(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
                    const ut8 *data, int len, RzAnalysisOpMask mask);

static bool evm_analysis_init(void **user);

static bool evm_analysis_fini(void *user);

#endif /* ANALYSIS_EVM_H */
