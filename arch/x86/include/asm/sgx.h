/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_SGX_H
#define _ASM_X86_SGX_H

#include <linux/types.h>

struct sgx_pageinfo;

#if IS_ENABLED(CONFIG_KVM_INTEL)
int sgx_ecreate(struct sgx_pageinfo *pageinfo, void __user *secs, int *trapnr);
int sgx_einit(void __user *sigstruct, void __user *token,
	      void __user *secs, u64 *lepubkeyhash, int *trapnr);
#endif

#endif /* _ASM_X86_SGX_H */
