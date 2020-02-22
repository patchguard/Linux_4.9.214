// SPDX-License-Identifier: GPL-2.0

#include <linux/cdev.h>
#include <linux/mm.h>
#include <linux/mman.h>
//#include <linux/sched/signal.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <uapi/asm/sgx.h>
#include <linux/miscdevice.h>
#include <asm/uaccess.h>

#include "encls.h"
#include "sgx.h"
#include "virt.h"

#define ENCLS_FAULT_FLAG 0x40000000


/**
 * encls_faulted() - Check if ENCLS leaf function faulted
 * @ret:	the return value of an ENCLS leaf function call
 *
 * Return: true if the fault flag is set
 */
static inline bool encls_faulted(int ret)
{
	return (ret & ENCLS_FAULT_FLAG) != 0;
}

struct sgx_virt_epc_page {
	struct sgx_epc_page *epc_page;
};

struct sgx_virt_epc {
	struct radix_tree_root page_tree;
	struct rw_semaphore lock;
};

static inline unsigned long sgx_virt_epc_calc_index(struct vm_area_struct *vma,
						    unsigned long addr)
{
	return vma->vm_pgoff + PFN_DOWN(addr - vma->vm_start);
}

static struct sgx_virt_epc_page *__sgx_virt_epc_fault(struct sgx_virt_epc *epc,
						      struct vm_area_struct *vma,
						      unsigned long addr)
{
	struct sgx_virt_epc_page *page;
	struct sgx_epc_page *epc_page;
	unsigned long index;
	int ret;

	index = sgx_virt_epc_calc_index(vma, addr);

	page = radix_tree_lookup(&epc->page_tree, index);
	if (page) {
		if (page->epc_page)
			return page;
	} else {
		page = kzalloc(sizeof(*page), GFP_KERNEL);
		if (!page)
			return ERR_PTR(-ENOMEM);

		ret = radix_tree_insert(&epc->page_tree, index, page);
		if (unlikely(ret)) {
			kfree(page);
			return ERR_PTR(ret);
		}
	}

	epc_page = sgx_alloc_page(&epc, false);
	if (IS_ERR(epc_page))
		return ERR_CAST(epc_page);

	ret = vm_insert_pfn(vma, addr, PFN_DOWN(epc_page->desc));
	//if (unlikely(ret != VM_FAULT_NOPAGE)) {
	if (ret) {
		sgx_free_page(epc_page);
		return ERR_PTR(-EFAULT);
	}

	page->epc_page = epc_page;

	return page;
}

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

#define LINUX_VERSION_CODE KERNEL_VERSION(4,9,214)

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,1,0))
static unsigned int sgx_virt_epc_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct sgx_virt_epc *epc = (struct sgx_virt_epc *)vma->vm_private_data;
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
static int sgx_virt_epc_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct sgx_virt_epc *epc = (struct sgx_virt_epc *)vma->vm_private_data;
#else
static int sgx_virt_epc_fault(struct vm_area_struct *vma, struct vm_fault *vmf) 
{
	struct sgx_virt_epc *epc = (struct sgx_virt_epc *)vma->vm_private_data;
#endif

//static vm_fault_t sgx_virt_epc_fault(struct vm_fault *vmf)
//static int sgx_virt_epc_fault(struct vm_fault *vmf)
//{
	struct sgx_virt_epc_page *page;

	down_write(&epc->lock);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))
	page = __sgx_virt_epc_fault(epc, vma, vmf->address);
#else
	page = __sgx_virt_epc_fault(epc, vma, (unsigned long)vmf->virtual_address);
#endif

	up_write(&epc->lock);

	if (!IS_ERR(page) || signal_pending(current))
		return VM_FAULT_NOPAGE;

	if (PTR_ERR(page) == -EBUSY && (vmf->flags & FAULT_FLAG_ALLOW_RETRY)) {
		up_read(&vma->vm_mm->mmap_sem);
		return VM_FAULT_RETRY;
	}

	return VM_FAULT_SIGBUS;
}

static struct sgx_virt_epc_page *sgx_virt_epc_get_page(struct sgx_virt_epc *epc,
						       unsigned long index)
{
	struct sgx_virt_epc_page *page;

	down_read(&epc->lock);
	page = radix_tree_lookup(&epc->page_tree, index);
	if (!page || !page->epc_page)
		page = ERR_PTR(-EFAULT);
	up_read(&epc->lock);

	return page;
}

static int sgx_virt_epc_access(struct vm_area_struct *vma, unsigned long start,
			       void *buf, int len, int write)
{
	/* EDBG{RD,WR} are naturally sized, i.e. always 8-byte on 64-bit. */
	unsigned char data[sizeof(unsigned long)];
	struct sgx_virt_epc_page *page;
	struct sgx_virt_epc *epc;
	unsigned long addr, index;
	int offset, cnt, i;
	int ret = 0;
	void *p;

	epc = vma->vm_private_data;

	for (i = 0; i < len && !ret; i += cnt) {
		addr = start + i;
		if (i == 0 || PFN_DOWN(addr) != PFN_DOWN(addr - cnt))
			index = sgx_virt_epc_calc_index(vma, addr);

		page = sgx_virt_epc_get_page(epc, index);

		/*
		 * EDBG{RD,WR} require an active enclave, and given that VMM
		 * EPC oversubscription isn't supported, a not-present EPC page
		 * means the guest hasn't accessed the page and therefore can't
		 * possibility have added the page to an enclave.
		 */
		if (IS_ERR(page))
			return PTR_ERR(page);

		offset = addr & (sizeof(unsigned long) - 1);
		addr = ALIGN_DOWN(addr, sizeof(unsigned long));
		cnt = min((int)sizeof(unsigned long) - offset, len - i);

		p = sgx_epc_addr(page->epc_page) + (addr & ~PAGE_MASK);

		/* EDBGRD for read, or to do RMW for a partial write. */
		if (!write || cnt != sizeof(unsigned long))
			ret = __edbgrd(p, (void *)data);

		if (!ret) {
			if (write) {
				memcpy(data + offset, buf + i, cnt);
				ret = __edbgwr(p, (void *)data);
			} else {
				memcpy(buf + i, data + offset, cnt);
			}
		}
	}

	if (ret)
		return -EIO;
	return i;
}

const struct vm_operations_struct sgx_virt_epc_vm_ops = {
	.fault = sgx_virt_epc_fault,
	.access = sgx_virt_epc_access,
};

static int sgx_virt_epc_mmap(struct file *file, struct vm_area_struct *vma)
{
	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	vma->vm_ops = &sgx_virt_epc_vm_ops;
	vma->vm_flags |= VM_PFNMAP | VM_IO | VM_DONTDUMP;
	vma->vm_private_data = file->private_data;

	return 0;
}

static int sgx_virt_epc_release(struct inode *inode, struct file *file)
{
	struct sgx_virt_epc *epc = file->private_data;
	struct radix_tree_iter iter;
	struct sgx_virt_epc_page *page;
	void **slot;

	LIST_HEAD(secs_pages);

	radix_tree_for_each_slot(slot, &epc->page_tree, &iter, 0) {
		page = *slot;
		if (page->epc_page )
	        {
       	               	sgx_free_page(page->epc_page);
       	               	continue;
                }
		kfree(page);
		radix_tree_delete(&epc->page_tree, iter.index);
	}

	/*
	 * Because we don't track which pages are SECS pages, it's possible
	 * for EREMOVE to fail, e.g. a SECS page can have children if a VM
	 * shutdown unexpectedly.  Retry all failed pages after iterating
	 * through the entire tree, at which point all children should be
	 * removed and the SECS pages can be nuked as well.
	 */
	radix_tree_for_each_slot(slot, &epc->page_tree, &iter, 0) {
		page = *slot;
		if (!(WARN_ON(!page->epc_page)))
			sgx_free_page(page->epc_page);
		radix_tree_delete(&epc->page_tree, iter.index);
	}

	kfree(epc);

	return 0;
}

static int sgx_virt_epc_open(struct inode *inode, struct file *file)
{
	struct sgx_virt_epc *epc;

	epc = kzalloc(sizeof(struct sgx_virt_epc), GFP_KERNEL);
	if (!epc)
		return -ENOMEM;

	init_rwsem(&epc->lock);
	INIT_RADIX_TREE(&epc->page_tree, GFP_KERNEL);

	file->private_data = epc;

	return 0;
}

static const struct file_operations sgx_virt_epc_fops = {
	.owner			= THIS_MODULE,
	.open			= sgx_virt_epc_open,
	.release		= sgx_virt_epc_release,
	.mmap			= sgx_virt_epc_mmap,
};

static struct miscdevice sgx_dev_virt_epc = {
        .minor = MISC_DYNAMIC_MINOR,
        .name = "virt_epc",
        .nodename = "sgx/virt_epc",
        .fops = &sgx_virt_epc_fops,
};



int __init sgx_virt_epc_init(void)
{
       int ret = 0;

       ret = misc_register(&sgx_dev_virt_epc);
        if (ret) {
                pr_err("Creating /dev/sgx/virt_epc failed with %d.\n", ret);
                return ret;
        }

	return 0;
}

#if IS_ENABLED(CONFIG_KVM_INTEL)
int sgx_ecreate(struct sgx_pageinfo *pageinfo, void __user *secs, int *trapnr)
{
	int ret;

	__uaccess_begin();
	ret = __ecreate(pageinfo, (void *)secs);
	__uaccess_end();

	if (encls_faulted(ret)) {
		*trapnr = ENCLS_TRAPNR(ret);
		return -EFAULT;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(sgx_ecreate);

static int __sgx_einit(void __user *sigstruct, void __user *token,
		       void __user *secs)
{
	int ret;

	__uaccess_begin();
	ret =  __einit((void *)sigstruct, (void *)token, (void *)secs);
	__uaccess_end();
	return ret;
}

int sgx_einit(void __user *sigstruct, void __user *token,
	      void __user *secs, u64 *lepubkeyhash, int *trapnr)
{
	int ret;

	if (!boot_cpu_has(X86_FEATURE_SGX_LC)) {
		ret = __sgx_einit(sigstruct, token, secs);
	} else {
		preempt_disable();
		sgx_update_lepubkeyhash_msrs(lepubkeyhash, false);
		ret = __sgx_einit(sigstruct, token, secs);
		if (ret == SGX_INVALID_EINITTOKEN) {
			sgx_update_lepubkeyhash_msrs(lepubkeyhash, true);
			ret = __sgx_einit(sigstruct, token, secs);
		}
		preempt_enable();
	}

	if (encls_faulted(ret)) {
		*trapnr = ENCLS_TRAPNR(ret);
		return -EFAULT;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(sgx_einit);
#endif
