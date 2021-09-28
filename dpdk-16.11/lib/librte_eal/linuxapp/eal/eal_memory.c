/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*   BSD LICENSE
 *
 *   Copyright(c) 2013 6WIND.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of 6WIND S.A. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/file.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <signal.h>
#include <setjmp.h>

#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_eal_memconfig.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_common.h>
#include <rte_string_fns.h>

#include "eal_private.h"
#include "eal_internal_cfg.h"
#include "eal_filesystem.h"
#include "eal_hugepages.h"

#define PFN_MASK_SIZE	8

#ifdef RTE_LIBRTE_XEN_DOM0
int rte_xen_dom0_supported(void)
{
	return internal_config.xen_dom0_support;
}
#endif

/**
 * @file
 * Huge page mapping under linux
 *
 * To reserve a big contiguous amount of memory, we use the hugepage
 * feature of linux. For that, we need to have hugetlbfs mounted. This
 * code will create many files in this directory (one per page) and
 * map them in virtual memory. For each page, we will retrieve its
 * physical address and remap it in order to have a virtual contiguous
 * zone as well as a physical contiguous zone.
 */

static uint64_t baseaddr_offset;

static unsigned proc_pagemap_readable;

#define RANDOMIZE_VA_SPACE_FILE "/proc/sys/kernel/randomize_va_space"

/*******************************************************
  ������:		test_proc_pagemap_readable
  ��������: 	�����ڴ�������Ϣ�Ƿ�ɶ�
  ��������: 	
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static void
test_proc_pagemap_readable(void)
{
	int fd = open("/proc/self/pagemap", O_RDONLY);

	/*ͨ����ȡ/proc/self/pagemapҳ���ļ����õ��������������ַ�������ַ��ӳ���ϵ*/
	if (fd < 0) 
	{
		RTE_LOG(ERR, EAL,
			"Cannot open /proc/self/pagemap: %s. "
			"virt2phys address translation will not work\n",
			strerror(errno));
		
		return;
	}

	/* Is readable */
	close(fd);
	
	proc_pagemap_readable = 1;
}

/* Lock page in physical memory and prevent from swapping. */
int
rte_mem_lock_page(const void *virt)
{
	unsigned long virtual = (unsigned long)virt;
	int page_size = getpagesize();
	unsigned long aligned = (virtual & ~ (page_size - 1));
	return mlock((void*)aligned, page_size);
}

/*
 * Get physical address of any mapped virtual address in the current process.
 */
phys_addr_t
rte_mem_virt2phy(const void *virtaddr)
{
	int fd, retval;
	uint64_t page, physaddr;
	unsigned long virt_pfn;
	int page_size;
	off_t offset;

	/* when using dom0, /proc/self/pagemap always returns 0, check in
	 * dpdk memory by browsing the memsegs */
	if (rte_xen_dom0_supported()) {
		struct rte_mem_config *mcfg;
		struct rte_memseg *memseg;
		unsigned i;

		mcfg = rte_eal_get_configuration()->mem_config;
		for (i = 0; i < RTE_MAX_MEMSEG; i++) {
			memseg = &mcfg->memseg[i];
			if (memseg->addr == NULL)
				break;
			if (virtaddr > memseg->addr &&
					virtaddr < RTE_PTR_ADD(memseg->addr,
						memseg->len)) {
				return memseg->phys_addr +
					RTE_PTR_DIFF(virtaddr, memseg->addr);
			}
		}

		return RTE_BAD_PHYS_ADDR;
	}

	/* Cannot parse /proc/self/pagemap, no need to log errors everywhere */
	if (!proc_pagemap_readable)
		return RTE_BAD_PHYS_ADDR;

	/* standard page size */
	page_size = getpagesize();

	fd = open("/proc/self/pagemap", O_RDONLY);
	if (fd < 0) {
		RTE_LOG(ERR, EAL, "%s(): cannot open /proc/self/pagemap: %s\n",
			__func__, strerror(errno));
		return RTE_BAD_PHYS_ADDR;
	}

	virt_pfn = (unsigned long)virtaddr / page_size;
	offset = sizeof(uint64_t) * virt_pfn;
	if (lseek(fd, offset, SEEK_SET) == (off_t) -1) {
		RTE_LOG(ERR, EAL, "%s(): seek error in /proc/self/pagemap: %s\n",
				__func__, strerror(errno));
		close(fd);
		return RTE_BAD_PHYS_ADDR;
	}

	retval = read(fd, &page, PFN_MASK_SIZE);
	close(fd);
	if (retval < 0) {
		RTE_LOG(ERR, EAL, "%s(): cannot read /proc/self/pagemap: %s\n",
				__func__, strerror(errno));
		return RTE_BAD_PHYS_ADDR;
	} else if (retval != PFN_MASK_SIZE) {
		RTE_LOG(ERR, EAL, "%s(): read %d bytes from /proc/self/pagemap "
				"but expected %d:\n",
				__func__, retval, PFN_MASK_SIZE);
		return RTE_BAD_PHYS_ADDR;
	}

	/*
	 * the pfn (page frame number) are bits 0-54 (see
	 * pagemap.txt in linux Documentation)
	 */
	physaddr = ((page & 0x7fffffffffffffULL) * page_size)
		+ ((unsigned long)virtaddr % page_size);

	return physaddr;
}

/*
 * For each hugepage in all_hugepage_file_info, fill the physaddr value. We find
 * it by browsing the /proc/self/pagemap special file.
 */
 
/*******************************************************
  ������:		find_physaddrs
  ��������: 	��ҳ�����ַת���������ַ
  				all_hugepage_file_info--ĳ����´�ҳ��ʼ��ַ
  				hugepage_info---ĳ����ҳ��Ϣinfo
  ��������: 	
  ����ֵ  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static int
find_physaddrs(struct hugepage_file *all_hugepage_file_info, struct hugepage_info *hugepage_info)
{
	unsigned i;
	phys_addr_t addr;

	/*����������´�ҳ����*/
	for (i = 0; i < hugepage_info->pages_num[0]; i++) 
	{
		/*��ҳ�����ַת���������ַ*/
		addr = rte_mem_virt2phy(all_hugepage_file_info[i].orig_virtaddr);

		if (addr == RTE_BAD_PHYS_ADDR)
			return -1;

		all_hugepage_file_info[i].physaddr = addr;
	}
	
	return 0;
}

/*
 * Check whether address-space layout randomization is enabled in
 * the kernel. This is important for multi-process as it can prevent
 * two processes mapping data to the same virtual address
 * Returns:
 *    0 - address space randomization disabled
 *    1/2 - address space randomization enabled
 *    negative error code on error
 */

/*******************************************************
  ������:		aslr_enabled
  ��������: 	���̴߳�ҳ�ڴ�attach
  ��������: 	
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static int aslr_enabled(void)
{
	char c;

	/*��/proc/sys/kernel/randomize_va_space ��������ַ�ռ�*/
	int retval, fd = open(RANDOMIZE_VA_SPACE_FILE, O_RDONLY);
	if (fd < 0)
	{
		return -errno;
	}

	/*��ȡһ���ַ�*/
	retval = read(fd, &c, 1);
	close(fd);

	if (retval < 0)
	{
		return -errno;
	}
	
	if (retval == 0)
	{
	
		return -EIO;
	}
	
	switch (c) 
	{
		case '0' : return 0;
		case '1' : return 1;
		case '2' : return 2;

		default: return -EINVAL;
	}
	
}

/*
 * Try to mmap *size bytes in /dev/zero. If it is successful, return the
 * pointer to the mmap'd area and keep *size unmodified. Else, retry
 * with a smaller zone: decrease *size by hugepage_sz until it reaches
 * 0. In this case, return NULL. Note: this function returns an address
 * which is a multiple of hugepage size.
 */
  /*******************************************************
  ������:		get_virtual_area
  ��������: 	��ȡ�����ַ�ռ�,������ӳ��
  ��������: 	size---������´�ҳ��size
  				hugepage_sz---������ҳsize
  ����ֵ	  : 
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static void *get_virtual_area(size_t *size, size_t hugepage_sz)
{
	void *addr;
	int fd;
	long aligned_addr;

	if (internal_config.base_virtaddr != 0) 
	{
		addr = (void*) (uintptr_t) (internal_config.base_virtaddr + baseaddr_offset);
	}
	else 
	{
		addr = NULL;
	}
	
	RTE_LOG(DEBUG, EAL, "Ask a virtual area of 0x%zx bytes\n", *size);

	fd = open("/dev/zero", O_RDONLY);
	if (fd < 0)
	{
		RTE_LOG(ERR, EAL, "Cannot open /dev/zero\n");
		return NULL;
	}
	do 
	{
		/*ӳ�����д�ҳ�����̵�ַ�ռ䣬ֱ��ӳ��ɹ�,��ӳ��һ��ҳ*/
		addr = mmap(addr, (*size) + hugepage_sz, PROT_READ, MAP_PRIVATE, fd, 0);
		if (addr == MAP_FAILED)
		{
			/*ӳ��ʧ���򣬼���ҳ*/
			*size -= hugepage_sz;
		}
	} while (addr == MAP_FAILED && *size > 0);

	/*ȫ��ӳ��ʧ��*/
	if (addr == MAP_FAILED) 
	{
		close(fd);
		RTE_LOG(ERR, EAL, "Cannot get a virtual area: %s\n", strerror(errno));

		return NULL;
	}

	/*ȡ��ӳ��*/
	munmap(addr, (*size) + hugepage_sz);
	
	close(fd);

	/* align addr to a huge page size boundary */
	/*��ַ������ҳ����*/
	aligned_addr = (long)addr;
	aligned_addr += (hugepage_sz - 1);
	aligned_addr &= (~(hugepage_sz - 1));
	addr = (void *)(aligned_addr);

	RTE_LOG(DEBUG, EAL, "Virtual area found at %p (size = 0x%zx)\n", addr, *size);

	/* increment offset */
	/*���ӻ���ַƫ�ƣ�sizeΪ��������д�ҳsize*/
	baseaddr_offset += *size;

	return addr;
}

static sigjmp_buf huge_jmpenv;

static void huge_sigbus_handler(int signo __rte_unused)
{
	siglongjmp(huge_jmpenv, 1);
}

/* Put setjmp into a wrap method to avoid compiling error. Any non-volatile,
 * non-static local variable in the stack frame calling sigsetjmp might be
 * clobbered by a call to longjmp.
 */
static int huge_wrap_sigsetjmp(void)
{
	return sigsetjmp(huge_jmpenv, 1);
}

/*
 * Mmap all hugepages of hugepage table: it first open a file in
 * hugetlbfs, then mmap() hugepage_sz data in it. If orig is set, the
 * virtual address is stored in all_hugepage_file_info[i].orig_virtaddr, else it is stored
 * in all_hugepage_file_info[i].final_virtaddr. The second mapping (when orig is 0) tries to
 * map continguous physical blocks in contiguous virtual blocks.
 */
 /*******************************************************
  ������:		ap_all_hugepages
  ��������: 	��ҳ�ڴ�ӳ�䵽���̵�ַ�ռ䣬��һ����ӳ��һ�����Ĵ�ҳ,������ȡ�ռ䣬��ӳ��ÿ����ҳ
  				ori ��ҳӳ�䣬Ȼ��֤������������ٰ�ҳӳ��
  ��������: 	all_hugepage_file_info---���й���µĴ�ҳ�ṹ����
  				hugepage_info---ĳ����ҳ��Ϣ�ṹ
  ����ֵ	  : ӳ��ɹ��Ĵ�ҳ��
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static unsigned map_all_hugepages(struct hugepage_file *all_hugepage_file_info, struct hugepage_info *hugepage_info, int orig)
{
	int fd;
	unsigned i;
	void *virtaddr;
	void *vma_addr = NULL;
	size_t virmem_size = 0;

	/*������������д�ҳ*/
	for (i = 0; i < hugepage_info->pages_num[0]; i++)
	{
		uint64_t hugepage_sz = hugepage_info->hugepage_sz;

		/*����ĳ�ʼ��������װfilepath�������Ѵ�ҳӳ�䵽���̵�ַ�ռ䣬����¼�����ַ*/
		if (orig) 
		{
			/*����ҳ����ID*/
			all_hugepage_file_info[i].file_id = i;
			all_hugepage_file_info[i].size = hugepage_sz;

			/*��װ��ҳ�ļ�·������/dev/hugepages/rte_smap_1*/
			eal_get_hugefile_path(all_hugepage_file_info[i].filepath, sizeof(all_hugepage_file_info[i].filepath), hugepage_info->hugepage_file_dir, all_hugepage_file_info[i].file_id);

			all_hugepage_file_info[i].filepath[sizeof(all_hugepage_file_info[i].filepath) - 1] = '\0';
		}
		
#ifndef RTE_ARCH_64
		/* for 32-bit systems, don't remap 1G and 16G pages, just reuse
		 * original map address as final map address.
		 */
		 /*�������ҳ��1G��16G�Ĵ�ҳ����ֱ�Ӽ�¼ӳ��������ַΪfinal��ַ*/
		else if ((hugepage_sz == RTE_PGSIZE_1G)
			|| (hugepage_sz == RTE_PGSIZE_16G)) 
		{
			/*��ҳ���������ַ��ӳ�䵽���̵�ַ�ռ�������ַ*/
			/*�Ѿ�ӳ����ֱ�Ӹ�ֵΪfinal��ҳ��ַ*/
			all_hugepage_file_info[i].final_virtaddr = all_hugepage_file_info[i].orig_virtaddr;
			all_hugepage_file_info[i].orig_virtaddr = NULL;
			continue;
		}
#endif
		/*ori=0ʱ*/
		/*��������ҳ*/
		else if (virmem_size == 0) /*������ҳ��һ����ӳ�䵽���̵�ַ�ռ�*/ 
		{
			unsigned j, pages_num;

			/* reserve a virtual area for next contiguous
			 * physical block: count the number of
			 * contiguous physical pages. */

			/*��������´�ҳ��У�������ַ�Ƿ�������*/
			for (j = i+1; j < hugepage_info->pages_num[0] ; j++) 
			{
#ifdef RTE_ARCH_PPC_64
				/* The physical addresses are sorted in
				 * descending order on PPC64 */

				/*�����ַ�Ƿ�����*/
				if (all_hugepage_file_info[j].physaddr != all_hugepage_file_info[j-1].physaddr - hugepage_sz)
					break;
#else
				if (all_hugepage_file_info[j].physaddr != all_hugepage_file_info[j-1].physaddr + hugepage_sz)
					break;
#endif
			}

			/*������ַ����У��ͨ����Ĵ�ҳ����*/
			pages_num = j - i;

			/*������ҳ�´�ҳsize*/
			virmem_size = pages_num * hugepage_sz;

			/* get the biggest virtual memory area up to
			 * virmem_size. If it fails, vma_addr is NULL, so
			 * let the kernel provide the address. */

			/*��ȡ����������д�ҳsize�����ַ�ռ�*/
			/*��������д�ҳ��һ����ӳ�䵽���̵�ַ�ռ䣬��ȡ��ӳ�䣬Ϊ���ǻ�ȡ�㹻�����Ŀռ䣬�����ַ����ӳ�����ҳ�ڴ�*/ 

			/*һ���Ի�ȡ������ҳ�㹻���ӳ��ռ�*/
			vma_addr = get_virtual_area(&virmem_size, hugepage_info->hugepage_sz);

			if (vma_addr == NULL)
			{
				virmem_size = hugepage_sz;
			}
		}

		/* try to create hugepage file */
		/*������ҳ�ļ���Ϊ�˷����ڴ棬/dev/hugepages/rte_smap_1*/
		fd = open(all_hugepage_file_info[i].filepath, O_CREAT | O_RDWR, 0600);
		if (fd < 0)
		{
			RTE_LOG(DEBUG, EAL, "%s(): open failed: %s\n", __func__,
					strerror(errno));
			return i;
		}

		/* map the segment, and populate page tables,
		 * the kernel fills this segment with zeros */

	    /*��ҳ�ļ�ӳ�������ַ�ռ�*/
		/*�ڴ��ļ�ӳ�䵽�ڴ棬һ����ҳ��С����vma_addr��ַ��ʼӳ�䣬��ʼ��ַ����ʵӳ�䣬�ӻ�ȡ�������ַ��ʼӳ�䣬��ͨ��fd����*/
		virtaddr = mmap(vma_addr, hugepage_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, 0);
		if (virtaddr == MAP_FAILED) 
		{
			RTE_LOG(DEBUG, EAL, "%s(): mmap failed: %s\n", __func__, strerror(errno));
			
			close(fd);

			return i;
		}

		/*ҳ�����ַ��¼*/
		if (orig) 
		{
			/*ԭʼ��ҳ��ַӳ�䵽�����ַ�ռ��ַ*/
			all_hugepage_file_info[i].orig_virtaddr = virtaddr;       /*��ҳӳ��ʱ����ҳӳ�䵽���̵�ַ�ռ������ַ*/
		}
		else
		{
			all_hugepage_file_info[i].final_virtaddr = virtaddr;      /*���������ַ���������һ����ӳ�䵽���̵�ַ�ռ䣬�ٷָ���ҳ*/
		}

		if (orig)
		{
			/* In linux, hugetlb limitations, like cgroup, are
			 * enforced at fault time instead of mmap(), even
			 * with the option of MAP_POPULATE. Kernel will send
			 * a SIGBUS signal. To avoid to be killed, save stack
			 * environment here, if SIGBUS happens, we can jump
			 * back here.
			 */
			/*�����ź���ת*/
			if (huge_wrap_sigsetjmp()) 
			{
				RTE_LOG(DEBUG, EAL, "SIGBUS: Cannot mmap more "
					"hugepages of size %u MB\n",
					(unsigned)(hugepage_sz / 0x100000));
				munmap(virtaddr, hugepage_sz);
				close(fd);
				unlink(all_hugepage_file_info[i].filepath);
				return i;
			}
			
			*(int *)virtaddr = 0;
		}


		/* set shared flock on the file. */
		/*�����ļ�Ⱥ��*/
		if (flock(fd, LOCK_SH | LOCK_NB) == -1) 
		{
			RTE_LOG(DEBUG, EAL, "%s(): Locking file failed:%s \n",
				__func__, strerror(errno));
			close(fd);
			return i;
		}

		close(fd);

		/*��һ����ҳ�����ַ���ں˵�ֱַ��ƫ��һ����ҳ size*/
		vma_addr = (char *)vma_addr + hugepage_sz;

		/*��ȥ��ӳ��Ĵ�ҳ*/
		virmem_size -= hugepage_sz;
	}

	return i;
}

/* Unmap all hugepages from original mapping */
 /*******************************************************
  ������:		unmap_all_hugepages_orig
  ��������: 	ȡ��ӳ��
  ��������: 	all_hugepage_file_info---���й���µĴ�ҳ�����ṹ��
				hugepage_info---��ҳ��Ϣhugepage_info,ĳ����µĴ�ҳ�ڴ�
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static int
unmap_all_hugepages_orig(struct hugepage_file *all_hugepage_file_info, struct hugepage_info *hugepage_info)
{
        unsigned i;
        for (i = 0; i < hugepage_info->pages_num[0]; i++)
		{
            if (all_hugepage_file_info[i].orig_virtaddr) 
			{
                munmap(all_hugepage_file_info[i].orig_virtaddr, hugepage_info->hugepage_sz);
                all_hugepage_file_info[i].orig_virtaddr = NULL;
            }
        }
        return 0;
}

/*
 * Parse /proc/self/numa_maps to get the NUMA socket ID for each huge
 * page.
 */

/*******************************************************
  ������:		find_numasocket
  ��������: 	��numa_maps���Ҵ�ҳ���ڵ�socket
  ��������: 	all_hugepage_file_info--ĳ����ҳ���飬�����Ԫ�ص�ַ
  ����ֵ  :     
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static int
find_numasocket(struct hugepage_file *all_hugepage_file_info, struct hugepage_info *hugepage_info)
{
	int socket_id;
	char *end, *nodestr;
	unsigned i, hugepage_count = 0;
	uint64_t virt_addr;
	char buf[BUFSIZ];
	char hugepage_file_dir_str[PATH_MAX];
	FILE *f;

	/*��numͼ,����numa�ڴ���Ϣ*/
	f = fopen("/proc/self/numa_maps", "r");
	if (f == NULL) 
	{
		RTE_LOG(NOTICE, EAL, "cannot open /proc/self/numa_maps,"
				" consider that all memory is in socket_id 0\n");
		return 0;
	}

	/*��ҳ�ļ�·�� /dev/hugepages/rtemap_6138*/
	snprintf(hugepage_file_dir_str, sizeof(hugepage_file_dir_str), "%s/%s", hugepage_info->hugepage_file_dir, internal_config.hugefile_prefix);

	/* parse numa map */
	/*�����ڴ���ص�ͼ*/

	/*��ȡ��ַ7fb2ed5b8000 prefer:1 file=/usr/lib64/libc-2.17.so anon=2 dirty=2 N1=2*/
	while (fgets(buf, sizeof(buf), f) != NULL) 
	{
		/* ignore non huge page */
		/*����ҳ������numa_maps ��*/
		if (strstr(buf, " huge ") == NULL && strstr(buf, hugepage_file_dir_str) == NULL)
		{
			continue;
		}
		
		/* get zone addr */
		/*��ȡ��ҳ�ڴ��ַ, ���ַ���ת����16����*/
		virt_addr = strtoull(buf, &end, 16);
		if (virt_addr == 0 || end == buf)
		{
			RTE_LOG(ERR, EAL, "%s(): error in numa_maps parsing\n", __func__);
			goto error;
		}

		/* get node id (socket id) */

		/*��ȡ�ڵ��ַ���N1=2*/
		nodestr = strstr(buf, " N");
		if (nodestr == NULL) 
		{
			RTE_LOG(ERR, EAL, "%s(): error in numa_maps parsing\n", __func__);
			goto error;
		}
		
		nodestr += 2;
		end = strstr(nodestr, "=");
		if (end == NULL) 
		{
			RTE_LOG(ERR, EAL, "%s(): error in numa_maps parsing\n", __func__);
			goto error;
		}
		end[0] = '\0';
		end = NULL;

		/*��ȡsocket id�� N1=2 �� 2����socket ID ҳ�����ĸ�socketϵͳ�ѻ��ֺ�*/
		socket_id = strtoul(nodestr, &end, 0);
		if ((nodestr[0] == '\0') || (end == NULL) || (*end != '\0')) 
		{
			RTE_LOG(ERR, EAL, "%s(): error in numa_maps parsing\n", __func__);
			goto error;
		}

		/* if we find this page in our mappings, set socket_id */

		/*��ҳsocket ��ֵ*/
		for (i = 0; i < hugepage_info->pages_num[0]; i++)
		{
			void *va = (void *)(unsigned long)virt_addr;

			/*������numa_maps ��ַ���Ǵ�ҳ�ĵ�ַ��˵����ҳ�ѹ�����numa_maps�����ȡsockid*/
			if (all_hugepage_file_info[i].orig_virtaddr == va) 
			{
				all_hugepage_file_info[i].socket_id = socket_id;
				hugepage_count++;
			}
		}
	}

	/*ҳ����δ����������δ���ֵ�map�Ĵ�ҳ*/
	if (hugepage_count < hugepage_info->pages_num[0])
	{
		goto error;
	}
	
	fclose(f);

	return 0;

error:

	fclose(f);
	return -1;
}

static int
cmp_physaddr(const void *a, const void *b)
{
#ifndef RTE_ARCH_PPC_64
	const struct hugepage_file *p1 = (const struct hugepage_file *)a;
	const struct hugepage_file *p2 = (const struct hugepage_file *)b;
#else
	/* PowerPC needs memory sorted in reverse order from x86 */
	const struct hugepage_file *p1 = (const struct hugepage_file *)b;
	const struct hugepage_file *p2 = (const struct hugepage_file *)a;
#endif
	if (p1->physaddr < p2->physaddr)
		return -1;
	else if (p1->physaddr > p2->physaddr)
		return 1;
	else
		return 0;
}

/*
 * Uses mmap to create a shared memory area for storage of data
 * Used in this file to store the hugepage file map on disk
 */
 /*******************************************************
  ������:		create_shared_memory
  ��������: 	fdӳ�䵽���̵�ַ�ռ䣬sizeΪ���д�ҳsize�ṹ
  ��������: 	filename---��ȡ��ҳ����·�� /var/run/rte_hugepage_info	
  				mem_size---��ҳ�ڴ�
  ����ֵ  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static void *
create_shared_memory(const char *filename, const size_t mem_size)
{
	void *retval;
	int fd = open(filename, O_CREAT | O_RDWR, 0666);
	if (fd < 0)
	{
		return NULL;
	}

	/*�޸�fd�ļ�Ϊָ��mem_size��С*/
	if (ftruncate(fd, mem_size) < 0)
	{
		close(fd);
		return NULL;
	}

	/*ӳ�䵽���̵�ַ�ռ�*/
	retval = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	close(fd);

	return retval;
}

/*
 * this copies *active* hugepages from one hugepage table to another.
 * destination is typically the shared memory.
 */

/*******************************************************
  ������:		copy_hugepages_to_shared_mem
  ��������: 	������ҳ��Ϣ�������ڴ�
  ��������: 	dst---hugepage��ҳ�ڴ������ṹ����
  				dest_size--��ҳ����
  				src--all_hugepage_file_info��ʱ��ҳ�ṹ����
  ����ֵ  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static int
copy_hugepages_to_shared_mem(struct hugepage_file * dst, int dest_size, const struct hugepage_file * src, int src_size)
{
	int src_pos, dst_pos = 0;

	for (src_pos = 0; src_pos < src_size; src_pos++) 
	{
		if (src[src_pos].final_virtaddr != NULL)
		{
			/* error on overflow attempt */
			if (dst_pos == dest_size)
			{
				return -1;
			}

			/*��ҳ��Ϣ������hugepage��ҳ�ڴ������ṹ�����ڴ�*/
			memcpy(&dst[dst_pos], &src[src_pos], sizeof(struct hugepage_file));

			dst_pos++;
		}
	}
	return 0;
}

/*******************************************************
  ������:		unlink_hugepage_files
  ��������: 	����ڴ�ʹ�ҳ�ļ��Ĺ���
  ��������: 	all_hugepage_file_info--all_hugepage_file_info��ʱ��ҳ�ṹ����
				num_hugepage_info--��ҳ����
  ����ֵ  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static int unlink_hugepage_files(struct hugepage_file *all_hugepage_file_info,unsigned num_hugepage_info)
{
	unsigned socket, size;
	int page, nrpages = 0;

	/* get total number of hugepages */
	/*�����ҳ��������socket�ϼ���*/
	for (size = 0; size < num_hugepage_info; size++)
	{
		for (socket = 0; socket < RTE_MAX_NUMA_NODES; socket++)
		{
			nrpages += internal_config.hugepage_info[size].pages_num[socket];
		}
	}
	
	/*��ҳ���ļ�ϵͳ�����������ɾ���ļ�ϵͳ�еĴ�ҳ�ļ�*/
	for (page = 0; page < nrpages; page++) 
	{
		struct hugepage_file *hp = &all_hugepage_file_info[page];

		if (hp->final_virtaddr != NULL && unlink(hp->filepath)) 
		{
			RTE_LOG(WARNING, EAL, "%s(): Removing %s failed: %s\n",
				__func__, hp->filepath, strerror(errno));
		}
	}
	
	return 0;
}

/*
 * unmaps hugepages that are not going to be used. since we originally allocate
 * ALL hugepages (not just those we need), additional unmapping needs to be done.
 */ 
/*******************************************************
  ������:		unmap_unneeded_hugepages
  ��������: 	����Ҫ�Ĵ�ҳ���ӳ��
  ��������: 	all_hugepage_file_info---���й���µĴ�ҳ�ṹ����
  				hugepage_info---��ʱ��ҳ�����Ϣ�ṹ
  				num_hugepage_info---���й���ҳ����
  ����ֵ  :
  ����޸���:
  �޸�����:     
********************************************************/
static int
unmap_unneeded_hugepages(struct hugepage_file *all_hugepage_file_info,
		struct hugepage_info *hugepage_info,
		unsigned hugepage_type_num)
{
	unsigned socket, type;
	int page, all_type_socket_pages_num = 0;

	/* get total number of hugepages */
	/*�������й���ҳ����������socket�ϴ�ҳ����֮��*/
	for (type = 0; type < hugepage_type_num; type++)
	{
		for (socket = 0; socket < RTE_MAX_NUMA_NODES; socket++)
		{
			all_type_socket_pages_num += internal_config.hugepage_info[type].pages_num[socket];
		}
	}

	/*���й���ҳ����*/
	for (type = 0; type < hugepage_type_num; type++)
	{
		/*����socket*/
		for (socket = 0; socket < RTE_MAX_NUMA_NODES; socket++)
		{
			unsigned pages_found = 0;

			/* traverse until we have unmapped all the unused pages */
			/*�������д�ҳ��δʹ�õĴ�ҳ���ӳ��*/
			for (page = 0; page < all_type_socket_pages_num; page++)
			{
				struct hugepage_file *hugepage = &all_hugepage_file_info[page];

				/* find a page that matches the criteria */
				/*��ҳ�����Ǹ���ҳ*/
				if ((hugepage->size == hugepage_info[type].hugepage_sz) && (hugepage->socket_id == (int) socket)) 
				{
					/* if we skipped enough pages, unmap the rest */

					/*��ҳ����*/
					if (pages_found == hugepage_info[type].pages_num[socket]) 
					{
						uint64_t unmap_len;

						/*��ҳsize*/
						unmap_len = hugepage->size;

						/* get start addr and len of the remaining segment */

						/*ȡ����ҳ��ӳ��*/
						munmap(hugepage->final_virtaddr, (size_t) unmap_len);

						hugepage->final_virtaddr = NULL;
						if (unlink(hugepage->filepath) == -1)
						{
							RTE_LOG(ERR, EAL, "%s(): Removing %s failed: %s\n",
									__func__, hugepage->filepath, strerror(errno));
							return -1;
						}
					} 
					else 
					{
						/* lock the page and skip */
						/*��ҳ����*/
						pages_found++;
					}
				} /* match page */
			} /* foreach page */
		} /* foreach socket */
	} /* foreach pagesize */

	return 0;
}

/*******************************************************
  ������:		get_socket_mem_size
  ��������:     ��ȡsocket���ڴ���size
  ��������: 	all_hugepage_file_info---���й���µĴ�ҳ�ṹ����
				hugepage_info---��ʱ��ҳ�����Ϣ�ṹ
				num_hugepage_info---���й���ҳ����
  ����ֵ  :
  ����޸���:
  �޸�����: 	
********************************************************/
static inline uint64_t get_socket_mem_size(int socket)
{
	uint64_t size = 0;
	unsigned i;

	/*�������й���ҳ,��ȡ��socket���д�ҳ�ڴ�֮��*/
	for (i = 0; i < internal_config.hugepage_type_num; i++)
	{
		struct hugepage_info *hugepage_info = &internal_config.hugepage_info[i];
		
		if (hugepage_info->hugepage_file_dir != NULL)
		{
			size += hugepage_info->hugepage_sz * hugepage_info->pages_num[socket];
		}
	}

	return size;
}

/*
 * This function is a NUMA-aware equivalent of calc_num_pages.
 * It takes in the list of hugepage sizes and the
 * number of pages thereof, and calculates the best number of
 * pages of each size to fulfill the request for <memory> ram
 */

/*******************************************************
  ������:		rte_eal_hugepage_init
  ��������: 	ÿsocket�ִ�ҳ
  ��������: 	socket_mem---ÿsocket�ڴ�size
  				hugepage_info---��ҳ�����Ϣ�ṹ
  				used_hugepage_info---ÿsocket�����ڴ����ڴ��ҳ������ҳ����
  				num_hugepage_info--���й���ҳ����
  ����ֵ  :     used_total_num_pages--�ɹ����ֿ��ô�ҳ����
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static int
calc_num_pages_per_socket(uint64_t * mem_size_per_socket, struct hugepage_info *hugepage_info, struct hugepage_info *used_hugepage_info,unsigned hugepage_type_num)
{
	unsigned socket, j, i = 0;
	unsigned requested, available;
	int used_total_num_pages = 0;
	uint64_t remaining_mem, type_socket_hugepage_mem_size;
	uint64_t total_mem = internal_config.memory;/*socket�����й���ҳ��size*/

	if (hugepage_type_num == 0)
	{
		return -1;
	}
	
	/* if specific memory amounts per socket weren't requested */
	/*û������ÿsocket�ڴ�*/
	if (internal_config.force_sockets == 0)
	{
		int cpu_num_on_per_socket[RTE_MAX_NUMA_NODES];
		size_t socket_default_mem_size, total_size;
		unsigned lcore_id;

		/* Compute number of cores per socket */
		/*����ÿsocket����*/
		memset(cpu_num_on_per_socket, 0, sizeof(cpu_num_on_per_socket));

		/*����ÿ��socketӵ�еĺ���*/
		RTE_LCORE_FOREACH(lcore_id) 
		{					/*��id ת���������ڵ�socket id*/
			cpu_num_on_per_socket[rte_lcore_to_socket_id(lcore_id)]++;
		}

		/*
		 * Automatically spread requested memory amongst detected sockets according
		 * to number of cores from cpu mask present on each socket
		 */
		/*���й���ҳ�ڴ���size*/
		total_size = internal_config.memory;

		/*8��socket*/
		for (socket = 0; socket < RTE_MAX_NUMA_NODES && total_size != 0; socket++)
		{
			/* Set memory amount per socket */
			/*ÿsocket�ڴ�Ĭ�ϴ�С����*/            /*socket ӵ�к���x���ڴ�/�߼����������ָ����к�*/
			socket_default_mem_size = (internal_config.memory * cpu_num_on_per_socket[socket]) / rte_lcore_count();
			/*ÿ��socket���Էֵ����ڴ棬ÿ��CPU���������ڵ�socket�����Գ���128*/

			/* Limit to maximum available memory on socket */
			/*socket�ڴ����ã�ȡ��Сֵ��Ĭ��ֵ��socket��ҳ�ڴ�֮�ͶԱ�*/

			/*socket����ʵ���ڴ��С����ֵ�Ĭ���ڴ��С���Ƚ�*/
			socket_default_mem_size = RTE_MIN(socket_default_mem_size, get_socket_mem_size(socket));

			/*socket�ڴ��¼*/
			mem_size_per_socket[socket] = socket_default_mem_size; /*ÿ��socket �趨�ڴ�sizeֵ��¼*/

			/*����socket���ڴ�size*/
			total_size -= socket_default_mem_size;
		}

		/*
		 * If some memory is remaining, try to allocate it by getting all
		 * available memory from sockets, one after the other
		 */

		
		/*ÿsocket�ڴ�sizeҪռ���������������ڴ�size*/
		/*���ڴ棬����ʣ���ڴ�*/
		for (socket = 0; socket < RTE_MAX_NUMA_NODES && total_size != 0; socket++) 
		{
			/* take whatever is available */
			/*ÿsocket�ڴ�sizeҪռ���������������ڴ�size*/
			/*��鵽���ĸ�socket����ʣ���ڴ棬���ֺ��ʣ��*/
			socket_default_mem_size = RTE_MIN(get_socket_mem_size(socket) - mem_size_per_socket[socket], total_size);

			/* Update sizes */
			/*ÿsocket�ڴ�����*/
			mem_size_per_socket[socket] += socket_default_mem_size;

			total_size -= socket_default_mem_size;
		}
	}

	/*����socket*/
	for (socket = 0; socket < RTE_MAX_NUMA_NODES && total_mem != 0; socket++) 
	{
		/* skips if the memory on specific socket wasn't requested */
		/*�������й���ҳ*/
		for (i = 0; i < hugepage_type_num && mem_size_per_socket[socket] != 0; i++)
		{
			/*��¼��ҳ���ص� /dev/hugepages*/
			used_hugepage_info[i].hugepage_file_dir = hugepage_info[i].hugepage_file_dir;

			/*socket �ֵ��Ĵ�ҳ��*/
			used_hugepage_info[i].pages_num[socket] = RTE_MIN( mem_size_per_socket[socket] / hugepage_info[i].hugepage_sz, hugepage_info[i].pages_num[socket]);

			/*��ǰ�����socket��ҳ�ڴ�*/
			type_socket_hugepage_mem_size = used_hugepage_info[i].pages_num[socket] * used_hugepage_info[i].hugepage_sz;
		
			mem_size_per_socket[socket] -= type_socket_hugepage_mem_size;
			
			total_mem -= type_socket_hugepage_mem_size;

			/*���ֳ�ȥ�Ĵ�ҳ����*/
			used_total_num_pages += used_hugepage_info[i].pages_num[socket];

			/* check if we have met all memory requests */

			/*socket�ϴ�ҳ������*/
			if (mem_size_per_socket[socket] == 0)
			{
				break;
			}
			
			/* check if we have any more pages left at this size, if so
			 * move on to next size */

			/*ǡ�÷���*/
			if (used_hugepage_info[i].pages_num[socket] == hugepage_info[i].pages_num[socket])
			{
				continue;
			}
			
			/* At this point we know that there are more pages available that are
			 * bigger than the memory we want, so lets see if we can get enough
			 * from other page sizes.
			 */
			remaining_mem = 0;

			/*����type��socket��ʣ���ҳ�ڴ�*/
			for (j = i+1; j < hugepage_type_num; j++)
			{
				remaining_mem += hugepage_info[j].hugepage_sz * hugepage_info[j].pages_num[socket];
			}
			
			/* is there enough other memory, if not allocate another page and quit */
			if (remaining_mem < mem_size_per_socket[socket])
			{
				/*socket��ʣ���ڴ�*/
				type_socket_hugepage_mem_size = RTE_MIN(mem_size_per_socket[socket],hugepage_info[i].hugepage_sz);

				/*�ڴ��ȥ*/
				mem_size_per_socket[socket] -= type_socket_hugepage_mem_size;
				total_mem -= type_socket_hugepage_mem_size;

				/*socket�ֵ��Ĵ�ҳ��������*/
				used_hugepage_info[i].pages_num[socket]++;
				
				used_total_num_pages++;

				break; /* we are done with this socket*/
			}
			
		}
		
		/* if we didn't satisfy all memory requirements per socket */
		/*ʣ���ڴ����һ��ҳ�����Էֳ�ȥһ��ҳ�����ڴ�ʣ�࣬˵���ڴ�����쳣������*/
		if (mem_size_per_socket[socket] > 0) 
		{
			/* to prevent icc errors */
			requested = (unsigned) (internal_config.socket_mem[socket] / 0x100000);

			available = requested - ((unsigned) (mem_size_per_socket[socket] / 0x100000));
			
			RTE_LOG(ERR, EAL, "Not enough memory available on socket %u! " "Requested: %uMB, available: %uMB\n", socket, requested, available);

			return -1;
		}
	}

	/* if we didn't satisfy total memory requirements */
	/*������ڴ���ʣ��*/
	if (total_mem > 0)
	{
		requested = (unsigned) (internal_config.memory / 0x100000);
		
		available = requested - (unsigned) (total_mem / 0x100000);

		RTE_LOG(ERR, EAL, "Not enough memory available! Requested: %uMB," " available: %uMB\n", requested, available);

		return -1;
	}
	
	return used_total_num_pages;
}

/*******************************************************
  ������:		eal_get_hugepage_mem_size
  ��������: 	�������й���ҳ��size
  ��������: 	
  ����ֵ  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static inline size_t
eal_get_hugepage_mem_size(void)
{
	uint64_t size = 0;
	unsigned i, j;

	/*������ҳ���*/
	for (i = 0; i < internal_config.hugepage_type_num; i++) 
	{
		struct hugepage_info *hugepage_info = &internal_config.hugepage_info[i];

		if (hugepage_info->hugepage_file_dir != NULL) 
		{
			for (j = 0; j < RTE_MAX_NUMA_NODES; j++)
			{
				size += hugepage_info->hugepage_sz * hugepage_info->pages_num[j];
			}
		}
	}

	return (size < SIZE_MAX) ? (size_t)(size) : SIZE_MAX;
}

static struct sigaction huge_action_old;
static int huge_need_recover;

/*******************************************************
  ������:		rte_eal_hugepage_init
  ��������: 	
  ��������: 	
  ����ֵ  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static void
huge_register_sigbus(void)
{
	sigset_t mask;
	struct sigaction action;

	sigemptyset(&mask);
	sigaddset(&mask, SIGBUS);
	action.sa_flags = 0;
	action.sa_mask = mask;
	action.sa_handler = huge_sigbus_handler;

	huge_need_recover = !sigaction(SIGBUS, &action, &huge_action_old);
}

static void
huge_recover_sigbus(void)
{
	if (huge_need_recover) {
		sigaction(SIGBUS, &huge_action_old, NULL);
		huge_need_recover = 0;
	}
}

/*
 * Prepare physical memory mapping: fill configuration structure with
 * these infos, return 0 on success.
 *  1. map N huge pages in separate files in hugetlbfs
 *  2. find associated physical addr
 *  3. find associated NUMA socket ID
 *  4. sort all huge pages by physical address
 *  5. remap these N huge pages in the correct order
 *  6. unmap the first mapping
 *  7. fill memsegs in configuration with contiguous zones
 */

/*******************************************************
  ������:		rte_eal_hugepage_init
  ��������: 	��ҳ�ڴ��������ڴ�Σ��Ҽ�¼������socket�������ַ�����ַ��ÿ���ڴ���Ͽ����кܶ��ҳ����¼�������ַ�������ַ
  				��ҳӳ�䵽��ַ�ռ䣬���д�ҳ��Ϣ��ֵ���ڴ����ýṹ������ٽ��ӳ�䣬Ϊɶ���ӳ��
  ��������: 	
  ����ֵ  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
int rte_eal_hugepage_init(void)
{
	struct rte_mem_config *mem_cfg;
	struct hugepage_file *all_hugepage = NULL, *all_hugepage_file_info = NULL;
	struct hugepage_info used_hugepage_info[MAX_HUGEPAGE_SIZES];

	uint64_t mem_size_per_socket[RTE_MAX_NUMA_NODES];

	unsigned index;
	int i, j, new_memseg;
	int nr_hugefiles, nr_hugepages = 0;
	void *addr;

	/*�ڴ�������Ϣpagemap�Ƿ�ɶ�����ҳ��ʼ�������ɷ���*/
	test_proc_pagemap_readable();

	memset(used_hugepage_info, 0, sizeof(used_hugepage_info));

	/*��ȡȫ���ڴ����ýṹ�����ļ�ӳ�䵽�ڴ��*/
	/* get pointer to global configuration */
	/*&rte_config ȫ������*/

	/*��ȡ��ҳ�ڴ������ṹ*/
	/* /var/run/rte_config�������ڴ���Ϣ*/
	mem_cfg = rte_eal_get_configuration()->mem_config;

	/* hugetlbfs can be disabled */
	/*�����˷Ǵ�ҳģʽ����ӳ��һ���ڴ��ֱ�ӷ���*/
	if (internal_config.no_hugetlbfs)
	{
		/*ӳ���ҳ�ڴ浽���̵�ַ�ռ䣬����޴�ҳ��internal_config.memory=64M*/
		addr = mmap(NULL, internal_config.memory, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
		if (addr == MAP_FAILED) 
		{
			RTE_LOG(ERR, EAL, "%s: mmap() failed: %s\n", __func__,
					strerror(errno));
			return -1;
		}

		/*�ڴ���Ϣ*/
		mem_cfg->memseg[0].phys_addr   = (phys_addr_t)(uintptr_t)addr;       /*�����ַתΪ�����ַ*/
		mem_cfg->memseg[0].addr        = addr;								 /*�����ַ*/
		mem_cfg->memseg[0].hugepage_sz = RTE_PGSIZE_4K;                      /*��ҳҳ��С*/
		mem_cfg->memseg[0].len         = internal_config.memory;             /*ҳ����*/
		mem_cfg->memseg[0].socket_id   = 0;                                  /*��ҳ�����ĸ�socket*/

		return 0;
	}

/* check if app runs on Xen Dom0 */
    /*�Ƿ�֧��*/
	if (internal_config.xen_dom0_support)
	{
#ifdef RTE_LIBRTE_XEN_DOM0
		/* use dom0_mm kernel driver to init memory */
		/*�������ڴ�����ʼ���ڴ�*/
		if (rte_xen_dom0_memory_init() < 0)
		{
			return -1;
		}
		else
		{
			return 0;
		}
#endif
	}

	/* calculate total number of hugepages available. at this point we haven't
	 * yet started sorting them so they all are on socket 0 */

	/*�������й���ҳ*/                    /*�����*/
	for (i = 0; i < (int) internal_config.hugepage_type_num; i++) 
	{
		/* meanwhile, also initialize used_hugepage_info hugepage sizes in used_hugepage_info */
		/*��¼��ҳsize*/
		used_hugepage_info[i].hugepage_sz = internal_config.hugepage_info[i].hugepage_sz;

		/*���й���ҳ����֮��*/
		nr_hugepages += internal_config.hugepage_info[i].pages_num[0];
	}

	/*
	 * allocate a memory area for hugepage table.
	 * this isn't shared memory yet. due to the fact that we need some
	 * processing done on these pages, shared memory will be created
	 * at a later stage.
	 */

	/*��ʱ���й���ҳ������Ϣ�ṹ*/
	all_hugepage_file_info = malloc(nr_hugepages * sizeof(struct hugepage_file));
	if (all_hugepage_file_info == NULL)
	{
		goto fail;
	}
	
	memset(all_hugepage_file_info, 0, nr_hugepages * sizeof(struct hugepage_file));

	index = 0; /* where we start the current page size entries */

	/*�Ĵ���ע��*/
	huge_register_sigbus();

	/* map all hugepages and sort them */
	/*�������й���ҳ��ӳ�䵽���̵�ַ�ռ䣬ÿ��ҳ��¼�Լ��������ַ*/
	for (i = 0; i < (int)internal_config.hugepage_type_num; i++)
	{
		unsigned hunge_pages_num_old, hunge_pages_num_new;
		struct hugepage_info *hugepage_info;

		/*
		 * we don't yet mark hugepages as used at this stage, so
		 * we just map all hugepages available to the system
		 * all hugepages are still located on socket 0
		 */

		/*��ҳ��Ϣ*/
		hugepage_info = &internal_config.hugepage_info[i];

		/*������ҳ�����ڣ���ҳ��Ϊ0*/
		if (hugepage_info->pages_num[0] == 0)
		{
			continue;
		}
		
		/* map all hugepages available */

		/*������ҳ����*/
		hunge_pages_num_old = hugepage_info->pages_num[0];

	    /*�ڴ�ҳӳ�䵽�����̣�all_hugepage_file_info[index] ���й���ҳ������һ�����飬
	    ����ӳ����Ҫ����filepath���ҵ�ҳӳ�䵽���̵�ַ�ռ䣬��¼��orig_virtaddr*/
		hunge_pages_num_new = map_all_hugepages(&all_hugepage_file_info[index], hugepage_info, 1);

		/*������Ч�Ĵ�ҳ����ҳ��������*/
		if (hunge_pages_num_new < hunge_pages_num_old)
		{
			RTE_LOG(DEBUG, EAL,
				"%d not %d hugepages of size %u MB allocated\n",
				hunge_pages_num_new, hunge_pages_num_old,
				(unsigned)(hugepage_info->hugepage_sz / 0x100000));

			int pages = hunge_pages_num_old - hunge_pages_num_new;

			/*��ҳ�����޸�*/
			nr_hugepages -= pages;

			/*������ҳ�����޸�*/
			hugepage_info->pages_num[0] = hunge_pages_num_new;

			if (hunge_pages_num_new == 0)
			{
				continue;
			}
		}

		/* find physical addresses and sockets for each hugepage */

		/*��ȡ��ҳ�����ַ*/
		if (find_physaddrs(&all_hugepage_file_info[index], hugepage_info) < 0)
		{
			RTE_LOG(DEBUG, EAL, "Failed to find phys addr for %u MB pages\n", (unsigned)(hugepage_info->hugepage_sz / 0x100000));
			goto fail;
		}

		/*��hugepage_info�Ĵ�ҳ��������socket id����ҳ���ص��Ѿ������˴�ҳ���ڵ�socket*/
		if (find_numasocket(&all_hugepage_file_info[index], hugepage_info) < 0)
		{
			RTE_LOG(DEBUG, EAL, "Failed to find NUMA socket for %u MB pages\n", (unsigned)(hugepage_info->hugepage_sz / 0x100000));
			goto fail;
		}

		/*���ݵ�ַ�Դ�ҳ����*/
		qsort(&all_hugepage_file_info[index], hugepage_info->pages_num[0], sizeof(struct hugepage_file), cmp_physaddr);

		/* remap all hugepages */
		/*����ӳ�䱾����´�ҳ*/
		if (map_all_hugepages(&all_hugepage_file_info[index], hugepage_info, 0) != hugepage_info->pages_num[0]) 
		{
			RTE_LOG(ERR, EAL, "Failed to remap %u MB pages\n",
					(unsigned)(hugepage_info->hugepage_sz / 0x100000));
			goto fail;
		}

		/* unmap original mappings */
		/*ȡ��originӳ�䣬����ҳӳ��,�ڶ����Ѿ�������µ�ҳӳ��*/
		if (unmap_all_hugepages_orig(&all_hugepage_file_info[index], hugepage_info) < 0)
		{
			goto fail;
		}
		
		/* we have processed a num of hugepages of this size, so inc offset */
		/*ƫ��һ�����Ĵ�ҳ����*/
		index += hugepage_info->pages_num[0];
	}

	huge_recover_sigbus();

	/*���й���ҳ��size���Ǵ�ҳģʽֵΪ64M*/
	if (internal_config.memory == 0 && internal_config.force_sockets == 0)
	{
		internal_config.memory = eal_get_hugepage_mem_size();
	}

	/*���й���ҳ����*/
	nr_hugefiles = nr_hugepages;


	/* clean out the numbers of pages */
	/*���й��Ĵ�ҳ��Ϣ�����ҳ��������ΪҪ��socket����*/
	for (i = 0; i < (int) internal_config.hugepage_type_num; i++)
	{
		for (j = 0; j < RTE_MAX_NUMA_NODES; j++)
		{
			                  /*��ҳ���*/   /*��ҳ�������*/
			internal_config.hugepage_info[i].pages_num[j] = 0;
		}
	}
	
	/* get hugepages for each socket */
	/*�������й���ҳ��ÿ��������3�Ŵ�ҳ����¼�����ҳ��Ϣ�ṹ*/
	/*��ҳ��Ϣ��ҳ������socket����*/
	for (i = 0; i < nr_hugefiles; i++) 
	{
		/*socket ID*/
		/*��ȡ��ҳ���ڵ�socket id*/
		int socket = all_hugepage_file_info[i].socket_id;

		/* find a hugepage info with right size and increment num_pages */

		/*���ʹ��3�Ŵ�ҳ����ȡ��Сֵ�������й���ҳ������3�ţ���ʹ�õ���3�Ŵ�ҳ��*/
		const int hugepage_types_num = RTE_MIN(MAX_HUGEPAGE_SIZES, (int)internal_config.hugepage_type_num);

		/*������ҳ���ͣ��ҵ���ǰ��ҳ���ڵ�����*/
		for (j = 0; j < hugepage_types_num; j++) 
		{
			/*�ҵ���ǰ��ҳ���ڵĴ�ҳsize����*/
			if (all_hugepage_file_info[i].size == internal_config.hugepage_info[j].hugepage_sz) 
			{
				/*ҳ����socket���¼�������ҳ���ڵ�socket*/
				/*��Ӧsocketҳ��������*/
				internal_config.hugepage_info[j].pages_num[socket]++;
			}
		}
	}

	/* make a copy of socket_mem, needed for number of pages calculation */

	/*8��socket�µ��ڴ����*/
	for (i = 0; i < RTE_MAX_NUMA_NODES; i++)
	{
		mem_size_per_socket[i] = internal_config.socket_mem[i];
	}
	
	/* calculate final number of pages */
	/*ÿsocket�ִ�ҳ*/
	/*��ҳ����*/
	nr_hugepages = calc_num_pages_per_socket(mem_size_per_socket, internal_config.hugepage_info, used_hugepage_info, internal_config.hugepage_type_num);

	/* error if not enough memory available */
	/*�����ڴ治��*/
	if (nr_hugepages < 0)
		goto fail;

	/* reporting in! */
	/*�������й���ҳ����ӡ�����ڵ�socket����ҳsize*/
	for (i = 0; i < (int) internal_config.hugepage_type_num; i++) 
	{
		for (j = 0; j < RTE_MAX_NUMA_NODES; j++) 
		{
			/*��socketֵ��¼�Ĵ�ҳ����ӡ*/
			if (used_hugepage_info[i].pages_num[j] > 0) 
			{
				RTE_LOG(DEBUG, EAL,
					"Requesting %u pages of size %uMB"
					" from socket %i\n",
					used_hugepage_info[i].pages_num[j],
					(unsigned)
					(used_hugepage_info[i].hugepage_sz / 0x100000),
					j);
			}
		}
	}

	/* create shared memory */
	/*��ҳ�����ṹ��ӳ�䵽�ڴ��ַ�ռ䣬ͨ��fd�ɷ���*/
	/*��ҳ�ļ�����ӳ�䵽���̿ռ䣬/var/run/rte_hugepage_info�ܴ�ҳ�ļ�·��*/	
	all_hugepage = create_shared_memory(eal_hugepage_info_path(), nr_hugefiles * sizeof(struct hugepage_file));

	if (all_hugepage == NULL)
	{
		RTE_LOG(ERR, EAL, "Failed to create shared memory!\n");
		goto fail;
	}
	memset(all_hugepage, 0, nr_hugefiles * sizeof(struct hugepage_file));

	/*
	 * unmap pages that we won't need (looks at used_hugepage_info).
	 * also, sets final_virtaddr to NULL on pages that were unmapped.
	 */

	/*����Ҫ�Ĵ�ҳ���ӳ��,Ϊʲô���ӳ���֣���Ϣ�Ѿ�������sharemem���ͷŵ��Ǵ�ҳ������Ϣ��������ʵ�Ĵ�ҳ�ڴ�ӳ��*/
	if (unmap_unneeded_hugepages(all_hugepage_file_info, used_hugepage_info, internal_config.hugepage_type_num) < 0)
	{
		RTE_LOG(ERR, EAL, "Unmapping and locking hugepages failed!\n");
		goto fail;
	}

	/*
	 * copy stuff from malloc'd hugepage* to the actual shared memory.
	 * this procedure only copies those hugepages that have final_virtaddr
	 * not NULL. has overflow protection.
	 */
	
	/*�������е���ӳ��Ĵ�ҳ�ṹ��Ϣ�������ڴ�*/
	if (copy_hugepages_to_shared_mem(all_hugepage, nr_hugefiles, all_hugepage_file_info, nr_hugefiles) < 0) 
	{
		RTE_LOG(ERR, EAL, "Copying tables to shared memory failed!\n");
		goto fail;
	}

	/* free the hugepage backing files */
	/*�ͷŴ�ҳӳ���ļ�all_hugepage_file_info*/
	if (internal_config.hugepage_unlink && unlink_hugepage_files(all_hugepage_file_info, internal_config.hugepage_type_num) < 0) 
	{
		RTE_LOG(ERR, EAL, "Unlinking hugepage files failed!\n");
		goto fail;
	}

	/* free the temporary hugepage table */
	free(all_hugepage_file_info);
	all_hugepage_file_info = NULL;



	/* first memseg index shall be 0 after incrementing it below */
	j = -1;

	/*�������д�ҳ*/
	for (i = 0; i < nr_hugefiles; i++)
	{
		new_memseg = 0;

		/* if this is a new section, create a new memseg */
		/*ͨ��socket id ��ҳsize �������ַ�������ַУ���ҳ�Ƿ����µ�memseg�ڴ��*/
		if (i == 0)
		{
			new_memseg = 1;
		}
		else if (all_hugepage[i].socket_id != all_hugepage[i-1].socket_id)
		{
			new_memseg = 1;
		}
		else if (all_hugepage[i].size != all_hugepage[i-1].size)
		{
			new_memseg = 1;
		}
		
#ifdef RTE_ARCH_PPC_64
		/* On PPC64 architecture, the mmap always start from higher
		 * virtual address to lower address. Here, both the physical
		 * address and virtual address are in descending order */

		/*��ַ�������������µ��ڴ��*/
		else if ((all_hugepage[i-1].physaddr - all_hugepage[i].physaddr) != all_hugepage[i].size)
		{
			new_memseg = 1;
		}
		else if (((unsigned long)all_hugepage[i-1].final_virtaddr - (unsigned long)all_hugepage[i].final_virtaddr) != all_hugepage[i].size)
		{
			new_memseg = 1;
		}
#else
		else if ((all_hugepage[i].physaddr - all_hugepage[i-1].physaddr) != all_hugepage[i].size)
		{
			new_memseg = 1;
		}
		else if (((unsigned long)all_hugepage[i].final_virtaddr - (unsigned long)all_hugepage[i-1].final_virtaddr) != all_hugepage[i].size)
		{
			new_memseg = 1;
		}
#endif

		/*socket size ��ͬ ��Ϊ��memseg*/
		if (new_memseg) 
		{
			j += 1;
			if (j == RTE_MAX_MEMSEG)
			{
				break;
			}

			/*��¼���ṹ*/
			mem_cfg->memseg[j].phys_addr   = all_hugepage[i].physaddr;
			mem_cfg->memseg[j].addr	       = all_hugepage[i].final_virtaddr;
			mem_cfg->memseg[j].len         = all_hugepage[i].size;
			mem_cfg->memseg[j].socket_id   = all_hugepage[i].socket_id;
			mem_cfg->memseg[j].hugepage_sz = all_hugepage[i].size;
		}
		/* continuation of previous memseg */
		else 
		{
#ifdef RTE_ARCH_PPC_64
		/* Use the phy and virt address of the last page as segment
		 * address for IBM Power architecture */

			/*����ҳ����һ����ҳ��ͬsocket size ���¼��ַ���ӳ��ȣ��������µ�memseg�������ڴ�ε������ַ�����ַ����*/
			mem_cfg->memseg[j].phys_addr = all_hugepage[i].physaddr;
			mem_cfg->memseg[j].addr      = all_hugepage[i].final_virtaddr;
#endif
			mem_cfg->memseg[j].len      += mem_cfg->memseg[j].hugepage_sz;
		}

		/*��¼��ҳ���ڵ�memseg*/
		all_hugepage[i].memseg_id = j;
	}

	if (i < nr_hugefiles) 
	{
		RTE_LOG(ERR, EAL, "Can only reserve %d pages "
			"from %d requested\n"
			"Current %s=%d is not enough\n"
			"Please either increase it or request less amount "
			"of memory.\n",
			i, nr_hugefiles, RTE_STR(CONFIG_RTE_MAX_MEMSEG),
			RTE_MAX_MEMSEG);
		goto fail;
	}

	/*��ַ��¼��ɺ���ӳ�䣬Ϊɶ��¼��ַ����ӳ�䣬����ʵ�ڴ���ӳ�䣬����������Ϣ���ӳ��*/
	munmap(all_hugepage, nr_hugefiles * sizeof(struct hugepage_file));

	return 0;

fail:
	
	huge_recover_sigbus();

	free(all_hugepage_file_info);
	
	if (all_hugepage != NULL)
	{
		munmap(all_hugepage, nr_hugefiles * sizeof(struct hugepage_file));
	}
	
	return -1;
}

/*
 * uses fstat to report the size of a file on disk
 */
static off_t
getFileSize(int fd)
{
	struct stat st;
	if (fstat(fd, &st) < 0)
	{
		return 0;
	}
	
	return st.st_size;
}

/*
 * This creates the memory mappings in the secondary process to match that of
 * the server process. It goes through each memory segment in the DPDK runtime
 * configuration and finds the hugepages which form that segment, mapping them
 * in order to form a contiguous block in the virtual memory space
 */
 /*******************************************************
  ������:		rte_eal_hugepage_attach
  ��������: 	���̴߳�ҳ�ڴ�attach
  ��������: 	
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
int rte_eal_hugepage_attach(void)
{
	const struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	
	struct hugepage_file *hugepage_file_info = NULL;
	unsigned num_hp = 0;
	unsigned i, s = 0; /* s used to track the segment number */
	unsigned max_seg = RTE_MAX_MEMSEG;
	off_t size = 0;

	int fd, fd_zero = -1, fd_hugepage = -1;

	/*aslr ģʽʹ��*/
	if (aslr_enabled() > 0) 
	{
		RTE_LOG(WARNING, EAL, "WARNING: Address Space Layout Randomization "
				"(ASLR) is enabled in the kernel.\n");
		RTE_LOG(WARNING, EAL, "   This may cause issues with mapping memory "
				"into secondary processes\n");
	}

	/*����ҳ��ҳmap�Ƿ�ɶ�*/
	test_proc_pagemap_readable();

	/*֧��xen_dom0ģʽ*/
	if (internal_config.xen_dom0_support) 
	{
	
#ifdef RTE_LIBRTE_XEN_DOM0
		/*�ڴ�attach�����̵�ַ�ռ�*/
		if (rte_xen_dom0_memory_attach() < 0)
		{
			RTE_LOG(ERR, EAL, "Failed to attach memory segments of primary " "process\n");
			return -1;
		}
		
		return 0;
#endif

	}

	/*��/dev/zero*/
	fd_zero = open("/dev/zero", O_RDONLY);
	if (fd_zero < 0) 
	{
		RTE_LOG(ERR, EAL, "Could not open /dev/zero\n");
		goto error;
	}

	/*�򿪴�ҳ·�� ��Ӧ���д�ҳ��/var/run/rte_hugepage_info����ҳ������Ϣ�ļ�*/
	fd_hugepage = open(eal_hugepage_info_path(), O_RDONLY);
	if (fd_hugepage < 0) 
	{
		RTE_LOG(ERR, EAL, "Could not open %s\n", eal_hugepage_info_path());
		goto error;
	}


	/* map all segments into memory to make sure we get the addrs */
	/*�����ڴ��*/
	for (s = 0; s < RTE_MAX_MEMSEG; ++s)
	{
		void *base_addr;

		/*
		 * the first memory segment with len==0 is the one that
		 * follows the last valid segment.
		 */
		 
		/*�ڴ�γ���Ϊ0*/
		if (mcfg->memseg[s].len == 0)
		{
			break;
		}
		
		/*
		 * fdzero is mmapped to get a contiguous block of virtual
		 * addresses of the appropriate memseg size.
		 * use mmap to get identical addresses as the primary process.
		 */

		/*�ڴ�������������ã�����ӳ�䵽��ַ�ռ䣬��addr��ַ��ʼӳ��*/

		/*ӳ�䵽�ӽ��̵�ַ�ռ�*/
		base_addr = mmap(mcfg->memseg[s].addr, mcfg->memseg[s].len, PROT_READ, MAP_PRIVATE, fd_zero, 0);
		if (base_addr == MAP_FAILED || base_addr != mcfg->memseg[s].addr) 
		{
			max_seg = s;
			if (base_addr != MAP_FAILED) 
			{
				/* errno is stale, don't use */
				RTE_LOG(ERR, EAL, "Could not mmap %llu bytes "
					"in /dev/zero at [%p], got [%p] - "
					"please use '--base-virtaddr' option\n",
					(unsigned long long)mcfg->memseg[s].len,
					mcfg->memseg[s].addr, base_addr);
				munmap(base_addr, mcfg->memseg[s].len);
			}
			else
			{
				RTE_LOG(ERR, EAL, "Could not mmap %llu bytes "
					"in /dev/zero at [%p]: '%s'\n",
					(unsigned long long)mcfg->memseg[s].len,
					mcfg->memseg[s].addr, strerror(errno));
			}

			if (aslr_enabled() > 0)
			{
				RTE_LOG(ERR, EAL, "It is recommended to "
					"disable ASLR in the kernel "
					"and retry running both primary "
					"and secondary processes\n");
			}
			goto error;
		}
	}

	/*��ȡ��ҳ��size*/
	size = getFileSize(fd_hugepage);

	/*��ӳ�䵽���̵�ַ�ռ�*/
	hugepage_file_info = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd_hugepage, 0);
	if (hugepage_file_info == MAP_FAILED)
	{
		RTE_LOG(ERR, EAL, "Could not mmap %s\n", eal_hugepage_info_path());
		goto error;
	}

	/*��ҳ������������Ϣ����*/
	num_hp = size / sizeof(struct hugepage_file);
	
	RTE_LOG(DEBUG, EAL, "Analysing %u files\n", num_hp);

	s = 0;

	/*�����ڴ�Σ�Ҳ�����д�ҳ��Ϣ*/
	while (s < RTE_MAX_MEMSEG && mcfg->memseg[s].len > 0)
	{
		void *addr, *base_addr;
		uintptr_t offset = 0;
		size_t mapping_size;
		/*
		 * free previously mapped memory so we can map the
		 * hugepages into the space
		 */

		/*ҳ����ַ*/
		base_addr = mcfg->memseg[s].addr;

		/*��ԭ�������ַ�����ӳ�䣬Ϊʲô*/
		munmap(base_addr, mcfg->memseg[s].len);

		/* find the hugepages for this segment and map them
		 * we don't need to worry about order, as the server sorted the
		 * entries before it did the second mmap of them */

		/*�������д�ҳ*/
		for (i = 0; i < num_hp && offset < mcfg->memseg[s].len; i++)
		{
			/*�ڴ��ID*/
			if (hugepage_file_info[i].memseg_id == (int)s)
			{
				/**/
				fd = open(hugepage_file_info[i].filepath, O_RDWR);
				if (fd < 0)
				{
					RTE_LOG(ERR, EAL, "Could not open %s\n", hugepage_file_info[i].filepath);
					goto error;
				}
				
				mapping_size = hugepage_file_info[i].size;

				/*��ҳsize������ӳ��*/  
				/*ӳ�䵽����ַ+ƫ��λ��*/
				addr = mmap(RTE_PTR_ADD(base_addr, offset), mapping_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
				close(fd); /* close file both on success and on failure */

				if (addr == MAP_FAILED 
					||	addr != RTE_PTR_ADD(base_addr, offset))
				{
					RTE_LOG(ERR, EAL, "Could not mmap %s\n", hugepage_file_info[i].filepath);
					goto error;
				}

				/*ӳ��λ�ú�ƫ*/
				offset += mapping_size;
			}
		}
		
		RTE_LOG(DEBUG, EAL, "Mapped segment %u of size 0x%llx\n", s, (unsigned long long)mcfg->memseg[s].len);
		s++;
	}
	
	/* unmap the hugepage config file, since we are done using it */
	munmap(hugepage_file_info, size);
	close(fd_zero);
	close(fd_hugepage);

	return 0;

error:
	
	/*������ӳ��*/
	for (i = 0; i < max_seg && mcfg->memseg[i].len > 0; i++)
		munmap(mcfg->memseg[i].addr, mcfg->memseg[i].len);
	if (hp != NULL && hp != MAP_FAILED)
		munmap(hp, size);
	if (fd_zero >= 0)
		close(fd_zero);
	if (fd_hugepage >= 0)
		close(fd_hugepage);
	return -1;
}
