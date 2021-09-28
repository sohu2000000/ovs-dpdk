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
  函数名:		test_proc_pagemap_readable
  功能描述: 	测试内存描述信息是否可读
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static void
test_proc_pagemap_readable(void)
{
	int fd = open("/proc/self/pagemap", O_RDONLY);

	/*通过读取/proc/self/pagemap页表文件，得到本进程中虚拟地址与物理地址的映射关系*/
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
  函数名:		find_physaddrs
  功能描述: 	大页虚拟地址转换成物理地址
  				all_hugepage_file_info--某规格下大页起始地址
  				hugepage_info---某规格大页信息info
  参数描述: 	
  返回值  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static int
find_physaddrs(struct hugepage_file *all_hugepage_file_info, struct hugepage_info *hugepage_info)
{
	unsigned i;
	phys_addr_t addr;

	/*遍历本规格下大页个数*/
	for (i = 0; i < hugepage_info->pages_num[0]; i++) 
	{
		/*大页虚拟地址转换成物理地址*/
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
  函数名:		aslr_enabled
  功能描述: 	从线程大页内存attach
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static int aslr_enabled(void)
{
	char c;

	/*打开/proc/sys/kernel/randomize_va_space 随机虚拟地址空间*/
	int retval, fd = open(RANDOMIZE_VA_SPACE_FILE, O_RDONLY);
	if (fd < 0)
	{
		return -errno;
	}

	/*读取一个字符*/
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
  函数名:		get_virtual_area
  功能描述: 	获取虚拟地址空间,非真正映射
  参数描述: 	size---本规格下大页总size
  				hugepage_sz---单个大页size
  返回值	  : 
  最后修改人:
  修改日期:    2017 -11-15
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
		/*映射所有大页到进程地址空间，直到映射成功,多映射一个页*/
		addr = mmap(addr, (*size) + hugepage_sz, PROT_READ, MAP_PRIVATE, fd, 0);
		if (addr == MAP_FAILED)
		{
			/*映射失败则，减少页*/
			*size -= hugepage_sz;
		}
	} while (addr == MAP_FAILED && *size > 0);

	/*全部映射失败*/
	if (addr == MAP_FAILED) 
	{
		close(fd);
		RTE_LOG(ERR, EAL, "Cannot get a virtual area: %s\n", strerror(errno));

		return NULL;
	}

	/*取消映射*/
	munmap(addr, (*size) + hugepage_sz);
	
	close(fd);

	/* align addr to a huge page size boundary */
	/*地址整数大页对齐*/
	aligned_addr = (long)addr;
	aligned_addr += (hugepage_sz - 1);
	aligned_addr &= (~(hugepage_sz - 1));
	addr = (void *)(aligned_addr);

	RTE_LOG(DEBUG, EAL, "Virtual area found at %p (size = 0x%zx)\n", addr, *size);

	/* increment offset */
	/*增加基地址偏移，size为本规格所有大页size*/
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
  函数名:		ap_all_hugepages
  功能描述: 	大页内存映射到进程地址空间，先一次性映射一个规格的大页,用来获取空间，再映射每个大页
  				ori 按页映射，然后保证规格下连续，再按页映射
  参数描述: 	all_hugepage_file_info---所有规格下的大页结构数组
  				hugepage_info---某规格大页信息结构
  返回值	  : 映射成功的大页数
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static unsigned map_all_hugepages(struct hugepage_file *all_hugepage_file_info, struct hugepage_info *hugepage_info, int orig)
{
	int fd;
	unsigned i;
	void *virtaddr;
	void *vma_addr = NULL;
	size_t virmem_size = 0;

	/*遍历本规格所有大页*/
	for (i = 0; i < hugepage_info->pages_num[0]; i++)
	{
		uint64_t hugepage_sz = hugepage_info->hugepage_sz;

		/*最初的初始化，即组装filepath，下面会把大页映射到进程地址空间，并记录虚拟地址*/
		if (orig) 
		{
			/*给大页编制ID*/
			all_hugepage_file_info[i].file_id = i;
			all_hugepage_file_info[i].size = hugepage_sz;

			/*组装大页文件路径名，/dev/hugepages/rte_smap_1*/
			eal_get_hugefile_path(all_hugepage_file_info[i].filepath, sizeof(all_hugepage_file_info[i].filepath), hugepage_info->hugepage_file_dir, all_hugepage_file_info[i].file_id);

			all_hugepage_file_info[i].filepath[sizeof(all_hugepage_file_info[i].filepath) - 1] = '\0';
		}
		
#ifndef RTE_ARCH_64
		/* for 32-bit systems, don't remap 1G and 16G pages, just reuse
		 * original map address as final map address.
		 */
		 /*如果本大页是1G或16G的大页，则直接记录映射的虚拟地址为final地址*/
		else if ((hugepage_sz == RTE_PGSIZE_1G)
			|| (hugepage_sz == RTE_PGSIZE_16G)) 
		{
			/*大页最后的虚拟地址，映射到进程地址空间的虚拟地址*/
			/*已经映射了直接赋值为final大页地址*/
			all_hugepage_file_info[i].final_virtaddr = all_hugepage_file_info[i].orig_virtaddr;
			all_hugepage_file_info[i].orig_virtaddr = NULL;
			continue;
		}
#endif
		/*ori=0时*/
		/*其它规格大页*/
		else if (virmem_size == 0) /*本规格大页先一次性映射到进程地址空间*/ 
		{
			unsigned j, pages_num;

			/* reserve a virtual area for next contiguous
			 * physical block: count the number of
			 * contiguous physical pages. */

			/*遍历规格下大页，校验物理地址是否是连续*/
			for (j = i+1; j < hugepage_info->pages_num[0] ; j++) 
			{
#ifdef RTE_ARCH_PPC_64
				/* The physical addresses are sorted in
				 * descending order on PPC64 */

				/*物理地址是否连续*/
				if (all_hugepage_file_info[j].physaddr != all_hugepage_file_info[j-1].physaddr - hugepage_sz)
					break;
#else
				if (all_hugepage_file_info[j].physaddr != all_hugepage_file_info[j-1].physaddr + hugepage_sz)
					break;
#endif
			}

			/*本规格地址连续校验通过后的大页个数*/
			pages_num = j - i;

			/*本规格大页下大页size*/
			virmem_size = pages_num * hugepage_sz;

			/* get the biggest virtual memory area up to
			 * virmem_size. If it fails, vma_addr is NULL, so
			 * let the kernel provide the address. */

			/*获取本规格下所有大页size虚拟地址空间*/
			/*本规格所有大页先一次性映射到进程地址空间，再取消映射，为的是获取足够连续的空间，虚拟地址，再映射给单页内存*/ 

			/*一次性获取本规格大页足够大的映射空间*/
			vma_addr = get_virtual_area(&virmem_size, hugepage_info->hugepage_sz);

			if (vma_addr == NULL)
			{
				virmem_size = hugepage_sz;
			}
		}

		/* try to create hugepage file */
		/*创建大页文件，为了访问内存，/dev/hugepages/rte_smap_1*/
		fd = open(all_hugepage_file_info[i].filepath, O_CREAT | O_RDWR, 0600);
		if (fd < 0)
		{
			RTE_LOG(DEBUG, EAL, "%s(): open failed: %s\n", __func__,
					strerror(errno));
			return i;
		}

		/* map the segment, and populate page tables,
		 * the kernel fills this segment with zeros */

	    /*大页文件映射虚拟地址空间*/
		/*内存文件映射到内存，一个大页大小，从vma_addr地址开始映射，起始地址，真实映射，从获取的虚拟地址开始映射，可通过fd访问*/
		virtaddr = mmap(vma_addr, hugepage_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, 0);
		if (virtaddr == MAP_FAILED) 
		{
			RTE_LOG(DEBUG, EAL, "%s(): mmap failed: %s\n", __func__, strerror(errno));
			
			close(fd);

			return i;
		}

		/*页虚拟地址记录*/
		if (orig) 
		{
			/*原始大页地址映射到虚拟地址空间地址*/
			all_hugepage_file_info[i].orig_virtaddr = virtaddr;       /*单页映射时，大页映射到进程地址空间虚拟地址*/
		}
		else
		{
			all_hugepage_file_info[i].final_virtaddr = virtaddr;      /*最终虚拟地址，本规格先一次性映射到进程地址空间，再分给单页*/
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
			/*设置信号跳转*/
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
		/*设置文件群集*/
		if (flock(fd, LOCK_SH | LOCK_NB) == -1) 
		{
			RTE_LOG(DEBUG, EAL, "%s(): Locking file failed:%s \n",
				__func__, strerror(errno));
			close(fd);
			return i;
		}

		close(fd);

		/*下一个大页虚拟地址，内核地址直接偏移一个大页 size*/
		vma_addr = (char *)vma_addr + hugepage_sz;

		/*减去已映射的大页*/
		virmem_size -= hugepage_sz;
	}

	return i;
}

/* Unmap all hugepages from original mapping */
 /*******************************************************
  函数名:		unmap_all_hugepages_orig
  功能描述: 	取消映射
  参数描述: 	all_hugepage_file_info---所有规格下的大页描述结构体
				hugepage_info---大页信息hugepage_info,某规格下的大页内存
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
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
  函数名:		find_numasocket
  功能描述: 	从numa_maps查找大页属于的socket
  参数描述: 	all_hugepage_file_info--某规格大页数组，本规格元素地址
  返回值  :     
  最后修改人:
  修改日期:    2017 -11-15
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

	/*打开num图,描述numa内存信息*/
	f = fopen("/proc/self/numa_maps", "r");
	if (f == NULL) 
	{
		RTE_LOG(NOTICE, EAL, "cannot open /proc/self/numa_maps,"
				" consider that all memory is in socket_id 0\n");
		return 0;
	}

	/*大页文件路径 /dev/hugepages/rtemap_6138*/
	snprintf(hugepage_file_dir_str, sizeof(hugepage_file_dir_str), "%s/%s", hugepage_info->hugepage_file_dir, internal_config.hugefile_prefix);

	/* parse numa map */
	/*解析内存挂载地图*/

	/*获取地址7fb2ed5b8000 prefer:1 file=/usr/lib64/libc-2.17.so anon=2 dirty=2 N1=2*/
	while (fgets(buf, sizeof(buf), f) != NULL) 
	{
		/* ignore non huge page */
		/*本大页存在于numa_maps 中*/
		if (strstr(buf, " huge ") == NULL && strstr(buf, hugepage_file_dir_str) == NULL)
		{
			continue;
		}
		
		/* get zone addr */
		/*获取大页内存地址, 由字符串转换，16进制*/
		virt_addr = strtoull(buf, &end, 16);
		if (virt_addr == 0 || end == buf)
		{
			RTE_LOG(ERR, EAL, "%s(): error in numa_maps parsing\n", __func__);
			goto error;
		}

		/* get node id (socket id) */

		/*获取节点字符串N1=2*/
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

		/*获取socket id， N1=2 的 2就是socket ID 页属于哪个socket系统已划分好*/
		socket_id = strtoul(nodestr, &end, 0);
		if ((nodestr[0] == '\0') || (end == NULL) || (*end != '\0')) 
		{
			RTE_LOG(ERR, EAL, "%s(): error in numa_maps parsing\n", __func__);
			goto error;
		}

		/* if we find this page in our mappings, set socket_id */

		/*大页socket 赋值*/
		for (i = 0; i < hugepage_info->pages_num[0]; i++)
		{
			void *va = (void *)(unsigned long)virt_addr;

			/*解析的numa_maps 地址就是大页的地址，说明大页已关联到numa_maps，则获取sockid*/
			if (all_hugepage_file_info[i].orig_virtaddr == va) 
			{
				all_hugepage_file_info[i].socket_id = socket_id;
				hugepage_count++;
			}
		}
	}

	/*页个数未填满，存在未划分到map的大页*/
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
  函数名:		create_shared_memory
  功能描述: 	fd映射到进程地址空间，size为所有大页size结构
  参数描述: 	filename---获取大页所在路径 /var/run/rte_hugepage_info	
  				mem_size---大页内存
  返回值  :
  最后修改人:
  修改日期:    2017 -11-15
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

	/*修改fd文件为指定mem_size大小*/
	if (ftruncate(fd, mem_size) < 0)
	{
		close(fd);
		return NULL;
	}

	/*映射到进程地址空间*/
	retval = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	close(fd);

	return retval;
}

/*
 * this copies *active* hugepages from one hugepage table to another.
 * destination is typically the shared memory.
 */

/*******************************************************
  函数名:		copy_hugepages_to_shared_mem
  功能描述: 	拷贝大页信息到共享内存
  参数描述: 	dst---hugepage大页内存描述结构数组
  				dest_size--大页个数
  				src--all_hugepage_file_info临时大页结构数组
  返回值  :
  最后修改人:
  修改日期:    2017 -11-15
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

			/*大页信息拷贝到hugepage大页内存描述结构数组内存*/
			memcpy(&dst[dst_pos], &src[src_pos], sizeof(struct hugepage_file));

			dst_pos++;
		}
	}
	return 0;
}

/*******************************************************
  函数名:		unlink_hugepage_files
  功能描述: 	解除内存和大页文件的关联
  参数描述: 	all_hugepage_file_info--all_hugepage_file_info临时大页结构数组
				num_hugepage_info--大页个数
  返回值  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static int unlink_hugepage_files(struct hugepage_file *all_hugepage_file_info,unsigned num_hugepage_info)
{
	unsigned socket, size;
	int page, nrpages = 0;

	/* get total number of hugepages */
	/*计算大页总数，从socket上计算*/
	for (size = 0; size < num_hugepage_info; size++)
	{
		for (socket = 0; socket < RTE_MAX_NUMA_NODES; socket++)
		{
			nrpages += internal_config.hugepage_info[size].pages_num[socket];
		}
	}
	
	/*大页与文件系统解除关联，即删除文件系统中的大页文件*/
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
  函数名:		unmap_unneeded_hugepages
  功能描述: 	不需要的大页解除映射
  参数描述: 	all_hugepage_file_info---所有规格下的大页结构数组
  				hugepage_info---临时大页规格信息结构
  				num_hugepage_info---所有规格大页个数
  返回值  :
  最后修改人:
  修改日期:     
********************************************************/
static int
unmap_unneeded_hugepages(struct hugepage_file *all_hugepage_file_info,
		struct hugepage_info *hugepage_info,
		unsigned hugepage_type_num)
{
	unsigned socket, type;
	int page, all_type_socket_pages_num = 0;

	/* get total number of hugepages */
	/*遍历所有规格大页，计数所有socket上大页个数之和*/
	for (type = 0; type < hugepage_type_num; type++)
	{
		for (socket = 0; socket < RTE_MAX_NUMA_NODES; socket++)
		{
			all_type_socket_pages_num += internal_config.hugepage_info[type].pages_num[socket];
		}
	}

	/*所有规格大页个数*/
	for (type = 0; type < hugepage_type_num; type++)
	{
		/*遍历socket*/
		for (socket = 0; socket < RTE_MAX_NUMA_NODES; socket++)
		{
			unsigned pages_found = 0;

			/* traverse until we have unmapped all the unused pages */
			/*遍历所有大页，未使用的大页解除映射*/
			for (page = 0; page < all_type_socket_pages_num; page++)
			{
				struct hugepage_file *hugepage = &all_hugepage_file_info[page];

				/* find a page that matches the criteria */
				/*大页就是那个大页*/
				if ((hugepage->size == hugepage_info[type].hugepage_sz) && (hugepage->socket_id == (int) socket)) 
				{
					/* if we skipped enough pages, unmap the rest */

					/*大页个数*/
					if (pages_found == hugepage_info[type].pages_num[socket]) 
					{
						uint64_t unmap_len;

						/*大页size*/
						unmap_len = hugepage->size;

						/* get start addr and len of the remaining segment */

						/*取消大页的映射*/
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
						/*大页跳过*/
						pages_found++;
					}
				} /* match page */
			} /* foreach page */
		} /* foreach socket */
	} /* foreach pagesize */

	return 0;
}

/*******************************************************
  函数名:		get_socket_mem_size
  功能描述:     获取socket上内存总size
  参数描述: 	all_hugepage_file_info---所有规格下的大页结构数组
				hugepage_info---临时大页规格信息结构
				num_hugepage_info---所有规格大页个数
  返回值  :
  最后修改人:
  修改日期: 	
********************************************************/
static inline uint64_t get_socket_mem_size(int socket)
{
	uint64_t size = 0;
	unsigned i;

	/*遍历所有规格大页,获取本socket所有大页内存之和*/
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
  函数名:		rte_eal_hugepage_init
  功能描述: 	每socket分大页
  参数描述: 	socket_mem---每socket内存size
  				hugepage_info---大页规格信息结构
  				used_hugepage_info---每socket划分内存后的内存大页数及大页个数
  				num_hugepage_info--所有规格大页总数
  返回值  :     used_total_num_pages--成功划分可用大页总数
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static int
calc_num_pages_per_socket(uint64_t * mem_size_per_socket, struct hugepage_info *hugepage_info, struct hugepage_info *used_hugepage_info,unsigned hugepage_type_num)
{
	unsigned socket, j, i = 0;
	unsigned requested, available;
	int used_total_num_pages = 0;
	uint64_t remaining_mem, type_socket_hugepage_mem_size;
	uint64_t total_mem = internal_config.memory;/*socket上所有规格大页总size*/

	if (hugepage_type_num == 0)
	{
		return -1;
	}
	
	/* if specific memory amounts per socket weren't requested */
	/*没有设置每socket内存*/
	if (internal_config.force_sockets == 0)
	{
		int cpu_num_on_per_socket[RTE_MAX_NUMA_NODES];
		size_t socket_default_mem_size, total_size;
		unsigned lcore_id;

		/* Compute number of cores per socket */
		/*计算每socket核数*/
		memset(cpu_num_on_per_socket, 0, sizeof(cpu_num_on_per_socket));

		/*计算每个socket拥有的核数*/
		RTE_LCORE_FOREACH(lcore_id) 
		{					/*核id 转换成它属于的socket id*/
			cpu_num_on_per_socket[rte_lcore_to_socket_id(lcore_id)]++;
		}

		/*
		 * Automatically spread requested memory amongst detected sockets according
		 * to number of cores from cpu mask present on each socket
		 */
		/*所有规格大页内存总size*/
		total_size = internal_config.memory;

		/*8个socket*/
		for (socket = 0; socket < RTE_MAX_NUMA_NODES && total_size != 0; socket++)
		{
			/* Set memory amount per socket */
			/*每socket内存默认大小设置*/            /*socket 拥有核数x总内存/逻辑核数，均分给所有核*/
			socket_default_mem_size = (internal_config.memory * cpu_num_on_per_socket[socket]) / rte_lcore_count();
			/*每个socket可以分到的内存，每个CPU都有所属于的socket，所以除以128*/

			/* Limit to maximum available memory on socket */
			/*socket内存设置，取较小值，默认值与socket大页内存之和对比*/

			/*socket上真实的内存大小与均分的默认内存大小作比较*/
			socket_default_mem_size = RTE_MIN(socket_default_mem_size, get_socket_mem_size(socket));

			/*socket内存记录*/
			mem_size_per_socket[socket] = socket_default_mem_size; /*每个socket 设定内存size值记录*/

			/*所有socket总内存size*/
			total_size -= socket_default_mem_size;
		}

		/*
		 * If some memory is remaining, try to allocate it by getting all
		 * available memory from sockets, one after the other
		 */

		
		/*每socket内存size要占用满，属于它的内存size*/
		/*总内存，还有剩余内存*/
		for (socket = 0; socket < RTE_MAX_NUMA_NODES && total_size != 0; socket++) 
		{
			/* take whatever is available */
			/*每socket内存size要占用满，属于它的内存size*/
			/*检查到是哪个socket上有剩余内存，均分后的剩余*/
			socket_default_mem_size = RTE_MIN(get_socket_mem_size(socket) - mem_size_per_socket[socket], total_size);

			/* Update sizes */
			/*每socket内存增加*/
			mem_size_per_socket[socket] += socket_default_mem_size;

			total_size -= socket_default_mem_size;
		}
	}

	/*遍历socket*/
	for (socket = 0; socket < RTE_MAX_NUMA_NODES && total_mem != 0; socket++) 
	{
		/* skips if the memory on specific socket wasn't requested */
		/*遍历所有规格大页*/
		for (i = 0; i < hugepage_type_num && mem_size_per_socket[socket] != 0; i++)
		{
			/*记录大页挂载点 /dev/hugepages*/
			used_hugepage_info[i].hugepage_file_dir = hugepage_info[i].hugepage_file_dir;

			/*socket 分到的大页数*/
			used_hugepage_info[i].pages_num[socket] = RTE_MIN( mem_size_per_socket[socket] / hugepage_info[i].hugepage_sz, hugepage_info[i].pages_num[socket]);

			/*当前规格上socket大页内存*/
			type_socket_hugepage_mem_size = used_hugepage_info[i].pages_num[socket] * used_hugepage_info[i].hugepage_sz;
		
			mem_size_per_socket[socket] -= type_socket_hugepage_mem_size;
			
			total_mem -= type_socket_hugepage_mem_size;

			/*划分出去的大页个数*/
			used_total_num_pages += used_hugepage_info[i].pages_num[socket];

			/* check if we have met all memory requests */

			/*socket上大页用完了*/
			if (mem_size_per_socket[socket] == 0)
			{
				break;
			}
			
			/* check if we have any more pages left at this size, if so
			 * move on to next size */

			/*恰好分配*/
			if (used_hugepage_info[i].pages_num[socket] == hugepage_info[i].pages_num[socket])
			{
				continue;
			}
			
			/* At this point we know that there are more pages available that are
			 * bigger than the memory we want, so lets see if we can get enough
			 * from other page sizes.
			 */
			remaining_mem = 0;

			/*计算type下socket上剩余大页内存*/
			for (j = i+1; j < hugepage_type_num; j++)
			{
				remaining_mem += hugepage_info[j].hugepage_sz * hugepage_info[j].pages_num[socket];
			}
			
			/* is there enough other memory, if not allocate another page and quit */
			if (remaining_mem < mem_size_per_socket[socket])
			{
				/*socket上剩余内存*/
				type_socket_hugepage_mem_size = RTE_MIN(mem_size_per_socket[socket],hugepage_info[i].hugepage_sz);

				/*内存减去*/
				mem_size_per_socket[socket] -= type_socket_hugepage_mem_size;
				total_mem -= type_socket_hugepage_mem_size;

				/*socket分到的大页个数增加*/
				used_hugepage_info[i].pages_num[socket]++;
				
				used_total_num_pages++;

				break; /* we are done with this socket*/
			}
			
		}
		
		/* if we didn't satisfy all memory requirements per socket */
		/*剩余内存多余一个页，所以分出去一个页还有内存剩余，说明内存分配异常，报错*/
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
	/*如果总内存有剩余*/
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
  函数名:		eal_get_hugepage_mem_size
  功能描述: 	计算所有规格大页总size
  参数描述: 	
  返回值  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static inline size_t
eal_get_hugepage_mem_size(void)
{
	uint64_t size = 0;
	unsigned i, j;

	/*遍历大页规格*/
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
  函数名:		rte_eal_hugepage_init
  功能描述: 	
  参数描述: 	
  返回值  :
  最后修改人:
  修改日期:    2017 -11-15
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
  函数名:		rte_eal_hugepage_init
  功能描述: 	大页内存做成了内存段，且记录了所属socket，虚拟地址物理地址，每个内存段上可以有很多大页，记录了虚拟地址，物理地址
  				大页映射到地址空间，所有大页信息赋值给内存配置结构，最后再解除映射，为啥解除映射
  参数描述: 	
  返回值  :
  最后修改人:
  修改日期:    2017 -11-15
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

	/*内存描述信息pagemap是否可读，大页初始化完成则可访问*/
	test_proc_pagemap_readable();

	memset(used_hugepage_info, 0, sizeof(used_hugepage_info));

	/*获取全局内存配置结构，从文件映射到内存的*/
	/* get pointer to global configuration */
	/*&rte_config 全局配置*/

	/*获取大页内存描述结构*/
	/* /var/run/rte_config，描述内存信息*/
	mem_cfg = rte_eal_get_configuration()->mem_config;

	/* hugetlbfs can be disabled */
	/*设置了非大页模式，则映射一段内存后直接返回*/
	if (internal_config.no_hugetlbfs)
	{
		/*映射大页内存到进程地址空间，如果无大页则internal_config.memory=64M*/
		addr = mmap(NULL, internal_config.memory, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
		if (addr == MAP_FAILED) 
		{
			RTE_LOG(ERR, EAL, "%s: mmap() failed: %s\n", __func__,
					strerror(errno));
			return -1;
		}

		/*内存信息*/
		mem_cfg->memseg[0].phys_addr   = (phys_addr_t)(uintptr_t)addr;       /*虚拟地址转为物理地址*/
		mem_cfg->memseg[0].addr        = addr;								 /*虚拟地址*/
		mem_cfg->memseg[0].hugepage_sz = RTE_PGSIZE_4K;                      /*大页页大小*/
		mem_cfg->memseg[0].len         = internal_config.memory;             /*页长度*/
		mem_cfg->memseg[0].socket_id   = 0;                                  /*大页属于哪个socket*/

		return 0;
	}

/* check if app runs on Xen Dom0 */
    /*是否支持*/
	if (internal_config.xen_dom0_support)
	{
#ifdef RTE_LIBRTE_XEN_DOM0
		/* use dom0_mm kernel driver to init memory */
		/*用驱动内存来初始化内存*/
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

	/*遍历所有规格大页*/                    /*规格数*/
	for (i = 0; i < (int) internal_config.hugepage_type_num; i++) 
	{
		/* meanwhile, also initialize used_hugepage_info hugepage sizes in used_hugepage_info */
		/*记录大页size*/
		used_hugepage_info[i].hugepage_sz = internal_config.hugepage_info[i].hugepage_sz;

		/*所有规格大页个数之和*/
		nr_hugepages += internal_config.hugepage_info[i].pages_num[0];
	}

	/*
	 * allocate a memory area for hugepage table.
	 * this isn't shared memory yet. due to the fact that we need some
	 * processing done on these pages, shared memory will be created
	 * at a later stage.
	 */

	/*临时所有规格大页描述信息结构*/
	all_hugepage_file_info = malloc(nr_hugepages * sizeof(struct hugepage_file));
	if (all_hugepage_file_info == NULL)
	{
		goto fail;
	}
	
	memset(all_hugepage_file_info, 0, nr_hugepages * sizeof(struct hugepage_file));

	index = 0; /* where we start the current page size entries */

	/*寄存器注册*/
	huge_register_sigbus();

	/* map all hugepages and sort them */
	/*遍历所有规格大页，映射到进程地址空间，每张页记录自己的虚拟地址*/
	for (i = 0; i < (int)internal_config.hugepage_type_num; i++)
	{
		unsigned hunge_pages_num_old, hunge_pages_num_new;
		struct hugepage_info *hugepage_info;

		/*
		 * we don't yet mark hugepages as used at this stage, so
		 * we just map all hugepages available to the system
		 * all hugepages are still located on socket 0
		 */

		/*大页信息*/
		hugepage_info = &internal_config.hugepage_info[i];

		/*本规格大页不存在，大页数为0*/
		if (hugepage_info->pages_num[0] == 0)
		{
			continue;
		}
		
		/* map all hugepages available */

		/*本规格大页个数*/
		hunge_pages_num_old = hugepage_info->pages_num[0];

	    /*内存页映射到本进程，all_hugepage_file_info[index] 所有规格大页放在了一个数组，
	    本次映射主要生产filepath，且单页映射到进程地址空间，记录到orig_virtaddr*/
		hunge_pages_num_new = map_all_hugepages(&all_hugepage_file_info[index], hugepage_info, 1);

		/*存在无效的大页，大页个数更新*/
		if (hunge_pages_num_new < hunge_pages_num_old)
		{
			RTE_LOG(DEBUG, EAL,
				"%d not %d hugepages of size %u MB allocated\n",
				hunge_pages_num_new, hunge_pages_num_old,
				(unsigned)(hugepage_info->hugepage_sz / 0x100000));

			int pages = hunge_pages_num_old - hunge_pages_num_new;

			/*大页总数修改*/
			nr_hugepages -= pages;

			/*本规格大页个数修改*/
			hugepage_info->pages_num[0] = hunge_pages_num_new;

			if (hunge_pages_num_new == 0)
			{
				continue;
			}
		}

		/* find physical addresses and sockets for each hugepage */

		/*获取大页物理地址*/
		if (find_physaddrs(&all_hugepage_file_info[index], hugepage_info) < 0)
		{
			RTE_LOG(DEBUG, EAL, "Failed to find phys addr for %u MB pages\n", (unsigned)(hugepage_info->hugepage_sz / 0x100000));
			goto fail;
		}

		/*给hugepage_info的大页查找它的socket id，大页挂载点已经决定了大页属于的socket*/
		if (find_numasocket(&all_hugepage_file_info[index], hugepage_info) < 0)
		{
			RTE_LOG(DEBUG, EAL, "Failed to find NUMA socket for %u MB pages\n", (unsigned)(hugepage_info->hugepage_sz / 0x100000));
			goto fail;
		}

		/*根据地址对大页排序*/
		qsort(&all_hugepage_file_info[index], hugepage_info->pages_num[0], sizeof(struct hugepage_file), cmp_physaddr);

		/* remap all hugepages */
		/*重新映射本规格下大页*/
		if (map_all_hugepages(&all_hugepage_file_info[index], hugepage_info, 0) != hugepage_info->pages_num[0]) 
		{
			RTE_LOG(ERR, EAL, "Failed to remap %u MB pages\n",
					(unsigned)(hugepage_info->hugepage_sz / 0x100000));
			goto fail;
		}

		/* unmap original mappings */
		/*取消origin映射，即单页映射,第二次已经按规格下的页映射*/
		if (unmap_all_hugepages_orig(&all_hugepage_file_info[index], hugepage_info) < 0)
		{
			goto fail;
		}
		
		/* we have processed a num of hugepages of this size, so inc offset */
		/*偏移一个规格的大页个数*/
		index += hugepage_info->pages_num[0];
	}

	huge_recover_sigbus();

	/*所有规格大页总size，非大页模式值为64M*/
	if (internal_config.memory == 0 && internal_config.force_sockets == 0)
	{
		internal_config.memory = eal_get_hugepage_mem_size();
	}

	/*所有规格大页总数*/
	nr_hugefiles = nr_hugepages;


	/* clean out the numbers of pages */
	/*所有规格的大页信息清除大页个数，因为要按socket计数*/
	for (i = 0; i < (int) internal_config.hugepage_type_num; i++)
	{
		for (j = 0; j < RTE_MAX_NUMA_NODES; j++)
		{
			                  /*大页规格*/   /*大页计数清除*/
			internal_config.hugepage_info[i].pages_num[j] = 0;
		}
	}
	
	/* get hugepages for each socket */
	/*遍历所有规格大页，每个规格最多3张大页，记录入规格大页信息结构*/
	/*大页信息大页计数按socket计数*/
	for (i = 0; i < nr_hugefiles; i++) 
	{
		/*socket ID*/
		/*获取大页属于的socket id*/
		int socket = all_hugepage_file_info[i].socket_id;

		/* find a hugepage info with right size and increment num_pages */

		/*最多使用3张大页，获取较小值，若所有规格大页数低于3张，则使用低于3张大页数*/
		const int hugepage_types_num = RTE_MIN(MAX_HUGEPAGE_SIZES, (int)internal_config.hugepage_type_num);

		/*遍历大页类型，找到当前大页属于的类型*/
		for (j = 0; j < hugepage_types_num; j++) 
		{
			/*找到当前大页属于的大页size类型*/
			if (all_hugepage_file_info[i].size == internal_config.hugepage_info[j].hugepage_sz) 
			{
				/*页按照socket重新计数，大页属于的socket*/
				/*对应socket页张数增加*/
				internal_config.hugepage_info[j].pages_num[socket]++;
			}
		}
	}

	/* make a copy of socket_mem, needed for number of pages calculation */

	/*8个socket下的内存计数*/
	for (i = 0; i < RTE_MAX_NUMA_NODES; i++)
	{
		mem_size_per_socket[i] = internal_config.socket_mem[i];
	}
	
	/* calculate final number of pages */
	/*每socket分大页*/
	/*大页总数*/
	nr_hugepages = calc_num_pages_per_socket(mem_size_per_socket, internal_config.hugepage_info, used_hugepage_info, internal_config.hugepage_type_num);

	/* error if not enough memory available */
	/*可用内存不足*/
	if (nr_hugepages < 0)
		goto fail;

	/* reporting in! */
	/*遍历所有规格大页，打印所属于的socket，大页size*/
	for (i = 0; i < (int) internal_config.hugepage_type_num; i++) 
	{
		for (j = 0; j < RTE_MAX_NUMA_NODES; j++) 
		{
			/*按socket值记录的大页数打印*/
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
	/*大页描述结构，映射到内存地址空间，通过fd可访问*/
	/*大页文件描述映射到进程空间，/var/run/rte_hugepage_info总大页文件路径*/	
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

	/*不需要的大页解除映射,为什么解除映射又，信息已经拷贝到sharemem，释放的是大页描述信息，而非真实的大页内存映射*/
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
	
	/*拷贝所有单张映射的大页结构信息到共享内存*/
	if (copy_hugepages_to_shared_mem(all_hugepage, nr_hugefiles, all_hugepage_file_info, nr_hugefiles) < 0) 
	{
		RTE_LOG(ERR, EAL, "Copying tables to shared memory failed!\n");
		goto fail;
	}

	/* free the hugepage backing files */
	/*释放大页映射文件all_hugepage_file_info*/
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

	/*遍历所有大页*/
	for (i = 0; i < nr_hugefiles; i++)
	{
		new_memseg = 0;

		/* if this is a new section, create a new memseg */
		/*通过socket id 大页size 和虚拟地址，物理地址校验大页是否是新的memseg内存段*/
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

		/*地址不连续，则是新的内存段*/
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

		/*socket size 不同 则为新memseg*/
		if (new_memseg) 
		{
			j += 1;
			if (j == RTE_MAX_MEMSEG)
			{
				break;
			}

			/*记录到结构*/
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

			/*若大页与上一个大页相同socket size 则记录地址增加长度，不开辟新的memseg，更新内存段的虚拟地址物理地址长度*/
			mem_cfg->memseg[j].phys_addr = all_hugepage[i].physaddr;
			mem_cfg->memseg[j].addr      = all_hugepage[i].final_virtaddr;
#endif
			mem_cfg->memseg[j].len      += mem_cfg->memseg[j].hugepage_sz;
		}

		/*记录大页属于的memseg*/
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

	/*地址记录完成后解除映射，为啥记录地址后解除映射，非真实内存解除映射，而是描述信息解除映射*/
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
  函数名:		rte_eal_hugepage_attach
  功能描述: 	从线程大页内存attach
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
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

	/*aslr 模式使能*/
	if (aslr_enabled() > 0) 
	{
		RTE_LOG(WARNING, EAL, "WARNING: Address Space Layout Randomization "
				"(ASLR) is enabled in the kernel.\n");
		RTE_LOG(WARNING, EAL, "   This may cause issues with mapping memory "
				"into secondary processes\n");
	}

	/*测试页大页map是否可读*/
	test_proc_pagemap_readable();

	/*支持xen_dom0模式*/
	if (internal_config.xen_dom0_support) 
	{
	
#ifdef RTE_LIBRTE_XEN_DOM0
		/*内存attach到进程地址空间*/
		if (rte_xen_dom0_memory_attach() < 0)
		{
			RTE_LOG(ERR, EAL, "Failed to attach memory segments of primary " "process\n");
			return -1;
		}
		
		return 0;
#endif

	}

	/*打开/dev/zero*/
	fd_zero = open("/dev/zero", O_RDONLY);
	if (fd_zero < 0) 
	{
		RTE_LOG(ERR, EAL, "Could not open /dev/zero\n");
		goto error;
	}

	/*打开大页路径 对应所有大页，/var/run/rte_hugepage_info，大页描述信息文件*/
	fd_hugepage = open(eal_hugepage_info_path(), O_RDONLY);
	if (fd_hugepage < 0) 
	{
		RTE_LOG(ERR, EAL, "Could not open %s\n", eal_hugepage_info_path());
		goto error;
	}


	/* map all segments into memory to make sure we get the addrs */
	/*遍历内存段*/
	for (s = 0; s < RTE_MAX_MEMSEG; ++s)
	{
		void *base_addr;

		/*
		 * the first memory segment with len==0 is the one that
		 * follows the last valid segment.
		 */
		 
		/*内存段长度为0*/
		if (mcfg->memseg[s].len == 0)
		{
			break;
		}
		
		/*
		 * fdzero is mmapped to get a contiguous block of virtual
		 * addresses of the appropriate memseg size.
		 * use mmap to get identical addresses as the primary process.
		 */

		/*内存段主进程已做好，进程映射到地址空间，从addr地址开始映射*/

		/*映射到从进程地址空间*/
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

	/*获取大页总size*/
	size = getFileSize(fd_hugepage);

	/*大映射到进程地址空间*/
	hugepage_file_info = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd_hugepage, 0);
	if (hugepage_file_info == MAP_FAILED)
	{
		RTE_LOG(ERR, EAL, "Could not mmap %s\n", eal_hugepage_info_path());
		goto error;
	}

	/*大页个数，描述信息个数*/
	num_hp = size / sizeof(struct hugepage_file);
	
	RTE_LOG(DEBUG, EAL, "Analysing %u files\n", num_hp);

	s = 0;

	/*遍历内存段，也是所有大页信息*/
	while (s < RTE_MAX_MEMSEG && mcfg->memseg[s].len > 0)
	{
		void *addr, *base_addr;
		uintptr_t offset = 0;
		size_t mapping_size;
		/*
		 * free previously mapped memory so we can map the
		 * hugepages into the space
		 */

		/*页基地址*/
		base_addr = mcfg->memseg[s].addr;

		/*从原来虚拟地址，解除映射，为什么*/
		munmap(base_addr, mcfg->memseg[s].len);

		/* find the hugepages for this segment and map them
		 * we don't need to worry about order, as the server sorted the
		 * entries before it did the second mmap of them */

		/*遍历所有大页*/
		for (i = 0; i < num_hp && offset < mcfg->memseg[s].len; i++)
		{
			/*内存段ID*/
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

				/*大页size，从新映射*/  
				/*映射到基地址+偏移位置*/
				addr = mmap(RTE_PTR_ADD(base_addr, offset), mapping_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
				close(fd); /* close file both on success and on failure */

				if (addr == MAP_FAILED 
					||	addr != RTE_PTR_ADD(base_addr, offset))
				{
					RTE_LOG(ERR, EAL, "Could not mmap %s\n", hugepage_file_info[i].filepath);
					goto error;
				}

				/*映射位置后偏*/
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
	
	/*错误解除映射*/
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
