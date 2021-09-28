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

#ifndef EAL_HUGEPAGES_H
#define EAL_HUGEPAGES_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#define MAX_HUGEPAGE_PATH PATH_MAX

/**
 * Structure used to store informations about hugepages that we mapped
 * through the files in hugetlbfs.
 */
/*页文件信息,描述一个大页内存，描述物理地址和虚拟地址对应关系*/
struct hugepage_file 
{
	void *orig_virtaddr;      /**< virtual addr of first mmap() */                /*大页映射到进程地址空间后的虚拟地址，原始的*/
	void *final_virtaddr;     /**< virtual addr of 2nd mmap() */                  /*指向页面的虚拟地址，最终在主从程序中映射的虚拟地址*/
	uint64_t physaddr;  /**< physical addr */                               /*大页物理地址，由映射到进程地址空间的虚拟地址转换而来*/
	size_t size;        /**< the page size */                               /*单个大页size*/
	int socket_id;      /**< NUMA socket ID */                              /*内存属于哪个socket,系统已划分好*/
	int file_id;        /**< the '%d' in HUGEFILE_FMT */                    /*本规格大页编制的大页ID*/
	int memseg_id;      /**< the memory segment to which page belongs */    /*页属于哪个内存段，记录内存段id*/
	char filepath[MAX_HUGEPAGE_PATH]; /**< path to backing file on filesystem */ /*文件系统中大页文件*/
};

/**
 * Read the information from linux on what hugepages are available
 * for the EAL to use
 */
int eal_hugepage_info_init(void);

#endif /* EAL_HUGEPAGES_H */
