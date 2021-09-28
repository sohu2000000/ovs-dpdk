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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/queue.h>

#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_eal_memconfig.h>
#include <rte_log.h>

#include "eal_private.h"
#include "eal_internal_cfg.h"

/*
 * Return a pointer to a read-only table of struct rte_physmem_desc
 * elements, containing the layout of all addressable physical
 * memory. The last element of the table contains a NULL address.
 */
const struct rte_memseg *
rte_eal_get_physmem_layout(void)
{
	return rte_eal_get_configuration()->mem_config->memseg;
}


/* get the total size of memory */
uint64_t
rte_eal_get_physmem_size(void)
{
	const struct rte_mem_config *mcfg;
	unsigned i = 0;
	uint64_t total_len = 0;

	/* get pointer to global configuration */
	mcfg = rte_eal_get_configuration()->mem_config;

	for (i = 0; i < RTE_MAX_MEMSEG; i++) {
		if (mcfg->memseg[i].addr == NULL)
			break;

		total_len += mcfg->memseg[i].len;
	}

	return total_len;
}

/* Dump the physical memory layout on console */
void
rte_dump_physmem_layout(FILE *f)
{
	const struct rte_mem_config *mcfg;
	unsigned i = 0;

	/* get pointer to global configuration */
	mcfg = rte_eal_get_configuration()->mem_config;

	for (i = 0; i < RTE_MAX_MEMSEG; i++) {
		if (mcfg->memseg[i].addr == NULL)
			break;

		fprintf(f, "Segment %u: phys:0x%"PRIx64", len:%zu, "
		       "virt:%p, socket_id:%"PRId32", "
		       "hugepage_sz:%"PRIu64", nchannel:%"PRIx32", "
		       "nrank:%"PRIx32"\n", i,
		       mcfg->memseg[i].phys_addr,
		       mcfg->memseg[i].len,
		       mcfg->memseg[i].addr,
		       mcfg->memseg[i].socket_id,
		       mcfg->memseg[i].hugepage_sz,
		       mcfg->memseg[i].nchannel,
		       mcfg->memseg[i].nrank);
	}
}

/* return the number of memory channels */
unsigned rte_memory_get_nchannel(void)
{
	return rte_eal_get_configuration()->mem_config->nchannel;
}

/* return the number of memory rank */
unsigned rte_memory_get_nrank(void)
{
	return rte_eal_get_configuration()->mem_config->nrank;
}

/*******************************************************
  函数名:		rte_eal_memdevice_init
  功能描述: 	内存设备初始化
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static int
rte_eal_memdevice_init(void)
{
	struct rte_config *config;

	if (rte_eal_process_type() == RTE_PROC_SECONDARY)
	{
		return 0;
	}

	/*全局配置*/
	config = rte_eal_get_configuration();

	/*启动参数中“-n”指定的值，不能为0，不能大于4。*/
	config->mem_config->nchannel = internal_config.force_nchannel;

	/*启动参数中“-r”指定的值。不能为0，不能大于16。*/
	config->mem_config->nrank = internal_config.force_nrank;

	return 0;
}

/*******************************************************
  函数名:		rte_eal_memory_init
  功能描述: 	大页内存映射到了进程地址空间记录到了memseg里
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
/* init memory subsystem */
int rte_eal_memory_init(void)
{
	RTE_LOG(DEBUG, EAL, "Setting up physically contiguous memory...\n");

	/*内存页申请，主进程完成大页映射，然后直接映射到次进程，记录到了memseg里*/
	const int retval = rte_eal_process_type() == RTE_PROC_PRIMARY ? rte_eal_hugepage_init() : rte_eal_hugepage_attach();
	if (retval < 0)
	{
		return -1;
	}
	
	/*没有设置内存共享*/
	if (internal_config.no_shconf == 0 && rte_eal_memdevice_init() < 0)
	{
		return -1;
	}
	
	return 0;
}
