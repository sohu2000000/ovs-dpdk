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

#ifndef _RTE_EAL_MEMCONFIG_H_
#define _RTE_EAL_MEMCONFIG_H_

#include <rte_tailq.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_malloc_heap.h>
#include <rte_rwlock.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * the structure for the memory configuration for the RTE.
 * Used by the rte_config structure. It is separated out, as for multi-process
 * support, the memory details should be shared across instances
 */

/*rte全局内存配置*/
struct rte_mem_config 
{
	volatile uint32_t magic;   /**< Magic number - Sanity check. */    /**/

	/* memory topology */
	uint32_t nchannel;    /**< Number of channels (0 if unknown). */   /*通道个数*/
	uint32_t nrank;       /**< Number of ranks (0 if unknown). */      /*阶级个数*/

	/**
	 * current lock nest order
	 *  - qlock->mlock (ring/hash/lpm)
	 *  - mplock->qlock->mlock (mempool)
	 * Notice:
	 *  *ALWAYS* obtain qlock first if having to obtain both qlock and mlock
	 */
	rte_rwlock_t mlock;   /**< only used by memzone LIB for thread-safe. */     /*memzone 锁，线程安全*/
	rte_rwlock_t qlock;   /**< used for tailq operation for thread safe. */     /*尾部队列锁*/
	rte_rwlock_t mplock;  /**< only used by mempool LIB for thread-safe. */     /*mempool锁*/

	uint32_t memzone_cnt; /**< Number of allocated memzones */                  /*memzone 个数*/

	/* memory segments and zones */
	struct rte_memseg memseg[RTE_MAX_MEMSEG];    /**< Physmem descriptors. */   /*物理内存描述信息，描述大页内存，每张大页对应一个结构*/
	struct rte_memzone memzone[RTE_MAX_MEMZONE]; /**< Memzone descriptors. */   /*mzone结构数组*/

	struct rte_tailq_head tailq_head[RTE_MAX_TAILQ]; /**< Tailqs for objects */ /*尾部队列头信息*/

	/* Heaps of Malloc per socket */
	struct malloc_heap malloc_heaps[RTE_MAX_NUMA_NODES];                        /*每socket内存大页链表*/

	/* address of mem_config in primary process. used to map shared config into
	 * exact same address the primary process maps it.
	 */
	uint64_t mem_cfg_addr;                                                      /*映射到主进程的内存配置结构*/
} __attribute__((__packed__));

/*******************************************************
  函数名:		rte_eal_mcfg_wait_complete
  功能描述: 	内存配置等待完成
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
inline static void
rte_eal_mcfg_wait_complete(struct rte_mem_config *mcfg)
{
	/* wait until shared mem_config finish initialising */
	/*等待共享内存结束初始化*/
	while(mcfg->magic != RTE_MAGIC)
		rte_pause();
}

#ifdef __cplusplus
}
#endif

#endif /*__RTE_EAL_MEMCONFIG_H_*/
