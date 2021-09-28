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
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_eal_memconfig.h>
#include <rte_launch.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_common.h>
#include <rte_string_fns.h>
#include <rte_spinlock.h>
#include <rte_memcpy.h>
#include <rte_atomic.h>

#include "malloc_elem.h"
#include "malloc_heap.h"


/*******************************************************
  函数名:		check_hugepage_sz
  功能描述: 	检查大页size
  参数描述: 	flags---大页属性
				hugepage_sz--页大小

  返回值	:   返回大页size及属性
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static unsigned
check_hugepage_sz(unsigned flags, uint64_t hugepage_sz)
{
	unsigned check_flag = 0;

	if (!(flags & ~RTE_MEMZONE_SIZE_HINT_ONLY))
	{
		return 1;
	}
	
	switch (hugepage_sz) 
	{
		case RTE_PGSIZE_256K:
			check_flag = RTE_MEMZONE_256KB;
			break;
		case RTE_PGSIZE_2M:
			check_flag = RTE_MEMZONE_2MB;
			break;
		case RTE_PGSIZE_16M:
			check_flag = RTE_MEMZONE_16MB;
			break;
		case RTE_PGSIZE_256M:
			check_flag = RTE_MEMZONE_256MB;
			break;
		case RTE_PGSIZE_512M:
			check_flag = RTE_MEMZONE_512MB;
			break;
		case RTE_PGSIZE_1G:
			check_flag = RTE_MEMZONE_1GB;
			break;
		case RTE_PGSIZE_4G:
			check_flag = RTE_MEMZONE_4GB;
			break;
		case RTE_PGSIZE_16G:
			check_flag = RTE_MEMZONE_16GB;
	}

	return check_flag & flags;
}

/*
 * Expand the heap with a memseg.
 * This reserves the zone and sets a dummy malloc_elem header at the end
 * to prevent overflow. The rest of the zone is added to free list as a single
 * large free block
 */
 /*******************************************************
  函数名:		malloc_heap_add_memseg
  功能描述: 	ms内存做成elem挂到heap空闲链
  参数描述: 	heap---socket 堆 socket_id做下标，mcfg->malloc_heaps[ms->socket_id]
  				ms---描述了一个映射到进程地址空间的内存大页
  				内存段可能有多个大页同属一个socket，内存做成elem,根据size挂到heap的对应size空闲链
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static void
malloc_heap_add_memseg(struct malloc_heap *heap, struct rte_memseg *ms)
{
	/* allocate the memory block headers, one at end, one at start */

	/*设定内存elem的起始地址终止地址，从ms内存长度取*/
	struct malloc_elem *start_elem = (struct malloc_elem *)ms->addr;
	                                                                /*mem头结构长度+尾部长度*/
	struct malloc_elem *end_elem = RTE_PTR_ADD(ms->addr, ms->len - MALLOC_ELEM_OVERHEAD);

	/*内存elem 64字节对齐*/
	end_elem = RTE_PTR_ALIGN_FLOOR(end_elem, RTE_CACHE_LINE_SIZE);

	/*真实elem长度*/
	const size_t elem_size = (uintptr_t)end_elem - (uintptr_t)start_elem;

	/*elem 地址 长度等赋值*/
	malloc_elem_init(start_elem, heap, ms, elem_size);

	/*尾部剩余内存段size设置成0 prev 设置成start elem*/
	malloc_elem_mkend(end_elem, start_elem);

	/*elem放入空闲链*/
	malloc_elem_free_list_insert(start_elem);

	/*heap总size 增加*/
	heap->total_size += elem_size;
}

/*
 * Iterates through the freelist for a heap to find a free element
 * which can store data of the required size and with the requested alignment.
 * If size is 0, find the biggest available elem.
 * Returns null on failure, or pointer to element on success.
 */
/*******************************************************
  函数名:		find_suitable_element
  功能描述: 	获取合适的元素
  参数描述: 	heap---socket内存堆
				size---requested_len请求长度，sizeof(rte_mempool) + 128个逻辑核cache内存128 * sizeof(struct rte_mempool_cache)+private目前等于0+64字节对齐，
				或，默认长度，为所有socket最长elem长度-sizeof(struct malloc_elem) - 64尾 - 对齐长度，即有效数据部分长度
  				flag---内存池的共享对齐等属性，1G大页或可用大页size
  				align--对齐
  返回值	  : 元素内存新计算的elem 地址，要求的内存包含在elem中，从最后面开始申请
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static struct malloc_elem *
find_suitable_element(struct malloc_heap *heap, size_t size, unsigned flags, size_t align, size_t bound)
{
	size_t idx;
	struct malloc_elem *elem, *alt_elem = NULL;

	/*根据需要内存size 获取堆空闲链表指针，遍历链表*/
	for (idx = malloc_elem_free_list_index(size); idx < RTE_HEAP_NUM_FREELISTS; idx++) 
	{
		/*遍历空闲链表，获取elem空闲元素*/
		for (elem = LIST_FIRST(&heap->free_head[idx]); !!elem; elem = LIST_NEXT(elem, free_list)) 
		{
			/*根据size对elem格式化*/
			if (malloc_elem_can_hold(elem, size, align, bound)) 
			{
				/*检查大页size,及页属性，检查elem哪个大页的size，是否是flag要求的大页，当前要求是1G大页或可用大页*/
				if (check_hugepage_sz(flags, elem->ms->hugepage_sz))
				{
					return elem;
				}
				
				if (alt_elem == NULL)
				{
					alt_elem = elem;
				}
			}
		}
	}

	if ((alt_elem != NULL) && (flags & RTE_MEMZONE_SIZE_HINT_ONLY))
	{
		return alt_elem;
	}
	
	return NULL;
}

/*
 * Main function to allocate a block of memory from the heap.
 * It locks the free list, scans it, and adds a new memseg if the
 * scan fails. Once the new memseg is added, it re-scans and should return
 * the new element after releasing the lock.
 */

/*******************************************************
  函数名:		malloc_heap_alloc
  功能描述: 	为socket获取ele内存
  参数描述: 	heap---socke对应的堆
  				type---当前为NULL
  				size---requested_len请求长度，sizeof(rte_mempool) + 128个逻辑核cache内存128 * sizeof(struct rte_mempool_cache)+private目前等于0+64字节对齐，
  				或，默认长度，为所有socket最长elem长度-sizeof(struct malloc_elem) - 64尾 - 对齐长度，即有效数据部分长度
  				align--64字节对齐
  				bound--当前值为0
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
void *
malloc_heap_alloc(struct malloc_heap *heap, const char *type //__attribute__//((unused))
, size_t size, unsigned flags, size_t align, size_t bound)
{
	struct malloc_elem *elem;

	/*size64字节对齐*/
	size  = RTE_CACHE_LINE_ROUNDUP(size);

	/*对齐标准也64字节对齐，可为64 128 192*/
	align = RTE_CACHE_LINE_ROUNDUP(align);

	/*获取堆锁*/
	rte_spinlock_lock(&heap->lock);

	/*根据size从heap查找足够大的elem内存元素*/
	elem = find_suitable_element(heap, size, flags, align, bound);
	if (elem != NULL)
	{
		/*分割elem元素，多余内存做成elem元素放入空闲链*/
		elem = malloc_elem_alloc(elem, size, align, bound);

		/* increase heap's count of allocated elements */
		heap->alloc_count++;
	}

	/*heap解锁*/
	rte_spinlock_unlock(&heap->lock);

	/*返回的是申请到的elem，elem[0]为剩余做成的elem*/
	return elem == NULL ? NULL : (void *)(&elem[1]);
}

/*
 * Function to retrieve data for heap on given socket
 */
/*******************************************************
  函数名:		malloc_heap_get_stats
  功能描述: 	socket 对应的heap 内存相关统计
  参数描述: 	heap---堆地址
  			    socket_stats--socket 内存使用情况统计
  返回值	:
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
int
malloc_heap_get_stats(const struct malloc_heap *heap, struct rte_malloc_socket_stats *socket_stats)
{
	size_t idx;
	struct malloc_elem *elem;

	/* Initialise variables for heap */
	/*初始化socket统计结构*/
	socket_stats->free_count         = 0;
	socket_stats->heap_freesz_bytes  = 0;
	socket_stats->greatest_free_size = 0;

	/* Iterate through free list */
	/*遍历获取堆上内存元素，获取最长的elem内存元素*/
	for (idx = 0; idx < RTE_HEAP_NUM_FREELISTS; idx++) 
	{
		for (elem = LIST_FIRST(&heap->free_head[idx]); !!elem; elem = LIST_NEXT(elem, free_list))
		{
			/*空闲节点个数，内存大小总和*/
			socket_stats->free_count++;
			socket_stats->heap_freesz_bytes += elem->size;

			/*记录最长内存节点*/
			if (elem->size > socket_stats->greatest_free_size)
			{
				socket_stats->greatest_free_size = elem->size;
			}
		}
	}
	
	/* Get stats on overall heap and allocated memory on this heap */
	/*本heap total size*/
	socket_stats->heap_totalsz_bytes = heap->total_size;

	/*本heap已使用字节数*/
	socket_stats->heap_allocsz_bytes = (socket_stats->heap_totalsz_bytes - socket_stats->heap_freesz_bytes);

	/*本heap已申请次数*/
	socket_stats->alloc_count        = heap->alloc_count;
	
	return 0;
}

/*******************************************************
  函数名:		rte_eal_memzone_init
  功能描述: 	dpdk分好的内存做成链表
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
int
rte_eal_malloc_heap_init(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	unsigned ms_cnt;
	struct rte_memseg *ms;
	
	if (mcfg == NULL)
	{
		return -1;
	}
	
	/*遍历内存块，挂到heap空闲链*/
	for (ms = &mcfg->memseg[0], ms_cnt = 0; (ms_cnt < RTE_MAX_MEMSEG) && (ms->len > 0); ms_cnt++, ms++) 
	{
		/*memseg内存挂链到所属socket heap*/
		malloc_heap_add_memseg(&mcfg->malloc_heaps[ms->socket_id], ms);
	}

	return 0;
}
