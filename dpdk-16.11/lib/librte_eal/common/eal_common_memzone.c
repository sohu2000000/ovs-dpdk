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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_eal_memconfig.h>
#include <rte_per_lcore.h>
#include <rte_errno.h>
#include <rte_string_fns.h>
#include <rte_common.h>

#include "malloc_heap.h"
#include "malloc_elem.h"
#include "eal_private.h"

/*******************************************************
  函数名:		memzone_lookup_thread_unsafe
  功能描述: 	根据名字匹配到memzone
  参数描述: 	name---内存池name
				len---内存池大小
				socket_id---内存池所属于的socket
				flags---内存池的共享对齐等属性
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static inline const struct rte_memzone *
memzone_lookup_thread_unsafe(const char *name)
{
	const struct rte_mem_config *mcfg;
	const struct rte_memzone *memzone;
	unsigned i = 0;

	/* get pointer to global configuration */
	/*全局内存配置*/
	mcfg = rte_eal_get_configuration()->mem_config;

	/*
	 * the algorithm is not optimal (linear), but there are few
	 * zones and this function should be called at init only
	 */

	/*根据name匹配到memzone，遍历2560个格子*/
	for (i = 0; i < RTE_MAX_MEMZONE; i++) 
	{
		memzone = &mcfg->memzone[i];
		if (memzone->addr != NULL && !strncmp(name, memzone->name, RTE_MEMZONE_NAMESIZE))
		{
			return &mcfg->memzone[i];
		}
	}

	return NULL;
}


/*******************************************************
  函数名:		get_next_free_memzone
  功能描述: 	获取下一个memzone
  参数描述: 	name---内存池name
				len---内存池大小
				socket_id---内存池所属于的socket
				flags---内存池的共享对齐等属性
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static inline struct rte_memzone *
get_next_free_memzone(void)
{
	struct rte_mem_config *mcfg;
	unsigned i = 0;

	/* get pointer to global configuration */
	mcfg = rte_eal_get_configuration()->mem_config;

	/*获取空闲mzone格子*/
	for (i = 0; i < RTE_MAX_MEMZONE; i++) 
	{
		if (mcfg->memzone[i].addr == NULL)
		{
			return &mcfg->memzone[i];
		}
	}

	return NULL;
}

/*******************************************************
  函数名:		find_heap_max_free_elem
  功能描述: 	获取最长的一个elem
  参数描述: 	name---内存池name
				len---内存池大小
				s---最长的elem 在的socket，8个socket，8个堆，8个numa
				align--64字节对齐
  返回值	:   返回除去头部长度的长度
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
/* This function will return the greatest free block if a heap has been
 * specified. If no heap has been specified, it will return the heap and
 * length of the greatest free block available in all heaps */
static size_t
find_heap_max_free_elem(int *s, unsigned align)
{
	struct rte_mem_config *mcfg;
	struct rte_malloc_socket_stats stats;
	int i, socket = *s;
	size_t len = 0;

	/* get pointer to global configuration */
	mcfg = rte_eal_get_configuration()->mem_config;

	/*遍历8个heap，socket个数，每个socket一个heap，获取最长的elem*/
	for (i = 0; i < RTE_MAX_NUMA_NODES; i++) 
	{
		if ((socket != SOCKET_ID_ANY) && (socket != i))
		{
			continue;
		}
		
		/*socket对应的heap内存使用情况统计，每socket heap遍历*/
		malloc_heap_get_stats(&mcfg->malloc_heaps[i], &stats);

		/*记录空闲内存最长elem元素*/
		if (stats.greatest_free_size > len)
		{
			len = stats.greatest_free_size;
			/*获取是哪个socket*/
			*s = i;
		}
	}

	/*找到的最长的elem 长度不合法，小于头部长度*/
	/*sizeof(struct malloc_elem) + 64 + 对齐长度*/
	if (len < MALLOC_ELEM_OVERHEAD + align)
		return 0;

	/*返回出去头部长度的长度，即可用长度*/
	return len - MALLOC_ELEM_OVERHEAD - align;
}


/*******************************************************
  函数名:		memzone_reserve_aligned_thread_unsafe
  功能描述: 	mzone内存获取和填充
  参数描述: 	name---内存池name当前为"MP_MBUF_POOL"
				len---sizeof(rte_mempool) + 128个逻辑核cache内存128 * sizeof(struct rte_mempool_cache) + pvivatesize目前为0 + 64字节对齐，或要获取的内存大小
				socket_id---内存池所属于的socket
				flags---内存池的共享对齐等属性，1G大页或可用大页size
				align---64字节对齐
				bound--当前为0
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static const struct rte_memzone *
memzone_reserve_aligned_thread_unsafe(const char *name, size_t len, int socket_id, unsigned flags, unsigned align, unsigned bound)
{
	struct rte_memzone *memzone;
	struct rte_mem_config *mcfg;
	size_t requested_len;
	int socket, i;

	/* get pointer to global configuration */
	/*内存池全局配置 &rte_config;   */
	mcfg = rte_eal_get_configuration()->mem_config;

	/* no more room in config */
	/*目前内存区个数已满*/
	if (mcfg->memzone_cnt >= RTE_MAX_MEMZONE)
	{
		RTE_LOG(ERR, EAL, "%s(): No more room in config\n", __func__);
		rte_errno = ENOSPC;
		return NULL;
	}

	/*name 长度过长*/
	if (strlen(name) > sizeof(memzone->name) - 1)
	{
		RTE_LOG(DEBUG, EAL, "%s(): memzone <%s>: name too long\n",
			__func__, name);
		rte_errno = ENAMETOOLONG;
		return NULL;
	}

	/* zone already exist */
	/*根据name匹配memzone是否已存在*/
	if ((memzone_lookup_thread_unsafe(name)) != NULL) 
	{
		RTE_LOG(DEBUG, EAL, "%s(): memzone <%s> already exists\n",
			__func__, name);
		rte_errno = EEXIST;
		return NULL;
	}

	/* if alignment is not a power of two */
	/*64字节对齐，字节数校验*/
	if (align && !rte_is_power_of_2(align)) 
	{
		RTE_LOG(ERR, EAL, "%s(): Invalid alignment: %u\n", __func__,
				align);
		rte_errno = EINVAL;
		return NULL;
	}

	/* alignment less than cache size is not allowed */
	/*对齐字节*/
	if (align < RTE_CACHE_LINE_SIZE)
	{
		align = RTE_CACHE_LINE_SIZE;
	}
	
	/* align length on cache boundary. Check for overflow before doing so */
	/*内存过长 max-64*/
	if (len > SIZE_MAX - RTE_CACHE_LINE_MASK) 
	{
		rte_errno = EINVAL; /* requested size too big */
		return NULL;
	}

	/*64字节扩展对齐，最后的内存补满64字节*/
	len += RTE_CACHE_LINE_MASK;
	len &= ~((size_t) RTE_CACHE_LINE_MASK);

	/* save minimal requested length */
	/*请求长度计算，最小长度64，与64字节比较获取较长的*/
	requested_len = RTE_MAX((size_t)RTE_CACHE_LINE_SIZE,  len);

	/* check that boundary condition is valid */
	/*边界，这里为0，检查边界是否生效*/
	if (bound != 0 && (requested_len > bound || !rte_is_power_of_2(bound))) 
	{
		rte_errno = EINVAL;
		return NULL;
	}

	/*socket不合法*/
	if ((socket_id != SOCKET_ID_ANY) && (socket_id >= RTE_MAX_NUMA_NODES)) 
	{
		rte_errno = EINVAL;
		return NULL;
	}

	/*非大页模式设置了*/
	if (!rte_eal_has_hugepages())
	{
		socket_id = SOCKET_ID_ANY;
	}

	/*获取请求长度如果为0,则请求最大的elem元素*/
	if (len == 0) 
	{
		if (bound != 0)
		{
			requested_len = bound;
		}
		else
		{
			/*遍历所有socket上堆内存，获取最长的elem，可用长度requested_len = elem长度-sizeof(struct malloc_elem) - 64尾 - 对齐长度*/
			requested_len = find_heap_max_free_elem(&socket_id, align);
			if (requested_len == 0)
			{
				rte_errno = ENOMEM;
				return NULL;
			}
		}
	}


	/*socket ID 获取*/
	if (socket_id == SOCKET_ID_ANY)
	{
		socket = malloc_get_numa_socket();
	}
	else
	{
		socket = socket_id;
	}
	
	/* allocate memory on heap */
	/*从堆获取合适的elemem元素地址，requested_len请求长度，sizeof(rte_mempool) + 128个逻辑核cache内存128 * sizeof(struct rte_mempool_cache)+private目前等于0+64字节对齐*/
														   
	void *mem_zone_addr = malloc_heap_alloc(&mcfg->malloc_heaps[socket], NULL, requested_len, flags, align, bound);

	/*如果不存在合适的elemem，且本socket没有申请到，未指定socket则可以从其他socket获取*/
	if ((mem_zone_addr == NULL) && (socket_id == SOCKET_ID_ANY)) 
	{
		/* try other heaps */
		
		for (i = 0; i < RTE_MAX_NUMA_NODES; i++)
		{
			if (socket == i)
			{
				continue;
			}
			
			/*elem内存地址*/
			mem_zone_addr = malloc_heap_alloc(&mcfg->malloc_heaps[i], NULL, requested_len, flags, align, bound);
			if (mem_zone_addr != NULL)
			{
				break;
			}
		}
	}

	if (mem_zone_addr == NULL)
	{
		rte_errno = ENOMEM;
		return NULL;
	}

	/*原始elem内存地址*/
	const struct malloc_elem *elem = malloc_elem_from_data(mem_zone_addr);

	/* fill the zone in config */
	/*获取全局配置空闲memzone格子*/
	memzone = get_next_free_memzone();

	if (memzone == NULL)
	{
		RTE_LOG(ERR, EAL, "%s(): Cannot find free memzone but there is room "
				"in config!\n", __func__);
		rte_errno = ENOSPC;
		return NULL;
	}

	/*mzone个数增加*/
	mcfg->memzone_cnt++;

	/*内存元素ele填充mzone*/
	snprintf(memzone->name, sizeof(memzone->name), "%s", name);

	memzone->phys_addr   = rte_malloc_virt2phy(mem_zone_addr);   /*elem 转为物理地址*/
	memzone->addr        = mem_zone_addr;                        /*elem虚拟地址*/
	memzone->len         = (requested_len == 0 ? elem->size : requested_len);//mempool结构头+128个逻辑核cache大小+private数据大小+64字节对齐*/
	memzone->hugepage_sz = elem->ms->hugepage_sz;          /*大页内存size,elem做成链表时，这些信息已填充*/
	memzone->socket_id   = elem->ms->socket_id;            /*elem 所属socket*/
	memzone->flags       = 0;
	memzone->memseg_id   = elem->ms - rte_eal_get_configuration()->mem_config->memseg; /*内存段ID*/

	/*所谓mzone就是elem内存外面加的一层壳*/
	return memzone;
}

/*******************************************************
  函数名:		rte_memzone_reserve_thread_safe
  功能描述: 	获取要求长度的elem内存元素，并做成mzone
  参数描述: 	name---mzone name当前为"MP_MBUF_POOL"
				len---sizeof(rte_mempool) + 128个逻辑核cache内存 128 * sizeof(struct rte_mempool_cache)+64字节对齐，或要获取的内存大小
				socket_id---本逻辑核的socketID，内存池所属于的socket
				flags---内存池的共享对齐等属性，1G大页或可用大页size
				align---64字节对齐
  返回值	  : mz--使用elem填充好的mzone
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static const struct rte_memzone *
rte_memzone_reserve_thread_safe(const char *name, size_t len, int socket_id, unsigned flags, unsigned align, unsigned bound)
{
	struct rte_mem_config *mem_cfg;
	const struct rte_memzone *memzone = NULL;

	/* get pointer to global configuration */

	/*全局内存配置结构*/
	mem_cfg = rte_eal_get_configuration()->mem_config;

	/*获取大页内存读写锁*/
	rte_rwlock_write_lock(&mem_cfg->mlock);

	/*获取mzone*/
	memzone = memzone_reserve_aligned_thread_unsafe(name, len, socket_id, flags, align, bound);

	/*释放大页锁*/
	rte_rwlock_write_unlock(&mem_cfg->mlock);

	return memzone;
}

/*
 * Return a pointer to a correctly filled memzone descriptor (with a
 * specified alignment and boundary). If the allocation cannot be done,
 * return NULL.
 */
const struct rte_memzone *
rte_memzone_reserve_bounded(const char *name, size_t len, int socket_id,
			    unsigned flags, unsigned align, unsigned bound)
{
	return rte_memzone_reserve_thread_safe(name, len, socket_id, flags,
					       align, bound);
}

/*
 * Return a pointer to a correctly filled memzone descriptor (with a
 * specified alignment). If the allocation cannot be done, return NULL.
 */
const struct rte_memzone *
rte_memzone_reserve_aligned(const char *name, size_t len, int socket_id,
			    unsigned flags, unsigned align)
{
	return rte_memzone_reserve_thread_safe(name, len, socket_id, flags, align, 0);
}

/*
 * Return a pointer to a correctly filled memzone descriptor. If the
 * allocation cannot be done, return NULL.
 */
 
/*******************************************************
  函数名:		rte_mempool_create_empty
  功能描述: 	memzone保留
  参数描述: 	name---mzone name
  				len---内存池大小 // /*rte_mempool + 128个逻辑核cache内存
  				socket_id---内存池所属于的socket
  				flags---内存池的共享对齐等属性
  				bound--当前为0
  返回值	  : 填充的mzone
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
const struct rte_memzone *rte_memzone_reserve(const char *name, size_t len, int socket_id,
		    unsigned flags)
{
	return rte_memzone_reserve_thread_safe(name, len, socket_id, flags, RTE_CACHE_LINE_SIZE, 0);
}


/*******************************************************
  函数名:		rte_memzone_free
  功能描述: 	memzone释放
  参数描述: 	mz---申请的mzone
  返回值	  : 填充的mzone
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
int
rte_memzone_free(const struct rte_memzone *mz)
{
	struct rte_mem_config *mcfg;
	int ret = 0;
	void *addr;
	unsigned idx;

	if (mz == NULL)
		return -EINVAL;

	mcfg = rte_eal_get_configuration()->mem_config;

	rte_rwlock_write_lock(&mcfg->mlock);

	/*通过地址计算index*/
	idx = ((uintptr_t)mz - (uintptr_t)mcfg->memzone);
	idx = idx / sizeof(struct rte_memzone);

	/*虚拟地址*/
	addr = mcfg->memzone[idx].addr;
	if (addr == NULL)
		ret = -EINVAL;
	else if (mcfg->memzone_cnt == 0) {
		rte_panic("%s(): memzone address not NULL but memzone_cnt is 0!\n",
				__func__);
	} else {
		/*mzone清空*/
		memset(&mcfg->memzone[idx], 0, sizeof(mcfg->memzone[idx]));
		mcfg->memzone_cnt--;
	}

	rte_rwlock_write_unlock(&mcfg->mlock);

	/*elem回收还回空闲链*/
	rte_free(addr);

	return ret;
}

/*
 * Lookup for the memzone identified by the given name
 */
 
/*******************************************************
  函数名:		rte_memzone_lookup
  功能描述: 	根据name匹配memzone
  参数描述: 	name---name
  返回值	:
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
const struct rte_memzone *
rte_memzone_lookup(const char *name)
{
	struct rte_mem_config *mcfg;
	const struct rte_memzone *memzone = NULL;

	mcfg = rte_eal_get_configuration()->mem_config;

	/*获取读锁*/
	rte_rwlock_read_lock(&mcfg->mlock);

	/*根据name匹配memzone*/
	memzone = memzone_lookup_thread_unsafe(name);

	/*释放读锁*/
	rte_rwlock_read_unlock(&mcfg->mlock);

	return memzone;
}

/* Dump all reserved memory zones on console */
void
rte_memzone_dump(FILE *f)
{
	struct rte_mem_config *mcfg;
	unsigned i = 0;

	/*get pointer to global configuration*/
	mcfg = rte_eal_get_configuration()->mem_config;

	rte_rwlock_read_lock(&mcfg->mlock);
	/* dump all zones */
	for (i=0; i<RTE_MAX_MEMZONE; i++) {
		if (mcfg->memzone[i].addr == NULL)
			break;
		fprintf(f, "Zone %u: name:<%s>, phys:0x%"PRIx64", len:0x%zx"
		       ", virt:%p, socket_id:%"PRId32", flags:%"PRIx32"\n", i,
		       mcfg->memzone[i].name,
		       mcfg->memzone[i].phys_addr,
		       mcfg->memzone[i].len,
		       mcfg->memzone[i].addr,
		       mcfg->memzone[i].socket_id,
		       mcfg->memzone[i].flags);
	}
	rte_rwlock_read_unlock(&mcfg->mlock);
}

/*******************************************************
  函数名:		rte_eal_memzone_init
  功能描述: 	dpdk分好的内存做成链表
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
/*
 * Init the memzone subsystem
 */
int rte_eal_memzone_init(void)
{
	struct rte_mem_config *mcfg;
	
	const struct rte_memseg *memseg;

	/* get pointer to global configuration */

	/*全局内存结构*/
	mcfg = rte_eal_get_configuration()->mem_config;

	/* secondary processes don't need to initialise anything */
	/*从线程*/
	if (rte_eal_process_type() == RTE_PROC_SECONDARY)
	{
		return 0;
	}

	/*校验memsg不为空*/
	memseg = rte_eal_get_physmem_layout();
	if (memseg == NULL) 
	{
		RTE_LOG(ERR, EAL, "%s(): Cannot get physical layout\n", __func__);
		return -1;
	}

	rte_rwlock_write_lock(&mcfg->mlock);

	/* delete all zones */

	/*删除所有内存块*/
	mcfg->memzone_cnt = 0;
	memset(mcfg->memzone, 0, sizeof(mcfg->memzone));

	rte_rwlock_write_unlock(&mcfg->mlock);

	/*heap初始化，ms内存挂到socket heap空闲链*/
	return rte_eal_malloc_heap_init();
}

/* Walk all reserved memory zones */
void rte_memzone_walk(void (*func)(const struct rte_memzone *, void *),
		      void *arg)
{
	struct rte_mem_config *mcfg;
	unsigned i;

	mcfg = rte_eal_get_configuration()->mem_config;

	rte_rwlock_read_lock(&mcfg->mlock);
	for (i=0; i<RTE_MAX_MEMZONE; i++)
	{
		if (mcfg->memzone[i].addr != NULL)
			(*func)(&mcfg->memzone[i], arg);
	}
	rte_rwlock_read_unlock(&mcfg->mlock);
}
