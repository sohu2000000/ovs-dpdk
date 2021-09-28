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
  ������:		memzone_lookup_thread_unsafe
  ��������: 	��������ƥ�䵽memzone
  ��������: 	name---�ڴ��name
				len---�ڴ�ش�С
				socket_id---�ڴ�������ڵ�socket
				flags---�ڴ�صĹ�����������
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static inline const struct rte_memzone *
memzone_lookup_thread_unsafe(const char *name)
{
	const struct rte_mem_config *mcfg;
	const struct rte_memzone *memzone;
	unsigned i = 0;

	/* get pointer to global configuration */
	/*ȫ���ڴ�����*/
	mcfg = rte_eal_get_configuration()->mem_config;

	/*
	 * the algorithm is not optimal (linear), but there are few
	 * zones and this function should be called at init only
	 */

	/*����nameƥ�䵽memzone������2560������*/
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
  ������:		get_next_free_memzone
  ��������: 	��ȡ��һ��memzone
  ��������: 	name---�ڴ��name
				len---�ڴ�ش�С
				socket_id---�ڴ�������ڵ�socket
				flags---�ڴ�صĹ�����������
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static inline struct rte_memzone *
get_next_free_memzone(void)
{
	struct rte_mem_config *mcfg;
	unsigned i = 0;

	/* get pointer to global configuration */
	mcfg = rte_eal_get_configuration()->mem_config;

	/*��ȡ����mzone����*/
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
  ������:		find_heap_max_free_elem
  ��������: 	��ȡ���һ��elem
  ��������: 	name---�ڴ��name
				len---�ڴ�ش�С
				s---���elem �ڵ�socket��8��socket��8���ѣ�8��numa
				align--64�ֽڶ���
  ����ֵ	:   ���س�ȥͷ�����ȵĳ���
  ����޸���:
  �޸�����:    2017 -11-15
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

	/*����8��heap��socket������ÿ��socketһ��heap����ȡ���elem*/
	for (i = 0; i < RTE_MAX_NUMA_NODES; i++) 
	{
		if ((socket != SOCKET_ID_ANY) && (socket != i))
		{
			continue;
		}
		
		/*socket��Ӧ��heap�ڴ�ʹ�����ͳ�ƣ�ÿsocket heap����*/
		malloc_heap_get_stats(&mcfg->malloc_heaps[i], &stats);

		/*��¼�����ڴ��elemԪ��*/
		if (stats.greatest_free_size > len)
		{
			len = stats.greatest_free_size;
			/*��ȡ���ĸ�socket*/
			*s = i;
		}
	}

	/*�ҵ������elem ���Ȳ��Ϸ���С��ͷ������*/
	/*sizeof(struct malloc_elem) + 64 + ���볤��*/
	if (len < MALLOC_ELEM_OVERHEAD + align)
		return 0;

	/*���س�ȥͷ�����ȵĳ��ȣ������ó���*/
	return len - MALLOC_ELEM_OVERHEAD - align;
}


/*******************************************************
  ������:		memzone_reserve_aligned_thread_unsafe
  ��������: 	mzone�ڴ��ȡ�����
  ��������: 	name---�ڴ��name��ǰΪ"MP_MBUF_POOL"
				len---sizeof(rte_mempool) + 128���߼���cache�ڴ�128 * sizeof(struct rte_mempool_cache) + pvivatesizeĿǰΪ0 + 64�ֽڶ��룬��Ҫ��ȡ���ڴ��С
				socket_id---�ڴ�������ڵ�socket
				flags---�ڴ�صĹ����������ԣ�1G��ҳ����ô�ҳsize
				align---64�ֽڶ���
				bound--��ǰΪ0
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static const struct rte_memzone *
memzone_reserve_aligned_thread_unsafe(const char *name, size_t len, int socket_id, unsigned flags, unsigned align, unsigned bound)
{
	struct rte_memzone *memzone;
	struct rte_mem_config *mcfg;
	size_t requested_len;
	int socket, i;

	/* get pointer to global configuration */
	/*�ڴ��ȫ������ &rte_config;   */
	mcfg = rte_eal_get_configuration()->mem_config;

	/* no more room in config */
	/*Ŀǰ�ڴ�����������*/
	if (mcfg->memzone_cnt >= RTE_MAX_MEMZONE)
	{
		RTE_LOG(ERR, EAL, "%s(): No more room in config\n", __func__);
		rte_errno = ENOSPC;
		return NULL;
	}

	/*name ���ȹ���*/
	if (strlen(name) > sizeof(memzone->name) - 1)
	{
		RTE_LOG(DEBUG, EAL, "%s(): memzone <%s>: name too long\n",
			__func__, name);
		rte_errno = ENAMETOOLONG;
		return NULL;
	}

	/* zone already exist */
	/*����nameƥ��memzone�Ƿ��Ѵ���*/
	if ((memzone_lookup_thread_unsafe(name)) != NULL) 
	{
		RTE_LOG(DEBUG, EAL, "%s(): memzone <%s> already exists\n",
			__func__, name);
		rte_errno = EEXIST;
		return NULL;
	}

	/* if alignment is not a power of two */
	/*64�ֽڶ��룬�ֽ���У��*/
	if (align && !rte_is_power_of_2(align)) 
	{
		RTE_LOG(ERR, EAL, "%s(): Invalid alignment: %u\n", __func__,
				align);
		rte_errno = EINVAL;
		return NULL;
	}

	/* alignment less than cache size is not allowed */
	/*�����ֽ�*/
	if (align < RTE_CACHE_LINE_SIZE)
	{
		align = RTE_CACHE_LINE_SIZE;
	}
	
	/* align length on cache boundary. Check for overflow before doing so */
	/*�ڴ���� max-64*/
	if (len > SIZE_MAX - RTE_CACHE_LINE_MASK) 
	{
		rte_errno = EINVAL; /* requested size too big */
		return NULL;
	}

	/*64�ֽ���չ���룬�����ڴ油��64�ֽ�*/
	len += RTE_CACHE_LINE_MASK;
	len &= ~((size_t) RTE_CACHE_LINE_MASK);

	/* save minimal requested length */
	/*���󳤶ȼ��㣬��С����64����64�ֽڱȽϻ�ȡ�ϳ���*/
	requested_len = RTE_MAX((size_t)RTE_CACHE_LINE_SIZE,  len);

	/* check that boundary condition is valid */
	/*�߽磬����Ϊ0�����߽��Ƿ���Ч*/
	if (bound != 0 && (requested_len > bound || !rte_is_power_of_2(bound))) 
	{
		rte_errno = EINVAL;
		return NULL;
	}

	/*socket���Ϸ�*/
	if ((socket_id != SOCKET_ID_ANY) && (socket_id >= RTE_MAX_NUMA_NODES)) 
	{
		rte_errno = EINVAL;
		return NULL;
	}

	/*�Ǵ�ҳģʽ������*/
	if (!rte_eal_has_hugepages())
	{
		socket_id = SOCKET_ID_ANY;
	}

	/*��ȡ���󳤶����Ϊ0,����������elemԪ��*/
	if (len == 0) 
	{
		if (bound != 0)
		{
			requested_len = bound;
		}
		else
		{
			/*��������socket�϶��ڴ棬��ȡ���elem�����ó���requested_len = elem����-sizeof(struct malloc_elem) - 64β - ���볤��*/
			requested_len = find_heap_max_free_elem(&socket_id, align);
			if (requested_len == 0)
			{
				rte_errno = ENOMEM;
				return NULL;
			}
		}
	}


	/*socket ID ��ȡ*/
	if (socket_id == SOCKET_ID_ANY)
	{
		socket = malloc_get_numa_socket();
	}
	else
	{
		socket = socket_id;
	}
	
	/* allocate memory on heap */
	/*�Ӷѻ�ȡ���ʵ�elememԪ�ص�ַ��requested_len���󳤶ȣ�sizeof(rte_mempool) + 128���߼���cache�ڴ�128 * sizeof(struct rte_mempool_cache)+privateĿǰ����0+64�ֽڶ���*/
														   
	void *mem_zone_addr = malloc_heap_alloc(&mcfg->malloc_heaps[socket], NULL, requested_len, flags, align, bound);

	/*��������ں��ʵ�elemem���ұ�socketû�����뵽��δָ��socket����Դ�����socket��ȡ*/
	if ((mem_zone_addr == NULL) && (socket_id == SOCKET_ID_ANY)) 
	{
		/* try other heaps */
		
		for (i = 0; i < RTE_MAX_NUMA_NODES; i++)
		{
			if (socket == i)
			{
				continue;
			}
			
			/*elem�ڴ��ַ*/
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

	/*ԭʼelem�ڴ��ַ*/
	const struct malloc_elem *elem = malloc_elem_from_data(mem_zone_addr);

	/* fill the zone in config */
	/*��ȡȫ�����ÿ���memzone����*/
	memzone = get_next_free_memzone();

	if (memzone == NULL)
	{
		RTE_LOG(ERR, EAL, "%s(): Cannot find free memzone but there is room "
				"in config!\n", __func__);
		rte_errno = ENOSPC;
		return NULL;
	}

	/*mzone��������*/
	mcfg->memzone_cnt++;

	/*�ڴ�Ԫ��ele���mzone*/
	snprintf(memzone->name, sizeof(memzone->name), "%s", name);

	memzone->phys_addr   = rte_malloc_virt2phy(mem_zone_addr);   /*elem תΪ�����ַ*/
	memzone->addr        = mem_zone_addr;                        /*elem�����ַ*/
	memzone->len         = (requested_len == 0 ? elem->size : requested_len);//mempool�ṹͷ+128���߼���cache��С+private���ݴ�С+64�ֽڶ���*/
	memzone->hugepage_sz = elem->ms->hugepage_sz;          /*��ҳ�ڴ�size,elem��������ʱ����Щ��Ϣ�����*/
	memzone->socket_id   = elem->ms->socket_id;            /*elem ����socket*/
	memzone->flags       = 0;
	memzone->memseg_id   = elem->ms - rte_eal_get_configuration()->mem_config->memseg; /*�ڴ��ID*/

	/*��νmzone����elem�ڴ�����ӵ�һ���*/
	return memzone;
}

/*******************************************************
  ������:		rte_memzone_reserve_thread_safe
  ��������: 	��ȡҪ�󳤶ȵ�elem�ڴ�Ԫ�أ�������mzone
  ��������: 	name---mzone name��ǰΪ"MP_MBUF_POOL"
				len---sizeof(rte_mempool) + 128���߼���cache�ڴ� 128 * sizeof(struct rte_mempool_cache)+64�ֽڶ��룬��Ҫ��ȡ���ڴ��С
				socket_id---���߼��˵�socketID���ڴ�������ڵ�socket
				flags---�ڴ�صĹ����������ԣ�1G��ҳ����ô�ҳsize
				align---64�ֽڶ���
  ����ֵ	  : mz--ʹ��elem���õ�mzone
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static const struct rte_memzone *
rte_memzone_reserve_thread_safe(const char *name, size_t len, int socket_id, unsigned flags, unsigned align, unsigned bound)
{
	struct rte_mem_config *mem_cfg;
	const struct rte_memzone *memzone = NULL;

	/* get pointer to global configuration */

	/*ȫ���ڴ����ýṹ*/
	mem_cfg = rte_eal_get_configuration()->mem_config;

	/*��ȡ��ҳ�ڴ��д��*/
	rte_rwlock_write_lock(&mem_cfg->mlock);

	/*��ȡmzone*/
	memzone = memzone_reserve_aligned_thread_unsafe(name, len, socket_id, flags, align, bound);

	/*�ͷŴ�ҳ��*/
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
  ������:		rte_mempool_create_empty
  ��������: 	memzone����
  ��������: 	name---mzone name
  				len---�ڴ�ش�С // /*rte_mempool + 128���߼���cache�ڴ�
  				socket_id---�ڴ�������ڵ�socket
  				flags---�ڴ�صĹ�����������
  				bound--��ǰΪ0
  ����ֵ	  : ����mzone
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
const struct rte_memzone *rte_memzone_reserve(const char *name, size_t len, int socket_id,
		    unsigned flags)
{
	return rte_memzone_reserve_thread_safe(name, len, socket_id, flags, RTE_CACHE_LINE_SIZE, 0);
}


/*******************************************************
  ������:		rte_memzone_free
  ��������: 	memzone�ͷ�
  ��������: 	mz---�����mzone
  ����ֵ	  : ����mzone
  ����޸���:
  �޸�����:    2017 -11-15
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

	/*ͨ����ַ����index*/
	idx = ((uintptr_t)mz - (uintptr_t)mcfg->memzone);
	idx = idx / sizeof(struct rte_memzone);

	/*�����ַ*/
	addr = mcfg->memzone[idx].addr;
	if (addr == NULL)
		ret = -EINVAL;
	else if (mcfg->memzone_cnt == 0) {
		rte_panic("%s(): memzone address not NULL but memzone_cnt is 0!\n",
				__func__);
	} else {
		/*mzone���*/
		memset(&mcfg->memzone[idx], 0, sizeof(mcfg->memzone[idx]));
		mcfg->memzone_cnt--;
	}

	rte_rwlock_write_unlock(&mcfg->mlock);

	/*elem���ջ��ؿ�����*/
	rte_free(addr);

	return ret;
}

/*
 * Lookup for the memzone identified by the given name
 */
 
/*******************************************************
  ������:		rte_memzone_lookup
  ��������: 	����nameƥ��memzone
  ��������: 	name---name
  ����ֵ	:
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
const struct rte_memzone *
rte_memzone_lookup(const char *name)
{
	struct rte_mem_config *mcfg;
	const struct rte_memzone *memzone = NULL;

	mcfg = rte_eal_get_configuration()->mem_config;

	/*��ȡ����*/
	rte_rwlock_read_lock(&mcfg->mlock);

	/*����nameƥ��memzone*/
	memzone = memzone_lookup_thread_unsafe(name);

	/*�ͷŶ���*/
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
  ������:		rte_eal_memzone_init
  ��������: 	dpdk�ֺõ��ڴ���������
  ��������: 	
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
/*
 * Init the memzone subsystem
 */
int rte_eal_memzone_init(void)
{
	struct rte_mem_config *mcfg;
	
	const struct rte_memseg *memseg;

	/* get pointer to global configuration */

	/*ȫ���ڴ�ṹ*/
	mcfg = rte_eal_get_configuration()->mem_config;

	/* secondary processes don't need to initialise anything */
	/*���߳�*/
	if (rte_eal_process_type() == RTE_PROC_SECONDARY)
	{
		return 0;
	}

	/*У��memsg��Ϊ��*/
	memseg = rte_eal_get_physmem_layout();
	if (memseg == NULL) 
	{
		RTE_LOG(ERR, EAL, "%s(): Cannot get physical layout\n", __func__);
		return -1;
	}

	rte_rwlock_write_lock(&mcfg->mlock);

	/* delete all zones */

	/*ɾ�������ڴ��*/
	mcfg->memzone_cnt = 0;
	memset(mcfg->memzone, 0, sizeof(mcfg->memzone));

	rte_rwlock_write_unlock(&mcfg->mlock);

	/*heap��ʼ����ms�ڴ�ҵ�socket heap������*/
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
