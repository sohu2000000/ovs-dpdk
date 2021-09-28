/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   Copyright(c) 2016 6WIND S.A.
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
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/mman.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_malloc.h>
#include <rte_atomic.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_eal_memconfig.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_errno.h>
#include <rte_string_fns.h>
#include <rte_spinlock.h>

#include "rte_mempool.h"

TAILQ_HEAD(rte_mempool_list, rte_tailq_entry);

static struct rte_tailq_elem rte_mempool_tailq = {
	.name = "RTE_MEMPOOL",
};
EAL_REGISTER_TAILQ(rte_mempool_tailq)

#define CACHE_FLUSHTHRESH_MULTIPLIER 1.5
#define CALC_CACHE_FLUSHTHRESH(c)	\
	((typeof(c))((c) * CACHE_FLUSHTHRESH_MULTIPLIER))

/*
 * return the greatest common divisor between a and b (fast algorithm)
 *
 */

/*����ab�������*/
static unsigned get_gcd(unsigned a, unsigned b)
{
	unsigned c;

	if (0 == a)
		return b;
	if (0 == b)
		return a;

	/*a < b ��ô ab����*/
	if (a < b)
	{
		c = a;
		a = b;
		b = c;
	}

	/*4 3*/
	while (b != 0) 
	{
		c = a % b;
		a = b;
		b = c;
	}

	return a;
}

/*******************************************************
  ������:		optimize_object_size
  ��������: 	�����յ��ڴ��
  ��������: 	obj_size---����size��size
  ����ֵ  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
/*
 * Depending on memory configuration, objects addresses are spread
 * between channels and ranks in RAM: the pool allocator will add
 * padding between objects. This function return the new size of the
 * object.
 */
static unsigned optimize_object_size(unsigned obj_size)
{
	unsigned nrank, nchan;
	unsigned new_obj_size;

	/* get number of channels */

	/*��ȡn��channel*/
	nchan = rte_memory_get_nchannel();
	if (nchan == 0)
	{
		nchan = 4;
	}
	
	/*�ײ����*/
	nrank = rte_memory_get_nrank();
	if (nrank == 0)
	{
		nrank = 1;
	}
	
	/* process new object size */

	/*�ֽڶ������Ҫ������ٸ���λ��64�ֽ��ڴ�*/
	new_obj_size = (obj_size + RTE_MEMPOOL_ALIGN_MASK) / RTE_MEMPOOL_ALIGN;

	/*��չnew_obj_size��ʹ����ͨ��x�ײ㣬����󹫹����أ�new_obj_size��Ҫ��ͨ��x�ײ�ĸ���*/
	while (get_gcd(new_obj_size, nrank * nchan) != 1)
	{
		new_obj_size++;
	}
	
	/*���ض���+��չ��Ķ���size*/
	return new_obj_size * RTE_MEMPOOL_ALIGN;
}

/*******************************************************
  ������:		optimize_object_size
  ��������: 	mbuf�����
  ��������: 	mp--�ڴ��
 				obj--mp ƫ��mp header size��mbuf obj ͷ+x+β��x��ַ�������ַ
  				obj_size---����size��size
  				physaddr---mbuf obj ͷ+x+β��x��ַ�����ַ
  ����ֵ  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static void
mempool_add_elem(struct rte_mempool *mempool, void *obj, phys_addr_t physaddr)
{
	struct rte_mempool_objhdr *hdr;
	struct rte_mempool_objtlr *tlr __rte_unused;

	/* set mempool ptr in header */
	/*��ȡͷ����ַobj����header size*/
	hdr = RTE_PTR_SUB(obj, sizeof(*hdr));
	hdr->mp = mempool;
	hdr->physaddr = physaddr;

	/*��������β��*/
	/*mbuf obj ����*/
	STAILQ_INSERT_TAIL(&mempool->elt_list, hdr, next);

	/*������ڴ��¼*/
	mempool->populated_size++;

#ifdef RTE_LIBRTE_MEMPOOL_DEBUG

	hdr->cookie = RTE_MEMPOOL_HEADER_COOKIE2;
	tlr = __mempool_get_trailer(obj);
	tlr->cookie = RTE_MEMPOOL_TRAILER_COOKIE;

#endif

	/* enqueue in ring */
	/*x�����*/
    /* obj--mp ƫ��mp header size��mbuf obj ͷ+x+β��x��ַ�������ַ�������*/
	/*mbuf�����*/
	rte_mempool_ops_enqueue_bulk(mempool, &obj, 1);
}


/*******************************************************
  ������:	   rte_mempool_create
  ��������:    dpdk�ڴ������
  ��������:    name--�ڴ���
  			   obj_cb_arg---null
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
/* call obj_cb() for each mempool element */
uint32_t
rte_mempool_obj_iter(struct rte_mempool *mp, rte_mempool_obj_cb_t *obj_cb, void *obj_cb_arg)
{
	struct rte_mempool_objhdr *hdr;
	void *obj;
	unsigned n = 0;

	STAILQ_FOREACH(hdr, &mp->elt_list, next)
	{
		/*��ȡmbuf obj�ĵ�ַ*/
		obj = (char *)hdr + sizeof(*hdr);

		/*rte_pktmbuf_init(mp, obj_cb_arg, obj, n)*/
		obj_cb(mp, obj_cb_arg, obj, n);

		n++;
	}

	return n;
}

/*******************************************************************************
 ��������  :    rte_mempool_mem_iter
 ��������  :    
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
/* call mem_cb() for each mempool memory chunk */
uint32_t
rte_mempool_mem_iter(struct rte_mempool *mp,
	rte_mempool_mem_cb_t *mem_cb, void *mem_cb_arg)
{
	struct rte_mempool_memhdr *hdr;
	unsigned n = 0;

	STAILQ_FOREACH(hdr, &mp->mem_list, next) {
		mem_cb(mp, mem_cb_arg, hdr, n);
		n++;
	}

	return n;
}

/*******************************************************
  ������:		rte_mempool_calc_obj_size
  ��������: 	64�ֽڶ���Ӻ�ͨ��x�ײ���չ�������ʽ��������mbuf size

				��ȡ�����ĵ���mbuf����size
				sizeof(struct rte_mempool_objhdr)+elt_size+obj_size_info->trailer_size
			
  			
  ��������: 	pkt_size---һ������sizeof(rte_mbuf) + priv + 2176������mbuf obj size��priv=0
				flags---�ڴ�صĹ����������ԣ���ǰֵΪ0
				sz---�ڴ�ض���size�����ṹ
				obj_size_info---�ڴ�����¼�ĸ���size


				name---����������
				elt_size--mbufͷ�����ݲ���+priv���ȣ�����һ������rte_mbuf
				elt_size--/*rte_mbuf + prive_size + dataroom*/
				/*rte_mbuf+rte_pktmbufheadroom+dataroom
				flags---�ڴ�صĹ����������ԣ���ǰֵΪ0 flags---�ڴ�صĹ����������ԣ���ǰֵΪ0
				sz---�ڴ�ض���size�����ṹ

				
  ����ֵ	  : �ڴ���ڴ����obj size
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/

/* get the header, trailer and total size of a mempool element. */
uint32_t
rte_mempool_calc_obj_size(uint32_t pkt_size, uint32_t flags, struct rte_mempool_objsz *obj_size_info)
{
	struct rte_mempool_objsz tmp_obj_size_info;

	obj_size_info = (obj_size_info != NULL) ? obj_size_info : &tmp_obj_size_info;

	/*�ڴ���ڴ����ͷsize*/
	obj_size_info->header_size = sizeof(struct rte_mempool_objhdr);

	/*���δ�����ֽڷǶ��룬ͷ�����ȣ���64�ֽڶ���*/
	if ((flags & MEMPOOL_F_NO_CACHE_ALIGN) == 0)
	{
		obj_size_info->header_size = RTE_ALIGN_CEIL(obj_size_info->header_size, RTE_MEMPOOL_ALIGN);
	}
	

	/*�ڴ�ض��������ṹβ��size*/
#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
	obj_size_info->trailer_size = sizeof(struct rte_mempool_objtlr);
#else
	obj_size_info->trailer_size = 0;
#endif

	/* element size is 8 bytes-aligned at least */

	/*���� mbuf���������ṹ + priv���� + ���ݲ��֣����� ���ݲ���2176������64�ֽڶ���*/
	obj_size_info->pkt_size = RTE_ALIGN_CEIL(pkt_size, sizeof(uint64_t));

	/* expand trailer to next cache line */
	/*�ڴ��cacheδ���÷Ƕ���*/
	if ((flags & MEMPOOL_F_NO_CACHE_ALIGN) == 0) 
	{
		/*�ڴ�ض���totalsize=head_size+elt_size+trailer_size*/
		obj_size_info->total_size = obj_size_info->header_size + obj_size_info->elt_size + obj_size_info->trailer_size;

		/*��չ��64�ֽڶ���*/                        /*��ֵΪ64�ֽڶ�����Ҫ�����ֽ���*/
		obj_size_info->trailer_size += ((RTE_MEMPOOL_ALIGN - (obj_size_info->total_size & RTE_MEMPOOL_ALIGN_MASK)) & RTE_MEMPOOL_ALIGN_MASK);
	}

	/*
	 * increase trailer to add padding between objects in order to
	 * spread them across memory channels/ranks
	 */

	/*�ڴ��δ���÷���չ*/
	if ((flags & MEMPOOL_F_NO_SPREAD) == 0) 
	{
		unsigned new_size;

		/*��ͨ���ԱȺ󣬸�ʽ������ڴ�*/
		new_size = optimize_object_size(obj_size_info->header_size + obj_size_info->elt_size + obj_size_info->trailer_size);

		/*�޸���չ���β��size*/
		obj_size_info->trailer_size = new_size - obj_size_info->header_size - obj_size_info->elt_size;
	}

	/* this is the size of an object, including header and trailer */

	/*�µĶ�����size*/   /*sizeof(struct rte_mempool_objhdr)+ (rte_mbuf + prive_size + dataroom)+ sizeof(struct rte_mempool_objtlr) + 64�ֽڶ���*/
	obj_size_info->total_size = obj_size_info->header_size + obj_size_info->elt_size + obj_size_info->trailer_size;

	/*�ڴ�� mbuf����Ķ���size*/
	return obj_size_info->total_size;
}


/*
 * Calculate maximum amount of memory required to store given number of objects.
 */
/*******************************************************
  ������:		rte_mempool_xmem_size
  ��������: 	�����ڴ�����е�mbuf��Ҫ���ڴ�֮��
  ��������: 	elt_num--���ж˿�mbuf����֮��
                total_elt_sz---/*rte_mempool_objhdr ��������size��rte_mbuf+rte_pktmbufheadroom+dataroom rte_mempool_objtlr
  ����ֵ  :     pg_shift---��ҳsize,ת����1����λ��
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
size_t rte_mempool_xmem_size(uint32_t elt_num, size_t total_elt_sz, uint32_t pg_shift)
{
	size_t obj_per_page_elt_num, page_num, pg_sz;

	if (total_elt_sz == 0)
	{
		return 0;
	}

	if (pg_shift == 0)
	{
		return total_elt_sz * elt_num;         /*����mbuf ��Ҫ�ڴ�֮��*/
	}
	
	/*��ҳsize*/
	pg_sz = (size_t)1 << pg_shift;

	/*һ��ҳ�����и�ɵ�mbuf����*/
	obj_per_page_elt_num = pg_sz / total_elt_sz;

	/*�ڴ治�㣬*/
	if (obj_per_page_elt_num == 0)
	{
		return RTE_ALIGN_CEIL(total_elt_sz, pg_sz) * elt_num; /*total_elt_sz��pg_sz���� x mbuf������������mbuf��Ҫ���ڴ���*/
	}
	
	/*��mbuf��������Ҫ�ڴ�ҳ��֮��*/
	/*��Ҫ�Ĵ�ҳ����֮��*/
	page_num = (elt_num + obj_per_page_elt_num - 1) / obj_per_page_elt_num;

	/*pag_num x 1 << pg_shift�������ڴ�֮��*/
	return page_num << pg_shift;
}

/*
 * Calculate how much memory would be actually required with the
 * given memory footprint to store required number of elements.
 */
ssize_t
rte_mempool_xmem_usage(__rte_unused void *vaddr, uint32_t elt_num,
	size_t total_elt_sz, const phys_addr_t paddr[], uint32_t pg_num,
	uint32_t pg_shift)
{
	uint32_t elt_cnt = 0;
	phys_addr_t start, end;
	uint32_t paddr_idx;
	size_t pg_sz = (size_t)1 << pg_shift;

	/* if paddr is NULL, assume contiguous memory */
	if (paddr == NULL) {
		start = 0;
		end = pg_sz * pg_num;
		paddr_idx = pg_num;
	} else {
		start = paddr[0];
		end = paddr[0] + pg_sz;
		paddr_idx = 1;
	}
	while (elt_cnt < elt_num) {

		if (end - start >= total_elt_sz) {
			/* enough contiguous memory, add an object */
			start += total_elt_sz;
			elt_cnt++;
		} else if (paddr_idx < pg_num) {
			/* no room to store one obj, add a page */
			if (end == paddr[paddr_idx]) {
				end += pg_sz;
			} else {
				start = paddr[paddr_idx];
				end = paddr[paddr_idx] + pg_sz;
			}
			paddr_idx++;

		} else {
			/* no more page, return how many elements fit */
			return -(size_t)elt_cnt;
		}
	}

	return (size_t)paddr_idx << pg_shift;
}

/* free a memchunk allocated with rte_memzone_reserve() */
static void
rte_mempool_memchunk_mz_free(__rte_unused struct rte_mempool_memhdr *memhdr,
	void *opaque)
{
	const struct rte_memzone *mz = opaque;
	rte_memzone_free(mz);
}

/* Free memory chunks used by a mempool. Objects must be in pool */
static void
rte_mempool_free_memchunks(struct rte_mempool *mp)
{
	struct rte_mempool_memhdr *memhdr;
	void *elt;

	while (!STAILQ_EMPTY(&mp->elt_list)) {
		rte_mempool_ops_dequeue_bulk(mp, &elt, 1);
		(void)elt;
		STAILQ_REMOVE_HEAD(&mp->elt_list, next);
		mp->populated_size--;
	}

	while (!STAILQ_EMPTY(&mp->mem_list)) {
		memhdr = STAILQ_FIRST(&mp->mem_list);
		STAILQ_REMOVE_HEAD(&mp->mem_list, next);
		if (memhdr->free_cb != NULL)
			memhdr->free_cb(memhdr, memhdr->opaque);
		rte_free(memhdr);
		mp->nb_mem_chunks--;
	}
}

/* Add objects in the pool, using a physically contiguous memory
 * zone. Return the number of objects added, or a negative value
 * on error.
 */
 /*******************************************************
  ������:	   rte_mempool_populate_default
  ��������:    ��ҳ����mbuf�������
  ��������:    mempool--�ڴ�أ���ʵ��ַΪelem��ַ��128 �߼��� cache elem 
  			   addr---����mbuf��mezone��elem �����ַ
  			   paddr---mz�е�elem�����ַ
  			   len---ҳ�ڴ�size
  			   free_cb--mempool�ڴ��ͷŻص�����
  			   opaque--memzone��ַ��ָ���ַ
  			   
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
int rte_mempool_populate_phys(struct rte_mempool *mempool, char *vaddr, phys_addr_t paddr, size_t len, rte_mempool_memchunk_free_cb_t *free_cb, void *opaque)
{
	unsigned total_elt_sz;
	unsigned i = 0;
	size_t offset;
	struct rte_mempool_memhdr *memhdr;
	int ret;

	/* create the internal ring if not already done */
	/*elemδ���ñ�ʹ�����ڴ��*/
	if ((mempool->flags & MEMPOOL_F_POOL_CREATED) == 0) 
	{
		/*��ȡ�ڴ�ز�������*/
		ret = rte_mempool_ops_alloc(mp);
		if (ret != 0)
		{
			return ret;
		}
		
		mempool->flags |= MEMPOOL_F_POOL_CREATED;
	}

	/* mempool is already populated */
	/*�ڴ��Ѿ��������*/
	if (mempool->populated_size >= mempool->size)
	{
		return -ENOSPC;
	}

	/*����������size��rte_mempool_objhdr rte_mbuf+rte_pktmbufheadroom+dataroom  rte_mempool_objtlr*/
	total_elt_sz = mempool->header_size + mempool->elt_size + mempool->trailer_size;

	/*�Ӷ��л�ȡelem��������memhr*/
	/*����һ��ͷ�ṹ*/
	memhdr = rte_zmalloc("MEMPOOL_MEMHDR", sizeof(*memhdr), 0);
	if (memhdr == NULL)
	{
		return -ENOMEM;
	}
	
	/*����mp�ڴ棬Ҳ�Ǵ��ڴ���õ���elemԪ��*/
	memhdr->mp        = mempool;
	memhdr->addr      = vaddr;   /*mz�еĵ�elem�����ַ*/
	memhdr->phys_addr = paddr;   /*mz�еĵ�elem�����ַ*/
	memhdr->len       = len;     /*���ж˿� mbuf ��Ҫ���ڴ�֮��*/
	memhdr->free_cb   = free_cb; /*�ڴ��ͷŻص�����*/
	memhdr->opaque    = opaque;  /*mzָ��*/

	/*�����˷�cache����ģʽ*/
	if (mempool->flags & MEMPOOL_F_NO_CACHE_ALIGN)
	{
		/*8�ֽڶ�����Ҫ����ֽ���*/
		offset = RTE_PTR_ALIGN_CEIL(vaddr, 8) - vaddr;
	}
	else
	{
		/*64�ֽڶ�����Ҫ����ֽ���*/
		offset = RTE_PTR_ALIGN_CEIL(vaddr, RTE_CACHE_LINE_SIZE) - vaddr;
	}

	/*ҳ���mbuf*/
	while (offset + total_elt_sz <= len && mempool->populated_size < mempool->size)
	{
		/*ƫ��ͷ�� sizeof(struct rte_mempool_objtlr)*/
		offset += mempool->header_size;
		
		if (paddr == RTE_BAD_PHYS_ADDR)
		{
			/*�ڴ�ҵ�����*/
			mempool_add_elem(mempool, (char *)vaddr + offset, RTE_BAD_PHYS_ADDR);
		}
		else
		{
			/*mbuf ������У��ҹ���*/
			mempool_add_elem(mempool, (char *)vaddr + offset, paddr + offset);

			offset += mempool->elt_size + mempool->trailer_size;
		}
		
		i++;
	}

	/* not enough room to store one object */
	if (i == 0)
	{
		return -EINVAL;
	}

	/*memzone����������*/
	STAILQ_INSERT_TAIL(&mempool->mem_list, memhdr, next);

	/*�ڴ�����¼*/
	mempool->nb_mem_chunks++;

	return i;
}

/* Add objects in the pool, using a table of physical pages. Return the
 * number of objects added, or a negative value on error.
 */
int rte_mempool_populate_phys_tab(struct rte_mempool *mp, char *vaddr,
	const phys_addr_t paddr[], uint32_t pg_num, uint32_t pg_shift,
	rte_mempool_memchunk_free_cb_t *free_cb, void *opaque)
{
	uint32_t i, n;
	int ret, cnt = 0;
	size_t pg_sz = (size_t)1 << pg_shift;

	/* mempool must not be populated */
	if (mp->nb_mem_chunks != 0)
		return -EEXIST;

	if (mp->flags & MEMPOOL_F_NO_PHYS_CONTIG)
		return rte_mempool_populate_phys(mp, vaddr, RTE_BAD_PHYS_ADDR,
			pg_num * pg_sz, free_cb, opaque);

	for (i = 0; i < pg_num && mp->populated_size < mp->size; i += n) {

		/* populate with the largest group of contiguous pages */
		for (n = 1; (i + n) < pg_num &&
			     paddr[i + n - 1] + pg_sz == paddr[i + n]; n++)
			;

		ret = rte_mempool_populate_phys(mp, vaddr + i * pg_sz,
			paddr[i], n * pg_sz, free_cb, opaque);
		if (ret < 0) {
			rte_mempool_free_memchunks(mp);
			return ret;
		}
		/* no need to call the free callback for next chunks */
		free_cb = NULL;
		cnt += ret;
	}
	return cnt;
}

/* Populate the mempool with a virtual area. Return the number of
 * objects added, or a negative value on error.
 */
 /*******************************************************
  ������:	   rte_mempool_populate_virt
  ��������:    dpdk�ڴ������
  ��������:    mempool---128�߼�cache��elem��mempool
  			   addr---����mbuf��mezone��elem �����ַ
  			   len--����mbuf �ڴ�֮�� 
  			   free_cb---�ڴ���ͷź���
  			   opaque--mz��ַ
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
int
rte_mempool_populate_virt(struct rte_mempool *mempool, char *addr,
	size_t len, size_t page_size, rte_mempool_memchunk_free_cb_t *free_cb,
	void *opaque)
{
	phys_addr_t paddr;
	size_t offset, phys_len;
	int ret, cnt = 0;

	/* mempool must not be populated */
	if (mempool->nb_mem_chunks != 0)
	{
		return -EEXIST;
	}
	/* address and len must be page-aligned */

	/*�����ַ����ҳ����*/
	if (RTE_PTR_ALIGN_CEIL(addr, page_size) != addr)
	{
		return -EINVAL;
	}

	/*����Ҳ����ҳ����*/
	if (RTE_ALIGN_CEIL(len, page_size) != len)
	{
		return -EINVAL;
	}

	/*�ڴ���������ַ����*/
	if (mempool->flags & MEMPOOL_F_NO_PHYS_CONTIG)
	{
		return rte_mempool_populate_phys(mempool, addr, RTE_BAD_PHYS_ADDR, len, free_cb, opaque);
	}

	/*��ʼ����,��������ҳ������mbuf��������ˣ��ҹ���*/
	for (offset = 0; offset + page_size <= len && mempool->populated_size < mempool->size; offset += phys_len)
	{

		/*��ȡ�����ַ*/
		paddr = rte_mem_virt2phy(addr + offset);

		/* required for xen_dom0 to get the machine address */
		paddr = rte_mem_phy2mch(-1, paddr);

		if (paddr == RTE_BAD_PHYS_ADDR) 
		{
			ret = -EINVAL;
			goto fail;
		}

		/* populate with the largest group of contiguous pages */
		/*��������ҳ����飬��ȡ���ҳ��*/
		/*У������mbuf���ڴ��С�������ַ�Ƿ�����*/
		for (phys_len = page_size; offset + phys_len < len; phys_len += page_size) 
		{
			phys_addr_t paddr_tmp;

			paddr_tmp = rte_mem_virt2phy(addr + offset + phys_len);
			paddr_tmp = rte_mem_phy2mch(-1, paddr_tmp);

			if (paddr_tmp != paddr + phys_len)
			{
				break;
			}
		}

		/*ҳ�ڴ�����mbuf������ҹ���*/
		ret = rte_mempool_populate_phys(mempool, addr + offset, paddr, phys_len, free_cb, opaque);
		if (ret < 0)
		{
			goto fail;
		}
		
		/* no need to call the free callback for next chunks */
		free_cb = NULL;
		cnt += ret;
	}

	return cnt;

 fail:
	rte_mempool_free_memchunks(mempool);
	return ret;
}

/* Default function to populate the mempool: allocate memory in memzones,
 * and populate them. Return the number of objects added, or a negative
 * value on error.
 */
/*******************************************************
  ������:	   rte_mempool_populate_default
  ��������:    dpdk�ڴ������
  ��������:    mp--�ڴ�أ���ʵ��ַΪelem��ַ,��socket heap�����һ���ڴ������ַ
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
int rte_mempool_populate_default(struct rte_mempool *mem_pool)
{
	int mz_flags = RTE_MEMZONE_1GB|RTE_MEMZONE_SIZE_HINT_ONLY;
	char mz_name[RTE_MEMZONE_NAMESIZE];
	const struct rte_memzone *memzone;
	size_t size, total_elt_sz, align, pg_sz, pg_shift;
	phys_addr_t paddr;
	unsigned mz_id, n;
	int ret;

	/* mempool must not be populated */
	/*�ڴ�أ��ڴ湹����*/
	if (mem_pool->nb_mem_chunks != 0)
	{
		return -EEXIST;
	}
	
	/*�Ƿ�֧��10G*/
	if (rte_xen_dom0_supported())
	{
		pg_sz    = RTE_PGSIZE_2M;     /*��ҳsize 2M*/
		pg_shift = rte_bsf32(pg_sz);
		align    = pg_sz;
	}
	/*�����˷Ǵ�ҳģʽ*/
	else if (rte_eal_has_hugepages()) 
	{
		pg_shift = 0; /* not needed, zone is physically contiguous */
		pg_sz    = 0;
		align    = RTE_CACHE_LINE_SIZE;
	} 
	else
	{
		pg_sz    = getpagesize();
		pg_shift = rte_bsf32(pg_sz);
		align    = pg_sz;
	}

	/*�ܴ�С*/     /*rte_mempool_objhdr ��������size rte_mbuf+rte_pktmbufheadroom+dataroom rte_mempool_objtlr*/
	total_elt_sz = mem_pool->header_size + mem_pool->elt_size + mem_pool->trailer_size;

	/*����Ϊ��ЩԪ�ط�����ռ�*/
	/*n���ж˿�mbuf����֮��*/
	for (mz_id = 0, n = mem_pool->size; n > 0; mz_id++, n -= ret) 
	{
		/*�������ж˿� mbuf ��Ҫ���ڴ�֮��*/
		size = rte_mempool_xmem_size(n, total_elt_sz, pg_shift);

		ret = snprintf(mz_name, sizeof(mz_name), RTE_MEMPOOL_MZ_FORMAT "_%d", mem_pool->name, mz_id);
		if (ret < 0 || ret >= (int)sizeof(mz_name))
		{
			ret = -ENAMETOOLONG;
			goto fail;
		}

		/*�Ӷ��л�ȡsize��С�ڴ�elem�ҵ�memzone������ӣ�����*/
		/*����mbuf�ڴ�elem���룬��memzone�������ҵ���mem_pool->mem_list, �г�mbuf obj ���*/
		memzone = rte_memzone_reserve_aligned(mz_name, size, mem_pool->socket_id, mz_flags, align);
		
		/* not enough memory, retry with the biggest zone we have */

		/*û�к���size��elem,����size����elem */
		if (memzone == NULL)
		{
			memzone = rte_memzone_reserve_aligned(mz_name, 0, mem_pool->socket_id, mz_flags, align);
		}
		
		if (memzone == NULL)
		{
			ret = -rte_errno;
			goto fail;
		}

		/*�����ַ*/
		/*�ڴ�ز���Ҫ�����ַ������Ĭ�������ַ*/
		if (mem_pool->flags & MEMPOOL_F_NO_PHYS_CONTIG)
		{
			paddr = RTE_BAD_PHYS_ADDR;
		}
		else
		{
			paddr = memzone->phys_addr;   								/*��ȡ�����ַ*/
		}
		
		/*δ���÷Ǵ�ҳģʽ����֧��10G*/
		if (rte_eal_has_hugepages() && !rte_xen_dom0_supported())
		{
			/*���������ַ*/
			ret = rte_mempool_populate_phys(mem_pool, memzone->addr, paddr, memzone->len, rte_mempool_memchunk_mz_free, (void *)(uintptr_t)memzone);
		}
		else
		{
			/*���������ַ*/                          /*����mbuf elem��ַ*/ /*��Ҫ���ڴ泤��*/                     
			ret = rte_mempool_populate_virt(mem_pool, memzone->addr, memzone->len, pg_sz, rte_mempool_memchunk_mz_free, (void *)(uintptr_t)memzone);
		}
		
		if (ret < 0) 
		{
			rte_memzone_free(memzone);
			goto fail;
		}
	}

	return mem_pool->size;

 fail:
 	
	rte_mempool_free_memchunks(mem_pool);

	return ret;
}

/* return the memory size required for mempool objects in anonymous mem */
static size_t
get_anon_size(const struct rte_mempool *mp)
{
	size_t size, total_elt_sz, pg_sz, pg_shift;

	pg_sz = getpagesize();
	pg_shift = rte_bsf32(pg_sz);
	total_elt_sz = mp->header_size + mp->elt_size + mp->trailer_size;
	size = rte_mempool_xmem_size(mp->size, total_elt_sz, pg_shift);

	return size;
}

/* unmap a memory zone mapped by rte_mempool_populate_anon() */
static void
rte_mempool_memchunk_anon_free(struct rte_mempool_memhdr *memhdr,
	void *opaque)
{
	munmap(opaque, get_anon_size(memhdr->mp));
}

/* populate the mempool with an anonymous mapping */
int
rte_mempool_populate_anon(struct rte_mempool *mp)
{
	size_t size;
	int ret;
	char *addr;

	/* mempool is already populated, error */
	if (!STAILQ_EMPTY(&mp->mem_list)) {
		rte_errno = EINVAL;
		return 0;
	}

	/* get chunk of virtually continuous memory */
	size = get_anon_size(mp);
	addr = mmap(NULL, size, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		rte_errno = errno;
		return 0;
	}
	/* can't use MMAP_LOCKED, it does not exist on BSD */
	if (mlock(addr, size) < 0) {
		rte_errno = errno;
		munmap(addr, size);
		return 0;
	}

	ret = rte_mempool_populate_virt(mp, addr, size, getpagesize(),
		rte_mempool_memchunk_anon_free, addr);
	if (ret == 0)
		goto fail;

	return mp->populated_size;

 fail:
	rte_mempool_free_memchunks(mp);
	return 0;
}

/* free a mempool */
/*******************************************************
  ������:		rte_mempool_free
  ��������:     �ڴ���ͷ�
  ��������: 	
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
void
rte_mempool_free(struct rte_mempool *mp)
{
	struct rte_mempool_list *mempool_list = NULL;
	struct rte_tailq_entry *te;

	if (mp == NULL)
		return;

	/*��ȡ�ڴ����*/
	mempool_list = RTE_TAILQ_CAST(rte_mempool_tailq.head, rte_mempool_list);

	rte_rwlock_write_lock(RTE_EAL_TAILQ_RWLOCK);

	/* find out tailq entry */
	/*β���������*/
	TAILQ_FOREACH(te, mempool_list, next) {
		if (te->data == (void *)mp)
			break;
	}
	

	/*β������ɾ��*/
	if (te != NULL) {
		TAILQ_REMOVE(mempool_list, te, next);
		rte_free(te);
	}
	rte_rwlock_write_unlock(RTE_EAL_TAILQ_RWLOCK);

	rte_mempool_free_memchunks(mp);
	rte_mempool_ops_free(mp);
	rte_memzone_free(mp->mz);
}


/*******************************************************
  ������:		mempool_cache_init
  ��������: 	�����յ��ڴ��
  ��������: 	cache---��������ַ
				size---250��mbuf��ÿ�߼���������ص�mbuf����
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static void mempool_cache_init(struct rte_mempool_cache *cache, uint32_t size)
{
	cache->size = size;
	cache->flushthresh = CALC_CACHE_FLUSHTHRESH(size); /*1.5��cache*/
	cache->len = 0;
}

/*
 * Create and initialize a cache for objects that are retrieved from and
 * returned to an underlying mempool. This structure is identical to the
 * local_cache[lcore_id] pointed to by the mempool structure.
 */
struct rte_mempool_cache *
rte_mempool_cache_create(uint32_t size, int socket_id)
{
	struct rte_mempool_cache *cache;

	if (size == 0 || size > RTE_MEMPOOL_CACHE_MAX_SIZE) {
		rte_errno = EINVAL;
		return NULL;
	}

	cache = rte_zmalloc_socket("MEMPOOL_CACHE", sizeof(*cache),
				  RTE_CACHE_LINE_SIZE, socket_id);
	if (cache == NULL) {
		RTE_LOG(ERR, MEMPOOL, "Cannot allocate mempool cache.\n");
		rte_errno = ENOMEM;
		return NULL;
	}

	mempool_cache_init(cache, size);

	return cache;
}

/*
 * Free a cache. It's the responsibility of the user to make sure that any
 * remaining objects in the cache are flushed to the corresponding
 * mempool.
 */
void
rte_mempool_cache_free(struct rte_mempool_cache *cache)
{
	rte_free(cache);
}

/* create an empty mempool */

/*******************************************************
  ������:		rte_mempool_create_empty
  ��������: 	�����յ��ڴ�أ�β����������128���߼��˹�mbuf ��cache (sizeof(struct rte_mempool_cache))����������128 mbuf��cache
  ��������: 	name---�ڴ��name��"MBUF_POOL"
  				mbuf_num---���ж˿�mbuf ����֮�ͣ�ÿ���˿�8191��mbuf
  				pkt_mbuf_size--mbuf���������ṹ����+priv����+���ݲ��ֳ��ȣ�����һ������rte_mbuf + priv + 2176������mbuf size
  				��sizeof(struct rte_mbuf) + (unsigned)priv_size + (unsigned)data_room_size = sizeof(struct rte_mbuf)+0+2176
		  		rte_mbuf + prive_size + dataroom
  				cache_size---ÿ�߼���cache����ҵ�mbuf��������ǰ250��
  				socket_id---�ڴ�������ڵ�socket
  				private_data_size---���������ṹ��С, sizeof(struct rte_pktmbuf_pool_private),dataroom������private���������ṹ
  				flags---�ڴ�صĹ����������ԣ���ǰֵΪ0
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
struct rte_mempool *rte_mempool_create_empty(const char *name, unsigned mbuf_num, unsigned pkt_mbuf_size,unsigned cache_size, unsigned private_data_size, int socket_id, unsigned flags)
{
	char memzone_name[RTE_MEMZONE_NAMESIZE];
	struct rte_mempool_list *mempool_list;
	
	struct rte_mempool *mem_pool 	     = NULL;	
	struct rte_tailq_entry *mem_pool_list_node   = NULL;
	const struct rte_memzone *lcore_cache_memzone = NULL;
	
	size_t lcore_cache_mempool_size;
	
	int mz_flags = RTE_MEMZONE_1GB|RTE_MEMZONE_SIZE_HINT_ONLY;   /*1G����ʵ�size*/

	/*�ڴ�����¼�ĸ���size*/
	struct rte_mempool_objsz obj_size_info;  					 
	
	unsigned lcore_id;
	int ret;

	/* compilation-time checks */

	/*size��С��Ϊ0���*/
	/*��63ȡ�벻Ϊ0��˵��δʹ��64�ֽڶ��룬���ж��Ƿ�64�ֽڶ��룬������bugon*/

	/*���ṹ�Ƿ���64�ֽڶ�������*/
	RTE_BUILD_BUG_ON((sizeof(struct rte_mempool) & RTE_CACHE_LINE_MASK) != 0);
	
	RTE_BUILD_BUG_ON((sizeof(struct rte_mempool_cache) & RTE_CACHE_LINE_MASK) != 0);
	
#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
	RTE_BUILD_BUG_ON((sizeof(struct rte_mempool_debug_stats) & RTE_CACHE_LINE_MASK) != 0);
	RTE_BUILD_BUG_ON((offsetof(struct rte_mempool, stats) & RTE_CACHE_LINE_MASK) != 0);
#endif

	/*��ȡ����ͷ��rte_mempool_list����*/
	/*������ڴ������������*/
	mempool_list = RTE_TAILQ_CAST(rte_mempool_tailq.head, rte_mempool_list);

	/* asked cache too big */
	/*�ڴ��СУ��*/
	/*�߼���Ҫ�õ�cache size�Ƿ�Ϸ���250��mbuf��cache_sizeΪmbuf�ĸ���*/
	if (cache_size > RTE_MEMPOOL_CACHE_MAX_SIZE || CALC_CACHE_FLUSHTHRESH(cache_size) > mbuf_num) /*1.5��cache �Ƿ����n������mbuf����*/
	{
		rte_errno = EINVAL;
		return NULL;
	}

	/* "no cache align" imply "no spread" */
	/*�Ƕ��룬�����ڴ���Ϊ����չ*/
	if (flags & MEMPOOL_F_NO_CACHE_ALIGN)
	{
		flags |= MEMPOOL_F_NO_SPREAD;
	}
	
	/* calculate mempool object sizes. */

	/*�����ڴ�obj size��64�ֽڶ��룬ͨ��x�ײ���չ��Ķ���size*/
	/*�����ʽ����� mbuf size*/
	/*�������mbuf����size�������ֳ�����obj_size_info*/
	if (!rte_mempool_calc_obj_size(pkt_mbuf_size, flags, &obj_size_info)) 
	{
		rte_errno = EINVAL;
		return NULL;
	}

	/*�ڴ��д������*/
	rte_rwlock_write_lock(RTE_EAL_MEMPOOL_RWLOCK);

	/*
	 * reserve a memory zone for this mempool: private data is
	 * cache-aligned
	 */

	/*˽�������ڴ��С��64��ȫ����*/
	private_data_size = (private_data_size + RTE_MEMPOOL_ALIGN_MASK) & (~RTE_MEMPOOL_ALIGN_MASK);

	/* try to allocate tailq entry */
	/*����ڵ��ڴ棬��heap�õ������͵��ڴ�Ԫ��elem*/
	/*te����elemԪ��*/
	/*te��β�����нṹ struct rte_tailq_entry */
	/*��elem�л�ȡsizeof(struct rte_tailq_entry)��С�ڴ�*/
	mem_pool_list_node = rte_zmalloc("MEMPOOL_TAILQ_ENTRY", sizeof(struct rte_tailq_entry), 0);
	if (mem_pool_list_node == NULL) 
	{
		RTE_LOG(ERR, MEMPOOL, "Cannot allocate tailq entry!\n");
		goto exit_unlock;
	}

	/*�ڴ��ͷsize*/
	/*elem�ڴ���0������Ϊsizeof(rte_mempool) + 128���߼���cache�ڴ�128 * sizeof(struct rte_mempool_cache) + pvivatesizeĿǰΪ0 + 64�ֽڶ���*/
	lcore_cache_mempool_size  = MEMPOOL_HEADER_SIZE(mem_pool, cache_size);  			 /*sizeof(rte_mempool) + 128���߼���cache�ڴ�128 * sizeof(struct rte_mempool_cache)*/
	lcore_cache_mempool_size += private_data_size;                               /*��ǰֵΪ0*/
	lcore_cache_mempool_size  = RTE_ALIGN_CEIL(lcore_cache_mempool_size, RTE_MEMPOOL_ALIGN); /*mempool_size 64�ֽڶ���*/

	/*�ܳ���Ϊ128���߼���cache + priv + 64 �ֽڶ���*/
	
	/*mzone name ��ǰ "MP_MBUF_POOL"*/
	ret = snprintf(memzone_name, sizeof(memzone_name), RTE_MEMPOOL_MZ_FORMAT, name);
	if (ret < 0 || ret >= (int)sizeof(memzone_name)) 
	{
		rte_errno = ENAMETOOLONG;
		goto exit_unlock;
	}

	/*��socket���л�ȡelem ����mzone���ӣ�sizeof(rte_mempool) + 128���߼���cache�ڴ�128 * sizeof(struct rte_mempool_cache)+pvivatesizeĿǰΪ0+64�ֽڶ���*/
	/*128���߼���cache��memzone �������*/
	lcore_cache_memzone = rte_memzone_reserve(memzone_name, lcore_cache_mempool_size, socket_id, mz_flags);
	if (lcore_cache_memzone == NULL)
	{
		goto exit_unlock;
	}
	
	/* init the mempool structure */
	/*��ȡelem��ַ������Ϊmempool�ṹͷ+private+128���߼���cache��С���ݴ�С+64�ֽڶ���*/
	/*����memzone����ʵ��elem��ַ*/
	mem_pool = lcore_cache_memzone->addr;

	/*elem�ڴ���0������Ϊsizeof(rte_mempool) + 128���߼���cache�ڴ�128 * sizeof(struct rte_mempool_cache) + pvivatesizeĿǰΪ0 + 64�ֽڶ���*/
	memset(mem_pool, 0, MEMPOOL_HEADER_SIZE(mem_pool, cache_size));

	ret = snprintf(mem_pool->name, sizeof(mem_pool->name), "%s", name);
	if (ret < 0 || ret >= (int)sizeof(mem_pool->name))
	{
		rte_errno = ENAMETOOLONG;
		goto exit_unlock;
	}

	/*128���߼���cache�ṹmempool*/
	mem_pool->mz                = lcore_cache_memzone;          /*����memzone�ϵ��ڴ��¼�Լ����ڵ�memzone*/    
	mem_pool->socket_id         = socket_id;     			    /*elem ����socket*/
	mem_pool->size              = mbuf_num;             		/*���ж˿�mbuf����֮��*/
	mem_pool->flags             = flags;                        /*�ڴ�����*/
	mem_pool->socket_id         = socket_id;

	/*��������elt_size,����pkt_mbuf size*/
	mem_pool->elt_size          = obj_size_info.elt_size;             /*��������rte_mbuf + prive_size + dataroom*/
	mem_pool->header_size       = obj_size_info.header_size;          /*ͷ������, sizeof(struct rte_mempool_objhdr)*/
	mem_pool->trailer_size      = obj_size_info.trailer_size;         /*β������, sizeof(struct rte_mempool_objtlr)*/
	
	/* Size of default caches, zero means disabled. */
	mem_pool->cache_size        = cache_size;                 /*128�߼��˵���cache size 250 ������˼��������205��mbuf ÿ�߼���*/
	mem_pool->private_data_size = private_data_size;          /*˽������size,��ǰΪ0*/

	/*�����ʼ��*/
	STAILQ_INIT(&mem_pool->elt_list);
	STAILQ_INIT(&mem_pool->mem_list);

	/*
	 * local_cache pointer is set even if cache_size is zero.
	 * The local_cache points to just past the elt_pa[] array.
	 */

	/*128�߼���cache�׵�ַ*/
	mem_pool->local_cache = (struct rte_mempool_cache *)RTE_PTR_ADD(mem_pool, MEMPOOL_HEADER_SIZE(mem_pool, 0));

	/* Init all default caches. */

	/*�ڴ�ع���*/
	if (cache_size != 0) 
	{
		/*����128���߼���cache��ʼ��*/
		for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++)
		{
			mempool_cache_init(&mem_pool->local_cache[lcore_id], cache_size);
		}
	}

	/*�ڴ�������ڴ������ڵ�*/
	mem_pool_list_node->data = mem_pool;

	rte_rwlock_write_lock(RTE_EAL_TAILQ_RWLOCK);


	/*β���й���*/	
	TAILQ_INSERT_TAIL(mempool_list, mem_pool_list_node, next);

	/*����*/
	rte_rwlock_write_unlock(RTE_EAL_TAILQ_RWLOCK);

	/*����*/
	rte_rwlock_write_unlock(RTE_EAL_MEMPOOL_RWLOCK);

	/*elem��ַ*/
	return mem_pool;

exit_unlock:
	rte_rwlock_write_unlock(RTE_EAL_MEMPOOL_RWLOCK);
	rte_free(mem_pool_list_node);
	
	rte_mempool_free(mem_pool);
	return NULL;
}

/* create the mempool */

/*******************************************************
  ������:	   rte_mempool_create
  ��������:    dpdk�ڴ������
  ��������:    name--�ڴ����
  			   n---�ڴ��mbuf����
  			   elt ����mbuf size
  			   cache_size--����size
  			   private_data_size--˽������size
  			   mp_init---�ڴ�س�ʼ������
  			   mp_init_arg--�ڴ�س�ʼ������
  			   obj_init--�ڴ�ض����ʼ������
  			   obj_init_arg---�ڴ���ڴ�����ʼ��
  			   socket_id 
  			   flags---�ڴ���������
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
struct rte_mempool *
rte_mempool_create(const char *name, unsigned n, unsigned elt_size,
	unsigned cache_size, unsigned private_data_size,
	rte_mempool_ctor_t *mp_init, void *mp_init_arg,
	rte_mempool_obj_cb_t *obj_init, void *obj_init_arg,
	int socket_id, unsigned flags)
{
	struct rte_mempool *mp;

	/*mempool�ڴ����뼰��ʼ��*/
	mp = rte_mempool_create_empty(name, n, elt_size, cache_size, private_data_size, socket_id, flags);
	if (mp == NULL)
		return NULL;

	/*
	 * Since we have 4 combinations of the SP/SC/MP/MC examine the flags to
	 * set the correct index into the table of ops structs.
	 */
	if ((flags & MEMPOOL_F_SP_PUT) && (flags & MEMPOOL_F_SC_GET))
		rte_mempool_set_ops_byname(mp, "ring_sp_sc", NULL);
	else if (flags & MEMPOOL_F_SP_PUT)
		rte_mempool_set_ops_byname(mp, "ring_sp_mc", NULL);
	else if (flags & MEMPOOL_F_SC_GET)
		rte_mempool_set_ops_byname(mp, "ring_mp_sc", NULL);
	else
		rte_mempool_set_ops_byname(mp, "ring_mp_mc", NULL);

	/* call the mempool priv initializer */

	/*�ڴ�س�ʼ��*/
	if (mp_init)
		mp_init(mp, mp_init_arg);

	if (rte_mempool_populate_default(mp) < 0)
		goto fail;

	/* call the object initializers */
	if (obj_init)
		rte_mempool_obj_iter(mp, obj_init, obj_init_arg);

	return mp;

 fail:
	rte_mempool_free(mp);
	return NULL;
}

/*
 * Create the mempool over already allocated chunk of memory.
 * That external memory buffer can consists of physically disjoint pages.
 * Setting vaddr to NULL, makes mempool to fallback to rte_mempool_create()
 * behavior.
 */
struct rte_mempool *
rte_mempool_xmem_create(const char *name, unsigned n, unsigned elt_size,
		unsigned cache_size, unsigned private_data_size,
		rte_mempool_ctor_t *mp_init, void *mp_init_arg,
		rte_mempool_obj_cb_t *obj_init, void *obj_init_arg,
		int socket_id, unsigned flags, void *vaddr,
		const phys_addr_t paddr[], uint32_t pg_num, uint32_t pg_shift)
{
	struct rte_mempool *mp = NULL;
	int ret;

	/* no virtual address supplied, use rte_mempool_create() */
	if (vaddr == NULL)
		return rte_mempool_create(name, n, elt_size, cache_size,
			private_data_size, mp_init, mp_init_arg,
			obj_init, obj_init_arg, socket_id, flags);

	/* check that we have both VA and PA */
	if (paddr == NULL) {
		rte_errno = EINVAL;
		return NULL;
	}

	/* Check that pg_shift parameter is valid. */
	if (pg_shift > MEMPOOL_PG_SHIFT_MAX) {
		rte_errno = EINVAL;
		return NULL;
	}

	mp = rte_mempool_create_empty(name, n, elt_size, cache_size,
		private_data_size, socket_id, flags);
	if (mp == NULL)
		return NULL;

	/* call the mempool priv initializer */
	if (mp_init)
		mp_init(mp, mp_init_arg);

	ret = rte_mempool_populate_phys_tab(mp, vaddr, paddr, pg_num, pg_shift,
		NULL, NULL);
	if (ret < 0 || ret != (int)mp->size)
		goto fail;

	/* call the object initializers */
	if (obj_init)
		rte_mempool_obj_iter(mp, obj_init, obj_init_arg);

	return mp;

 fail:
	rte_mempool_free(mp);
	return NULL;
}

/* Return the number of entries in the mempool */
unsigned int
rte_mempool_avail_count(const struct rte_mempool *mp)
{
	unsigned count;
	unsigned lcore_id;

	count = rte_mempool_ops_get_count(mp);

	if (mp->cache_size == 0)
		return count;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++)
		count += mp->local_cache[lcore_id].len;

	/*
	 * due to race condition (access to len is not locked), the
	 * total can be greater than size... so fix the result
	 */
	if (count > mp->size)
		return mp->size;
	return count;
}

/* return the number of entries allocated from the mempool */
unsigned int
rte_mempool_in_use_count(const struct rte_mempool *mp)
{
	return mp->size - rte_mempool_avail_count(mp);
}

unsigned int
rte_mempool_count(const struct rte_mempool *mp)
{
	return rte_mempool_avail_count(mp);
}

/* dump the cache status */
static unsigned
rte_mempool_dump_cache(FILE *f, const struct rte_mempool *mp)
{
	unsigned lcore_id;
	unsigned count = 0;
	unsigned cache_count;

	fprintf(f, "  internal cache infos:\n");
	fprintf(f, "    cache_size=%"PRIu32"\n", mp->cache_size);

	if (mp->cache_size == 0)
		return count;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		cache_count = mp->local_cache[lcore_id].len;
		fprintf(f, "    cache_count[%u]=%"PRIu32"\n",
			lcore_id, cache_count);
		count += cache_count;
	}
	fprintf(f, "    total_cache_count=%u\n", count);
	return count;
}

#ifndef __INTEL_COMPILER
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif

/* check and update cookies or panic (internal) */
void rte_mempool_check_cookies(const struct rte_mempool *mp,
	void * const *obj_table_const, unsigned n, int free)
{
#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
	struct rte_mempool_objhdr *hdr;
	struct rte_mempool_objtlr *tlr;
	uint64_t cookie;
	void *tmp;
	void *obj;
	void **obj_table;

	/* Force to drop the "const" attribute. This is done only when
	 * DEBUG is enabled */
	tmp = (void *) obj_table_const;
	obj_table = (void **) tmp;

	while (n--) {
		obj = obj_table[n];

		if (rte_mempool_from_obj(obj) != mp)
			rte_panic("MEMPOOL: object is owned by another "
				  "mempool\n");

		hdr = __mempool_get_header(obj);
		cookie = hdr->cookie;

		if (free == 0) {
			if (cookie != RTE_MEMPOOL_HEADER_COOKIE1) {
				RTE_LOG(CRIT, MEMPOOL,
					"obj=%p, mempool=%p, cookie=%" PRIx64 "\n",
					obj, (const void *) mp, cookie);
				rte_panic("MEMPOOL: bad header cookie (put)\n");
			}
			hdr->cookie = RTE_MEMPOOL_HEADER_COOKIE2;
		} else if (free == 1) {
			if (cookie != RTE_MEMPOOL_HEADER_COOKIE2) {
				RTE_LOG(CRIT, MEMPOOL,
					"obj=%p, mempool=%p, cookie=%" PRIx64 "\n",
					obj, (const void *) mp, cookie);
				rte_panic("MEMPOOL: bad header cookie (get)\n");
			}
			hdr->cookie = RTE_MEMPOOL_HEADER_COOKIE1;
		} else if (free == 2) {
			if (cookie != RTE_MEMPOOL_HEADER_COOKIE1 &&
			    cookie != RTE_MEMPOOL_HEADER_COOKIE2) {
				RTE_LOG(CRIT, MEMPOOL,
					"obj=%p, mempool=%p, cookie=%" PRIx64 "\n",
					obj, (const void *) mp, cookie);
				rte_panic("MEMPOOL: bad header cookie (audit)\n");
			}
		}
		tlr = __mempool_get_trailer(obj);
		cookie = tlr->cookie;
		if (cookie != RTE_MEMPOOL_TRAILER_COOKIE) {
			RTE_LOG(CRIT, MEMPOOL,
				"obj=%p, mempool=%p, cookie=%" PRIx64 "\n",
				obj, (const void *) mp, cookie);
			rte_panic("MEMPOOL: bad trailer cookie\n");
		}
	}
#else
	RTE_SET_USED(mp);
	RTE_SET_USED(obj_table_const);
	RTE_SET_USED(n);
	RTE_SET_USED(free);
#endif
}

#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
static void
mempool_obj_audit(struct rte_mempool *mp, __rte_unused void *opaque,
	void *obj, __rte_unused unsigned idx)
{
	__mempool_check_cookies(mp, &obj, 1, 2);
}

static void
mempool_audit_cookies(struct rte_mempool *mp)
{
	unsigned num;

	num = rte_mempool_obj_iter(mp, mempool_obj_audit, NULL);
	if (num != mp->size) {
		rte_panic("rte_mempool_obj_iter(mempool=%p, size=%u) "
			"iterated only over %u elements\n",
			mp, mp->size, num);
	}
}
#else
#define mempool_audit_cookies(mp) do {} while(0)
#endif

#ifndef __INTEL_COMPILER
#pragma GCC diagnostic error "-Wcast-qual"
#endif

/* check cookies before and after objects */
static void
mempool_audit_cache(const struct rte_mempool *mp)
{
	/* check cache size consistency */
	unsigned lcore_id;

	if (mp->cache_size == 0)
		return;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		const struct rte_mempool_cache *cache;
		cache = &mp->local_cache[lcore_id];
		if (cache->len > cache->flushthresh) {
			RTE_LOG(CRIT, MEMPOOL, "badness on cache[%u]\n",
				lcore_id);
			rte_panic("MEMPOOL: invalid cache len\n");
		}
	}
}

/* check the consistency of mempool (size, cookies, ...) */
void
rte_mempool_audit(struct rte_mempool *mp)
{
	mempool_audit_cache(mp);
	mempool_audit_cookies(mp);

	/* For case where mempool DEBUG is not set, and cache size is 0 */
	RTE_SET_USED(mp);
}

/* dump the status of the mempool on the console */
void
rte_mempool_dump(FILE *f, struct rte_mempool *mp)
{
#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
	struct rte_mempool_debug_stats sum;
	unsigned lcore_id;
#endif
	struct rte_mempool_memhdr *memhdr;
	unsigned common_count;
	unsigned cache_count;
	size_t mem_len = 0;

	RTE_ASSERT(f != NULL);
	RTE_ASSERT(mp != NULL);

	fprintf(f, "mempool <%s>@%p\n", mp->name, mp);
	fprintf(f, "  flags=%x\n", mp->flags);
	fprintf(f, "  pool=%p\n", mp->pool_data);
	fprintf(f, "  phys_addr=0x%" PRIx64 "\n", mp->mz->phys_addr);
	fprintf(f, "  nb_mem_chunks=%u\n", mp->nb_mem_chunks);
	fprintf(f, "  size=%"PRIu32"\n", mp->size);
	fprintf(f, "  populated_size=%"PRIu32"\n", mp->populated_size);
	fprintf(f, "  header_size=%"PRIu32"\n", mp->header_size);
	fprintf(f, "  elt_size=%"PRIu32"\n", mp->elt_size);
	fprintf(f, "  trailer_size=%"PRIu32"\n", mp->trailer_size);
	fprintf(f, "  total_obj_size=%"PRIu32"\n",
	       mp->header_size + mp->elt_size + mp->trailer_size);

	fprintf(f, "  private_data_size=%"PRIu32"\n", mp->private_data_size);

	STAILQ_FOREACH(memhdr, &mp->mem_list, next)
		mem_len += memhdr->len;
	if (mem_len != 0) {
		fprintf(f, "  avg bytes/object=%#Lf\n",
			(long double)mem_len / mp->size);
	}

	cache_count = rte_mempool_dump_cache(f, mp);
	common_count = rte_mempool_ops_get_count(mp);
	if ((cache_count + common_count) > mp->size)
		common_count = mp->size - cache_count;
	fprintf(f, "  common_pool_count=%u\n", common_count);

	/* sum and dump statistics */
#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
	memset(&sum, 0, sizeof(sum));
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		sum.put_bulk += mp->stats[lcore_id].put_bulk;
		sum.put_objs += mp->stats[lcore_id].put_objs;
		sum.get_success_bulk += mp->stats[lcore_id].get_success_bulk;
		sum.get_success_objs += mp->stats[lcore_id].get_success_objs;
		sum.get_fail_bulk += mp->stats[lcore_id].get_fail_bulk;
		sum.get_fail_objs += mp->stats[lcore_id].get_fail_objs;
	}
	fprintf(f, "  stats:\n");
	fprintf(f, "    put_bulk=%"PRIu64"\n", sum.put_bulk);
	fprintf(f, "    put_objs=%"PRIu64"\n", sum.put_objs);
	fprintf(f, "    get_success_bulk=%"PRIu64"\n", sum.get_success_bulk);
	fprintf(f, "    get_success_objs=%"PRIu64"\n", sum.get_success_objs);
	fprintf(f, "    get_fail_bulk=%"PRIu64"\n", sum.get_fail_bulk);
	fprintf(f, "    get_fail_objs=%"PRIu64"\n", sum.get_fail_objs);
#else
	fprintf(f, "  no statistics available\n");
#endif

	rte_mempool_audit(mp);
}

/* dump the status of all mempools on the console */
void
rte_mempool_list_dump(FILE *f)
{
	struct rte_mempool *mp = NULL;
	struct rte_tailq_entry *te;
	struct rte_mempool_list *mempool_list;

	mempool_list = RTE_TAILQ_CAST(rte_mempool_tailq.head, rte_mempool_list);

	rte_rwlock_read_lock(RTE_EAL_MEMPOOL_RWLOCK);

	TAILQ_FOREACH(te, mempool_list, next) {
		mp = (struct rte_mempool *) te->data;
		rte_mempool_dump(f, mp);
	}

	rte_rwlock_read_unlock(RTE_EAL_MEMPOOL_RWLOCK);
}

/* search a mempool from its name */
struct rte_mempool *
rte_mempool_lookup(const char *name)
{
	struct rte_mempool *mp = NULL;
	struct rte_tailq_entry *te;
	struct rte_mempool_list *mempool_list;

	mempool_list = RTE_TAILQ_CAST(rte_mempool_tailq.head, rte_mempool_list);

	rte_rwlock_read_lock(RTE_EAL_MEMPOOL_RWLOCK);

	TAILQ_FOREACH(te, mempool_list, next) {
		mp = (struct rte_mempool *) te->data;
		if (strncmp(name, mp->name, RTE_MEMPOOL_NAMESIZE) == 0)
			break;
	}

	rte_rwlock_read_unlock(RTE_EAL_MEMPOOL_RWLOCK);

	if (te == NULL) {
		rte_errno = ENOENT;
		return NULL;
	}

	return mp;
}

void rte_mempool_walk(void (*func)(struct rte_mempool *, void *),
		      void *arg)
{
	struct rte_tailq_entry *te = NULL;
	struct rte_mempool_list *mempool_list;
	void *tmp_te;

	mempool_list = RTE_TAILQ_CAST(rte_mempool_tailq.head, rte_mempool_list);

	rte_rwlock_read_lock(RTE_EAL_MEMPOOL_RWLOCK);

	TAILQ_FOREACH_SAFE(te, mempool_list, next, tmp_te) {
		(*func)((struct rte_mempool *) te->data, arg);
	}

	rte_rwlock_read_unlock(RTE_EAL_MEMPOOL_RWLOCK);
}
