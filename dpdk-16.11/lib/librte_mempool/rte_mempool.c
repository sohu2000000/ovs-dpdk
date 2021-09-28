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

/*返回ab最大公因数*/
static unsigned get_gcd(unsigned a, unsigned b)
{
	unsigned c;

	if (0 == a)
		return b;
	if (0 == b)
		return a;

	/*a < b 那么 ab交换*/
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
  函数名:		optimize_object_size
  功能描述: 	创建空的内存池
  参数描述: 	obj_size---对象size总size
  返回值  :
  最后修改人:
  修改日期:    2017 -11-15
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

	/*获取n个channel*/
	nchan = rte_memory_get_nchannel();
	if (nchan == 0)
	{
		nchan = 4;
	}
	
	/*阶层个数*/
	nrank = rte_memory_get_nrank();
	if (nrank == 0)
	{
		nrank = 1;
	}
	
	/* process new object size */

	/*字节对齐后，需要分配多少个单位的64字节内存*/
	new_obj_size = (obj_size + RTE_MEMPOOL_ALIGN_MASK) / RTE_MEMPOOL_ALIGN;

	/*扩展new_obj_size，使它和通道x阶层，有最大公共因素，new_obj_size需要是通道x阶层的个数*/
	while (get_gcd(new_obj_size, nrank * nchan) != 1)
	{
		new_obj_size++;
	}
	
	/*返回对齐+拓展后的对象size*/
	return new_obj_size * RTE_MEMPOOL_ALIGN;
}

/*******************************************************
  函数名:		optimize_object_size
  功能描述: 	mbuf入队列
  参数描述: 	mp--内存池
 				obj--mp 偏过mp header size，mbuf obj 头+x+尾，x地址，虚拟地址
  				obj_size---对象size总size
  				physaddr---mbuf obj 头+x+尾，x地址物理地址
  返回值  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static void
mempool_add_elem(struct rte_mempool *mempool, void *obj, phys_addr_t physaddr)
{
	struct rte_mempool_objhdr *hdr;
	struct rte_mempool_objtlr *tlr __rte_unused;

	/* set mempool ptr in header */
	/*获取头部地址obj回退header size*/
	hdr = RTE_PTR_SUB(obj, sizeof(*hdr));
	hdr->mp = mempool;
	hdr->physaddr = physaddr;

	/*挂在链表尾部*/
	/*mbuf obj 链表*/
	STAILQ_INSERT_TAIL(&mempool->elt_list, hdr, next);

	/*构造的内存记录*/
	mempool->populated_size++;

#ifdef RTE_LIBRTE_MEMPOOL_DEBUG

	hdr->cookie = RTE_MEMPOOL_HEADER_COOKIE2;
	tlr = __mempool_get_trailer(obj);
	tlr->cookie = RTE_MEMPOOL_TRAILER_COOKIE;

#endif

	/* enqueue in ring */
	/*x入队列*/
    /* obj--mp 偏过mp header size，mbuf obj 头+x+尾，x地址，虚拟地址，入队列*/
	/*mbuf入队列*/
	rte_mempool_ops_enqueue_bulk(mempool, &obj, 1);
}


/*******************************************************
  函数名:	   rte_mempool_create
  功能描述:    dpdk内存池申请
  参数描述:    name--内存名
  			   obj_cb_arg---null
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
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
		/*获取mbuf obj的地址*/
		obj = (char *)hdr + sizeof(*hdr);

		/*rte_pktmbuf_init(mp, obj_cb_arg, obj, n)*/
		obj_cb(mp, obj_cb_arg, obj, n);

		n++;
	}

	return n;
}

/*******************************************************************************
 函数名称  :    rte_mempool_mem_iter
 功能描述  :    
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
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
  函数名:		rte_mempool_calc_obj_size
  功能描述: 	64字节对齐加和通道x阶层扩展，对齐格式化计算后的mbuf size

				获取构造后的单个mbuf对象size
				sizeof(struct rte_mempool_objhdr)+elt_size+obj_size_info->trailer_size
			
  			
  参数描述: 	pkt_size---一个报文sizeof(rte_mbuf) + priv + 2176，单个mbuf obj size，priv=0
				flags---内存池的共享对齐等属性，当前值为0
				sz---内存池对象size描述结构
				obj_size_info---内存对象记录的各种size


				name---缓冲区名字
				elt_size--mbuf头和数据部分+priv长度，代表一个报文rte_mbuf
				elt_size--/*rte_mbuf + prive_size + dataroom*/
				/*rte_mbuf+rte_pktmbufheadroom+dataroom
				flags---内存池的共享对齐等属性，当前值为0 flags---内存池的共享对齐等属性，当前值为0
				sz---内存池对象size描述结构

				
  返回值	  : 内存池内存对象obj size
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/

/* get the header, trailer and total size of a mempool element. */
uint32_t
rte_mempool_calc_obj_size(uint32_t pkt_size, uint32_t flags, struct rte_mempool_objsz *obj_size_info)
{
	struct rte_mempool_objsz tmp_obj_size_info;

	obj_size_info = (obj_size_info != NULL) ? obj_size_info : &tmp_obj_size_info;

	/*内存池内存对象头size*/
	obj_size_info->header_size = sizeof(struct rte_mempool_objhdr);

	/*如果未设置字节非对齐，头部长度，则64字节对齐*/
	if ((flags & MEMPOOL_F_NO_CACHE_ALIGN) == 0)
	{
		obj_size_info->header_size = RTE_ALIGN_CEIL(obj_size_info->header_size, RTE_MEMPOOL_ALIGN);
	}
	

	/*内存池对象描述结构尾部size*/
#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
	obj_size_info->trailer_size = sizeof(struct rte_mempool_objtlr);
#else
	obj_size_info->trailer_size = 0;
#endif

	/* element size is 8 bytes-aligned at least */

	/*单个 mbuf报文描述结构 + priv长度 + 数据部分，对齐 数据部分2176，总体64字节对齐*/
	obj_size_info->pkt_size = RTE_ALIGN_CEIL(pkt_size, sizeof(uint64_t));

	/* expand trailer to next cache line */
	/*内存池cache未设置非对齐*/
	if ((flags & MEMPOOL_F_NO_CACHE_ALIGN) == 0) 
	{
		/*内存池对象totalsize=head_size+elt_size+trailer_size*/
		obj_size_info->total_size = obj_size_info->header_size + obj_size_info->elt_size + obj_size_info->trailer_size;

		/*拓展到64字节对齐*/                        /*差值为64字节对齐需要补的字节数*/
		obj_size_info->trailer_size += ((RTE_MEMPOOL_ALIGN - (obj_size_info->total_size & RTE_MEMPOOL_ALIGN_MASK)) & RTE_MEMPOOL_ALIGN_MASK);
	}

	/*
	 * increase trailer to add padding between objects in order to
	 * spread them across memory channels/ranks
	 */

	/*内存池未设置非扩展*/
	if ((flags & MEMPOOL_F_NO_SPREAD) == 0) 
	{
		unsigned new_size;

		/*与通道对比后，格式化后的内存*/
		new_size = optimize_object_size(obj_size_info->header_size + obj_size_info->elt_size + obj_size_info->trailer_size);

		/*修改拓展后的尾部size*/
		obj_size_info->trailer_size = new_size - obj_size_info->header_size - obj_size_info->elt_size;
	}

	/* this is the size of an object, including header and trailer */

	/*新的对象总size*/   /*sizeof(struct rte_mempool_objhdr)+ (rte_mbuf + prive_size + dataroom)+ sizeof(struct rte_mempool_objtlr) + 64字节对齐*/
	obj_size_info->total_size = obj_size_info->header_size + obj_size_info->elt_size + obj_size_info->trailer_size;

	/*内存池 mbuf构造的对象size*/
	return obj_size_info->total_size;
}


/*
 * Calculate maximum amount of memory required to store given number of objects.
 */
/*******************************************************
  函数名:		rte_mempool_xmem_size
  功能描述: 	计算内存池所有的mbuf需要的内存之和
  参数描述: 	elt_num--所有端口mbuf个数之和
                total_elt_sz---/*rte_mempool_objhdr 单个报文size，rte_mbuf+rte_pktmbufheadroom+dataroom rte_mempool_objtlr
  返回值  :     pg_shift---大页size,转换成1左移位数
  最后修改人:
  修改日期:    2017 -11-15
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
		return total_elt_sz * elt_num;         /*所有mbuf 需要内存之和*/
	}
	
	/*大页size*/
	pg_sz = (size_t)1 << pg_shift;

	/*一个页可以切割成的mbuf个数*/
	obj_per_page_elt_num = pg_sz / total_elt_sz;

	/*内存不足，*/
	if (obj_per_page_elt_num == 0)
	{
		return RTE_ALIGN_CEIL(total_elt_sz, pg_sz) * elt_num; /*total_elt_sz按pg_sz对齐 x mbuf个数，计算总mbuf需要的内存数*/
	}
	
	/*总mbuf个数，需要内存页数之和*/
	/*需要的大页个数之和*/
	page_num = (elt_num + obj_per_page_elt_num - 1) / obj_per_page_elt_num;

	/*pag_num x 1 << pg_shift，所需内存之和*/
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
  函数名:	   rte_mempool_populate_default
  功能描述:    按页做成mbuf挂链入队
  参数描述:    mempool--内存池，真实地址为elem地址，128 逻辑核 cache elem 
  			   addr---所有mbuf的mezone的elem 虚拟地址
  			   paddr---mz中的elem物理地址
  			   len---页内存size
  			   free_cb--mempool内存释放回调函数
  			   opaque--memzone地址，指针地址
  			   
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
int rte_mempool_populate_phys(struct rte_mempool *mempool, char *vaddr, phys_addr_t paddr, size_t len, rte_mempool_memchunk_free_cb_t *free_cb, void *opaque)
{
	unsigned total_elt_sz;
	unsigned i = 0;
	size_t offset;
	struct rte_mempool_memhdr *memhdr;
	int ret;

	/* create the internal ring if not already done */
	/*elem未设置被使用做内存池*/
	if ((mempool->flags & MEMPOOL_F_POOL_CREATED) == 0) 
	{
		/*获取内存池操作函数*/
		ret = rte_mempool_ops_alloc(mp);
		if (ret != 0)
		{
			return ret;
		}
		
		mempool->flags |= MEMPOOL_F_POOL_CREATED;
	}

	/* mempool is already populated */
	/*内存已经构造完毕*/
	if (mempool->populated_size >= mempool->size)
	{
		return -ENOSPC;
	}

	/*单个报描述size，rte_mempool_objhdr rte_mbuf+rte_pktmbufheadroom+dataroom  rte_mempool_objtlr*/
	total_elt_sz = mempool->header_size + mempool->elt_size + mempool->trailer_size;

	/*从堆中获取elem，用来做memhr*/
	/*申请一个头结构*/
	memhdr = rte_zmalloc("MEMPOOL_MEMHDR", sizeof(*memhdr), 0);
	if (memhdr == NULL)
	{
		return -ENOMEM;
	}
	
	/*关联mp内存，也是从内存池拿到的elem元素*/
	memhdr->mp        = mempool;
	memhdr->addr      = vaddr;   /*mz中的的elem虚拟地址*/
	memhdr->phys_addr = paddr;   /*mz中的的elem物理地址*/
	memhdr->len       = len;     /*所有端口 mbuf 需要的内存之和*/
	memhdr->free_cb   = free_cb; /*内存释放回调函数*/
	memhdr->opaque    = opaque;  /*mz指针*/

	/*设置了非cache对齐模式*/
	if (mempool->flags & MEMPOOL_F_NO_CACHE_ALIGN)
	{
		/*8字节对齐需要填报的字节数*/
		offset = RTE_PTR_ALIGN_CEIL(vaddr, 8) - vaddr;
	}
	else
	{
		/*64字节对齐需要填补的字节数*/
		offset = RTE_PTR_ALIGN_CEIL(vaddr, RTE_CACHE_LINE_SIZE) - vaddr;
	}

	/*页拆成mbuf*/
	while (offset + total_elt_sz <= len && mempool->populated_size < mempool->size)
	{
		/*偏过头部 sizeof(struct rte_mempool_objtlr)*/
		offset += mempool->header_size;
		
		if (paddr == RTE_BAD_PHYS_ADDR)
		{
			/*内存挂到链表*/
			mempool_add_elem(mempool, (char *)vaddr + offset, RTE_BAD_PHYS_ADDR);
		}
		else
		{
			/*mbuf 放入队列，且挂链*/
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

	/*memzone都挂链在这*/
	STAILQ_INSERT_TAIL(&mempool->mem_list, memhdr, next);

	/*内存数记录*/
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
  函数名:	   rte_mempool_populate_virt
  功能描述:    dpdk内存池申请
  参数描述:    mempool---128逻辑cache的elem的mempool
  			   addr---所有mbuf的mezone的elem 虚拟地址
  			   len--所有mbuf 内存之和 
  			   free_cb---内存池释放函数
  			   opaque--mz地址
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
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

	/*虚拟地址必须页对齐*/
	if (RTE_PTR_ALIGN_CEIL(addr, page_size) != addr)
	{
		return -EINVAL;
	}

	/*长度也必须页对齐*/
	if (RTE_ALIGN_CEIL(len, page_size) != len)
	{
		return -EINVAL;
	}

	/*内存池无物理地址配置*/
	if (mempool->flags & MEMPOOL_F_NO_PHYS_CONTIG)
	{
		return rte_mempool_populate_phys(mempool, addr, RTE_BAD_PHYS_ADDR, len, free_cb, opaque);
	}

	/*开始构成,遍历所有页，做成mbuf，且入队了，且挂链*/
	for (offset = 0; offset + page_size <= len && mempool->populated_size < mempool->size; offset += phys_len)
	{

		/*获取物理地址*/
		paddr = rte_mem_virt2phy(addr + offset);

		/* required for xen_dom0 to get the machine address */
		paddr = rte_mem_phy2mch(-1, paddr);

		if (paddr == RTE_BAD_PHYS_ADDR) 
		{
			ret = -EINVAL;
			goto fail;
		}

		/* populate with the largest group of contiguous pages */
		/*构建连续页最大组，获取最大页组*/
		/*校验所有mbuf的内存大小，物理地址是否连续*/
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

		/*页内存做成mbuf入队了且挂链*/
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
  函数名:	   rte_mempool_populate_default
  功能描述:    dpdk内存池申请
  参数描述:    mp--内存池，真实地址为elem地址,从socket heap申请的一块内存虚拟地址
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
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
	/*内存池，内存构造标记*/
	if (mem_pool->nb_mem_chunks != 0)
	{
		return -EEXIST;
	}
	
	/*是否支持10G*/
	if (rte_xen_dom0_supported())
	{
		pg_sz    = RTE_PGSIZE_2M;     /*大页size 2M*/
		pg_shift = rte_bsf32(pg_sz);
		align    = pg_sz;
	}
	/*设置了非大页模式*/
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

	/*总大小*/     /*rte_mempool_objhdr 单个报文size rte_mbuf+rte_pktmbufheadroom+dataroom rte_mempool_objtlr*/
	total_elt_sz = mem_pool->header_size + mem_pool->elt_size + mem_pool->trailer_size;

	/*计算为这些元素分配多大空间*/
	/*n所有端口mbuf个数之和*/
	for (mz_id = 0, n = mem_pool->size; n > 0; mz_id++, n -= ret) 
	{
		/*计算所有端口 mbuf 需要的内存之和*/
		size = rte_mempool_xmem_size(n, total_elt_sz, pg_shift);

		ret = snprintf(mz_name, sizeof(mz_name), RTE_MEMPOOL_MZ_FORMAT "_%d", mem_pool->name, mz_id);
		if (ret < 0 || ret >= (int)sizeof(mz_name))
		{
			ret = -ENAMETOOLONG;
			goto fail;
		}

		/*从堆中获取size大小内存elem挂到memzone数组格子，返回*/
		/*所有mbuf内存elem申请，用memzone描述，挂到了mem_pool->mem_list, 切成mbuf obj 入队*/
		memzone = rte_memzone_reserve_aligned(mz_name, size, mem_pool->socket_id, mz_flags, align);
		
		/* not enough memory, retry with the biggest zone we have */

		/*没有合适size的elem,返回size最大的elem */
		if (memzone == NULL)
		{
			memzone = rte_memzone_reserve_aligned(mz_name, 0, mem_pool->socket_id, mz_flags, align);
		}
		
		if (memzone == NULL)
		{
			ret = -rte_errno;
			goto fail;
		}

		/*物理地址*/
		/*内存池不需要物理地址，设置默认物理地址*/
		if (mem_pool->flags & MEMPOOL_F_NO_PHYS_CONTIG)
		{
			paddr = RTE_BAD_PHYS_ADDR;
		}
		else
		{
			paddr = memzone->phys_addr;   								/*获取物理地址*/
		}
		
		/*未设置非大页模式，不支持10G*/
		if (rte_eal_has_hugepages() && !rte_xen_dom0_supported())
		{
			/*构造物理地址*/
			ret = rte_mempool_populate_phys(mem_pool, memzone->addr, paddr, memzone->len, rte_mempool_memchunk_mz_free, (void *)(uintptr_t)memzone);
		}
		else
		{
			/*构造虚拟地址*/                          /*所有mbuf elem地址*/ /*需要的内存长度*/                     
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
  函数名:		rte_mempool_free
  功能描述:     内存池释放
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
void
rte_mempool_free(struct rte_mempool *mp)
{
	struct rte_mempool_list *mempool_list = NULL;
	struct rte_tailq_entry *te;

	if (mp == NULL)
		return;

	/*获取内存池链*/
	mempool_list = RTE_TAILQ_CAST(rte_mempool_tailq.head, rte_mempool_list);

	rte_rwlock_write_lock(RTE_EAL_TAILQ_RWLOCK);

	/* find out tailq entry */
	/*尾部队列入口*/
	TAILQ_FOREACH(te, mempool_list, next) {
		if (te->data == (void *)mp)
			break;
	}
	

	/*尾部队列删除*/
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
  函数名:		mempool_cache_init
  功能描述: 	创建空的内存池
  参数描述: 	cache---缓冲区地址
				size---250个mbuf，每逻辑核允许挂载的mbuf个数
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static void mempool_cache_init(struct rte_mempool_cache *cache, uint32_t size)
{
	cache->size = size;
	cache->flushthresh = CALC_CACHE_FLUSHTHRESH(size); /*1.5倍cache*/
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
  函数名:		rte_mempool_create_empty
  功能描述: 	创建空的内存池，尾部队列申请128个逻辑核挂mbuf 的cache (sizeof(struct rte_mempool_cache))，单纯创建128 mbuf的cache
  参数描述: 	name---内存池name，"MBUF_POOL"
  				mbuf_num---所有端口mbuf 个数之和，每个端口8191个mbuf
  				pkt_mbuf_size--mbuf报文描述结构长度+priv长度+数据部分长度，代表一个报文rte_mbuf + priv + 2176，单个mbuf size
  				即sizeof(struct rte_mbuf) + (unsigned)priv_size + (unsigned)data_room_size = sizeof(struct rte_mbuf)+0+2176
		  		rte_mbuf + prive_size + dataroom
  				cache_size---每逻辑核cache允许挂的mbuf个数，当前250个
  				socket_id---内存池所属于的socket
  				private_data_size---长度描述结构大小, sizeof(struct rte_pktmbuf_pool_private),dataroom长度与private长度描述结构
  				flags---内存池的共享对齐等属性，当前值为0
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
struct rte_mempool *rte_mempool_create_empty(const char *name, unsigned mbuf_num, unsigned pkt_mbuf_size,unsigned cache_size, unsigned private_data_size, int socket_id, unsigned flags)
{
	char memzone_name[RTE_MEMZONE_NAMESIZE];
	struct rte_mempool_list *mempool_list;
	
	struct rte_mempool *mem_pool 	     = NULL;	
	struct rte_tailq_entry *mem_pool_list_node   = NULL;
	const struct rte_memzone *lcore_cache_memzone = NULL;
	
	size_t lcore_cache_mempool_size;
	
	int mz_flags = RTE_MEMZONE_1GB|RTE_MEMZONE_SIZE_HINT_ONLY;   /*1G或合适的size*/

	/*内存对象记录的各种size*/
	struct rte_mempool_objsz obj_size_info;  					 
	
	unsigned lcore_id;
	int ret;

	/* compilation-time checks */

	/*size大小不为0检查*/
	/*根63取与不为0，说明未使用64字节对齐，即判断是否64字节对齐，对齐则bugon*/

	/*各结构是否是64字节对齐申请*/
	RTE_BUILD_BUG_ON((sizeof(struct rte_mempool) & RTE_CACHE_LINE_MASK) != 0);
	
	RTE_BUILD_BUG_ON((sizeof(struct rte_mempool_cache) & RTE_CACHE_LINE_MASK) != 0);
	
#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
	RTE_BUILD_BUG_ON((sizeof(struct rte_mempool_debug_stats) & RTE_CACHE_LINE_MASK) != 0);
	RTE_BUILD_BUG_ON((offsetof(struct rte_mempool, stats) & RTE_CACHE_LINE_MASK) != 0);
#endif

	/*获取链表头，rte_mempool_list类型*/
	/*申请的内存池做成了链表*/
	mempool_list = RTE_TAILQ_CAST(rte_mempool_tailq.head, rte_mempool_list);

	/* asked cache too big */
	/*内存大小校验*/
	/*逻辑核要用的cache size是否合法，250个mbuf，cache_size为mbuf的个数*/
	if (cache_size > RTE_MEMPOOL_CACHE_MAX_SIZE || CALC_CACHE_FLUSHTHRESH(cache_size) > mbuf_num) /*1.5倍cache 是否大于n，所有mbuf个数*/
	{
		rte_errno = EINVAL;
		return NULL;
	}

	/* "no cache align" imply "no spread" */
	/*非对齐，设置内存标记为非扩展*/
	if (flags & MEMPOOL_F_NO_CACHE_ALIGN)
	{
		flags |= MEMPOOL_F_NO_SPREAD;
	}
	
	/* calculate mempool object sizes. */

	/*计算内存obj size，64字节对齐，通道x阶层扩展后的对象size*/
	/*对齐格式化后的 mbuf size*/
	/*构造出的mbuf对象size，各部分长度在obj_size_info*/
	if (!rte_mempool_calc_obj_size(pkt_mbuf_size, flags, &obj_size_info)) 
	{
		rte_errno = EINVAL;
		return NULL;
	}

	/*内存读写锁上锁*/
	rte_rwlock_write_lock(RTE_EAL_MEMPOOL_RWLOCK);

	/*
	 * reserve a memory zone for this mempool: private data is
	 * cache-aligned
	 */

	/*私有数据内存大小，64补全对齐*/
	private_data_size = (private_data_size + RTE_MEMPOOL_ALIGN_MASK) & (~RTE_MEMPOOL_ALIGN_MASK);

	/* try to allocate tailq entry */
	/*申请节点内存，从heap拿到本类型的内存元素elem*/
	/*te就是elem元素*/
	/*te是尾部队列结构 struct rte_tailq_entry */
	/*从elem中获取sizeof(struct rte_tailq_entry)大小内存*/
	mem_pool_list_node = rte_zmalloc("MEMPOOL_TAILQ_ENTRY", sizeof(struct rte_tailq_entry), 0);
	if (mem_pool_list_node == NULL) 
	{
		RTE_LOG(ERR, MEMPOOL, "Cannot allocate tailq entry!\n");
		goto exit_unlock;
	}

	/*内存池头size*/
	/*elem内存清0，长度为sizeof(rte_mempool) + 128个逻辑核cache内存128 * sizeof(struct rte_mempool_cache) + pvivatesize目前为0 + 64字节对齐*/
	lcore_cache_mempool_size  = MEMPOOL_HEADER_SIZE(mem_pool, cache_size);  			 /*sizeof(rte_mempool) + 128个逻辑核cache内存128 * sizeof(struct rte_mempool_cache)*/
	lcore_cache_mempool_size += private_data_size;                               /*当前值为0*/
	lcore_cache_mempool_size  = RTE_ALIGN_CEIL(lcore_cache_mempool_size, RTE_MEMPOOL_ALIGN); /*mempool_size 64字节对齐*/

	/*总长度为128个逻辑核cache + priv + 64 字节对齐*/
	
	/*mzone name 当前 "MP_MBUF_POOL"*/
	ret = snprintf(memzone_name, sizeof(memzone_name), RTE_MEMPOOL_MZ_FORMAT, name);
	if (ret < 0 || ret >= (int)sizeof(memzone_name)) 
	{
		rte_errno = ENAMETOOLONG;
		goto exit_unlock;
	}

	/*从socket堆中获取elem 放入mzone格子，sizeof(rte_mempool) + 128个逻辑核cache内存128 * sizeof(struct rte_mempool_cache)+pvivatesize目前为0+64字节对齐*/
	/*128个逻辑核cache的memzone 数组格子*/
	lcore_cache_memzone = rte_memzone_reserve(memzone_name, lcore_cache_mempool_size, socket_id, mz_flags);
	if (lcore_cache_memzone == NULL)
	{
		goto exit_unlock;
	}
	
	/* init the mempool structure */
	/*获取elem地址，长度为mempool结构头+private+128个逻辑核cache大小数据大小+64字节对齐*/
	/*挂载memzone上真实的elem地址*/
	mem_pool = lcore_cache_memzone->addr;

	/*elem内存清0，长度为sizeof(rte_mempool) + 128个逻辑核cache内存128 * sizeof(struct rte_mempool_cache) + pvivatesize目前为0 + 64字节对齐*/
	memset(mem_pool, 0, MEMPOOL_HEADER_SIZE(mem_pool, cache_size));

	ret = snprintf(mem_pool->name, sizeof(mem_pool->name), "%s", name);
	if (ret < 0 || ret >= (int)sizeof(mem_pool->name))
	{
		rte_errno = ENAMETOOLONG;
		goto exit_unlock;
	}

	/*128个逻辑核cache结构mempool*/
	mem_pool->mz                = lcore_cache_memzone;          /*挂载memzone上的内存记录自己属于的memzone*/    
	mem_pool->socket_id         = socket_id;     			    /*elem 所属socket*/
	mem_pool->size              = mbuf_num;             		/*所有端口mbuf个数之和*/
	mem_pool->flags             = flags;                        /*内存属性*/
	mem_pool->socket_id         = socket_id;

	/*单个报文elt_size,单个pkt_mbuf size*/
	mem_pool->elt_size          = obj_size_info.elt_size;             /*单个报文rte_mbuf + prive_size + dataroom*/
	mem_pool->header_size       = obj_size_info.header_size;          /*头部长度, sizeof(struct rte_mempool_objhdr)*/
	mem_pool->trailer_size      = obj_size_info.trailer_size;         /*尾部长度, sizeof(struct rte_mempool_objtlr)*/
	
	/* Size of default caches, zero means disabled. */
	mem_pool->cache_size        = cache_size;                 /*128逻辑核单个cache size 250 个，意思是最多挂载205个mbuf 每逻辑核*/
	mem_pool->private_data_size = private_data_size;          /*私有数据size,当前为0*/

	/*链表初始化*/
	STAILQ_INIT(&mem_pool->elt_list);
	STAILQ_INIT(&mem_pool->mem_list);

	/*
	 * local_cache pointer is set even if cache_size is zero.
	 * The local_cache points to just past the elt_pa[] array.
	 */

	/*128逻辑核cache首地址*/
	mem_pool->local_cache = (struct rte_mempool_cache *)RTE_PTR_ADD(mem_pool, MEMPOOL_HEADER_SIZE(mem_pool, 0));

	/* Init all default caches. */

	/*内存池挂链*/
	if (cache_size != 0) 
	{
		/*遍历128个逻辑核cache初始化*/
		for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++)
		{
			mempool_cache_init(&mem_pool->local_cache[lcore_id], cache_size);
		}
	}

	/*内存池做成内存池链表节点*/
	mem_pool_list_node->data = mem_pool;

	rte_rwlock_write_lock(RTE_EAL_TAILQ_RWLOCK);


	/*尾队列挂链*/	
	TAILQ_INSERT_TAIL(mempool_list, mem_pool_list_node, next);

	/*上锁*/
	rte_rwlock_write_unlock(RTE_EAL_TAILQ_RWLOCK);

	/*上锁*/
	rte_rwlock_write_unlock(RTE_EAL_MEMPOOL_RWLOCK);

	/*elem地址*/
	return mem_pool;

exit_unlock:
	rte_rwlock_write_unlock(RTE_EAL_MEMPOOL_RWLOCK);
	rte_free(mem_pool_list_node);
	
	rte_mempool_free(mem_pool);
	return NULL;
}

/* create the mempool */

/*******************************************************
  函数名:	   rte_mempool_create
  功能描述:    dpdk内存池申请
  参数描述:    name--内存池名
  			   n---内存池mbuf个数
  			   elt 单个mbuf size
  			   cache_size--缓存size
  			   private_data_size--私有数据size
  			   mp_init---内存池初始化函数
  			   mp_init_arg--内存池初始化参数
  			   obj_init--内存池对象初始化函数
  			   obj_init_arg---内存池内存对象初始化
  			   socket_id 
  			   flags---内存属性设置
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
struct rte_mempool *
rte_mempool_create(const char *name, unsigned n, unsigned elt_size,
	unsigned cache_size, unsigned private_data_size,
	rte_mempool_ctor_t *mp_init, void *mp_init_arg,
	rte_mempool_obj_cb_t *obj_init, void *obj_init_arg,
	int socket_id, unsigned flags)
{
	struct rte_mempool *mp;

	/*mempool内存申请及初始化*/
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

	/*内存池初始化*/
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
