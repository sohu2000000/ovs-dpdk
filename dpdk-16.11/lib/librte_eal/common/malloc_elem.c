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
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_common.h>
#include <rte_spinlock.h>

#include "malloc_elem.h"
#include "malloc_heap.h"

#define MIN_DATA_SIZE (RTE_CACHE_LINE_SIZE)

/*
 * initialise a general malloc_elem header structure
 */ 
 /*******************************************************
  函数名:		malloc_elem_init
  功能描述: 	做成elem
  参数描述: 	elem---分割出的新的elem元素,new_elem
                heap---堆地址
                ms---内存信息
                size---新的elem内存长度
                
  返回值	:
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
void malloc_elem_init(struct malloc_elem *elem, struct malloc_heap *heap, const struct rte_memseg *ms, size_t size)
{
	//|..........................................|..............................new_elem_size.......................................|
	/*|----------剩余内存old_elem_size-----------|-------sizeof(struct malloc_elem)--------|--------size---------|--64--|---trail--*/
	/*elem*/							 /*new_elem*/								/*new_data_start*/

	elem->heap  = heap;
	elem->ms    = ms;
	elem->prev  = NULL;

	/*新elem空闲链置初始化*/
	memset(&elem->free_list, 0, sizeof(elem->free_list));

	elem->state = ELEM_FREE;
	elem->size  = size;
	elem->pad   = 0;

	/*设置头部cookie值*/
	set_header(elem);

	/*设置尾部cookie值*/
	set_trailer(elem);
}

/*
 * initialise a dummy malloc_elem header for the end-of-memseg marker
 */
/*******************************************************
  函数名:		malloc_elem_mkend
  功能描述: 	初始化内存元素
  参数描述: 	elem---作为下一个elem来分出
  				prev--当前已分出的elem  				
                
  返回值	:
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
void
malloc_elem_mkend(struct malloc_elem *elem, struct malloc_elem *prev)
{
	malloc_elem_init(elem, prev->heap, prev->ms, 0);
	elem->prev = prev;
	elem->state = ELEM_BUSY; /* mark busy so its never merged */
}

/*
 * calculate the starting point of where data of the requested size
 * and alignment would fit in the current element. If the data doesn't
 * fit, return NULL.
 */
/*******************************************************************************
 函数名称  : elem_start_pt
 功能描述  : 根据size对elem内存元素格式化，获取格式化后的新elem起始地址,从elem的尾部获取size字节
 输入参数  : elem----检查的原始内存元素
             size---要获取的内存size，优先从elem最后面获取
             align--字节对齐
             bound----0
             
 输出参数  : elem:/--header--|------size----------|--trail-/
 返 回 值  : 新elem地址，所需的size 在elem 中，新elem地址对齐后已重新调整
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者   : 
 修改目的   : 修改函数
 修改日期   : 20140426
*******************************************************************************/ 
static void *
elem_start_pt(struct malloc_elem *elem, size_t size, unsigned align, size_t bound)
{
	const size_t bmask = ~(bound - 1);

	/*结束地址，留出尾部长度64字节*/
	/*|------------------|--64--|----*/
	   /*elem*/	        /*end_ptr*/               /*end_ptr*/
	uintptr_t end_pt = (uintptr_t)elem + elem->size - MALLOC_ELEM_TRAILER_LEN;

	/*起始地址，尾部地址，左移队列指针数组大小，作为数据部分起始地址*/
	/*|---------|-------------------------------|--------needsize---------|--64--|*/
   /*elem*/ 
	                                         /*new_data_start*/
	uintptr_t new_data_start = RTE_ALIGN_FLOOR((end_pt - size), align);

	uintptr_t new_elem_start;

	/* check boundary */
	/*内存起始终止地址边界检查，起始终止地址是否相等，检查elem内存size不为0*/
	if ((new_data_start & bmask) != ((end_pt - 1) & bmask)) 
	{
		/*end_pt按照bound对齐*/
		end_pt = RTE_ALIGN_FLOOR(end_pt, bound);

		/*new_data_start按照align对齐*/
		new_data_start = RTE_ALIGN_FLOOR((end_pt - size), align);

		/*校验是否对齐*/
		if (((end_pt - 1) & bmask) != (new_data_start & bmask))
		{
			return NULL;
		}
	}

	/*起始数据地址左偏sizeof(struct malloc_elem)==new_elem_start*/

	/*|--------------------------------------|-------sizeof(struct malloc_elem)--------|-------needsize----------|--64--|-----*/
	/*elem*/                            /*new_elem_start*/                     /*new_data_start*/
	new_elem_start = new_data_start - MALLOC_ELEM_HEADER_LEN;

	/*格式化后elem新地址，真实使用内存起始地址*/
	/* if the new start point is before the exist start, it won't fit */
	return (new_elem_start < (uintptr_t)elem) ? NULL : (void *)new_elem_start;
}

/*
 * use elem_start_pt to determine if we get meet the size and
 * alignment request from the current element
 */
/*******************************************************************************
 函数名称  : malloc_elem_can_hold
 功能描述  : 根据所需size检查elem内存是否足够长，并对elem内存元素格式化
 输入参数  : elem----获取的内存元素
             size---要获取的内存size
             align--64字节对齐
             bound---当前为0
             
 输出参数  : 
 返 回 值  : 
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者   : 
 修改目的   : 修改函数
 修改日期   : 20140426
*******************************************************************************/ 
int
malloc_elem_can_hold(struct malloc_elem *elem, size_t size,	 unsigned align,
		size_t bound)
{
	return elem_start_pt(elem, size, align, bound) != NULL;
}

/*
 * split an existing element into two smaller elements at the given
 * split_pt parameter.
 */
 /*******************************************************************************
 函数名称  : malloc_elem_alloc
 功能描述  : 对size大小处理后放入空闲链
 			 new_elem，next_elem挂链，next_elem是剩余trailer做成的elem
 输入参数  : elem--内存元素
             split_pt---new_elem
             
 输出参数  : 
 返 回 值  : 
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者   : 
 修改目的   : 修改函数
 修改日期   : 20140426
*******************************************************************************/ 
static void
split_elem(struct malloc_elem *elem, struct malloc_elem *split_pt)
{
	//|..........................................|..............................new_elem_size.......................................|
	/*|----------剩余内存old_elem_size-----------|-------sizeof(struct malloc_elem)--------|--------size---------|--64--|---trail--*/
	/*elem*/							 /*new_elem*/                               /*new_data_start*/

	/*下一个elem 地址，原始地址*/
	/*|-------------------------|----------|*/
	//elem                    next_elem
	struct malloc_elem *next_elem = RTE_PTR_ADD(elem, elem->size);

	/*原来的elem 剩余size*/
	const size_t old_elem_size = (uintptr_t)split_pt - (uintptr_t)elem;

	
	/*已拿去的elem size*/
	const size_t new_elem_size = elem->size - old_elem_size;

	/*new_elem初始化*/
	malloc_elem_init(split_pt, elem->heap, elem->ms, new_elem_size);

	/*新格式化后的下一个elem挂链到上一个原始elem*/
	split_pt->prev  = elem;

	/*剩余尾部做成的elem，接在new_elem后*/
	next_elem->prev = split_pt;

	/*修改老的元素size*/
	elem->size      = old_elem_size;

	/*设置尾部cooker*/
	set_trailer(elem);
}

/*
 * Given an element size, compute its freelist index.
 * We free an element into the freelist containing similarly-sized elements.
 * We try to allocate elements starting with the freelist containing
 * similarly-sized elements, and if necessary, we search freelists
 * containing larger elements.
 *
 * Example element size ranges for a heap with five free lists:
 *   heap->free_head[0] - (0   , 2^8]
 *   heap->free_head[1] - (2^8 , 2^10]
 *   heap->free_head[2] - (2^10 ,2^12]
 *   heap->free_head[3] - (2^12, 2^14]
 *   heap->free_head[4] - (2^14, MAX_SIZE]
 */
/*******************************************************************************
 函数名称  : malloc_elem_free_list_index
 功能描述  : 计算空闲内存元素链表索引
 输入参数  : size---队列指针数组大小
 输出参数  : 
 返 回 值  : 堆链表索引
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者   : 
 修改目的   : 修改函数
 修改日期   : 20140426
*******************************************************************************/ 
size_t
malloc_elem_free_list_index(size_t size)
{
#define MALLOC_MINSIZE_LOG2   8
#define MALLOC_LOG2_INCREMENT 2

	size_t log2;
	size_t index;

	/*小于128字节*/
	if (size <= (1UL << MALLOC_MINSIZE_LOG2))
	{
		return 0;
	}
	
	/* Find next power of 2 >= size. */
	/*内存节点大小计算链表索引*/
	log2 = sizeof(size) * 8 - __builtin_clzl(size-1);

	/* Compute freelist index, based on log2(size). */

	/*根据指针数组大小计数index*/
	index = (log2 - MALLOC_MINSIZE_LOG2 + MALLOC_LOG2_INCREMENT - 1) / MALLOC_LOG2_INCREMENT;

	return index <= RTE_HEAP_NUM_FREELISTS-1 ? index: RTE_HEAP_NUM_FREELISTS-1;
}

/*
 * Add the specified element to its heap's free list.
 */
 /*******************************************************************************
 函数名称  : malloc_elem_free_list_insert
 功能描述  : 新分割出来的elem元素挂链
 输入参数  : elem---格式化后的elem
             
 输出参数  : 
 返 回 值  : 
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者   : 
 修改目的   : 修改函数
 修改日期   : 20140426
*******************************************************************************/ 
void
malloc_elem_free_list_insert(struct malloc_elem *elem)
{
	size_t idx;

	/*根据size计算索引*/  /*elem->size - MALLOC_ELEM_HEADER_LEN,除去结构本身size*/
	/*根据size计算elem 属于哪一个heap*/

	idx = malloc_elem_free_list_index(elem->size - MALLOC_ELEM_HEADER_LEN);
	
	elem->state = ELEM_FREE;

	/*elem挂到空闲链*/
	LIST_INSERT_HEAD(&elem->heap->free_head[idx], elem, free_list);
}

/*
 * Remove the specified element from its heap's free list.
 */
static void
elem_free_list_remove(struct malloc_elem *elem)
{
	LIST_REMOVE(elem, free_list);
}

/*
 * reserve a block of data in an existing malloc_elem. If the malloc_elem
 * is much larger than the data block requested, we split the element in two.
 * This function is only called from malloc_heap_alloc so parameter checking
 * is not done here, as it's done there previously.
 */
/*******************************************************************************
 函数名称  : malloc_elem_alloc
 功能描述  : 分割elem元素，多余内存做成elem元素并挂链
 输入参数  : elem--内存元素
			 size---requested_len请求长度，sizeof(rte_mempool) + 128个逻辑核cache内存128 * sizeof(struct rte_mempool_cache)+private目前等于0+64字节对齐，
			 或，默认长度，为所有socket最长elem长度-sizeof(struct malloc_elem) - 64尾 - 对齐长度，即有效数据部分长度
             align--64字节对齐
             bound--边界对齐
             
 输出参数  : 
 返 回 值  : 
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者   : 
 修改目的   : 修改函数
 修改日期   : 20140426
*******************************************************************************/ 
struct malloc_elem *
malloc_elem_alloc(struct malloc_elem *elem, size_t size, unsigned align,
		size_t bound)
{
	/*根据size格式化后的新elem地址/*----------剩余内存-----------|-------sizeof(struct malloc_elem)--------|--------size---------|--64--*/
						  		 /*elem*/					/*new_elem*/                           /*new_data_start*/
	struct malloc_elem *new_elem = elem_start_pt(elem, size, align, bound);

	/*差值size，在最前面，elem剩余的内存，在前面*/
	/*----------剩余内存old_elem_size-----------|-------sizeof(struct malloc_elem)--------|--------size---------|--64--*/
										 /*new_elem*/                               /*new_data_start*/
	
	const size_t old_elem_size = (uintptr_t)new_elem - (uintptr_t)elem;

	
	/*----------剩余内存old_elem_size-----------|--------sizeof(struct malloc_elem)--------|--------size---------|--64--|--trailer_size-*/	
	const size_t trailer_size = elem->size - old_elem_size - size - MALLOC_ELEM_OVERHEAD;

	/*从空闲链表摘除*/
	elem_free_list_remove(elem);

	/*尾部剩余长度大小超过sizeof(struct malloc_elem)+ 64数据 + 64尾，可以做成新的elem*/
	if (trailer_size > MALLOC_ELEM_OVERHEAD + MIN_DATA_SIZE) 
	{
		/* split it, too much free space after elem */
		/*尾部过长，把尾部分出来，获取新elem地址*/      /*新elem地址偏过size + sizeof(struct malloc_elem) + 64尾*/

		/*----------剩余内存old_elem_size-----------|-------sizeof(struct malloc_elem)--------|--------size---------|-----64----|------trailer--------*/
									            /*new_elem*/                            /*new_data_start*/                 /*new_free_elem*/
		struct malloc_elem *new_free_elem = RTE_PTR_ADD(new_elem, size + MALLOC_ELEM_OVERHEAD);

		/*分割出新elem，并挂链*/
		split_elem(elem, new_free_elem);

		/*新分割出来的elem挂链*/
		malloc_elem_free_list_insert(new_free_elem);
	}

	/*元素本身内存小，则填充，最少填充64字节*/
	if (old_elem_size < MALLOC_ELEM_OVERHEAD + MIN_DATA_SIZE) 
	{
		/* don't split it, pad the element instead */
		/*填充*/
		elem->state = ELEM_BUSY;
		/*头部差值作为填充长度*/
		elem->pad = old_elem_size;

		/* put a dummy header in padding, to point to real element header */
		if (elem->pad > 0) 
		{ /* pad will be at least 64-bytes, as everything
		                     * is cache-line aligned */

			/*头部差值作为填充*/			
			new_elem->pad   = elem->pad;
			new_elem->state = ELEM_PAD;

			/*长度减去头部差值*/
			new_elem->size  = elem->size - elem->pad;

			/*设置头部cookie值*/
			set_header(new_elem);
		}

		return new_elem;
	}

	/* we are going to split the element in two. The original element
	 * remains free, and the new element is the one allocated.
	 * Re-insert original element, in case its new size makes it
	 * belong on a different list.
	*/

	/*格式化后的new_elem 挂链*/
	split_elem(elem, new_elem);
	
	new_elem->state = ELEM_BUSY;

	/*挂链到heap*/
	malloc_elem_free_list_insert(elem);

	return new_elem;
}

/*
 * joing two struct malloc_elem together. elem1 and elem2 must
 * be contiguous in memory.
 */
static inline void
join_elem(struct malloc_elem *elem1, struct malloc_elem *elem2)
{
	struct malloc_elem *next = RTE_PTR_ADD(elem2, elem2->size);
	elem1->size += elem2->size;
	next->prev = elem1;
}

/*
 * free a malloc_elem block by adding it to the free list. If the
 * blocks either immediately before or immediately after newly freed block
 * are also free, the blocks are merged together.
 */
 /*******************************************************************************
 函数名称  :  malloc_elem_free
 功能描述  :  elem还回空闲链
 输入参数  :  elem---内存元素地址
 输出参数  : 
 返 回 值  : 
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者   : 
 修改目的   : 
 修改日期   : 
*******************************************************************************/ 
int
malloc_elem_free(struct malloc_elem *elem)
{
	/*检查elem状态*/
	if (!malloc_elem_cookies_ok(elem) || elem->state != ELEM_BUSY)
		return -1;

	rte_spinlock_lock(&(elem->heap->lock));
	
	size_t sz = elem->size - sizeof(*elem);
	
	uint8_t *ptr = (uint8_t *)&elem[1];

	/*获取elem 指向的下一个elem*/
	struct malloc_elem *next = RTE_PTR_ADD(elem, elem->size);

	/*下一个elem空闲，则把它挂链到当前elem*/
	if (next->state == ELEM_FREE){
		/* remove from free list, join to this one */
		/**/
		elem_free_list_remove(next);
		join_elem(elem, next);
		sz += sizeof(*elem);
	}

	/* check if previous element is free, if so join with it and return,
	 * need to re-insert in free list, as that element's size is changing
	 */
	/*挂链到上一个elem*/
	if (elem->prev != NULL && elem->prev->state == ELEM_FREE) {

		/*pre节点从链表移除*/
		elem_free_list_remove(elem->prev);

		/*挂链合并到当前节点*/
		join_elem(elem->prev, elem);
		sz += sizeof(*elem);
		ptr -= sizeof(*elem);
		elem = elem->prev;
	}

	/*elem元素挂入堆空闲链*/
	malloc_elem_free_list_insert(elem);

	/* decrease heap's count of allocated elements */

	/*减少elem个数*/
	elem->heap->alloc_count--;

	memset(ptr, 0, sz);

	rte_spinlock_unlock(&(elem->heap->lock));

	return 0;
}

/*
 * attempt to resize a malloc_elem by expanding into any free space
 * immediately after it in memory.
 */

/*******************************************************
  函数名:		malloc_elem_resize
  功能描述: 	重新设定elem内存元素的大小
  参数描述: 	elem---内存元素地址
  				size---队列大小				
  返回值 :
  最后修改人:
  修改日期: 	2018 -3-26
********************************************************/
int
malloc_elem_resize(struct malloc_elem *elem, size_t size)
{
	/*需要的新队列size*/                   /*sizeof(struct malloc_elem)+64*/
	const size_t new_size = size + MALLOC_ELEM_OVERHEAD;
	/* if we request a smaller size, then always return ok */

	/*真实elem大小*/
	const size_t current_size = elem->size - elem->pad;
	if (current_size >= new_size)
		return 0;

	/*下一个elem地址*/
	struct malloc_elem *next = RTE_PTR_ADD(elem, elem->size);

	/*每socket堆上锁*/
	rte_spinlock_lock(&elem->heap->lock);

	/*elem 在使用中*/
	if (next ->state != ELEM_FREE)
		goto err_return;

	/*当前elem元素大小加上下一个elem元素大小不足,加上next elem 不足新的size*/
	if (current_size + next->size < new_size)
		goto err_return;

	/* we now know the element fits, so remove from free list,
	 * join the two
	 */

	/*ele元素挂链追加*/
	elem_free_list_remove(next);
	join_elem(elem, next);

	/*2个elem合成的elem size 还有剩余*/
	if (elem->size - new_size >= MIN_DATA_SIZE + MALLOC_ELEM_OVERHEAD)
	{
		/* now we have a big block together. Lets cut it down a bit, by splitting */

		/*需要切出的elem地址*/
		struct malloc_elem *split_pt = RTE_PTR_ADD(elem, new_size);

		/**/
		split_pt = RTE_PTR_ALIGN_CEIL(split_pt, RTE_CACHE_LINE_SIZE);

		/*切出后的elem*/
		split_elem(elem, split_pt);

		/*切出的elem挂链*/
		malloc_elem_free_list_insert(split_pt);
	}
	rte_spinlock_unlock(&elem->heap->lock);
	return 0;

err_return:
	rte_spinlock_unlock(&elem->heap->lock);
	return -1;
}
