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
  ������:		malloc_elem_init
  ��������: 	����elem
  ��������: 	elem---�ָ�����µ�elemԪ��,new_elem
                heap---�ѵ�ַ
                ms---�ڴ���Ϣ
                size---�µ�elem�ڴ泤��
                
  ����ֵ	:
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
void malloc_elem_init(struct malloc_elem *elem, struct malloc_heap *heap, const struct rte_memseg *ms, size_t size)
{
	//|..........................................|..............................new_elem_size.......................................|
	/*|----------ʣ���ڴ�old_elem_size-----------|-------sizeof(struct malloc_elem)--------|--------size---------|--64--|---trail--*/
	/*elem*/							 /*new_elem*/								/*new_data_start*/

	elem->heap  = heap;
	elem->ms    = ms;
	elem->prev  = NULL;

	/*��elem�������ó�ʼ��*/
	memset(&elem->free_list, 0, sizeof(elem->free_list));

	elem->state = ELEM_FREE;
	elem->size  = size;
	elem->pad   = 0;

	/*����ͷ��cookieֵ*/
	set_header(elem);

	/*����β��cookieֵ*/
	set_trailer(elem);
}

/*
 * initialise a dummy malloc_elem header for the end-of-memseg marker
 */
/*******************************************************
  ������:		malloc_elem_mkend
  ��������: 	��ʼ���ڴ�Ԫ��
  ��������: 	elem---��Ϊ��һ��elem���ֳ�
  				prev--��ǰ�ѷֳ���elem  				
                
  ����ֵ	:
  ����޸���:
  �޸�����:    2017 -11-15
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
 ��������  : elem_start_pt
 ��������  : ����size��elem�ڴ�Ԫ�ظ�ʽ������ȡ��ʽ�������elem��ʼ��ַ,��elem��β����ȡsize�ֽ�
 �������  : elem----����ԭʼ�ڴ�Ԫ��
             size---Ҫ��ȡ���ڴ�size�����ȴ�elem������ȡ
             align--�ֽڶ���
             bound----0
             
 �������  : elem:/--header--|------size----------|--trail-/
 �� �� ֵ  : ��elem��ַ�������size ��elem �У���elem��ַ����������µ���
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����   : 
 �޸�Ŀ��   : �޸ĺ���
 �޸�����   : 20140426
*******************************************************************************/ 
static void *
elem_start_pt(struct malloc_elem *elem, size_t size, unsigned align, size_t bound)
{
	const size_t bmask = ~(bound - 1);

	/*������ַ������β������64�ֽ�*/
	/*|------------------|--64--|----*/
	   /*elem*/	        /*end_ptr*/               /*end_ptr*/
	uintptr_t end_pt = (uintptr_t)elem + elem->size - MALLOC_ELEM_TRAILER_LEN;

	/*��ʼ��ַ��β����ַ�����ƶ���ָ�������С����Ϊ���ݲ�����ʼ��ַ*/
	/*|---------|-------------------------------|--------needsize---------|--64--|*/
   /*elem*/ 
	                                         /*new_data_start*/
	uintptr_t new_data_start = RTE_ALIGN_FLOOR((end_pt - size), align);

	uintptr_t new_elem_start;

	/* check boundary */
	/*�ڴ���ʼ��ֹ��ַ�߽��飬��ʼ��ֹ��ַ�Ƿ���ȣ����elem�ڴ�size��Ϊ0*/
	if ((new_data_start & bmask) != ((end_pt - 1) & bmask)) 
	{
		/*end_pt����bound����*/
		end_pt = RTE_ALIGN_FLOOR(end_pt, bound);

		/*new_data_start����align����*/
		new_data_start = RTE_ALIGN_FLOOR((end_pt - size), align);

		/*У���Ƿ����*/
		if (((end_pt - 1) & bmask) != (new_data_start & bmask))
		{
			return NULL;
		}
	}

	/*��ʼ���ݵ�ַ��ƫsizeof(struct malloc_elem)==new_elem_start*/

	/*|--------------------------------------|-------sizeof(struct malloc_elem)--------|-------needsize----------|--64--|-----*/
	/*elem*/                            /*new_elem_start*/                     /*new_data_start*/
	new_elem_start = new_data_start - MALLOC_ELEM_HEADER_LEN;

	/*��ʽ����elem�µ�ַ����ʵʹ���ڴ���ʼ��ַ*/
	/* if the new start point is before the exist start, it won't fit */
	return (new_elem_start < (uintptr_t)elem) ? NULL : (void *)new_elem_start;
}

/*
 * use elem_start_pt to determine if we get meet the size and
 * alignment request from the current element
 */
/*******************************************************************************
 ��������  : malloc_elem_can_hold
 ��������  : ��������size���elem�ڴ��Ƿ��㹻��������elem�ڴ�Ԫ�ظ�ʽ��
 �������  : elem----��ȡ���ڴ�Ԫ��
             size---Ҫ��ȡ���ڴ�size
             align--64�ֽڶ���
             bound---��ǰΪ0
             
 �������  : 
 �� �� ֵ  : 
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����   : 
 �޸�Ŀ��   : �޸ĺ���
 �޸�����   : 20140426
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
 ��������  : malloc_elem_alloc
 ��������  : ��size��С�������������
 			 new_elem��next_elem������next_elem��ʣ��trailer���ɵ�elem
 �������  : elem--�ڴ�Ԫ��
             split_pt---new_elem
             
 �������  : 
 �� �� ֵ  : 
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����   : 
 �޸�Ŀ��   : �޸ĺ���
 �޸�����   : 20140426
*******************************************************************************/ 
static void
split_elem(struct malloc_elem *elem, struct malloc_elem *split_pt)
{
	//|..........................................|..............................new_elem_size.......................................|
	/*|----------ʣ���ڴ�old_elem_size-----------|-------sizeof(struct malloc_elem)--------|--------size---------|--64--|---trail--*/
	/*elem*/							 /*new_elem*/                               /*new_data_start*/

	/*��һ��elem ��ַ��ԭʼ��ַ*/
	/*|-------------------------|----------|*/
	//elem                    next_elem
	struct malloc_elem *next_elem = RTE_PTR_ADD(elem, elem->size);

	/*ԭ����elem ʣ��size*/
	const size_t old_elem_size = (uintptr_t)split_pt - (uintptr_t)elem;

	
	/*����ȥ��elem size*/
	const size_t new_elem_size = elem->size - old_elem_size;

	/*new_elem��ʼ��*/
	malloc_elem_init(split_pt, elem->heap, elem->ms, new_elem_size);

	/*�¸�ʽ�������һ��elem��������һ��ԭʼelem*/
	split_pt->prev  = elem;

	/*ʣ��β�����ɵ�elem������new_elem��*/
	next_elem->prev = split_pt;

	/*�޸��ϵ�Ԫ��size*/
	elem->size      = old_elem_size;

	/*����β��cooker*/
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
 ��������  : malloc_elem_free_list_index
 ��������  : ��������ڴ�Ԫ����������
 �������  : size---����ָ�������С
 �������  : 
 �� �� ֵ  : ����������
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����   : 
 �޸�Ŀ��   : �޸ĺ���
 �޸�����   : 20140426
*******************************************************************************/ 
size_t
malloc_elem_free_list_index(size_t size)
{
#define MALLOC_MINSIZE_LOG2   8
#define MALLOC_LOG2_INCREMENT 2

	size_t log2;
	size_t index;

	/*С��128�ֽ�*/
	if (size <= (1UL << MALLOC_MINSIZE_LOG2))
	{
		return 0;
	}
	
	/* Find next power of 2 >= size. */
	/*�ڴ�ڵ��С������������*/
	log2 = sizeof(size) * 8 - __builtin_clzl(size-1);

	/* Compute freelist index, based on log2(size). */

	/*����ָ�������С����index*/
	index = (log2 - MALLOC_MINSIZE_LOG2 + MALLOC_LOG2_INCREMENT - 1) / MALLOC_LOG2_INCREMENT;

	return index <= RTE_HEAP_NUM_FREELISTS-1 ? index: RTE_HEAP_NUM_FREELISTS-1;
}

/*
 * Add the specified element to its heap's free list.
 */
 /*******************************************************************************
 ��������  : malloc_elem_free_list_insert
 ��������  : �·ָ������elemԪ�ع���
 �������  : elem---��ʽ�����elem
             
 �������  : 
 �� �� ֵ  : 
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����   : 
 �޸�Ŀ��   : �޸ĺ���
 �޸�����   : 20140426
*******************************************************************************/ 
void
malloc_elem_free_list_insert(struct malloc_elem *elem)
{
	size_t idx;

	/*����size��������*/  /*elem->size - MALLOC_ELEM_HEADER_LEN,��ȥ�ṹ����size*/
	/*����size����elem ������һ��heap*/

	idx = malloc_elem_free_list_index(elem->size - MALLOC_ELEM_HEADER_LEN);
	
	elem->state = ELEM_FREE;

	/*elem�ҵ�������*/
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
 ��������  : malloc_elem_alloc
 ��������  : �ָ�elemԪ�أ������ڴ�����elemԪ�ز�����
 �������  : elem--�ڴ�Ԫ��
			 size---requested_len���󳤶ȣ�sizeof(rte_mempool) + 128���߼���cache�ڴ�128 * sizeof(struct rte_mempool_cache)+privateĿǰ����0+64�ֽڶ��룬
			 ��Ĭ�ϳ��ȣ�Ϊ����socket�elem����-sizeof(struct malloc_elem) - 64β - ���볤�ȣ�����Ч���ݲ��ֳ���
             align--64�ֽڶ���
             bound--�߽����
             
 �������  : 
 �� �� ֵ  : 
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����   : 
 �޸�Ŀ��   : �޸ĺ���
 �޸�����   : 20140426
*******************************************************************************/ 
struct malloc_elem *
malloc_elem_alloc(struct malloc_elem *elem, size_t size, unsigned align,
		size_t bound)
{
	/*����size��ʽ�������elem��ַ/*----------ʣ���ڴ�-----------|-------sizeof(struct malloc_elem)--------|--------size---------|--64--*/
						  		 /*elem*/					/*new_elem*/                           /*new_data_start*/
	struct malloc_elem *new_elem = elem_start_pt(elem, size, align, bound);

	/*��ֵsize������ǰ�棬elemʣ����ڴ棬��ǰ��*/
	/*----------ʣ���ڴ�old_elem_size-----------|-------sizeof(struct malloc_elem)--------|--------size---------|--64--*/
										 /*new_elem*/                               /*new_data_start*/
	
	const size_t old_elem_size = (uintptr_t)new_elem - (uintptr_t)elem;

	
	/*----------ʣ���ڴ�old_elem_size-----------|--------sizeof(struct malloc_elem)--------|--------size---------|--64--|--trailer_size-*/	
	const size_t trailer_size = elem->size - old_elem_size - size - MALLOC_ELEM_OVERHEAD;

	/*�ӿ�������ժ��*/
	elem_free_list_remove(elem);

	/*β��ʣ�೤�ȴ�С����sizeof(struct malloc_elem)+ 64���� + 64β�����������µ�elem*/
	if (trailer_size > MALLOC_ELEM_OVERHEAD + MIN_DATA_SIZE) 
	{
		/* split it, too much free space after elem */
		/*β����������β���ֳ�������ȡ��elem��ַ*/      /*��elem��ַƫ��size + sizeof(struct malloc_elem) + 64β*/

		/*----------ʣ���ڴ�old_elem_size-----------|-------sizeof(struct malloc_elem)--------|--------size---------|-----64----|------trailer--------*/
									            /*new_elem*/                            /*new_data_start*/                 /*new_free_elem*/
		struct malloc_elem *new_free_elem = RTE_PTR_ADD(new_elem, size + MALLOC_ELEM_OVERHEAD);

		/*�ָ����elem��������*/
		split_elem(elem, new_free_elem);

		/*�·ָ������elem����*/
		malloc_elem_free_list_insert(new_free_elem);
	}

	/*Ԫ�ر����ڴ�С������䣬�������64�ֽ�*/
	if (old_elem_size < MALLOC_ELEM_OVERHEAD + MIN_DATA_SIZE) 
	{
		/* don't split it, pad the element instead */
		/*���*/
		elem->state = ELEM_BUSY;
		/*ͷ����ֵ��Ϊ��䳤��*/
		elem->pad = old_elem_size;

		/* put a dummy header in padding, to point to real element header */
		if (elem->pad > 0) 
		{ /* pad will be at least 64-bytes, as everything
		                     * is cache-line aligned */

			/*ͷ����ֵ��Ϊ���*/			
			new_elem->pad   = elem->pad;
			new_elem->state = ELEM_PAD;

			/*���ȼ�ȥͷ����ֵ*/
			new_elem->size  = elem->size - elem->pad;

			/*����ͷ��cookieֵ*/
			set_header(new_elem);
		}

		return new_elem;
	}

	/* we are going to split the element in two. The original element
	 * remains free, and the new element is the one allocated.
	 * Re-insert original element, in case its new size makes it
	 * belong on a different list.
	*/

	/*��ʽ�����new_elem ����*/
	split_elem(elem, new_elem);
	
	new_elem->state = ELEM_BUSY;

	/*������heap*/
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
 ��������  :  malloc_elem_free
 ��������  :  elem���ؿ�����
 �������  :  elem---�ڴ�Ԫ�ص�ַ
 �������  : 
 �� �� ֵ  : 
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����   : 
 �޸�Ŀ��   : 
 �޸�����   : 
*******************************************************************************/ 
int
malloc_elem_free(struct malloc_elem *elem)
{
	/*���elem״̬*/
	if (!malloc_elem_cookies_ok(elem) || elem->state != ELEM_BUSY)
		return -1;

	rte_spinlock_lock(&(elem->heap->lock));
	
	size_t sz = elem->size - sizeof(*elem);
	
	uint8_t *ptr = (uint8_t *)&elem[1];

	/*��ȡelem ָ�����һ��elem*/
	struct malloc_elem *next = RTE_PTR_ADD(elem, elem->size);

	/*��һ��elem���У��������������ǰelem*/
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
	/*��������һ��elem*/
	if (elem->prev != NULL && elem->prev->state == ELEM_FREE) {

		/*pre�ڵ�������Ƴ�*/
		elem_free_list_remove(elem->prev);

		/*�����ϲ�����ǰ�ڵ�*/
		join_elem(elem->prev, elem);
		sz += sizeof(*elem);
		ptr -= sizeof(*elem);
		elem = elem->prev;
	}

	/*elemԪ�ع���ѿ�����*/
	malloc_elem_free_list_insert(elem);

	/* decrease heap's count of allocated elements */

	/*����elem����*/
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
  ������:		malloc_elem_resize
  ��������: 	�����趨elem�ڴ�Ԫ�صĴ�С
  ��������: 	elem---�ڴ�Ԫ�ص�ַ
  				size---���д�С				
  ����ֵ :
  ����޸���:
  �޸�����: 	2018 -3-26
********************************************************/
int
malloc_elem_resize(struct malloc_elem *elem, size_t size)
{
	/*��Ҫ���¶���size*/                   /*sizeof(struct malloc_elem)+64*/
	const size_t new_size = size + MALLOC_ELEM_OVERHEAD;
	/* if we request a smaller size, then always return ok */

	/*��ʵelem��С*/
	const size_t current_size = elem->size - elem->pad;
	if (current_size >= new_size)
		return 0;

	/*��һ��elem��ַ*/
	struct malloc_elem *next = RTE_PTR_ADD(elem, elem->size);

	/*ÿsocket������*/
	rte_spinlock_lock(&elem->heap->lock);

	/*elem ��ʹ����*/
	if (next ->state != ELEM_FREE)
		goto err_return;

	/*��ǰelemԪ�ش�С������һ��elemԪ�ش�С����,����next elem �����µ�size*/
	if (current_size + next->size < new_size)
		goto err_return;

	/* we now know the element fits, so remove from free list,
	 * join the two
	 */

	/*eleԪ�ع���׷��*/
	elem_free_list_remove(next);
	join_elem(elem, next);

	/*2��elem�ϳɵ�elem size ����ʣ��*/
	if (elem->size - new_size >= MIN_DATA_SIZE + MALLOC_ELEM_OVERHEAD)
	{
		/* now we have a big block together. Lets cut it down a bit, by splitting */

		/*��Ҫ�г���elem��ַ*/
		struct malloc_elem *split_pt = RTE_PTR_ADD(elem, new_size);

		/**/
		split_pt = RTE_PTR_ALIGN_CEIL(split_pt, RTE_CACHE_LINE_SIZE);

		/*�г����elem*/
		split_elem(elem, split_pt);

		/*�г���elem����*/
		malloc_elem_free_list_insert(split_pt);
	}
	rte_spinlock_unlock(&elem->heap->lock);
	return 0;

err_return:
	rte_spinlock_unlock(&elem->heap->lock);
	return -1;
}
