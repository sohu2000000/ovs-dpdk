/*
 * Copyright (c) 2014, 2016 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "pvector.h"

/* Writers will preallocate space for some entries at the end to avoid future
 * reallocations. */
enum { PVECTOR_EXTRA_ALLOC = 4 };

static struct pvector_impl *
pvector_impl_get(const struct pvector *pvec)
{
    return ovsrcu_get(struct pvector_impl *, &pvec->impl);
}

static struct pvector_impl *
pvector_impl_alloc(size_t size)
{
    struct pvector_impl *impl;

    impl = xmalloc(sizeof *impl + size * sizeof impl->vector[0]);
    impl->size = 0;
    impl->allocated = size;

    return impl;
}

static struct pvector_impl *
pvector_impl_dup(struct pvector_impl *old)
{
    struct pvector_impl *impl;
    size_t alloc = old->size + PVECTOR_EXTRA_ALLOC;

    impl = xmalloc(sizeof *impl + alloc * sizeof impl->vector[0]);
    impl->allocated = alloc;
    impl->size = old->size;
    memcpy(impl->vector, old->vector, old->size * sizeof old->vector[0]);
    return impl;
}

/* Initializes 'pvec' as an empty concurrent priority vector. */
void
pvector_init(struct pvector *pvec)
{
    ovsrcu_set(&pvec->impl, pvector_impl_alloc(PVECTOR_EXTRA_ALLOC));
    pvec->temp = NULL;
}

/* Destroys 'pvec'.
 *
 * The client is responsible for destroying any data previously held in
 * 'pvec'. */
void
pvector_destroy(struct pvector *pvec)
{
    free(pvec->temp);
    pvec->temp = NULL;
    ovsrcu_postpone(free, pvector_impl_get(pvec));
    ovsrcu_set(&pvec->impl, NULL); /* Poison. */
}

/* Iterators for callers that need the 'index' afterward. */
#define PVECTOR_IMPL_FOR_EACH(ENTRY, INDEX, IMPL)          \
    for ((INDEX) = 0;                                      \
         (INDEX) < (IMPL)->size                            \
             && ((ENTRY) = &(IMPL)->vector[INDEX], true);  \
         (INDEX)++)

static int
pvector_entry_cmp(const void *a_, const void *b_)
{
    const struct pvector_entry *ap = a_;
    const struct pvector_entry *bp = b_;
    int a = ap->priority;
    int b = bp->priority;

    return a > b ? -1 : a < b;
}

static void
pvector_impl_sort(struct pvector_impl *impl)
{
    qsort(impl->vector, impl->size, sizeof *impl->vector, pvector_entry_cmp);
}

/*******************************************************************************
 函数名称  :  pvector_impl_find
 功能描述  :  查询
 输入参数  :  
 			  
 输出参数  :  
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Returns the index of the 'ptr' in the vector, or -1 if none is found. */
static int
pvector_impl_find(struct pvector_impl *impl, void *target)
{
    const struct pvector_entry *entry;
    int index;

    PVECTOR_IMPL_FOR_EACH (entry, index, impl) 
	{
        if (entry->ptr == target) 
		{
            return index;
        }
    }
    return -1;
}

/*******************************************************************************
 函数名称  :  pvector_insert
 功能描述  :  擦哈如
 输入参数  :  
 			  
 输出参数  :  
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
void
pvector_insert(struct pvector *pvec, void *ptr, int priority)
{
    struct pvector_impl *temp = pvec->temp;
    struct pvector_impl *old = pvector_impl_get(pvec);

    ovs_assert(ptr != NULL);

    /* Check if can add to the end without reallocation. */
    if (!temp && old->allocated > old->size &&
        (!old->size || priority <= old->vector[old->size - 1].priority)) {
        old->vector[old->size].ptr = ptr;
        old->vector[old->size].priority = priority;
        /* Size increment must not be visible to the readers before the new
         * entry is stored. */
        atomic_thread_fence(memory_order_release);
        ++old->size;
    } else {
        if (!temp) {
            temp = pvector_impl_dup(old);
            pvec->temp = temp;
        } else if (temp->size == temp->allocated) {
            temp = pvector_impl_dup(temp);
            free(pvec->temp);
            pvec->temp = temp;
        }
        /* Insert at the end, publish will sort. */
        temp->vector[temp->size].ptr = ptr;
        temp->vector[temp->size].priority = priority;
        temp->size += 1;
    }
}

/*******************************************************************************
 函数名称  :  pvector_remove
 功能描述  :  删除
 输入参数  :  pvec---优先级，每个优先级包含对应的掩码
 			  ptr---subtable
 输出参数  :  
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
void
pvector_remove(struct pvector *pvec, void *ptr)
{
	/*优先级，每个优先级包含对应的掩码*/
    struct pvector_impl *temp = pvec->temp;
    int index;

	/*优先级，每个优先级包含对应的掩码*/
    if (!temp) 
	{
        temp = pvector_impl_dup(pvector_impl_get(pvec));
        pvec->temp = temp;
    }
	
    ovs_assert(temp->size > 0);

	index = pvector_impl_find(temp, ptr);

	ovs_assert(index >= 0);
    /* Now at the index of the entry to be deleted.
     * Swap another entry in if needed, publish will sort anyway. */

	temp->size--;

	/**/
	if (index != temp->size) 
	{
        temp->vector[index] = temp->vector[temp->size];
    }
}

/* Change entry's 'priority' and keep the vector ordered. */
void
pvector_change_priority(struct pvector *pvec, void *ptr, int priority)
{
    struct pvector_impl *old = pvec->temp;
    int index;

    if (!old) {
        old = pvector_impl_get(pvec);
    }

    index = pvector_impl_find(old, ptr);

    ovs_assert(index >= 0);
    /* Now at the index of the entry to be updated. */

    /* Check if can not update in place. */
    if ((priority > old->vector[index].priority && index > 0
         && priority > old->vector[index - 1].priority)
        || (priority < old->vector[index].priority && index < old->size - 1
            && priority < old->vector[index + 1].priority)) {
        /* Have to use a temp. */
        if (!pvec->temp) {
            /* Have to reallocate to reorder. */
            pvec->temp = pvector_impl_dup(old);
            old = pvec->temp;
            /* Publish will sort. */
        }
    }
    old->vector[index].priority = priority;
}

/*******************************************************************************
 函数名称  :  pvector_publish__
 功能描述  :  pmd发送端口的报文
 输入参数  :  
 			  
 输出参数  :  
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Make the modified pvector available for iteration. */
void pvector_publish__(struct pvector *pvec)
{
    struct pvector_impl *temp = pvec->temp;

    pvec->temp = NULL;

	/**/
    pvector_impl_sort(temp); /* Also removes gaps. */

	ovsrcu_postpone(free, ovsrcu_get_protected(struct pvector_impl *,  &pvec->impl));

	/*设置temp*/
	ovsrcu_set(&pvec->impl, temp);
}
