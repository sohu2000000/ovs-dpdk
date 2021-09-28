/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FLEX_ARRAY_H
#define _FLEX_ARRAY_H

#include <linux/types.h>
#include <linux/reciprocal_div.h>
#include <asm/page.h>

#define FLEX_ARRAY_PART_SIZE PAGE_SIZE
#define FLEX_ARRAY_BASE_SIZE PAGE_SIZE

struct flex_array_part;

/*
 * This is meant to replace cases where an array-like
 * structure has gotten too big to fit into kmalloc()
 * and the developer is getting tempted to use
 * vmalloc().
 */

/*流表的hash头结点,弹性数组，共1页内存，不够可多页内存*/
struct flex_array {

	/*共用体的大小为FLEX_ARRAY_BASE_SIZE（即是一个页的大小：4096）*/
	union {

		/**/
		struct {
			int element_size;								//每个元素大小
			int total_nr_elements;							// 这是数组元素的总个数
			int elems_per_part;							    // 每个part包含的元素个数
			struct reciprocal_value reciprocal_elems;
			struct flex_array_part *parts[];                // 结构体指针数组，里面存放的是struct flex_array_part结构的指针，多个分页内存
		};
		/*
		 * This little trick makes sure that
		 * sizeof(flex_array) == PAGE_SIZE
		 */
		char padding[FLEX_ARRAY_BASE_SIZE];                 /*一页4096字节*/
	};
};

/* Number of bytes left in base struct flex_array, excluding metadata */
#define FLEX_ARRAY_BASE_BYTES_LEFT					\
	(FLEX_ARRAY_BASE_SIZE - offsetof(struct flex_array, parts))

/* Number of pointers in base to struct flex_array_part pages */
#define FLEX_ARRAY_NR_BASE_PTRS						\
	(FLEX_ARRAY_BASE_BYTES_LEFT / sizeof(struct flex_array_part *))

/* Number of elements of size that fit in struct flex_array_part */
#define FLEX_ARRAY_ELEMENTS_PER_PART(size)				\
	(FLEX_ARRAY_PART_SIZE / size)

/*
 * Defines a statically allocated flex array and ensures its parameters are
 * valid.
 */
#define DEFINE_FLEX_ARRAY(__arrayname, __element_size, __total)		\
	struct flex_array __arrayname = { { {				\
		.element_size = (__element_size),			\
		.total_nr_elements = (__total),				\
	} } };								\
	static inline void __arrayname##_invalid_parameter(void)	\
	{								\
		BUILD_BUG_ON((__total) > FLEX_ARRAY_NR_BASE_PTRS *	\
			FLEX_ARRAY_ELEMENTS_PER_PART(__element_size));	\
	}

/**
 * flex_array_alloc() - Creates a flexible array.
 * @element_size:	individual object size.
 * @total:		maximum number of objects which can be stored.
 * @flags:		GFP flags
 *
 * Return:		Returns an object of structure flex_array.
 */
struct flex_array *flex_array_alloc(int element_size, unsigned int total,
		gfp_t flags);

/**
 * flex_array_prealloc() - Ensures that memory for the elements indexed in the
 * range defined by start and nr_elements has been allocated.
 * @fa:			array to allocate memory to.
 * @start:		start address
 * @nr_elements:	number of elements to be allocated.
 * @flags:		GFP flags
 *
 */
int flex_array_prealloc(struct flex_array *fa, unsigned int start,
		unsigned int nr_elements, gfp_t flags);

/**
 * flex_array_free() - Removes all elements of a flexible array.
 * @fa:		array to be freed.
 */
void flex_array_free(struct flex_array *fa);

/**
 * flex_array_free_parts() - Removes all elements of a flexible array, but
 * leaves the array itself in place.
 * @fa:		array to be emptied.
 */
void flex_array_free_parts(struct flex_array *fa);

/**
 * flex_array_put() - Stores data into a flexible array.
 * @fa:		array where element is to be stored.
 * @element_nr:	position to copy, must be less than the maximum specified when
 *		the array was created.
 * @src:	data source to be copied into the array.
 * @flags:	GFP flags
 *
 * Return:	Returns zero on success, a negative error code otherwise.
 */
int flex_array_put(struct flex_array *fa, unsigned int element_nr, void *src,
		gfp_t flags);

/**
 * flex_array_clear() - Clears an individual element in the array, sets the
 * given element to FLEX_ARRAY_FREE.
 * @element_nr:	element position to clear.
 * @fa:		array to which element to be cleared belongs.
 *
 * Return:	Returns zero on success, -EINVAL otherwise.
 */
int flex_array_clear(struct flex_array *fa, unsigned int element_nr);

/**
 * flex_array_get() - Retrieves data into a flexible array.
 *
 * @element_nr:	Element position to retrieve data from.
 * @fa:		array from which data is to be retrieved.
 *
 * Return:	Returns a pointer to the data element, or NULL if that
 *		particular element has never been allocated.
 */


/*******************************************************************************
 函数名称  :	masked_flow_lookup
 功能描述  :	mask链的流查询
 输入参数  :	fa---ti->buckets 哈希桶头
				element_nr---hash & (ti->n_buckets - 1) 定位到哈希桶buckets位置
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
void *flex_array_get(struct flex_array *fa, unsigned int element_nr);

/**
 * flex_array_shrink() - Reduces the allocated size of an array.
 * @fa:		array to shrink.
 *
 * Return:	Returns number of pages of memory actually freed.
 *
 */
int flex_array_shrink(struct flex_array *fa);

#define flex_array_put_ptr(fa, nr, src, gfp) \
	flex_array_put(fa, nr, (void *)&(src), gfp)

void *flex_array_get_ptr(struct flex_array *fa, unsigned int element_nr);

#endif /* _FLEX_ARRAY_H */
