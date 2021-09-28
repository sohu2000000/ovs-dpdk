/*
 * Copyright (c) 2014 Nicira, Inc.
 * Copyright (c) 2014 Netronome.
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
#include "id-pool.h"
#include "openvswitch/hmap.h"
#include "hash.h"

/*ID节点*/
struct id_node {
    struct hmap_node node;
    uint32_t id;					/*ID值*/
};

/*id池*/
struct id_pool {
    struct hmap map;
    uint32_t base;         /* IDs in the range of [base, base + n_ids). */			/*id最小值*/
    uint32_t n_ids;        /* Total number of ids in the pool. */					/*id 总数*/
    uint32_t next_free_id; /* Possible next free id. */								/*下一个空闲id*/
};

static void id_pool_init(struct id_pool *pool,
                         uint32_t base, uint32_t n_ids);
static void id_pool_uninit(struct id_pool *pool);
static struct id_node *id_pool_find(struct id_pool *pool, uint32_t id);

struct id_pool *
id_pool_create(uint32_t base, uint32_t n_ids)
{
    struct id_pool *pool;

    pool = xmalloc(sizeof *pool);
    id_pool_init(pool, base, n_ids);

    return pool;
}

void
id_pool_destroy(struct id_pool *pool)
{
    if (pool) {
        id_pool_uninit(pool);
        free(pool);
    }
}

static void
id_pool_init(struct id_pool *pool, uint32_t base, uint32_t n_ids)
{
    pool->base = base;
    pool->n_ids = n_ids;
    pool->next_free_id = base;
    hmap_init(&pool->map);
}

static void
id_pool_uninit(struct id_pool *pool)
{
    struct id_node *id_node;

    HMAP_FOR_EACH_POP(id_node, node, &pool->map) {
        free(id_node);
    }

    hmap_destroy(&pool->map);
}

/*******************************************************************************
 函数名称  :  id_pool_find
 功能描述  :  找到链表找到ID对应节点
 输入参数  :  pool---id节点池
 			  id---下一个空闲的ID
 			  
 输出参数  :  
 返 回 值  : id_node---id对应的节点
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static struct id_node *
id_pool_find(struct id_pool *pool, uint32_t id)
{
    size_t hash;
    struct id_node *id_node;

	/*id算哈希*/
    hash = hash_int(id, 0);

	/*找到链表找到ID对应节点*/
    HMAP_FOR_EACH_WITH_HASH(id_node, node, hash, &pool->map) 
    {
        if (id == id_node->id) 
		{
            return id_node;
        }
    }
    return NULL;
}

/*******************************************************************************
 函数名称  :  id_pool_add
 功能描述  :  id插入id池
 输入参数  :  pool---id池
 			  id---要添加的id
 			  
 输出参数  :  
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
void
id_pool_add(struct id_pool *pool, uint32_t id)
{
	/*申请一个id节点*/
    struct id_node *id_node = xmalloc(sizeof *id_node);
    size_t hash;

	/*赋值id值*/
    id_node->id = id;

	/*根据id算哈希*/
    hash = hash_int(id, 0);

	/*插入*/
    hmap_insert(&pool->map, &id_node->node, hash);
}

/*******************************************************************************
 函数名称  :    id_pool_alloc_id
 功能描述  :    id申请池空闲id
 输入参数  :  	pool---队列ID池
 				id_---接收申请到的发送队列ID
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
bool
id_pool_alloc_id(struct id_pool *pool, uint32_t *id_)
{
    uint32_t id;

	/*id 池为空*/
    if (pool->n_ids == 0) 
	{
        return false;
    }

	/*id没有对应节点，代表id free*/
    if (!(id_pool_find(pool, pool->next_free_id))) 
	{
        id = pool->next_free_id;
        goto found_free_id;
    }

    for(id = pool->base; id < pool->base + pool->n_ids; id++) 
	{
		/*存在没有节点的id*/
        if (!id_pool_find(pool, id)) 
		{
            goto found_free_id;
        }
    }

    /* Not available. */
    return false;

found_free_id:

	/*id插入id池，hmap*/
    id_pool_add(pool, id);

	/*更新空闲id值为当前id+1*/
    if (id + 1 < pool->base + pool->n_ids) 
	{
        pool->next_free_id = id + 1;
    }
	else 
	{
		/*否则id置为base值*/
        pool->next_free_id = pool->base;
    }

	/*要使用的id为当前id*/
    *id_ = id;
	
    return true;
}

/*******************************************************************************
 函数名称  :  id_pool_free_id
 功能描述  :  释放发队列id
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
id_pool_free_id(struct id_pool *pool, uint32_t id)
{
    struct id_node *id_node;

	/*id值合法*/
    if (id >= pool->base && (id < pool->base + pool->n_ids)) 
	{
		/*找对应的id 节点*/
        id_node = id_pool_find(pool, id);
        if (id_node) 
		{
			/*从hmap删掉id节点*/
            hmap_remove(&pool->map, &id_node->node);

			/*要释放的id*/
            if (id < pool->next_free_id) 
			{
                pool->next_free_id = id;
            }

			/*释放节点内存*/
            free(id_node);
        }
    }
}
