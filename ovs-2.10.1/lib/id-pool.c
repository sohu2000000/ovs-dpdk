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

/*ID�ڵ�*/
struct id_node {
    struct hmap_node node;
    uint32_t id;					/*IDֵ*/
};

/*id��*/
struct id_pool {
    struct hmap map;
    uint32_t base;         /* IDs in the range of [base, base + n_ids). */			/*id��Сֵ*/
    uint32_t n_ids;        /* Total number of ids in the pool. */					/*id ����*/
    uint32_t next_free_id; /* Possible next free id. */								/*��һ������id*/
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
 ��������  :  id_pool_find
 ��������  :  �ҵ������ҵ�ID��Ӧ�ڵ�
 �������  :  pool---id�ڵ��
 			  id---��һ�����е�ID
 			  
 �������  :  
 �� �� ֵ  : id_node---id��Ӧ�Ľڵ�
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static struct id_node *
id_pool_find(struct id_pool *pool, uint32_t id)
{
    size_t hash;
    struct id_node *id_node;

	/*id���ϣ*/
    hash = hash_int(id, 0);

	/*�ҵ������ҵ�ID��Ӧ�ڵ�*/
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
 ��������  :  id_pool_add
 ��������  :  id����id��
 �������  :  pool---id��
 			  id---Ҫ��ӵ�id
 			  
 �������  :  
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
void
id_pool_add(struct id_pool *pool, uint32_t id)
{
	/*����һ��id�ڵ�*/
    struct id_node *id_node = xmalloc(sizeof *id_node);
    size_t hash;

	/*��ֵidֵ*/
    id_node->id = id;

	/*����id���ϣ*/
    hash = hash_int(id, 0);

	/*����*/
    hmap_insert(&pool->map, &id_node->node, hash);
}

/*******************************************************************************
 ��������  :    id_pool_alloc_id
 ��������  :    id����ؿ���id
 �������  :  	pool---����ID��
 				id_---�������뵽�ķ��Ͷ���ID
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
bool
id_pool_alloc_id(struct id_pool *pool, uint32_t *id_)
{
    uint32_t id;

	/*id ��Ϊ��*/
    if (pool->n_ids == 0) 
	{
        return false;
    }

	/*idû�ж�Ӧ�ڵ㣬����id free*/
    if (!(id_pool_find(pool, pool->next_free_id))) 
	{
        id = pool->next_free_id;
        goto found_free_id;
    }

    for(id = pool->base; id < pool->base + pool->n_ids; id++) 
	{
		/*����û�нڵ��id*/
        if (!id_pool_find(pool, id)) 
		{
            goto found_free_id;
        }
    }

    /* Not available. */
    return false;

found_free_id:

	/*id����id�أ�hmap*/
    id_pool_add(pool, id);

	/*���¿���idֵΪ��ǰid+1*/
    if (id + 1 < pool->base + pool->n_ids) 
	{
        pool->next_free_id = id + 1;
    }
	else 
	{
		/*����id��Ϊbaseֵ*/
        pool->next_free_id = pool->base;
    }

	/*Ҫʹ�õ�idΪ��ǰid*/
    *id_ = id;
	
    return true;
}

/*******************************************************************************
 ��������  :  id_pool_free_id
 ��������  :  �ͷŷ�����id
 �������  :  
 			  
 �������  :  
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
void
id_pool_free_id(struct id_pool *pool, uint32_t id)
{
    struct id_node *id_node;

	/*idֵ�Ϸ�*/
    if (id >= pool->base && (id < pool->base + pool->n_ids)) 
	{
		/*�Ҷ�Ӧ��id �ڵ�*/
        id_node = id_pool_find(pool, id);
        if (id_node) 
		{
			/*��hmapɾ��id�ڵ�*/
            hmap_remove(&pool->map, &id_node->node);

			/*Ҫ�ͷŵ�id*/
            if (id < pool->next_free_id) 
			{
                pool->next_free_id = id;
            }

			/*�ͷŽڵ��ڴ�*/
            free(id_node);
        }
    }
}
