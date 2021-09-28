/*
 * Copyright (c) 2007-2013 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#include "flow.h"
#include "datapath.h"
#include <linux/uaccess.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <net/llc_pdu.h>
#include <linux/kernel.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/llc.h>
#include <linux/module.h>
#include <linux/in.h>
#include <linux/rcupdate.h>
#include <linux/cpumask.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/sctp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/rculist.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ndisc.h>

#include "flow_netlink.h"

#define TBL_MIN_BUCKETS		1024
#define MASK_ARRAY_SIZE_MIN	16
#define REHASH_INTERVAL		(10 * 60 * HZ)

#define MC_HASH_SHIFT		8
#define MC_HASH_ENTRIES		(1u << MC_HASH_SHIFT)    /*256*/
#define MC_HASH_SEGS		((sizeof(uint32_t) * 8) / MC_HASH_SHIFT)

/*流信息内存*/
static struct kmem_cache *flow_cache;

/*流统计内存*/
struct kmem_cache *flow_stats_cache __read_mostly;

static u16 range_n_bytes(const struct sw_flow_key_range *range)
{
	return range->end - range->start;
}


/*******************************************************************************
 函数名称  :	masked_flow_lookup
 功能描述  :	skb key与mask的key取与算出masked_key, &mask->range范围
 输入参数  :	
				dst---skb的key与掩码key取与后的masked_key结果
				src---skb的key
				ti---流表实例
				unmasked---skb的key
				full---false
				mask---table中的链节点，流表掩码结构体sw_flow_mask
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
void ovs_flow_mask_key(struct sw_flow_key *dst, const struct sw_flow_key *src,
		       bool full, const struct sw_flow_mask *mask)
{
	/*掩码key起始位置*/
	int start = full ? 0 : mask->range.start;
	/*掩码key长度*/
	int len = full ? sizeof *dst : range_n_bytes(&mask->range);

	/*掩码key*/
	const long *m = (const long *)((const u8 *)&mask->key + start);

	/*报文匹配key起始*/
	const long *s = (const long *)((const u8 *)src + start);

	/*匹配出的key*/
	long *d = (long *)((u8 *)dst + start);
	int i;

	/* If 'full' is true then all of 'dst' is fully initialized. Otherwise,
	 * if 'full' is false the memory outside of the 'mask->range' is left
	 * uninitialized. This can be used as an optimization when further
	 * operations on 'dst' only use contents within 'mask->range'.
	 */

	/*skb key与mask的key取与算出maskeed_key*/
	for (i = 0; i < len; i += sizeof(long))
	{
		*d++ = *s++ & *m++;
	}
}

struct sw_flow *ovs_flow_alloc(void)
{
	struct sw_flow *flow;
	struct flow_stats *stats;

	flow = kmem_cache_zalloc(flow_cache, GFP_KERNEL);
	if (!flow)
		return ERR_PTR(-ENOMEM);

	flow->stats_last_writer = -1;

	/* Initialize the default stat node. */
	stats = kmem_cache_alloc_node(flow_stats_cache,
				      GFP_KERNEL | __GFP_ZERO,
				      node_online(0) ? 0 : NUMA_NO_NODE);
	if (!stats)
		goto err;

	spin_lock_init(&stats->lock);

	RCU_INIT_POINTER(flow->stats[0], stats);

	cpumask_set_cpu(0, &flow->cpu_used_mask);

	return flow;
err:
	kmem_cache_free(flow_cache, flow);
	return ERR_PTR(-ENOMEM);
}

int ovs_flow_tbl_count(const struct flow_table *table)
{
	return table->count;
}

/*******************************************************************************
 函数名称  :	alloc_buckets
 功能描述  :	桶申请
 输入参数  :	new_size--1024个桶
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static struct flex_array *alloc_buckets(unsigned int n_buckets)
{
	struct flex_array *buckets;
	int i, err;

	/*桶申请*/
	buckets = flex_array_alloc(sizeof(struct hlist_head),
				   n_buckets, GFP_KERNEL);
	if (!buckets)
		return NULL;

	err = flex_array_prealloc(buckets, 0, n_buckets, GFP_KERNEL);
	if (err) {
		flex_array_free(buckets);
		return NULL;
	}

	/*桶初始化*/
	for (i = 0; i < n_buckets; i++)
		INIT_HLIST_HEAD((struct hlist_head *)
					flex_array_get(buckets, i));

	return buckets;
}

static void flow_free(struct sw_flow *flow)
{
	int cpu;

	if (ovs_identifier_is_key(&flow->id))
		kfree(flow->id.unmasked_key);
	if (flow->sf_acts)
		ovs_nla_free_flow_actions((struct sw_flow_actions __force *)flow->sf_acts);
	/* We open code this to make sure cpu 0 is always considered */
	for (cpu = 0; cpu < nr_cpu_ids; cpu = cpumask_next(cpu, &flow->cpu_used_mask))
		if (flow->stats[cpu])
			kmem_cache_free(flow_stats_cache,
					rcu_dereference_raw(flow->stats[cpu]));
	kmem_cache_free(flow_cache, flow);
}

static void rcu_free_flow_callback(struct rcu_head *rcu)
{
	struct sw_flow *flow = container_of(rcu, struct sw_flow, rcu);

	flow_free(flow);
}

void ovs_flow_free(struct sw_flow *flow, bool deferred)
{
	if (!flow)
		return;

	if (deferred)
		call_rcu(&flow->rcu, rcu_free_flow_callback);
	else
		flow_free(flow);
}

static void free_buckets(struct flex_array *buckets)
{
	flex_array_free(buckets);
}


static void __table_instance_destroy(struct table_instance *ti)
{
	free_buckets(ti->buckets);
	kfree(ti);
}

/*******************************************************************************
 函数名称  :	ovs_flow_tbl_init
 功能描述  :	流表申请
 输入参数  :	new_size--1024个桶
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static struct table_instance *table_instance_alloc(int new_size)
{
	/*流表实例*/
	struct table_instance *ti = kmalloc(sizeof(*ti), GFP_KERNEL);
	if (!ti)
		return NULL;

	/*1024个桶申请*/
	ti->buckets = alloc_buckets(new_size);

	if (!ti->buckets) {
		kfree(ti);
		return NULL;
	}
	
	ti->n_buckets = new_size;
	ti->node_ver = 0;
	ti->keep_flows = false;
	get_random_bytes(&ti->hash_seed, sizeof(u32));

	return ti;
}

static void mask_array_rcu_cb(struct rcu_head *rcu)
{
	struct mask_array *ma = container_of(rcu, struct mask_array, rcu);

	kfree(ma);
}

/*******************************************************************************
 函数名称  :	tbl_mask_array_alloc
 功能描述  :	掩码数组申请结构头 + 16个指针
 输入参数  :    table--网桥流表指针
 				size---结构个数16
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static struct mask_array *tbl_mask_array_alloc(int size)
{
	struct mask_array *new;

	/*16个网桥掩码结构申请*/
	size = max(MASK_ARRAY_SIZE_MIN, size);

	/*掩码数组结构+16个掩码指针*/
	new = kzalloc(sizeof(struct mask_array) + sizeof(struct sw_flow_mask *) * size, GFP_KERNEL);
	if (!new)
		return NULL;

	new->count = 0;
	new->max = size;

	return new;
}

static int tbl_mask_array_realloc(struct flow_table *tbl, int size)
{
	struct mask_array *old;
	struct mask_array *new;

	new = tbl_mask_array_alloc(size);
	if (!new)
		return -ENOMEM;

	old = ovsl_dereference(tbl->mask_array);
	if (old) {
		int i, count = 0;

		for (i = 0; i < old->max; i++) {
			if (ovsl_dereference(old->masks[i]))
				new->masks[count++] = old->masks[i];
		}

		new->count = count;
	}
	rcu_assign_pointer(tbl->mask_array, new);

	if (old)
		call_rcu(&old->rcu, mask_array_rcu_cb);

	return 0;
}

/*******************************************************************************
 函数名称  :	ovs_flow_tbl_init
 功能描述  :	流表申请
 输入参数  :    table--网桥流表指针
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
int ovs_flow_tbl_init(struct flow_table *table)
{
	struct table_instance *ti, *ufid_ti;
	struct mask_array *ma;

	/*每CPU256张掩码申请*/
	table->mask_cache = __alloc_percpu(sizeof(struct mask_cache_entry) * MC_HASH_ENTRIES, __alignof__(struct mask_cache_entry));
	if (!table->mask_cache)
		return -ENOMEM;

	/*16个网桥掩码结构申请*/
	ma = tbl_mask_array_alloc(MASK_ARRAY_SIZE_MIN);
	if (!ma)
		goto free_mask_cache;

	/*申请流表实例 1024个桶*/
	ti = table_instance_alloc(TBL_MIN_BUCKETS);
	if (!ti)
		goto free_mask_array;

	/*1024个流表*/
	ufid_ti = table_instance_alloc(TBL_MIN_BUCKETS);
	if (!ufid_ti)
		goto free_ti;

	/*流表指针记录*/
	rcu_assign_pointer(table->ti, ti);
	rcu_assign_pointer(table->ufid_ti, ufid_ti);
	rcu_assign_pointer(table->mask_array, ma);

	table->last_rehash = jiffies;
	table->count = 0;
	table->ufid_count = 0;
	return 0;

free_ti:
	__table_instance_destroy(ti);
free_mask_array:
	kfree(ma);
free_mask_cache:
	free_percpu(table->mask_cache);
	return -ENOMEM;
}

static void flow_tbl_destroy_rcu_cb(struct rcu_head *rcu)
{
	struct table_instance *ti = container_of(rcu, struct table_instance, rcu);

	__table_instance_destroy(ti);
}

static void table_instance_destroy(struct table_instance *ti,
				   struct table_instance *ufid_ti,
				   bool deferred)
{
	int i;

	if (!ti)
		return;

	BUG_ON(!ufid_ti);
	if (ti->keep_flows)
		goto skip_flows;

	for (i = 0; i < ti->n_buckets; i++) {
		struct sw_flow *flow;
		struct hlist_head *head = flex_array_get(ti->buckets, i);
		struct hlist_node *n;
		int ver = ti->node_ver;
		int ufid_ver = ufid_ti->node_ver;

		hlist_for_each_entry_safe(flow, n, head, flow_table.node[ver]) {
			hlist_del_rcu(&flow->flow_table.node[ver]);
			if (ovs_identifier_is_ufid(&flow->id))
				hlist_del_rcu(&flow->ufid_table.node[ufid_ver]);
			ovs_flow_free(flow, deferred);
		}
	}

skip_flows:
	if (deferred) {
		call_rcu(&ti->rcu, flow_tbl_destroy_rcu_cb);
		call_rcu(&ufid_ti->rcu, flow_tbl_destroy_rcu_cb);
	} else {
		__table_instance_destroy(ti);
		__table_instance_destroy(ufid_ti);
	}
}

/* No need for locking this function is called from RCU callback or
 * error path.
 */
void ovs_flow_tbl_destroy(struct flow_table *table)
{
	struct table_instance *ti = rcu_dereference_raw(table->ti);
	struct table_instance *ufid_ti = rcu_dereference_raw(table->ufid_ti);

	free_percpu(table->mask_cache);
	kfree(rcu_dereference_raw(table->mask_array));
	table_instance_destroy(ti, ufid_ti, false);
}

struct sw_flow *ovs_flow_tbl_dump_next(struct table_instance *ti,
				       u32 *bucket, u32 *last)
{
	struct sw_flow *flow;
	struct hlist_head *head;
	int ver;
	int i;

	ver = ti->node_ver;
	while (*bucket < ti->n_buckets) {
		i = 0;
		head = flex_array_get(ti->buckets, *bucket);
		hlist_for_each_entry_rcu(flow, head, flow_table.node[ver]) {
			if (i < *last) {
				i++;
				continue;
			}
			*last = i + 1;
			return flow;
		}
		(*bucket)++;
		*last = 0;
	}

	return NULL;
}

/*******************************************************************************
 函数名称  :	find_bucket
 功能描述  :	查找哈希桶
 输入参数  :	fa---ti->buckets 哈希桶头
				element_nr---hash & (ti->n_buckets - 1) 定位到哈希桶buckets位置
 输出参数  :	bucket哈希桶
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static struct hlist_head *find_bucket(struct table_instance *ti, u32 hash)
{
	/*hash关键字hash_1word()算新哈希*/
	hash = jhash_1word(hash, ti->hash_seed);

	/*哈希关键字传入flex_array_get()命中返回哈希桶bucket*/
	return flex_array_get(ti->buckets,(hash & (ti->n_buckets - 1)));
}

static void table_instance_insert(struct table_instance *ti,
				  struct sw_flow *flow)
{
	struct hlist_head *head;

	head = find_bucket(ti, flow->flow_table.hash);
	hlist_add_head_rcu(&flow->flow_table.node[ti->node_ver], head);
}

static void ufid_table_instance_insert(struct table_instance *ti,
				       struct sw_flow *flow)
{
	struct hlist_head *head;

	head = find_bucket(ti, flow->ufid_table.hash);
	hlist_add_head_rcu(&flow->ufid_table.node[ti->node_ver], head);
}

static void flow_table_copy_flows(struct table_instance *old,
				  struct table_instance *new, bool ufid)
{
	int old_ver;
	int i;

	old_ver = old->node_ver;
	new->node_ver = !old_ver;

	/* Insert in new table. */
	for (i = 0; i < old->n_buckets; i++) {
		struct sw_flow *flow;
		struct hlist_head *head;

		head = flex_array_get(old->buckets, i);

		if (ufid)
			hlist_for_each_entry(flow, head,
					     ufid_table.node[old_ver])
				ufid_table_instance_insert(new, flow);
		else
			hlist_for_each_entry(flow, head,
					     flow_table.node[old_ver])
				table_instance_insert(new, flow);
	}

	old->keep_flows = true;
}

static struct table_instance *table_instance_rehash(struct table_instance *ti,
						    int n_buckets, bool ufid)
{
	struct table_instance *new_ti;

	new_ti = table_instance_alloc(n_buckets);
	if (!new_ti)
		return NULL;

	flow_table_copy_flows(ti, new_ti, ufid);

	return new_ti;
}

int ovs_flow_tbl_flush(struct flow_table *flow_table)
{
	struct table_instance *old_ti, *new_ti;
	struct table_instance *old_ufid_ti, *new_ufid_ti;

	new_ti = table_instance_alloc(TBL_MIN_BUCKETS);
	if (!new_ti)
		return -ENOMEM;
	new_ufid_ti = table_instance_alloc(TBL_MIN_BUCKETS);
	if (!new_ufid_ti)
		goto err_free_ti;

	old_ti = ovsl_dereference(flow_table->ti);
	old_ufid_ti = ovsl_dereference(flow_table->ufid_ti);

	rcu_assign_pointer(flow_table->ti, new_ti);
	rcu_assign_pointer(flow_table->ufid_ti, new_ufid_ti);
	flow_table->last_rehash = jiffies;
	flow_table->count = 0;
	flow_table->ufid_count = 0;

	table_instance_destroy(old_ti, old_ufid_ti, true);
	return 0;

err_free_ti:
	__table_instance_destroy(new_ti);
	return -ENOMEM;
}

static u32 flow_hash(const struct sw_flow_key *key,
		     const struct sw_flow_key_range *range)
{
	int key_start = range->start;
	int key_end = range->end;
	const u32 *hash_key = (const u32 *)((const u8 *)key + key_start);
	int hash_u32s = (key_end - key_start) >> 2;

	/* Make sure number of hash bytes are multiple of u32. */
	BUILD_BUG_ON(sizeof(long) % sizeof(u32));

	return jhash2(hash_key, hash_u32s, 0);
}

static int flow_key_start(const struct sw_flow_key *key)
{
	if (key->tun_proto)
		return 0;
	else
		return rounddown(offsetof(struct sw_flow_key, phy),
					  sizeof(long));
}


/*******************************************************************************
 函数名称  :	cmp_key
 功能描述  :	对比是否精确命中流表项的key，range->start-range->end存在一个位不同则置1
 输入参数  :	key1---流表项的key
 输出参数  :	key2---masked_key
 				range->start, range->end
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static bool cmp_key(const struct sw_flow_key *key1,
		    const struct sw_flow_key *key2,
		    int key_start, int key_end)
{
	const long *cp1 = (const long *)((const u8 *)key1 + key_start);
	const long *cp2 = (const long *)((const u8 *)key2 + key_start);
	long diffs = 0;
	int i;

	/*对比是否精确匹配*/
	for (i = key_start; i < key_end;  i += sizeof(long))
	{

		/*存在一个位不同则置1*/
		diffs |= *cp1++ ^ *cp2++;
	}
	
	return diffs == 0;
}

/*******************************************************************************
 函数名称  :	flow_cmp_masked_key
 功能描述  :	对比masked_key是否精确命中流表项的key，range->start-range->end存在一个位不同则置1
 输入参数  :	tbl---网桥流表
 输出参数  :	flow---流表项，遍历bucket哈希桶上流表项
 				key---数据包key与mask key 取与生成masked_key
 				range---key范围
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static bool flow_cmp_masked_key(const struct sw_flow *flow,
				const struct sw_flow_key *key,
				const struct sw_flow_key_range *range)
{
	return cmp_key(&flow->key, key, range->start, range->end);
}

static bool ovs_flow_cmp_unmasked_key(const struct sw_flow *flow,
				      const struct sw_flow_match *match)
{
	struct sw_flow_key *key = match->key;
	int key_start = flow_key_start(key);
	int key_end = match->range.end;

	BUG_ON(ovs_identifier_is_ufid(&flow->id));
	return cmp_key(flow->id.unmasked_key, key, key_start, key_end);
}

/*******************************************************************************
 函数名称  :	masked_flow_lookup
 功能描述  :	mask链的流查询
 输入参数  :	tbl---网桥流表
				ti---流表实例
				mask---table中的链节点，流表掩码结构体sw_flow_mask，链表节点
				unmasked---skb的key
				n_mask_hit---0
 输出参数  :	flow---命中的流表项
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static struct sw_flow *masked_flow_lookup(struct table_instance *ti,
					  const struct sw_flow_key *unmasked,
					  const struct sw_flow_mask *mask,
					  u32 *n_mask_hit)
{
	struct sw_flow *flow;
	struct hlist_head *head;// 哈希表头结点
	u32 hash;
	struct sw_flow_key masked_key;

	/*数据包key与mask key 取与生成masked_key*/
	ovs_flow_mask_key(&masked_key, unmasked, false, mask);

	/*masked_key算jhash2()哈希*/
	hash = flow_hash(&masked_key, &mask->range);

	/*根据哈希值命中bucket哈希桶，返回bucket 哈希桶*/
	head = find_bucket(ti, hash);

	/*掩码命中计数*/
	(*n_mask_hit)++;

	/*遍历bucket哈希桶上流表项，对比mask key，查找流表项，命中返回流表项*/
	hlist_for_each_entry_rcu(flow, head, flow_table.node[ti->node_ver]) 
	{
		/*maske命中 且 哈希命中 且 对比masked_key相等*/
		if (flow->mask == mask && flow->flow_table.hash == hash &&
		    flow_cmp_masked_key(flow, &masked_key, &mask->range))
		{
			// 上面的flow是流表项，masked_key是与操作后的key值
			return flow;
		}
	}
	
	return NULL;
}

/* Flow lookup does full lookup on flow table. It starts with
 * mask from index passed in *index.
 */

/*******************************************************************************
 函数名称  :	flow_lookup
 功能描述  :	流表查询
 输入参数  :    tbl---网桥流表
 				ti---流表实例
 				ma--流表掩码数组
 				key---报文key值
 				n_mask_hit---0
 				index---0
 输出参数  :	flow---命中的流表项
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static struct sw_flow *flow_lookup(struct flow_table *tbl,
				   struct table_instance *ti,
				   const struct mask_array *ma,
				   const struct sw_flow_key *key,
				   u32 *n_mask_hit,
				   u32 *index)
{
	struct sw_flow_mask *mask;
	struct sw_flow *flow;
	int i;

	/*查询mask链*/
	/*如果index的值小于mask的entry数量，说明index是有效值，基于该值获取sw_flow_mask值*/
	if (*index < ma->max) 
	{
		/*根据index获取流表掩码结构体*/
		mask = rcu_dereference_ovsl(ma->masks[*index]);
		if (mask)
		{
			/*流表查询，&mask->range key 精确匹配*/
			flow = masked_flow_lookup(ti, key, mask, n_mask_hit);
			if (flow)
			{
				return flow;
			}
		}
	}

	for (i = 0; i < ma->max; i++)  
	{
		//前面已查询过，所以跳过该mask
		if (i == *index)
		{
			continue;
		}
		
		mask = rcu_dereference_ovsl(ma->masks[i]);
		if (!mask)
		{
			continue;
		}

		/*掩码链查询*/
		flow = masked_flow_lookup(ti, key, mask, n_mask_hit);
		if (flow)
		{ /* Found */
			//更新index指向的值，下次可以直接命中；此处说明cache没有命中，下一次可以直接命中 
			*index = i;
			return flow;
		}
	}

	return NULL;
}

/*
 * mask_cache maps flow to probable mask. This cache is not tightly
 * coupled cache, It means updates to  mask list can result in inconsistent
 * cache entry in mask cache.
 * This is per cpu cache and is divided in MC_HASH_SEGS segments.
 * In case of a hash collision the entry is hashed in next segment.
 */

/*******************************************************************************
 函数名称  :	ovs_flow_tbl_lookup_stats
 功能描述  :	流表查询
 输入参数  :    tbl---dp的流表
 				key---由ovs_flow_key_extract函数根据skb生成提取的报文的key  
 输出参数  :	skb_hash---skb中携带的信息
 返 回 值  :	n_mask_hit---命中流表计数
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
struct sw_flow *ovs_flow_tbl_lookup_stats(struct flow_table *tbl,
					  const struct sw_flow_key *key, u32 skb_hash, u32 *n_mask_hit)
{
	/*链表掩码数组，一个网桥一个，缓存key*/
	struct mask_array *ma = rcu_dereference(tbl->mask_array);

	/*得到table实例*/
	struct table_instance *ti = rcu_dereference(tbl->ti);
	struct mask_cache_entry *entries, *ce;
	struct sw_flow *flow;
	u32 hash;
	int seg;

	*n_mask_hit = 0;

	//如果报文没有hash值，则mask_index为0，全遍历所有的mask
	if (unlikely(!skb_hash)) 
	{
		u32 mask_index = 0;

		/*查询流表*/
		return flow_lookup(tbl, ti, ma, key, n_mask_hit, &mask_index);
	}

	/* Pre and post recirulation flows usually have the same skb_hash
	 * value. To avoid hash collisions, rehash the 'skb_hash' with
	 * 'recirc_id'.  */
	if (key->recirc_id)
	{
		skb_hash = jhash_1word(skb_hash, key->recirc_id);
	}
	
	ce = NULL;
	hash = skb_hash;
	entries = this_cpu_ptr(tbl->mask_cache);

	/* Find the cache entry 'ce' to operate on. */

	//32位的hash值被分成4段，每段8字节，作为cache的索引  
	for (seg = 0; seg < MC_HASH_SEGS; seg++)
	{
		int index = hash & (MC_HASH_ENTRIES - 1);
		struct mask_cache_entry *e;

		//entry最大为256项  
		e = &entries[index];

		//如果在cache entry找到报文hash相同项，则根据该entry指定的mask查表 
		if (e->skb_hash == skb_hash) 
		{
			//没有命中，ce作为新的cache项，将被刷新，下一次可以直接命中  
			flow = flow_lookup(tbl, ti, ma, key, n_mask_hit, &e->mask_index);
			if (!flow)
				e->skb_hash = 0;
			return flow;
		}

		if (!ce || e->skb_hash < ce->skb_hash)
			ce = e;  /* A better replacement cache candidate. */

		hash >>= MC_HASH_SHIFT;
	}

	/* Cache miss, do full lookup. */

	/*全流表查询*/
	flow = flow_lookup(tbl, ti, ma, key, n_mask_hit, &ce->mask_index);
	if (flow)
	{
		ce->skb_hash = skb_hash;
	}
	
	return flow;
}

struct sw_flow *ovs_flow_tbl_lookup(struct flow_table *tbl,
				    const struct sw_flow_key *key)
{
	struct table_instance *ti = rcu_dereference_ovsl(tbl->ti);
	struct mask_array *ma = rcu_dereference_ovsl(tbl->mask_array);
	u32 __always_unused n_mask_hit;
	u32 index = 0;

	return flow_lookup(tbl, ti, ma, key, &n_mask_hit, &index);
}

struct sw_flow *ovs_flow_tbl_lookup_exact(struct flow_table *tbl,
					  const struct sw_flow_match *match)
{
	struct mask_array *ma = ovsl_dereference(tbl->mask_array);
	int i;

	/* Always called under ovs-mutex. */
	for (i = 0; i < ma->max; i++) {
		struct table_instance *ti = ovsl_dereference(tbl->ti);
		u32 __always_unused n_mask_hit;
		struct sw_flow_mask *mask;
		struct sw_flow *flow;

		mask = ovsl_dereference(ma->masks[i]);
		if (!mask)
			continue;
		flow = masked_flow_lookup(ti, match->key, mask, &n_mask_hit);
		if (flow && ovs_identifier_is_key(&flow->id) &&
		    ovs_flow_cmp_unmasked_key(flow, match))
			return flow;
	}
	return NULL;
}

static u32 ufid_hash(const struct sw_flow_id *sfid)
{
	return jhash(sfid->ufid, sfid->ufid_len, 0);
}

static bool ovs_flow_cmp_ufid(const struct sw_flow *flow,
			      const struct sw_flow_id *sfid)
{
	if (flow->id.ufid_len != sfid->ufid_len)
		return false;

	return !memcmp(flow->id.ufid, sfid->ufid, sfid->ufid_len);
}

bool ovs_flow_cmp(const struct sw_flow *flow, const struct sw_flow_match *match)
{
	if (ovs_identifier_is_ufid(&flow->id))
		return flow_cmp_masked_key(flow, match->key, &match->range);

	return ovs_flow_cmp_unmasked_key(flow, match);
}

struct sw_flow *ovs_flow_tbl_lookup_ufid(struct flow_table *tbl,
					 const struct sw_flow_id *ufid)
{
	struct table_instance *ti = rcu_dereference_ovsl(tbl->ufid_ti);
	struct sw_flow *flow;
	struct hlist_head *head;
	u32 hash;

	hash = ufid_hash(ufid);
	head = find_bucket(ti, hash);
	hlist_for_each_entry_rcu(flow, head, ufid_table.node[ti->node_ver]) {
		if (flow->ufid_table.hash == hash &&
		    ovs_flow_cmp_ufid(flow, ufid))
			return flow;
	}
	return NULL;
}

int ovs_flow_tbl_num_masks(const struct flow_table *table)
{
	struct mask_array *ma;

	ma = rcu_dereference_ovsl(table->mask_array);
	return ma->count;
}

static struct table_instance *table_instance_expand(struct table_instance *ti,
						    bool ufid)
{
	return table_instance_rehash(ti, ti->n_buckets * 2, ufid);
}

static void tbl_mask_array_delete_mask(struct mask_array *ma,
				       struct sw_flow_mask *mask)
{
	int i;

	/* Remove the deleted mask pointers from the array */
	for (i = 0; i < ma->max; i++) {
		if (mask == ovsl_dereference(ma->masks[i])) {
			RCU_INIT_POINTER(ma->masks[i], NULL);
			ma->count--;
			kfree_rcu(mask, rcu);
			return;
		}
	}
	BUG();
}

/* Remove 'mask' from the mask list, if it is not needed any more. */
static void flow_mask_remove(struct flow_table *tbl, struct sw_flow_mask *mask)
{
	if (mask) {
		/* ovs-lock is required to protect mask-refcount and
		 * mask list.
		 */
		ASSERT_OVSL();
		BUG_ON(!mask->ref_count);
		mask->ref_count--;

		if (!mask->ref_count) {
			struct mask_array *ma;

			ma = ovsl_dereference(tbl->mask_array);
			tbl_mask_array_delete_mask(ma, mask);

			/* Shrink the mask array if necessary. */
			if (ma->max >= (MASK_ARRAY_SIZE_MIN * 2) &&
			    ma->count <= (ma->max / 3))
				tbl_mask_array_realloc(tbl, ma->max / 2);

		}
	}
}

/* Must be called with OVS mutex held. */
void ovs_flow_tbl_remove(struct flow_table *table, struct sw_flow *flow)
{
	struct table_instance *ti = ovsl_dereference(table->ti);
	struct table_instance *ufid_ti = ovsl_dereference(table->ufid_ti);

	BUG_ON(table->count == 0);
	hlist_del_rcu(&flow->flow_table.node[ti->node_ver]);
	table->count--;
	if (ovs_identifier_is_ufid(&flow->id)) {
		hlist_del_rcu(&flow->ufid_table.node[ufid_ti->node_ver]);
		table->ufid_count--;
	}

	/* RCU delete the mask. 'flow->mask' is not NULLed, as it should be
	 * accessible as long as the RCU read lock is held.
	 */
	flow_mask_remove(table, flow->mask);
}

static struct sw_flow_mask *mask_alloc(void)
{
	struct sw_flow_mask *mask;

	mask = kmalloc(sizeof(*mask), GFP_KERNEL);
	if (mask)
		mask->ref_count = 1;

	return mask;
}

static bool mask_equal(const struct sw_flow_mask *a,
		       const struct sw_flow_mask *b)
{
	const u8 *a_ = (const u8 *)&a->key + a->range.start;
	const u8 *b_ = (const u8 *)&b->key + b->range.start;

	return  (a->range.end == b->range.end)
		&& (a->range.start == b->range.start)
		&& (memcmp(a_, b_, range_n_bytes(&a->range)) == 0);
}

static struct sw_flow_mask *flow_mask_find(const struct flow_table *tbl,
					   const struct sw_flow_mask *mask)
{
	struct mask_array *ma;
	int i;

	ma = ovsl_dereference(tbl->mask_array);
	for (i = 0; i < ma->max; i++) {
		struct sw_flow_mask *t;

		t = ovsl_dereference(ma->masks[i]);
		if (t && mask_equal(mask, t))
			return t;
	}

	return NULL;
}

/* Add 'mask' into the mask list, if it is not already there. */
static int flow_mask_insert(struct flow_table *tbl, struct sw_flow *flow,
			    const struct sw_flow_mask *new)
{
	struct sw_flow_mask *mask;

	mask = flow_mask_find(tbl, new);
	if (!mask) {
		struct mask_array *ma;
		int i;

		/* Allocate a new mask if none exsits. */
		mask = mask_alloc();
		if (!mask)
			return -ENOMEM;

		mask->key = new->key;
		mask->range = new->range;

		/* Add mask to mask-list. */
		ma = ovsl_dereference(tbl->mask_array);
		if (ma->count >= ma->max) {
			int err;

			err = tbl_mask_array_realloc(tbl, ma->max +
							  MASK_ARRAY_SIZE_MIN);
			if (err) {
				kfree(mask);
				return err;
			}
			ma = ovsl_dereference(tbl->mask_array);
		}

		for (i = 0; i < ma->max; i++) {
			struct sw_flow_mask *t;

			t = ovsl_dereference(ma->masks[i]);
			if (!t) {
				rcu_assign_pointer(ma->masks[i], mask);
				ma->count++;
				break;
			}
		}

	} else {
		BUG_ON(!mask->ref_count);
		mask->ref_count++;
	}

	flow->mask = mask;
	return 0;
}

/* Must be called with OVS mutex held. */
static void flow_key_insert(struct flow_table *table, struct sw_flow *flow)
{
	struct table_instance *new_ti = NULL;
	struct table_instance *ti;

	flow->flow_table.hash = flow_hash(&flow->key, &flow->mask->range);
	ti = ovsl_dereference(table->ti);
	table_instance_insert(ti, flow);
	table->count++;

	/* Expand table, if necessary, to make room. */
	if (table->count > ti->n_buckets)
		new_ti = table_instance_expand(ti, false);
	else if (time_after(jiffies, table->last_rehash + REHASH_INTERVAL))
		new_ti = table_instance_rehash(ti, ti->n_buckets, false);

	if (new_ti) {
		rcu_assign_pointer(table->ti, new_ti);
		call_rcu(&ti->rcu, flow_tbl_destroy_rcu_cb);
		table->last_rehash = jiffies;
	}
}

/* Must be called with OVS mutex held. */
static void flow_ufid_insert(struct flow_table *table, struct sw_flow *flow)
{
	struct table_instance *ti;

	flow->ufid_table.hash = ufid_hash(&flow->id);
	ti = ovsl_dereference(table->ufid_ti);
	ufid_table_instance_insert(ti, flow);
	table->ufid_count++;

	/* Expand table, if necessary, to make room. */
	if (table->ufid_count > ti->n_buckets) {
		struct table_instance *new_ti;

		new_ti = table_instance_expand(ti, true);
		if (new_ti) {
			rcu_assign_pointer(table->ufid_ti, new_ti);
			call_rcu(&ti->rcu, flow_tbl_destroy_rcu_cb);
		}
	}
}

/* Must be called with OVS mutex held. */
int ovs_flow_tbl_insert(struct flow_table *table, struct sw_flow *flow,
			const struct sw_flow_mask *mask)
{
	int err;

	err = flow_mask_insert(table, flow, mask);
	if (err)
		return err;
	flow_key_insert(table, flow);
	if (ovs_identifier_is_ufid(&flow->id))
		flow_ufid_insert(table, flow);

	return 0;
}

/* Initializes the flow module.
 * Returns zero if successful or a negative error code.
 */
/*******************************************************************************
 函数名称  :	ovs_flow_init
 功能描述  :	ovs流模块初始化
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
int ovs_flow_init(void)
{
	BUILD_BUG_ON(__alignof__(struct sw_flow_key) % __alignof__(long));
	BUILD_BUG_ON(sizeof(struct sw_flow_key) % sizeof(long));


	/*流信息内存，交换机流信息结构+ 每CPU 流 流量指针*/
	flow_cache = kmem_cache_create("sw_flow", sizeof(struct sw_flow)
				       + (nr_cpu_ids * sizeof(struct flow_stats *)),
				       0, 0, NULL);
	if (flow_cache == NULL)
	{
		return -ENOMEM;
	}


	/*流统计内存申请*/
	flow_stats_cache
		= kmem_cache_create("sw_flow_stats", sizeof(struct flow_stats),
				    0, SLAB_HWCACHE_ALIGN, NULL);
	if (flow_stats_cache == NULL) 
	{
		kmem_cache_destroy(flow_cache);
		flow_cache = NULL;
		return -ENOMEM;
	}

	return 0;
}

/* Uninitializes the flow module. */
void ovs_flow_exit(void)
{
	kmem_cache_destroy(flow_stats_cache);
	kmem_cache_destroy(flow_cache);
}
