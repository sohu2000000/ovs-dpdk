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

#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H 1

#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/openvswitch.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/if_ether.h>
#include <linux/in6.h>
#include <linux/jiffies.h>
#include <linux/time.h>
#include <linux/flex_array.h>

#include <net/inet_ecn.h>
#include <net/ip_tunnels.h>

#include "flow.h"

/*掩码缓存入口*/
struct mask_cache_entry 
{
	u32 skb_hash;
	u32 mask_index;
};

/*掩码数组结构*/
struct mask_array {
	struct rcu_head rcu;
	int count, max;
	struct sw_flow_mask __rcu *masks[];               /*掩码数组*/
};

/*流表实例*/
struct table_instance
{
	struct flex_array *buckets;                       /*哈希桶地址，弹性变量*/
	unsigned int n_buckets;                           /*哈希桶个数*/
	struct rcu_head rcu;                              /*rcu锁*/
	int node_ver;
	u32 hash_seed;                                    /*哈希种子后期匹配*/
	bool keep_flows;                                  /*是否保留流表项*/
};

/*流表*/
struct flow_table
{
	struct table_instance __rcu *ti;                  /*流表实例*/
	struct table_instance __rcu *ufid_ti;
	struct mask_cache_entry __percpu *mask_cache;     /*256个结构*/
	struct mask_array __rcu *mask_array;              /*掩码数组指针rcu*/ 
	unsigned long last_rehash;
	unsigned int count;								  // 哈希桶个数
	unsigned int ufid_count;
};

extern struct kmem_cache *flow_stats_cache;

int ovs_flow_init(void);
void ovs_flow_exit(void);

struct sw_flow *ovs_flow_alloc(void);
void ovs_flow_free(struct sw_flow *, bool deferred);

int ovs_flow_tbl_init(struct flow_table *);
int ovs_flow_tbl_count(const struct flow_table *table);
void ovs_flow_tbl_destroy(struct flow_table *table);
int ovs_flow_tbl_flush(struct flow_table *flow_table);

int ovs_flow_tbl_insert(struct flow_table *table, struct sw_flow *flow,
			const struct sw_flow_mask *mask);
void ovs_flow_tbl_remove(struct flow_table *table, struct sw_flow *flow);
int  ovs_flow_tbl_num_masks(const struct flow_table *table);
struct sw_flow *ovs_flow_tbl_dump_next(struct table_instance *table,
				       u32 *bucket, u32 *idx);
struct sw_flow *ovs_flow_tbl_lookup_stats(struct flow_table *,
					  const struct sw_flow_key *,
					  u32 skb_hash,
					  u32 *n_mask_hit);
struct sw_flow *ovs_flow_tbl_lookup(struct flow_table *,
				    const struct sw_flow_key *);
struct sw_flow *ovs_flow_tbl_lookup_exact(struct flow_table *tbl,
					  const struct sw_flow_match *match);
struct sw_flow *ovs_flow_tbl_lookup_ufid(struct flow_table *,
					 const struct sw_flow_id *);

bool ovs_flow_cmp(const struct sw_flow *, const struct sw_flow_match *);

void ovs_flow_mask_key(struct sw_flow_key *dst, const struct sw_flow_key *src,
		       bool full, const struct sw_flow_mask *mask);
#endif /* flow_table.h */
