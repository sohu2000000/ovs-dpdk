/*
 * Copyright (c) 2007-2015 Nicira, Inc.
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
/*******************************************************************************
  Copyright (C)
 --------------------------------------------------------------------------------
 文件名称: vport.c
 功能描述: vport新建删除等
*******************************************************************************/
#include <linux/etherdevice.h>
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <linux/compat.h>
#include <linux/module.h>
#include <linux/if_link.h>
#include <net/net_namespace.h>
#include <net/lisp.h>
#include <net/gre.h>
#include <net/geneve.h>
#include <net/stt.h>
#include <net/vxlan.h>

#include "datapath.h"
#include "gso.h"
#include "vport.h"
#include "vport-internal_dev.h"

//static LIST_HEAD(vport_ops_list);
/*虚拟端口操作函数全局链表*/
static struct list_head vport_ops_list;         

static bool compat_gre_loaded = false;
static bool compat_ip6_tunnel_loaded = false;

/* Protected by RCU read lock for reading, ovs_mutex for writing. */
/*1024个虚拟端口链表头*/
static struct hlist_head *dev_table;
#define VPORT_HASH_BUCKETS 1024

/**
 *	ovs_vport_init - initialize vport subsystem
 *
 * Called at module load time to initialize the vport subsystem.
 */
 /*******************************************************************************
 函数名称  :	ovs_vport_init
 功能描述  :	虚拟端口初始化
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
int ovs_vport_init(void)
{
	int err;

	/*虚拟端口链表头1024个*/
	dev_table = kzalloc(VPORT_HASH_BUCKETS * sizeof(struct hlist_head),
			    GFP_KERNEL);
	if (!dev_table)
	{
		return -ENOMEM;
	}

	/*lisp模块初始化*/
	err = lisp_init_module();
	if (err)
	{
		goto err_lisp;
	}

	/*gre ipv4 模块初始化*/
	err = gre_init();
	if (err && err != -EEXIST)
	{
		goto err_gre;
	}
	else
	{
		if (err == -EEXIST) 
		{
			pr_warn("Cannot take GRE protocol rx entry"\
				"- The GRE/ERSPAN rx feature not supported\n");
			/* continue GRE tx */
		}

		/*gre初始化*/
		err = ipgre_init();
		if (err && err != -EEXIST) 
		{
			goto err_ipgre;
		}
		
		compat_gre_loaded = true;
	}

	/*gre ipv6模块初始化*/
	err = ip6gre_init();
	if (err && err != -EEXIST)
	{
		goto err_ip6gre;
	} 
	else 
	{
		if (err == -EEXIST)
		{
			pr_warn("IPv6 GRE/ERSPAN Rx mode is not supported\n");
			goto skip_ip6_tunnel_init;
		}
	}

	/*v6通道初始化*/
	err = ip6_tunnel_init();
	if (err)
	{
		goto err_ip6_tunnel;
	}
	else
	{
		compat_ip6_tunnel_loaded = true;
	}
	
skip_ip6_tunnel_init:

	/*geneve模块初始化*/
	err = geneve_init_module();
	if (err)
	{
		goto err_geneve;
	}

	/*vxlan模块初始化*/
	err = vxlan_init_module();
	if (err)
	{
		goto err_vxlan;
	}

	/*stt模块初始化*/
	err = ovs_stt_init_module();
	if (err)
	{
		goto err_stt;
	}
	
	return 0;
	ovs_stt_cleanup_module();

err_stt:
	vxlan_cleanup_module();

err_vxlan:
	geneve_cleanup_module();

err_geneve:
	ip6_tunnel_cleanup();

err_ip6_tunnel:
	ip6gre_fini();

err_ip6gre:
	ipgre_fini();

err_ipgre:
	gre_exit();

err_gre:
	lisp_cleanup_module();

err_lisp:
	kfree(dev_table);
	
	return err;
}

/**
 *	ovs_vport_exit - shutdown vport subsystem
 *
 * Called at module exit time to shutdown the vport subsystem.
 */
void ovs_vport_exit(void)
{
	if (compat_gre_loaded) {
		gre_exit();
		ipgre_fini();
	}
	ovs_stt_cleanup_module();
	vxlan_cleanup_module();
	geneve_cleanup_module();
	if (compat_ip6_tunnel_loaded)
		ip6_tunnel_cleanup();
	ip6gre_fini();
	lisp_cleanup_module();
	kfree(dev_table);
}

 /*******************************************************************************
 函数名称  :	hash_bucket
 功能描述  :	虚拟端口初始化
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static struct hlist_head *hash_bucket(const struct net *net, const char *name)
{
	/*根据name算哈希返回设备链表头*/
	unsigned int hash = jhash(name, strlen(name), (unsigned long) net);
	return &dev_table[hash & (VPORT_HASH_BUCKETS - 1)];
}

/*******************************************************************************
 函数名称  :	__ovs_vport_ops_register
 功能描述  :	操作函数注册
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
int __ovs_vport_ops_register(struct vport_ops *ops)
{
	int err = -EEXIST;
	struct vport_ops *o;

	ovs_lock();

	/*操作函数是否存在*/
	list_for_each_entry(o, &vport_ops_list, list)
	{
		if (ops->type == o->type)
		{
			goto errout;
		}
	}

	/*填链尾*/
	list_add_tail(&ops->list, &vport_ops_list);

	err = 0;

errout:

	ovs_unlock();
	
	return err;
}
EXPORT_SYMBOL_GPL(__ovs_vport_ops_register);

void ovs_vport_ops_unregister(struct vport_ops *ops)
{
	ovs_lock();
	list_del(&ops->list);
	ovs_unlock();
}
EXPORT_SYMBOL_GPL(ovs_vport_ops_unregister);

/**
 *	ovs_vport_locate - find a port that has already been created
 *
 * @name: name of port to find
 *
 * Must be called with ovs or RCU read lock.
 */

/*******************************************************************************
 函数名称  :	ovs_vport_locate
 功能描述  :	报文长度
 输入参数  :	net---虚拟端口定位
 				name---端口name
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
struct vport *ovs_vport_locate(const struct net *net, const char *name)
{
	struct hlist_head *bucket = hash_bucket(net, name);
	struct vport *vport;

	/*获取虚拟端口*/
	hlist_for_each_entry_rcu(vport, bucket, hash_node)
		if (!strcmp(name, ovs_vport_name(vport)) &&
		    net_eq(ovs_dp_get_net(vport->dp), net))
	{
			return vport;
	}
		
	return NULL;
}

/**
 *	ovs_vport_alloc - allocate and initialize new vport
 *
 * @priv_size: Size of private data area to allocate.
 * @ops: vport device ops
 *
 * Allocate and initialize a new vport defined by @ops.  The vport will contain
 * a private data area of size @priv_size that can be accessed using
 * vport_priv().  vports that are no longer needed should be released with
 * vport_free().
 */
/*******************************************************************************
 函数名称  :	ovs_vport_alloc
 功能描述  :	虚拟端口申请
 输入参数  :   	priv_size---私有数据size
 				ops---虚拟端口操作函数ovs_netdev_vport_ops
 				parms---虚拟端口参数
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
struct vport *ovs_vport_alloc(int priv_size, const struct vport_ops *ops,
			  const struct vport_parms *parms)
{
	struct vport *vport;
	size_t alloc_size;

	/*虚拟端口结构size*/
	alloc_size = sizeof(struct vport);
	if (priv_size) 
	{
		alloc_size = ALIGN(alloc_size, VPORT_ALIGN);
		alloc_size += priv_size;
	}

	/*虚拟端口结构内存申请*/
	vport = kzalloc(alloc_size, GFP_KERNEL);
	if (!vport)
	{
		return ERR_PTR(-ENOMEM);
	}

	/*数据面、端口ID、操作函数*/
	vport->dp      = parms->dp;
	vport->port_no = parms->port_no;
	vport->ops     = ops;

	/*初始化虚拟端口链表头*/
	INIT_HLIST_NODE(&vport->dp_hash_node);

	/*虚拟端口用户态通信设置*/
	if (ovs_vport_set_upcall_portids(vport, parms->upcall_portids))
	{
		kfree(vport);
		return ERR_PTR(-EINVAL);
	}

	return vport;
}
EXPORT_SYMBOL_GPL(ovs_vport_alloc);

/**
 *	ovs_vport_free - uninitialize and free vport
 *
 * @vport: vport to free
 *
 * Frees a vport allocated with vport_alloc() when it is no longer needed.
 *
 * The caller must ensure that an RCU grace period has passed since the last
 * time @vport was in a datapath.
 */
void ovs_vport_free(struct vport *vport)
{
	/* vport is freed from RCU callback or error path, Therefore
	 * it is safe to use raw dereference.
	 */
	kfree(rcu_dereference_raw(vport->upcall_portids));
	kfree(vport);
}
EXPORT_SYMBOL_GPL(ovs_vport_free);

/*******************************************************************************
 函数名称  :	ovs_vport_lookup
 功能描述  :	虚拟端口操作函数查询
 输入参数  :	parms---虚拟端口参数
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static struct vport_ops *ovs_vport_lookup(const struct vport_parms *parms)
{
	struct vport_ops *ops;

	/*操作函数查询查是否已存在*/
	list_for_each_entry(ops, &vport_ops_list, list)
		if (ops->type == parms->type)
		{
			return ops;
		}
		
	return NULL;
}

/**
 *	ovs_vport_add - add vport device (for kernel callers)
 *
 * @parms: Information about new vport.
 *
 * Creates a new vport with the specified configuration (which is dependent on
 * device type).  ovs_mutex must be held.
 */

/*******************************************************************************
 函数名称  :	ovs_vport_add
 功能描述  :	虚拟端口添加1024之一链表
 输入参数  :	priv_size---私有数据size
				ops---虚拟端口操作函数
				parms---虚拟端口参数
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
struct vport *ovs_vport_add(const struct vport_parms *parms)
{
	struct vport_ops *ops;
	struct vport *vport;

	/*操作函数查询*/
	ops = ovs_vport_lookup(parms);
	if (ops) 
	{
		struct hlist_head *bucket;

		/*模块是否存在*/
		if (!try_module_get(ops->owner))
		{
			return ERR_PTR(-EAFNOSUPPORT);
		}

		/*创建新端口*/
		vport = ops->create(parms);
		if (IS_ERR(vport)) 
		{
			module_put(ops->owner);
			return vport;
		}

		/*查询哈希桶链*/
		bucket = hash_bucket(ovs_dp_get_net(vport->dp),	ovs_vport_name(vport));

		/*新端口挂入哈希链*/
		hlist_add_head_rcu(&vport->hash_node, bucket);

		return vport;
	}

	if (parms->type == OVS_VPORT_TYPE_GRE && !compat_gre_loaded) 
	{
		pr_warn("GRE protocol already loaded!\n");
		return ERR_PTR(-EAFNOSUPPORT);
	}
	
	/* Unlock to attempt module load and return -EAGAIN if load
	 * was successful as we need to restart the port addition
	 * workflow.
	 */

	/*请求虚拟端口模块*/
	ovs_unlock();
	request_module("vport-type-%d", parms->type);
	ovs_lock();

	/*端口查询*/
	if (!ovs_vport_lookup(parms))
	{
		return ERR_PTR(-EAFNOSUPPORT);
	}
	else
	{
		return ERR_PTR(-EAGAIN);
	}
}

/**
 *	ovs_vport_set_options - modify existing vport device (for kernel callers)
 *
 * @vport: vport to modify.
 * @options: New configuration.
 *
 * Modifies an existing device with the specified configuration (which is
 * dependent on device type).  ovs_mutex must be held.
 */

/*******************************************************************************
 函数名称  :	ovs_vport_set_options
 功能描述  :	设置虚拟端口
 输入参数  :	vport---虚拟端口
				options---操作函数
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
int ovs_vport_set_options(struct vport *vport, struct nlattr *options)
{
	if (!vport->ops->set_options)
	{
		return -EOPNOTSUPP;
	}
	
	return vport->ops->set_options(vport, options);
}

/**
 *	ovs_vport_del - delete existing vport device
 *
 * @vport: vport to delete.
 *
 * Detaches @vport from its datapath and destroys it.  ovs_mutex must be
 * held.
 */
 
/*******************************************************************************
 函数名称  :	ovs_vport_add
 功能描述  :	分离虚拟端口与datap并销毁
 输入参数  :	priv_size---私有数据size
				ops---虚拟端口操作函数
				parms---虚拟端口参数
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
void ovs_vport_del(struct vport *vport)
{
	ASSERT_OVSL();

	hlist_del_rcu(&vport->hash_node);
	module_put(vport->ops->owner);
	vport->ops->destroy(vport);
}

/**
 *	ovs_vport_get_stats - retrieve device stats
 *
 * @vport: vport from which to retrieve the stats
 * @stats: location to store stats
 *
 * Retrieves transmit, receive, and error stats for the given device.
 *
 * Must be called with ovs_mutex or rcu_read_lock.
 */

/*******************************************************************************
 函数名称  :	ovs_vport_get_stats
 功能描述  :	分离虚拟端口与datap并销毁
 输入参数  :	vport---虚拟端口
				stats---虚拟端口流量数据
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
void ovs_vport_get_stats(struct vport *vport, struct ovs_vport_stats *stats)
{
	const struct rtnl_link_stats64 *dev_stats;
	struct rtnl_link_stats64 temp;

	dev_stats = dev_get_stats(vport->dev, &temp);
	stats->rx_errors  = dev_stats->rx_errors;
	stats->tx_errors  = dev_stats->tx_errors;
	stats->tx_dropped = dev_stats->tx_dropped;
	stats->rx_dropped = dev_stats->rx_dropped;

	stats->rx_bytes	  = dev_stats->rx_bytes;
	stats->rx_packets = dev_stats->rx_packets;
	stats->tx_bytes	  = dev_stats->tx_bytes;
	stats->tx_packets = dev_stats->tx_packets;
}

/**
 *	ovs_vport_get_options - retrieve device options
 *
 * @vport: vport from which to retrieve the options.
 * @skb: sk_buff where options should be appended.
 *
 * Retrieves the configuration of the given device, appending an
 * %OVS_VPORT_ATTR_OPTIONS attribute that in turn contains nested
 * vport-specific attributes to @skb.
 *
 * Returns 0 if successful, -EMSGSIZE if @skb has insufficient room, or another
 * negative error code if a real error occurred.  If an error occurs, @skb is
 * left unmodified.
 *
 * Must be called with ovs_mutex or rcu_read_lock.
 */


/*******************************************************************************
 函数名称  :	ovs_vport_get_options
 功能描述  :	分离虚拟端口与datap并销毁
 输入参数  :	vport---虚拟端口
				skb---虚拟端口skb报文数据
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
int ovs_vport_get_options(const struct vport *vport, struct sk_buff *skb)
{
	struct nlattr *nla;
	int err;

	if (!vport->ops->get_options)
	{
		return 0;
	}
	
	nla = nla_nest_start(skb, OVS_VPORT_ATTR_OPTIONS);
	if (!nla)
	{
		return -EMSGSIZE;
	}
	
	err = vport->ops->get_options(vport, skb);
	if (err)
	{
		nla_nest_cancel(skb, nla);
		return err;
	}

	nla_nest_end(skb, nla);
	return 0;
}

/**
 *	ovs_vport_set_upcall_portids - set upcall portids of @vport.
 *
 * @vport: vport to modify.
 * @ids: new configuration, an array of port ids.
 *
 * Sets the vport's upcall_portids to @ids.
 *
 * Returns 0 if successful, -EINVAL if @ids is zero length or cannot be parsed
 * as an array of U32.
 *
 * Must be called with ovs_mutex.
 */
 
 /*******************************************************************************
 函数名称  :	ovs_vport_set_upcall_portids
 功能描述  :	用户态通信端口ID设置
 输入参数  :    vport---用户态端口
 				ids--
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
int ovs_vport_set_upcall_portids(struct vport *vport, const struct nlattr *ids)
{
	struct vport_portids *old, *vport_portids;

	if (!nla_len(ids) || nla_len(ids) % sizeof(u32))
	{
		return -EINVAL;
	}
	
	old = ovsl_dereference(vport->upcall_portids);

	vport_portids = kmalloc(sizeof(*vport_portids) + nla_len(ids),
				GFP_KERNEL);
	if (!vport_portids)
	{
		return -ENOMEM;
	}
	
	vport_portids->n_ids   = nla_len(ids) / sizeof(u32);
	vport_portids->rn_ids = reciprocal_value(vport_portids->n_ids);
	nla_memcpy(vport_portids->ids, ids, nla_len(ids));

	rcu_assign_pointer(vport->upcall_portids, vport_portids);

	if (old)
	{
		kfree_rcu(old, rcu);
	}
	
	return 0;
}

/**
 *	ovs_vport_get_upcall_portids - get the upcall_portids of @vport.
 *
 * @vport: vport from which to retrieve the portids.
 * @skb: sk_buff where portids should be appended.
 *
 * Retrieves the configuration of the given vport, appending the
 * %OVS_VPORT_ATTR_UPCALL_PID attribute which is the array of upcall
 * portids to @skb.
 *
 * Returns 0 if successful, -EMSGSIZE if @skb has insufficient room.
 * If an error occurs, @skb is left unmodified.  Must be called with
 * ovs_mutex or rcu_read_lock.
 */
int ovs_vport_get_upcall_portids(const struct vport *vport,
				 struct sk_buff *skb)
{
	struct vport_portids *ids;

	ids = rcu_dereference_ovsl(vport->upcall_portids);

	if (vport->dp->user_features & OVS_DP_F_VPORT_PIDS)
		return nla_put(skb, OVS_VPORT_ATTR_UPCALL_PID,
			       ids->n_ids * sizeof(u32), (void *)ids->ids);
	else
		return nla_put_u32(skb, OVS_VPORT_ATTR_UPCALL_PID, ids->ids[0]);
}

/**
 *	ovs_vport_find_upcall_portid - find the upcall portid to send upcall.
 *
 * @vport: vport from which the missed packet is received.
 * @skb: skb that the missed packet was received.
 *
 * Uses the skb_get_hash() to select the upcall portid to send the
 * upcall.
 *
 * Returns the portid of the target socket.  Must be called with rcu_read_lock.
 */
u32 ovs_vport_find_upcall_portid(const struct vport *vport, struct sk_buff *skb)
{
	struct vport_portids *ids;
	u32 ids_index;
	u32 hash;

	ids = rcu_dereference(vport->upcall_portids);

	if (ids->n_ids == 1 && ids->ids[0] == 0)
		return 0;

	hash = skb_get_hash(skb);
	ids_index = hash - ids->n_ids * reciprocal_divide(hash, ids->rn_ids);
	return ids->ids[ids_index];
}

/**
 *	ovs_vport_receive - pass up received packet to the datapath for processing
 *
 * @vport: vport that received the packet
 * @skb: skb that was received
 * @tun_key: tunnel (if any) that carried packet
 *
 * Must be called with rcu_read_lock.  The packet cannot be shared and
 * skb->data should point to the Ethernet header.
 */
 
 /*******************************************************************************
 函数名称  :    ovs_vport_receive
 功能描述  :    虚拟端口从网卡收包
				加载网卡时把网卡绑定到Open vSwitch端口上（ovs-vsctl add-port br0 eth0）
				绑定后每当有数据包过来时，都会调用该函数，把数据包传送给这个函数去处理
				不是像开始那样（未绑定前）把数据包往内核网络协议栈中发送，让内核协议栈去处理
 
 输入参数  :    vport---入口端口
 				skb---数据包指针
 				tun_info---通道信息
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
int ovs_vport_receive(struct vport *vport, struct sk_buff *skb,
		      const struct ip_tunnel_info *tun_info)
{
	/*数据包key值，提取数据包中协议相关信息*/
	struct sw_flow_key key;
	int error;

	OVS_CB(skb)->input_vport = vport;
	OVS_CB(skb)->mru         = 0;
	OVS_CB(skb)->cutlen      = 0;

	if (unlikely(dev_net(skb->dev) != ovs_dp_get_net(vport->dp))) 
	{
		u32 mark;

		mark = skb->mark;
		skb_scrub_packet(skb, true);
		skb->mark = mark;
		tun_info = NULL;
	}

	/*内部协议*/
	ovs_skb_init_inner_protocol(skb);

	/*清除ovs回调*/
	skb_clear_ovs_gso_cb(skb);

	/*从skb提取key值*/
	/* Extract flow from 'skb' into 'key'. */
	error = ovs_flow_key_extract(tun_info, skb, &key);
	if (unlikely(error)) 
	{
		kfree_skb(skb);
		return error;
	}

	/*datapath包处理入口*/
	ovs_dp_process_packet(skb, &key);
	
	return 0;
}

/*******************************************************************************
 函数名称  :	packet_length
 功能描述  :	报文长度
 输入参数  :	vport---出端口
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static int packet_length(const struct sk_buff *skb,
			 struct net_device *dev)
{
	int length = skb->len - dev->hard_header_len;

	if (!skb_vlan_tag_present(skb) &&
	    eth_type_vlan(skb->protocol))
	{
		length -= VLAN_HLEN;
	}
	
	/* Don't subtract for multiple VLAN tags. Most (all?) drivers allow
	 * (ETH_LEN + VLAN_HLEN) in addition to the mtu value, but almost none
	 * account for 802.1ad. e.g. is_skb_forwardable().
	 */

	return length > 0 ? length: 0;
}

/*******************************************************************************
 函数名称  :    ovs_vport_send
 功能描述  :    ovs出接口，从虚拟端口处
 输入参数  :    vport---出端口
 				skb---要出的包
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
void ovs_vport_send(struct vport *vport, struct sk_buff *skb, u8 mac_proto)
{
	int mtu = vport->dev->mtu;

	/*接口硬件类型，在<if_arp.h>中定义了每一个接口硬件类型；*/
	switch (vport->dev->type)
	{
		case ARPHRD_NONE:
		{
			if (mac_proto == MAC_PROTO_ETHERNET) 
			{
				skb_reset_network_header(skb);
				skb_reset_mac_len(skb);
				skb->protocol = htons(ETH_P_TEB);
			}
			else if (mac_proto != MAC_PROTO_NONE) 
			{
				WARN_ON_ONCE(1);
				goto drop;
			}
			break;
		}
		case ARPHRD_ETHER:
		{
			if (mac_proto != MAC_PROTO_ETHERNET)
			{
				goto drop;
			}

			break;
		}
		default:
		{
			goto drop;
		}
	}

	if (unlikely(packet_length(skb, vport->dev) > mtu &&
		     !skb_is_gso(skb)))
	{
		net_warn_ratelimited("%s: dropped over-mtu packet: %d > %d\n",
				     vport->dev->name,
				     packet_length(skb, vport->dev), mtu);

		vport->dev->stats.tx_errors++;
		goto drop;
	}

	/*skb的dev设备，设置成vport关联的netdev设备*/
	skb->dev = vport->dev;

	/*端口出方向真实出函数*/
	/*调用vport对应vport_ops的send函数，如果是ovs_netdev_vport_ops，
	则调用内核的dev_queue_xmit函数，发出去
	OVS接口类型为system时，vport->ops->send函数为netdev_send*/
	vport->ops->send(skb);

	return;

drop:
	
	kfree_skb(skb);
}
