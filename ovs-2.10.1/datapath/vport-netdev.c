/*
 * Copyright (c) 2007-2012 Nicira, Inc.
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/if_arp.h>
#include <linux/if_bridge.h>
#include <linux/if_vlan.h>
#include <linux/kernel.h>
#include <linux/llc.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/openvswitch.h>
#include <linux/export.h>

#include <net/ip_tunnels.h>
#include <net/rtnetlink.h>

#include "datapath.h"
#include "gso.h"
#include "vport.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

/*虚拟端口操作函数*/
static struct vport_ops ovs_netdev_vport_ops;

/* Must be called with rcu_read_lock. */
/*******************************************************************************
 函数名称  :	netdev_port_receive
 功能描述  :	虚拟端口收包
 				1. 首先得到一个packet的拷贝，否则会损坏先于我们而来的packet使用者
 输入参数  :    skb---真实报文
 				tun_info---报文解出的tunnel信息
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	2019-01-21
*******************************************************************************/
void netdev_port_receive(struct sk_buff *skb, struct ip_tunnel_info *tun_info)
{
	struct vport *vport;

	/*通过netdev设备获得vport对象，是实现在datapath中转发的基础*/
	vport = ovs_netdev_get_vport(skb->dev);
	if (unlikely(!vport))
	{
		goto error;
	}

	/*报文LRO若使能则不可转发*/
	if (unlikely(skb_warn_if_lro(skb)))
	{
		goto error;
	}
	
	/* Make our own copy of the packet.  Otherwise we will mangle the
	 * packet for anyone who came before us (e.g. tcpdump via AF_PACKET).
	 */
	/*分享检查*/
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb))
	{
		return;
	}

	/*arp头*/
	if (skb->dev->type == ARPHRD_ETHER) 
	{
		//GFP_ATOMIC用于在中断处理例程或其它运行于进程上下文之外的地方分配内存，不会休眠（LDD214）。
		//将skb的数据区向后移动*_HLEN长度，为了存入帧头；而skb_put是扩展数据区后面为存数据memcpy做准备。
		skb_push(skb, ETH_HLEN);
		skb_postpush_rcsum(skb, skb->data, ETH_HLEN);
	}

	/*虚拟端口报文处理*/
	ovs_vport_receive(vport, skb, tun_info);
	
	return;

error:

	kfree_skb(skb);
}

/* Called with rcu_read_lock and bottom-halves disabled. */


/*******************************************************************************
 函数名称  :	netdev_frame_hook
 功能描述  :	在网卡注册hook，报文到达vport调用这个函数
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	2019-01-21
*******************************************************************************/
static rx_handler_result_t netdev_frame_hook(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;

	
	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
	{
		return RX_HANDLER_PASS;
	}
	
#ifndef USE_UPSTREAM_TUNNEL
	netdev_port_receive(skb, NULL);
#else

	/*端口收包处理函数*/
	netdev_port_receive(skb, skb_tunnel_info(skb));
#endif
	return RX_HANDLER_CONSUMED;
}

static struct net_device *get_dpdev(const struct datapath *dp)
{
	struct vport *local;

	local = ovs_vport_ovsl(dp, OVSP_LOCAL);
	BUG_ON(!local);
	return local->dev;
}

/*******************************************************************************
 函数名称  :	ovs_netdev_link
 功能描述  :	链接虚拟端口，vport接到报文处理函数注册netdev_frame_hook
 输入参数  :  	vport---申请的vport结构
 				name---vport的name
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
struct vport *ovs_netdev_link(struct vport *vport, const char *name)
{
	int err;

	//通过interface name比如eth0 得到具体具体的net_device 结构体，然后下面注册 rx_handler;
	vport->dev = dev_get_by_name(ovs_dp_get_net(vport->dp), name);
	if (!vport->dev) 
	{
		err = -ENODEV;
		goto error_free_vport;
	}


	//不是环回接口；而且底层链路层是以太网；netdev->netdev_ops == &internal_dev_netdev_ops 显然为false
	if (vport->dev->flags & IFF_LOOPBACK ||
	    (vport->dev->type != ARPHRD_ETHER &&
	     vport->dev->type != ARPHRD_NONE) ||
	    ovs_is_internal_dev(vport->dev)) 
	{
		err = -EINVAL;
		goto error_put;
	}

	rtnl_lock();
	err = netdev_master_upper_dev_link(vport->dev,
					   get_dpdev(vport->dp),
					   NULL, NULL, NULL);
	if (err)
	{
		goto error_unlock;
	}

	/*网卡收包函数注册*/	/*netdev注册 到rx_handler*/
	/*为网络设备dev注册一个receive handler,rx_handler_data指向的是这个receive handler,
	handler 以后会被 __netif_receive_skb() 呼叫,netif_receive_skb收到报文后调用handler*/
	err = netdev_rx_handler_register(vport->dev, netdev_frame_hook, vport);
	if (err)
	{
		goto error_master_upper_dev_unlink;
	}
	
	dev_disable_lro(vport->dev);

	/*设置为混杂模式*/
	dev_set_promiscuity(vport->dev, 1);

	/*设置netdevice私有区域的标识*/
	vport->dev->priv_flags |= IFF_OVS_DATAPATH;
	rtnl_unlock();

	return vport;

error_master_upper_dev_unlink:
	netdev_upper_dev_unlink(vport->dev, get_dpdev(vport->dp));
error_unlock:
	rtnl_unlock();
error_put:
	dev_put(vport->dev);
error_free_vport:
	ovs_vport_free(vport);
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(ovs_netdev_link);

/*******************************************************************************
 函数名称  :	netdev_create
 功能描述  :	虚拟网卡设备创建时注册vport
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static struct vport *netdev_create(const struct vport_parms *parms)
{
	struct vport *vport;

	/*网卡设备端口申请*/
	vport = ovs_vport_alloc(0, &ovs_netdev_vport_ops, parms);
	if (IS_ERR(vport))
	{
		return vport;
	}
	
	/*网卡设备链接虚拟端口*/
	return ovs_netdev_link(vport, parms->name);
}

/*******************************************************************************
 函数名称  :	vport_netdev_free
 功能描述  :	网卡设备释放
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static void vport_netdev_free(struct rcu_head *rcu)
{
	struct vport *vport = container_of(rcu, struct vport, rcu);

	if (vport->dev)
	{
		dev_put(vport->dev);
	}
	
	ovs_vport_free(vport);
}

/*******************************************************************************
 函数名称  :	ovs_netdev_detach_dev
 功能描述  :	port dev分离
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
void ovs_netdev_detach_dev(struct vport *vport)
{
	ASSERT_RTNL();
	vport->dev->priv_flags &= ~IFF_OVS_DATAPATH;
	netdev_rx_handler_unregister(vport->dev);
	netdev_upper_dev_unlink(vport->dev, netdev_master_upper_dev_get(vport->dev));
	dev_set_promiscuity(vport->dev, -1);
}

/*******************************************************************************
 函数名称  :	netdev_destroy
 功能描述  :	网卡设备消耗
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static void netdev_destroy(struct vport *vport)
{
	rtnl_lock();
	if (vport->dev->priv_flags & IFF_OVS_DATAPATH)
	{
		/*网络dev分离*/
		ovs_netdev_detach_dev(vport);
	}
	
	rtnl_unlock();

	call_rcu(&vport->rcu, vport_netdev_free);
}

void ovs_netdev_tunnel_destroy(struct vport *vport)
{
	rtnl_lock();
	if (vport->dev->priv_flags & IFF_OVS_DATAPATH)
		ovs_netdev_detach_dev(vport);

	/* We can be invoked by both explicit vport deletion and
	 * underlying netdev deregistration; delete the link only
	 * if it's not already shutting down.
	 */
	if (vport->dev->reg_state == NETREG_REGISTERED)
		rtnl_delete_link(vport->dev);
	dev_put(vport->dev);
	vport->dev = NULL;
	rtnl_unlock();

	call_rcu(&vport->rcu, vport_netdev_free);
}
EXPORT_SYMBOL_GPL(ovs_netdev_tunnel_destroy);

/*******************************************************************************
 函数名称  :	ovs_netdev_get_vport
 功能描述  :	虚拟端口收包
 输入参数  :    skb---真实报文
 				tun_info---通道信息
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	2019-01-21
*******************************************************************************/
/* Returns null if this device is not attached to a datapath. */
struct vport *ovs_netdev_get_vport(struct net_device *dev)
{
	if (likely(dev->priv_flags & IFF_OVS_DATAPATH))
		return (struct vport *)
			rcu_dereference_rtnl(dev->rx_handler_data);
	else
		return NULL;
}

/*虚拟网卡设备操作函数*/
static struct vport_ops ovs_netdev_vport_ops = 
{
	.type		= OVS_VPORT_TYPE_NETDEV,               /*网络设备类型netdev*/
	.create		= netdev_create,                       /*虚拟网卡创建*/
	.destroy	= netdev_destroy,                      /*虚拟网卡销毁*/
	.send		= dev_queue_xmit,
};

int __init ovs_netdev_init(void)
{
	/*注册ovs_netdev_vport_ops操作函数挂入全局虚拟端口链vport_ops_list*/
	return ovs_vport_ops_register(&ovs_netdev_vport_ops);
}

void ovs_netdev_exit(void)
{
	/*vport操作函数删除*/
	ovs_vport_ops_unregister(&ovs_netdev_vport_ops);
}
