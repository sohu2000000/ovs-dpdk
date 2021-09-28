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

/*����˿ڲ�������*/
static struct vport_ops ovs_netdev_vport_ops;

/* Must be called with rcu_read_lock. */
/*******************************************************************************
 ��������  :	netdev_port_receive
 ��������  :	����˿��հ�
 				1. ���ȵõ�һ��packet�Ŀ�������������������Ƕ�����packetʹ����
 �������  :    skb---��ʵ����
 				tun_info---���Ľ����tunnel��Ϣ
 �������  :	
 �� �� ֵ  :	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	:	
 �޸�����	:	2019-01-21
*******************************************************************************/
void netdev_port_receive(struct sk_buff *skb, struct ip_tunnel_info *tun_info)
{
	struct vport *vport;

	/*ͨ��netdev�豸���vport������ʵ����datapath��ת���Ļ���*/
	vport = ovs_netdev_get_vport(skb->dev);
	if (unlikely(!vport))
	{
		goto error;
	}

	/*����LRO��ʹ���򲻿�ת��*/
	if (unlikely(skb_warn_if_lro(skb)))
	{
		goto error;
	}
	
	/* Make our own copy of the packet.  Otherwise we will mangle the
	 * packet for anyone who came before us (e.g. tcpdump via AF_PACKET).
	 */
	/*������*/
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb))
	{
		return;
	}

	/*arpͷ*/
	if (skb->dev->type == ARPHRD_ETHER) 
	{
		//GFP_ATOMIC�������жϴ������̻����������ڽ���������֮��ĵط������ڴ棬�������ߣ�LDD214����
		//��skb������������ƶ�*_HLEN���ȣ�Ϊ�˴���֡ͷ����skb_put����չ����������Ϊ������memcpy��׼����
		skb_push(skb, ETH_HLEN);
		skb_postpush_rcsum(skb, skb->data, ETH_HLEN);
	}

	/*����˿ڱ��Ĵ���*/
	ovs_vport_receive(vport, skb, tun_info);
	
	return;

error:

	kfree_skb(skb);
}

/* Called with rcu_read_lock and bottom-halves disabled. */


/*******************************************************************************
 ��������  :	netdev_frame_hook
 ��������  :	������ע��hook�����ĵ���vport�����������
 �������  :  
 �������  :	
 �� �� ֵ  :	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	:	
 �޸�����	:	2019-01-21
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

	/*�˿��հ�������*/
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
 ��������  :	ovs_netdev_link
 ��������  :	��������˿ڣ�vport�ӵ����Ĵ�����ע��netdev_frame_hook
 �������  :  	vport---�����vport�ṹ
 				name---vport��name
 �������  :	
 �� �� ֵ  :	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	:	
 �޸�����	:	
*******************************************************************************/
struct vport *ovs_netdev_link(struct vport *vport, const char *name)
{
	int err;

	//ͨ��interface name����eth0 �õ���������net_device �ṹ�壬Ȼ������ע�� rx_handler;
	vport->dev = dev_get_by_name(ovs_dp_get_net(vport->dp), name);
	if (!vport->dev) 
	{
		err = -ENODEV;
		goto error_free_vport;
	}


	//���ǻ��ؽӿڣ����ҵײ���·������̫����netdev->netdev_ops == &internal_dev_netdev_ops ��ȻΪfalse
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

	/*�����հ�����ע��*/	/*netdevע�� ��rx_handler*/
	/*Ϊ�����豸devע��һ��receive handler,rx_handler_dataָ��������receive handler,
	handler �Ժ�ᱻ __netif_receive_skb() ����,netif_receive_skb�յ����ĺ����handler*/
	err = netdev_rx_handler_register(vport->dev, netdev_frame_hook, vport);
	if (err)
	{
		goto error_master_upper_dev_unlink;
	}
	
	dev_disable_lro(vport->dev);

	/*����Ϊ����ģʽ*/
	dev_set_promiscuity(vport->dev, 1);

	/*����netdevice˽������ı�ʶ*/
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
 ��������  :	netdev_create
 ��������  :	���������豸����ʱע��vport
 �������  :  
 �������  :	
 �� �� ֵ  :	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	:	
 �޸�����	:	
*******************************************************************************/
static struct vport *netdev_create(const struct vport_parms *parms)
{
	struct vport *vport;

	/*�����豸�˿�����*/
	vport = ovs_vport_alloc(0, &ovs_netdev_vport_ops, parms);
	if (IS_ERR(vport))
	{
		return vport;
	}
	
	/*�����豸��������˿�*/
	return ovs_netdev_link(vport, parms->name);
}

/*******************************************************************************
 ��������  :	vport_netdev_free
 ��������  :	�����豸�ͷ�
 �������  :  
 �������  :	
 �� �� ֵ  :	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	:	
 �޸�����	:	
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
 ��������  :	ovs_netdev_detach_dev
 ��������  :	port dev����
 �������  :  
 �������  :	
 �� �� ֵ  :	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	:	
 �޸�����	:	
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
 ��������  :	netdev_destroy
 ��������  :	�����豸����
 �������  :  
 �������  :	
 �� �� ֵ  :	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	:	
 �޸�����	:	
*******************************************************************************/
static void netdev_destroy(struct vport *vport)
{
	rtnl_lock();
	if (vport->dev->priv_flags & IFF_OVS_DATAPATH)
	{
		/*����dev����*/
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
 ��������  :	ovs_netdev_get_vport
 ��������  :	����˿��հ�
 �������  :    skb---��ʵ����
 				tun_info---ͨ����Ϣ
 �������  :	
 �� �� ֵ  :	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	:	
 �޸�����	:	2019-01-21
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

/*���������豸��������*/
static struct vport_ops ovs_netdev_vport_ops = 
{
	.type		= OVS_VPORT_TYPE_NETDEV,               /*�����豸����netdev*/
	.create		= netdev_create,                       /*������������*/
	.destroy	= netdev_destroy,                      /*������������*/
	.send		= dev_queue_xmit,
};

int __init ovs_netdev_init(void)
{
	/*ע��ovs_netdev_vport_ops������������ȫ������˿���vport_ops_list*/
	return ovs_vport_ops_register(&ovs_netdev_vport_ops);
}

void ovs_netdev_exit(void)
{
	/*vport��������ɾ��*/
	ovs_vport_ops_unregister(&ovs_netdev_vport_ops);
}
