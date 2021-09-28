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
 文件名称: datapath.c
 功能描述:网桥新建删除等
*******************************************************************************/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/jhash.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/etherdevice.h>
#include <linux/genetlink.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/ethtool.h>
#include <linux/wait.h>
#include <asm/div64.h>
#include <linux/highmem.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inetdevice.h>
#include <linux/list.h>
#include <linux/openvswitch.h>
#include <linux/rculist.h>
#include <linux/dmi.h>
#include <net/genetlink.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/nsh.h>

#include "datapath.h"
#include "conntrack.h"
#include "flow.h"
#include "flow_table.h"
#include "flow_netlink.h"
#include "meter.h"
#include "gso.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

unsigned int ovs_net_id __read_mostly;

static struct genl_family dp_packet_genl_family;
static struct genl_family dp_flow_genl_family;              /*流表netlink*/
static struct genl_family dp_datapath_genl_family;

static const struct nla_policy flow_policy[];

static struct genl_multicast_group ovs_dp_flow_multicast_group = {
	.name = OVS_FLOW_MCGROUP
};

static struct genl_multicast_group ovs_dp_datapath_multicast_group = {
	.name = OVS_DATAPATH_MCGROUP
};

struct genl_multicast_group ovs_dp_vport_multicast_group = {
	.name = OVS_VPORT_MCGROUP
};

/* Check if need to build a reply message.
 * OVS userspace sets the NLM_F_ECHO flag if it needs the reply.
 */
static bool ovs_must_notify(struct genl_family *family, struct genl_info *info,
			    unsigned int group)
{
	return info->nlhdr->nlmsg_flags & NLM_F_ECHO ||
	       genl_has_listeners(family, genl_info_net(info), group);
}

static void ovs_notify(struct genl_family *family, struct genl_multicast_group *grp,
		       struct sk_buff *skb, struct genl_info *info)
{
	genl_notify(family, skb, info, GROUP_ID(grp), GFP_KERNEL);
}

/**
 * DOC: Locking:
 *
 * All writes e.g. Writes to device state (add/remove datapath, port, set
 * operations on vports, etc.), Writes to other state (flow table
 * modifications, set miscellaneous datapath parameters, etc.) are protected
 * by ovs_lock.
 *
 * Reads are protected by RCU.
 *
 * There are a few special cases (mostly stats) that have their own
 * synchronization but they nest under all of above and don't interact with
 * each other.
 *
 * The RTNL lock nests inside ovs_mutex.
 */

static DEFINE_MUTEX(ovs_mutex);

void ovs_lock(void)
{
	mutex_lock(&ovs_mutex);
}

void ovs_unlock(void)
{
	mutex_unlock(&ovs_mutex);
}

#ifdef CONFIG_LOCKDEP
int lockdep_ovsl_is_held(void)
{
	if (debug_locks)
		return lockdep_is_held(&ovs_mutex);
	else
		return 1;
}
#endif

static int queue_gso_packets(struct datapath *dp, struct sk_buff *,
			     const struct sw_flow_key *,
			     const struct dp_upcall_info *,
			     uint32_t cutlen);
static int queue_userspace_packet(struct datapath *dp, struct sk_buff *,
				  const struct sw_flow_key *,
				  const struct dp_upcall_info *,
				  uint32_t cutlen);

/* Must be called with rcu_read_lock or ovs_mutex. */
const char *ovs_dp_name(const struct datapath *dp)
{
	struct vport *vport = ovs_vport_ovsl_rcu(dp, OVSP_LOCAL);
	return ovs_vport_name(vport);
}

static int get_dpifindex(const struct datapath *dp)
{
	struct vport *local;
	int ifindex;

	rcu_read_lock();

	local = ovs_vport_rcu(dp, OVSP_LOCAL);
	if (local)
		ifindex = local->dev->ifindex;
	else
		ifindex = 0;

	rcu_read_unlock();

	return ifindex;
}

static void destroy_dp_rcu(struct rcu_head *rcu)
{
	struct datapath *dp = container_of(rcu, struct datapath, rcu);

	ovs_flow_tbl_destroy(&dp->table);
	free_percpu(dp->stats_percpu);
	kfree(dp->ports);
	ovs_meters_exit(dp);
	kfree(dp);
}

static struct hlist_head *vport_hash_bucket(const struct datapath *dp,
					    u16 port_no)
{
	return &dp->ports[port_no & (DP_VPORT_HASH_BUCKETS - 1)];
}

/* Called with ovs_mutex or RCU read lock. */
/*******************************************************************************
 函数名称  :	ovs_lookup_vport
 功能描述  :	虚拟端口查询
 输入参数  :    dp---网桥
 				port_no---虚拟端口号
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	2019-01-21
*******************************************************************************/
struct vport *ovs_lookup_vport(const struct datapath *dp, u16 port_no)
{
	struct vport *vport;
	struct hlist_head *head;

	/*网桥虚拟端口链*/
	head = vport_hash_bucket(dp, port_no);

	/*遍历虚拟端口链匹配端口号返回虚拟端口*/
	hlist_for_each_entry_rcu(vport, head, dp_hash_node) {
		if (vport->port_no == port_no)
			return vport;
	}
	return NULL;
}

/*******************************************************************************
 函数名称  :	new_vport
 功能描述  :	新建vport
 输入参数  :    parms--网桥参数
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	2019-01-21
*******************************************************************************/
/* Called with ovs_mutex. */
static struct vport *new_vport(const struct vport_parms *parms)
{
	struct vport *vport;

	/*虚拟端口新建*/
	vport = ovs_vport_add(parms);
	if (!IS_ERR(vport)) 
	{
		struct datapath *dp = parms->dp;

		/*虚拟端口链表头*/
		struct hlist_head *head = vport_hash_bucket(dp, vport->port_no);

		hlist_add_head_rcu(&vport->dp_hash_node, head);
	}
	return vport;
}

/*******************************************************************************
 函数名称  :	new_vport
 功能描述  :	新建vport
 输入参数  :	parms--网桥参数
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	2019-01-21
*******************************************************************************/
void ovs_dp_detach_port(struct vport *p)
{
	ASSERT_OVSL();

	/* First drop references to device. */
	hlist_del_rcu(&p->dp_hash_node);

	/* Then destroy it. */
	ovs_vport_del(p);
}


/*******************************************************************************
 函数名称  :    ovs_dp_process_packet
 功能描述  :    dp处理报文内核版
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Must be called with rcu_read_lock. */
void ovs_dp_process_packet(struct sk_buff *skb, struct sw_flow_key *key)
{
	const struct vport *p = OVS_CB(skb)->input_vport;  /*skb in_port*/
	struct datapath *dp = p->dp;                        /*端口所属网桥*/
	struct sw_flow *flow;                               /*流表*/
	struct sw_flow_actions *sf_acts;                   /*命中动作*/
	struct dp_stats_percpu *stats;                     /*CPU统计*/
	u64 *stats_counter;
	u32 n_mask_hit;

	/*网桥dp每CPU流量统计*/
	stats = this_cpu_ptr(dp->stats_percpu);

	/* Look up flow. */
	/*根据mask和key值流表查询，返回流表项flow，flow---命中的流表项*/
	flow = ovs_flow_tbl_lookup_stats(&dp->table, key, skb_get_hash(skb), &n_mask_hit);

	/*未命中流，发到用户空间进行慢速匹配*/
	/*
	 * 未匹配到任何流表，则将key值封装到Netlink消息中通过
	 * netlink发送到用户态ovs-vswitchd进程
	 * 由用户态进程来决定如何处理数据包
	*/
	if (unlikely(!flow))
	{
		// 定义一个结构体，设置相应的值，然后把数据包发送到用户空间
		struct dp_upcall_info upcall;
		int error;

		memset(&upcall, 0, sizeof(upcall));

		/*填充netlink通信结构*/
		
		upcall.cmd = OVS_PACKET_CMD_MISS; // MISS

		// netLink通信时的id号 
		upcall.portid = ovs_vport_find_upcall_portid(p, skb); 
		
		upcall.mru = OVS_CB(skb)->mru;

		/*数据包发向用户空间，把数据包发送到用户空间  */
		/*封装Netlink消息并发送给用户态ovs-vswitchd进程*/
		error = ovs_dp_upcall(dp, skb, key, &upcall, 0);
		if (unlikely(error))
		{
			kfree_skb(skb);
		}
		else
		{
			/*销毁skb，此skb是copy的一份*/
			consume_skb(skb);
		}

		/*流表未匹配计数*/
		stats_counter = &stats->n_missed;
		goto out;
	}

	/*流统计更新，流表匹配的包数及字节数*/
	ovs_flow_stats_update(flow, key->tp.flags, skb);

	/*获取匹配的流表项的执行动作*/
	sf_acts = rcu_dereference(flow->sf_acts);

	/*根据命中执行action动作*/
	ovs_execute_actions(dp, skb, sf_acts, key);

	/*命中流量统计*/
	stats_counter = &stats->n_hit;

	/*未匹配处理流程*/
out:
	/* Update datapath statistics. */

	// 这是流表匹配失败，数据包发到用户空间后，跳转到该处，  
    // 对处理过的数据包数进行调整（虽然没匹配到流表，但也算是处理掉了一个数据包，所以计数器变量应该增加1） 
	u64_stats_update_begin(&stats->syncp);

	/*收包总数*/
	(*stats_counter)++;

	/*流表查询次数*/	
	stats->n_mask_hit += n_mask_hit;

	u64_stats_update_end(&stats->syncp);
}

/*******************************************************************************
 函数名称  :	ovs_dp_upcall
 功能描述  :	让用户态去查找流表
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	2019-01-21
*******************************************************************************/
int ovs_dp_upcall(struct datapath *dp, struct sk_buff *skb,
		  const struct sw_flow_key *key,
		  const struct dp_upcall_info *upcall_info,
		  uint32_t cutlen)
{
	struct dp_stats_percpu *stats;
	int err;

	if (upcall_info->portid == 0)
	{
		err = -ENOTCONN;
		goto err;
	}

	if (!skb_is_gso(skb))
	{
		/*用户态处理报文，查流表*/
		err = queue_userspace_packet(dp, skb, key, upcall_info, cutlen);
	}
	else
	{
		err = queue_gso_packets(dp, skb, key, upcall_info, cutlen);
	}
	
	if (err)
	{
		goto err;
	}
	
	return 0;

err:

	/*流量统计*/
	stats = this_cpu_ptr(dp->stats_percpu);

	u64_stats_update_begin(&stats->syncp);
	stats->n_lost++;
	u64_stats_update_end(&stats->syncp);

	return err;
}

static int queue_gso_packets(struct datapath *dp, struct sk_buff *skb,
			     const struct sw_flow_key *key,
			     const struct dp_upcall_info *upcall_info,
				 uint32_t cutlen)
{
#ifdef HAVE_SKB_GSO_UDP
	unsigned int gso_type = skb_shinfo(skb)->gso_type;
	struct sw_flow_key later_key;
#endif
	struct sk_buff *segs, *nskb;
	struct ovs_skb_cb ovs_cb;
	int err;

	ovs_cb = *OVS_CB(skb);
	segs = __skb_gso_segment(skb, NETIF_F_SG, false);
	*OVS_CB(skb) = ovs_cb;
	if (IS_ERR(segs))
		return PTR_ERR(segs);
	if (segs == NULL)
		return -EINVAL;
#ifdef HAVE_SKB_GSO_UDP
	if (gso_type & SKB_GSO_UDP) {
		/* The initial flow key extracted by ovs_flow_key_extract()
		 * in this case is for a first fragment, so we need to
		 * properly mark later fragments.
		 */
		later_key = *key;
		later_key.ip.frag = OVS_FRAG_TYPE_LATER;
	}
#endif
	/* Queue all of the segments. */
	skb = segs;
	do {
		*OVS_CB(skb) = ovs_cb;
#ifdef HAVE_SKB_GSO_UDP
		if (gso_type & SKB_GSO_UDP && skb != segs)
			key = &later_key;
#endif
		err = queue_userspace_packet(dp, skb, key, upcall_info, cutlen);
		if (err)
			break;

	} while ((skb = skb->next));

	/* Free all of the segments. */
	skb = segs;
	do {
		nskb = skb->next;
		if (err)
			kfree_skb(skb);
		else
			consume_skb(skb);
	} while ((skb = nskb));
	return err;
}

static size_t upcall_msg_size(const struct dp_upcall_info *upcall_info,
			      unsigned int hdrlen, int actions_attrlen)
{
	size_t size = NLMSG_ALIGN(sizeof(struct ovs_header))
		+ nla_total_size(hdrlen) /* OVS_PACKET_ATTR_PACKET */
		+ nla_total_size(ovs_key_attr_size()) /* OVS_PACKET_ATTR_KEY */
		+ nla_total_size(sizeof(unsigned int)); /* OVS_PACKET_ATTR_LEN */

	/* OVS_PACKET_ATTR_USERDATA */
	if (upcall_info->userdata)
		size += NLA_ALIGN(upcall_info->userdata->nla_len);

	/* OVS_PACKET_ATTR_EGRESS_TUN_KEY */
	if (upcall_info->egress_tun_info)
		size += nla_total_size(ovs_tun_key_attr_size());

	/* OVS_PACKET_ATTR_ACTIONS */
	if (upcall_info->actions_len)
		size += nla_total_size(actions_attrlen);

	/* OVS_PACKET_ATTR_MRU */
	if (upcall_info->mru)
		size += nla_total_size(sizeof(upcall_info->mru));

	return size;
}

static void pad_packet(struct datapath *dp, struct sk_buff *skb)
{
	if (!(dp->user_features & OVS_DP_F_UNALIGNED)) {
		size_t plen = NLA_ALIGN(skb->len) - skb->len;

		if (plen > 0)
			skb_put_zero(skb, plen);
	}
}

/*******************************************************************************
 函数名称  :	queue_userspace_packet
 功能描述  :	用户态报文处理，基于netlink
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	2019-01-21
*******************************************************************************/
static int queue_userspace_packet(struct datapath *dp, struct sk_buff *skb,
				  const struct sw_flow_key *key,
				  const struct dp_upcall_info *upcall_info,
				  uint32_t cutlen)
{
	struct ovs_header *upcall;
	struct sk_buff *nskb = NULL;
	struct sk_buff *user_skb = NULL; /* to be queued to userspace */
	struct nlattr *nla;
	size_t len;
	unsigned int hlen;
	int err, dp_ifindex;

	dp_ifindex = get_dpifindex(dp);
	if (!dp_ifindex)
		return -ENODEV;

	if (skb_vlan_tag_present(skb)) 
	{
		nskb = skb_clone(skb, GFP_ATOMIC);
		if (!nskb)
			return -ENOMEM;

		nskb = __vlan_hwaccel_push_inside(nskb);
		if (!nskb)
			return -ENOMEM;

		skb = nskb;
	}

	if (nla_attr_size(skb->len) > USHRT_MAX) 
	{
		err = -EFBIG;
		goto out;
	}

	/* Complete checksum if needed */
	if (skb->ip_summed == CHECKSUM_PARTIAL &&
	    (err = skb_csum_hwoffload_help(skb, 0)))
	{
		goto out;
	}
	
	/* Older versions of OVS user space enforce alignment of the last
	 * Netlink attribute to NLA_ALIGNTO which would require extensive
	 * padding logic. Only perform zerocopy if padding is not required.
	 */
	if (dp->user_features & OVS_DP_F_UNALIGNED)
	{
		hlen = skb_zerocopy_headlen(skb);
	}
	else
	{
		hlen = skb->len;
	}
	
	len = upcall_msg_size(upcall_info, hlen - cutlen,
			      OVS_CB(skb)->acts_origlen);
	user_skb = genlmsg_new(len, GFP_ATOMIC);
	if (!user_skb) {
		err = -ENOMEM;
		goto out;
	}

	upcall = genlmsg_put(user_skb, 0, 0, &dp_packet_genl_family,
			     0, upcall_info->cmd);
	upcall->dp_ifindex = dp_ifindex;

	err = ovs_nla_put_key(key, key, OVS_PACKET_ATTR_KEY, false, user_skb);
	BUG_ON(err);

	if (upcall_info->userdata)
		__nla_put(user_skb, OVS_PACKET_ATTR_USERDATA,
			  nla_len(upcall_info->userdata),
			  nla_data(upcall_info->userdata));


	if (upcall_info->egress_tun_info) {
		nla = nla_nest_start(user_skb, OVS_PACKET_ATTR_EGRESS_TUN_KEY);
		err = ovs_nla_put_tunnel_info(user_skb,
					      upcall_info->egress_tun_info);
		BUG_ON(err);
		nla_nest_end(user_skb, nla);
	}

	if (upcall_info->actions_len) {
		nla = nla_nest_start(user_skb, OVS_PACKET_ATTR_ACTIONS);
		err = ovs_nla_put_actions(upcall_info->actions,
					  upcall_info->actions_len,
					  user_skb);
		if (!err)
			nla_nest_end(user_skb, nla);
		else
			nla_nest_cancel(user_skb, nla);
	}

	/* Add OVS_PACKET_ATTR_MRU */
	if (upcall_info->mru) {
		if (nla_put_u16(user_skb, OVS_PACKET_ATTR_MRU,
				upcall_info->mru)) {
			err = -ENOBUFS;
			goto out;
		}
		pad_packet(dp, user_skb);
	}

	/* Add OVS_PACKET_ATTR_LEN when packet is truncated */
	if (cutlen > 0) {
		if (nla_put_u32(user_skb, OVS_PACKET_ATTR_LEN,
				skb->len)) {
			err = -ENOBUFS;
			goto out;
		}
		pad_packet(dp, user_skb);
	}

	/* Only reserve room for attribute header, packet data is added
	 * in skb_zerocopy()
	 */
	if (!(nla = nla_reserve(user_skb, OVS_PACKET_ATTR_PACKET, 0))) {
		err = -ENOBUFS;
		goto out;
	}
	nla->nla_len = nla_attr_size(skb->len - cutlen);

	err = skb_zerocopy(user_skb, skb, skb->len - cutlen, hlen);
	if (err)
		goto out;

	/* Pad OVS_PACKET_ATTR_PACKET if linear copy was performed */
	pad_packet(dp, user_skb);

	((struct nlmsghdr *) user_skb->data)->nlmsg_len = user_skb->len;

	/*基于netlink向用户态发消息，用户态，有线程监听消息，一旦有消息，则触发udpif_upcall_handler*/
	err = genlmsg_unicast(ovs_dp_get_net(dp), user_skb, upcall_info->portid);
	user_skb = NULL;
out:
	if (err)
		skb_tx_error(skb);
	kfree_skb(user_skb);
	kfree_skb(nskb);
	return err;
}

/*******************************************************************************
 函数名称  :	ovs_packet_cmd_execute
 功能描述  :	命令行执行
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	2019-01-21
*******************************************************************************/
static int ovs_packet_cmd_execute(struct sk_buff *skb, struct genl_info *info)
{
	struct ovs_header *ovs_header = info->userhdr;
	struct net *net = sock_net(skb->sk);
	struct nlattr **a = info->attrs;
	struct sw_flow_actions *acts;
	struct sk_buff *packet;
	struct sw_flow *flow;
	struct sw_flow_actions *sf_acts;
	struct datapath *dp;
	struct vport *input_vport;
	u16 mru = 0;
	int len;
	int err;
	bool log = !a[OVS_PACKET_ATTR_PROBE];

	err = -EINVAL;
	if (!a[OVS_PACKET_ATTR_PACKET] || !a[OVS_PACKET_ATTR_KEY] ||
	    !a[OVS_PACKET_ATTR_ACTIONS])
		goto err;

	len = nla_len(a[OVS_PACKET_ATTR_PACKET]);
	packet = __dev_alloc_skb(NET_IP_ALIGN + len, GFP_KERNEL);
	err = -ENOMEM;
	if (!packet)
		goto err;
	skb_reserve(packet, NET_IP_ALIGN);

	nla_memcpy(__skb_put(packet, len), a[OVS_PACKET_ATTR_PACKET], len);

	/* Set packet's mru */
	if (a[OVS_PACKET_ATTR_MRU]) {
		mru = nla_get_u16(a[OVS_PACKET_ATTR_MRU]);
		packet->ignore_df = 1;
	}
	OVS_CB(packet)->mru = mru;

	/* Build an sw_flow for sending this packet. */
	flow = ovs_flow_alloc();
	err = PTR_ERR(flow);
	if (IS_ERR(flow))
		goto err_kfree_skb;

	err = ovs_flow_key_extract_userspace(net, a[OVS_PACKET_ATTR_KEY],
					     packet, &flow->key, log);
	if (err)
		goto err_flow_free;

	err = ovs_nla_copy_actions(net, a[OVS_PACKET_ATTR_ACTIONS],
				   &flow->key, &acts, log);
	if (err)
		goto err_flow_free;

	rcu_assign_pointer(flow->sf_acts, acts);
	packet->priority = flow->key.phy.priority;
	packet->mark = flow->key.phy.skb_mark;

	rcu_read_lock();
	dp = get_dp_rcu(net, ovs_header->dp_ifindex);
	err = -ENODEV;
	if (!dp)
		goto err_unlock;

	input_vport = ovs_vport_rcu(dp, flow->key.phy.in_port);
	if (!input_vport)
		input_vport = ovs_vport_rcu(dp, OVSP_LOCAL);

	if (!input_vport)
		goto err_unlock;

	packet->dev = input_vport->dev;
	OVS_CB(packet)->input_vport = input_vport;
	sf_acts = rcu_dereference(flow->sf_acts);

	local_bh_disable();
	err = ovs_execute_actions(dp, packet, sf_acts, &flow->key);
	local_bh_enable();
	rcu_read_unlock();

	ovs_flow_free(flow, false);
	return err;

err_unlock:
	rcu_read_unlock();
err_flow_free:
	ovs_flow_free(flow, false);
err_kfree_skb:
	kfree_skb(packet);
err:
	return err;
}

static const struct nla_policy packet_policy[OVS_PACKET_ATTR_MAX + 1] = {
	[OVS_PACKET_ATTR_PACKET] = { .len = ETH_HLEN },
	[OVS_PACKET_ATTR_KEY] = { .type = NLA_NESTED },
	[OVS_PACKET_ATTR_ACTIONS] = { .type = NLA_NESTED },
	[OVS_PACKET_ATTR_PROBE] = { .type = NLA_FLAG },
	[OVS_PACKET_ATTR_MRU] = { .type = NLA_U16 },
};

/*数据面对packet的操作*/
static struct genl_ops dp_packet_genl_ops[] = {
	{ .cmd = OVS_PACKET_CMD_EXECUTE,
	  .flags = GENL_UNS_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = packet_policy,
	  .doit = ovs_packet_cmd_execute
	}
};

static struct genl_family dp_packet_genl_family __ro_after_init = {
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_PACKET_FAMILY,
	.version = OVS_PACKET_VERSION,
	.maxattr = OVS_PACKET_ATTR_MAX,
	.netnsok = true,
	.parallel_ops = true,
	.ops = dp_packet_genl_ops,
	.n_ops = ARRAY_SIZE(dp_packet_genl_ops),
	.module = THIS_MODULE,
};

/*******************************************************************************
 函数名称  :	get_dp_stats
 功能描述  :	获取数据平台流量统计
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static void get_dp_stats(const struct datapath *dp, struct ovs_dp_stats *stats,
			 struct ovs_dp_megaflow_stats *mega_stats)
{
	int i;

	memset(mega_stats, 0, sizeof(*mega_stats));

	stats->n_flows = ovs_flow_tbl_count(&dp->table);
	mega_stats->n_masks = ovs_flow_tbl_num_masks(&dp->table);

	stats->n_hit = stats->n_missed = stats->n_lost = 0;

	for_each_possible_cpu(i) 
	{
		const struct dp_stats_percpu *percpu_stats;
		struct dp_stats_percpu local_stats;
		unsigned int start;

		percpu_stats = per_cpu_ptr(dp->stats_percpu, i);

		do 
		{
			start = u64_stats_fetch_begin_irq(&percpu_stats->syncp);
			local_stats = *percpu_stats;
		} while (u64_stats_fetch_retry_irq(&percpu_stats->syncp, start));

		stats->n_hit += local_stats.n_hit;
		stats->n_missed += local_stats.n_missed;
		stats->n_lost += local_stats.n_lost;
		mega_stats->n_mask_hit += local_stats.n_mask_hit;
	}
}

static bool should_fill_key(const struct sw_flow_id *sfid, uint32_t ufid_flags)
{
	return ovs_identifier_is_ufid(sfid) &&
	       !(ufid_flags & OVS_UFID_F_OMIT_KEY);
}

static bool should_fill_mask(uint32_t ufid_flags)
{
	return !(ufid_flags & OVS_UFID_F_OMIT_MASK);
}

static bool should_fill_actions(uint32_t ufid_flags)
{
	return !(ufid_flags & OVS_UFID_F_OMIT_ACTIONS);
}

static size_t ovs_flow_cmd_msg_size(const struct sw_flow_actions *acts,
				    const struct sw_flow_id *sfid,
				    uint32_t ufid_flags)
{
	size_t len = NLMSG_ALIGN(sizeof(struct ovs_header));

	/* OVS_FLOW_ATTR_UFID */
	if (sfid && ovs_identifier_is_ufid(sfid))
		len += nla_total_size(sfid->ufid_len);

	/* OVS_FLOW_ATTR_KEY */
	if (!sfid || should_fill_key(sfid, ufid_flags))
		len += nla_total_size(ovs_key_attr_size());

	/* OVS_FLOW_ATTR_MASK */
	if (should_fill_mask(ufid_flags))
		len += nla_total_size(ovs_key_attr_size());

	/* OVS_FLOW_ATTR_ACTIONS */
	if (should_fill_actions(ufid_flags))
		len += nla_total_size(acts->orig_len);

	return len
		+ nla_total_size_64bit(sizeof(struct ovs_flow_stats)) /* OVS_FLOW_ATTR_STATS */
		+ nla_total_size(1) /* OVS_FLOW_ATTR_TCP_FLAGS */
		+ nla_total_size_64bit(8); /* OVS_FLOW_ATTR_USED */
}

/* Called with ovs_mutex or RCU read lock. */
static int ovs_flow_cmd_fill_stats(const struct sw_flow *flow,
				   struct sk_buff *skb)
{
	struct ovs_flow_stats stats;
	__be16 tcp_flags;
	unsigned long used;

	/*流量获取*/
	ovs_flow_stats_get(flow, &stats, &used, &tcp_flags);

	if (used &&
	    nla_put_u64_64bit(skb, OVS_FLOW_ATTR_USED, ovs_flow_used_time(used),
			      OVS_FLOW_ATTR_PAD))
		return -EMSGSIZE;

	if (stats.n_packets &&
	    nla_put_64bit(skb, OVS_FLOW_ATTR_STATS,
			  sizeof(struct ovs_flow_stats), &stats,
			  OVS_FLOW_ATTR_PAD))
		return -EMSGSIZE;

	if ((u8)ntohs(tcp_flags) &&
	     nla_put_u8(skb, OVS_FLOW_ATTR_TCP_FLAGS, (u8)ntohs(tcp_flags)))
		return -EMSGSIZE;

	return 0;
}

/*******************************************************************************
 函数名称  :	ovs_flow_cmd_fill_actions
 功能描述  :	填充flow的action执行动作
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
******************************************************************************/
/* Called with ovs_mutex or RCU read lock. */
static int ovs_flow_cmd_fill_actions(const struct sw_flow *flow,
				     struct sk_buff *skb, int skb_orig_len)
{
	struct nlattr *start;
	int err;

	/* If OVS_FLOW_ATTR_ACTIONS doesn't fit, skip dumping the actions if
	 * this is the first flow to be dumped into 'skb'.  This is unusual for
	 * Netlink but individual action lists can be longer than
	 * NLMSG_GOODSIZE and thus entirely undumpable if we didn't do this.
	 * The userspace caller can always fetch the actions separately if it
	 * really wants them.  (Most userspace callers in fact don't care.)
	 *
	 * This can only fail for dump operations because the skb is always
	 * properly sized for single flows.
	 */
	start = nla_nest_start(skb, OVS_FLOW_ATTR_ACTIONS);
	if (start) {
		const struct sw_flow_actions *sf_acts;

		sf_acts = rcu_dereference_ovsl(flow->sf_acts);
		err = ovs_nla_put_actions(sf_acts->actions,
					  sf_acts->actions_len, skb);

		if (!err)
			nla_nest_end(skb, start);
		else {
			if (skb_orig_len)
				return err;

			nla_nest_cancel(skb, start);
		}
	} else if (skb_orig_len) {
		return -EMSGSIZE;
	}

	return 0;
}

/* Called with ovs_mutex or RCU read lock. */
static int ovs_flow_cmd_fill_info(const struct sw_flow *flow, int dp_ifindex,
				  struct sk_buff *skb, u32 portid,
				  u32 seq, u32 flags, u8 cmd, u32 ufid_flags)
{
	const int skb_orig_len = skb->len;
	struct ovs_header *ovs_header;
	int err;

	ovs_header = genlmsg_put(skb, portid, seq, &dp_flow_genl_family,
				 flags, cmd);
	if (!ovs_header)
		return -EMSGSIZE;

	ovs_header->dp_ifindex = dp_ifindex;

	err = ovs_nla_put_identifier(flow, skb);
	if (err)
		goto error;

	if (should_fill_key(&flow->id, ufid_flags)) {
		err = ovs_nla_put_masked_key(flow, skb);
		if (err)
			goto error;
	}

	if (should_fill_mask(ufid_flags)) {
		err = ovs_nla_put_mask(flow, skb);
		if (err)
			goto error;
	}

	err = ovs_flow_cmd_fill_stats(flow, skb);
	if (err)
		goto error;

	if (should_fill_actions(ufid_flags)) {
		err = ovs_flow_cmd_fill_actions(flow, skb, skb_orig_len);
		if (err)
			goto error;
	}

	genlmsg_end(skb, ovs_header);
	return 0;

error:
	genlmsg_cancel(skb, ovs_header);
	return err;
}

/* May not be called with RCU read lock. */
static struct sk_buff *ovs_flow_cmd_alloc_info(const struct sw_flow_actions *acts,
					       const struct sw_flow_id *sfid,
					       struct genl_info *info,
					       bool always,
					       uint32_t ufid_flags)
{
	struct sk_buff *skb;
	size_t len;

	if (!always && !ovs_must_notify(&dp_flow_genl_family, info,
					GROUP_ID(&ovs_dp_flow_multicast_group)))
		return NULL;

	len = ovs_flow_cmd_msg_size(acts, sfid, ufid_flags);
	skb = genlmsg_new(len, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	return skb;
}

/* Called with ovs_mutex. */
static struct sk_buff *ovs_flow_cmd_build_info(const struct sw_flow *flow,
					       int dp_ifindex,
					       struct genl_info *info, u8 cmd,
					       bool always, u32 ufid_flags)
{
	struct sk_buff *skb;
	int retval;

	skb = ovs_flow_cmd_alloc_info(ovsl_dereference(flow->sf_acts),
				      &flow->id, info, always, ufid_flags);
	if (IS_ERR_OR_NULL(skb))
		return skb;

	retval = ovs_flow_cmd_fill_info(flow, dp_ifindex, skb,
					info->snd_portid, info->snd_seq, 0,
					cmd, ufid_flags);
	BUG_ON(retval < 0);
	return skb;
}

/*******************************************************************************
 函数名称  :	ovs_flow_cmd_new
 功能描述  :	datapath流表更新
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
******************************************************************************/
static int ovs_flow_cmd_new(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sw_flow *flow = NULL, *new_flow;
	struct sw_flow_mask mask;
	struct sk_buff *reply;
	struct datapath *dp;
	struct sw_flow_actions *acts;
	struct sw_flow_match match;
	u32 ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);
	int error;
	bool log = !a[OVS_FLOW_ATTR_PROBE];

	/* Must have key and actions. */
	error = -EINVAL;
	if (!a[OVS_FLOW_ATTR_KEY]) 
	{
		OVS_NLERR(log, "Flow key attr not present in new flow.");
		goto error;
	}

	if (!a[OVS_FLOW_ATTR_ACTIONS]) 
	{
		OVS_NLERR(log, "Flow actions attr not present in new flow.");
		goto error;
	}

	/* Most of the time we need to allocate a new flow, do it before
	 * locking.
	 */

	/*分配sw_flow并初始化*/
	new_flow = ovs_flow_alloc();

	if (IS_ERR(new_flow)) 
	{
		error = PTR_ERR(new_flow);
		goto error;
	}

	/* Extract key. */
	ovs_match_init(&match, &new_flow->key, false, &mask);

	/*解析key和mask，放入sw_flow_match中*/
	error = ovs_nla_get_match(net, &match, a[OVS_FLOW_ATTR_KEY],
				  a[OVS_FLOW_ATTR_MASK], log);
	if (error)
	{
		goto err_kfree_flow;
	}
	
	/* Extract flow identifier. */
	
	error = ovs_nla_get_identifier(&new_flow->id, a[OVS_FLOW_ATTR_UFID],
				       &new_flow->key, log);
	if (error)
	{
		goto err_kfree_flow;
	}
	
	/* unmasked key is needed to match when ufid is not used. */
	/**/
	if (ovs_identifier_is_key(&new_flow->id))
	{
		match.key = new_flow->id.unmasked_key;
	}

	/*根据key和mask->range重新生成掩码后的key放入new_flow->key*/
	ovs_flow_mask_key(&new_flow->key, &new_flow->key, true, &mask);

	/* Validate actions. */
	error = ovs_nla_copy_actions(net, a[OVS_FLOW_ATTR_ACTIONS],
				     &new_flow->key, &acts, log);
	if (error) 
	{
		OVS_NLERR(log, "Flow actions may not be safe on all matching packets.");
		goto err_kfree_flow;
	}

	/*分配发向用户空间的数据区*/
	reply = ovs_flow_cmd_alloc_info(acts, &new_flow->id, info, false,
					ufid_flags);
	if (IS_ERR(reply)) 
	{
		error = PTR_ERR(reply);
		goto err_kfree_acts;
	}

	ovs_lock();

	/*根据dp索引获取dp*/
	dp = get_dp(net, ovs_header->dp_ifindex);
	if (unlikely(!dp)) 
	{
		error = -ENODEV;
		goto err_unlock_ovs;
	}

	/* Check if this is a duplicate flow */
	/*检查flow是否存在*/
	if (ovs_identifier_is_ufid(&new_flow->id))
	{
		flow = ovs_flow_tbl_lookup_ufid(&dp->table, &new_flow->id);
	}
	
	if (!flow)
	{
		flow = ovs_flow_tbl_lookup(&dp->table, &new_flow->key);
	}
	
	if (likely(!flow)) 
	{
		rcu_assign_pointer(new_flow->sf_acts, acts);

		/* Put flow in bucket. */
		/*mask插入到table->instance->mask_array*/
		/*flow插入到table->instance->ti流表实例*/
		/*flow插入到table->instance->ufid_ti*/
		error = ovs_flow_tbl_insert(&dp->table, new_flow, &mask);
		if (unlikely(error)) 
		{
			acts = NULL;
			goto err_unlock_ovs;
		}

		if (unlikely(reply)) 
		{
			error = ovs_flow_cmd_fill_info(new_flow,
						       ovs_header->dp_ifindex,
						       reply, info->snd_portid,
						       info->snd_seq, 0,
						       OVS_FLOW_CMD_NEW,
						       ufid_flags);
			BUG_ON(error < 0);
		}
		ovs_unlock();
	}
	else
	{
		struct sw_flow_actions *old_acts;

		/* Bail out if we're not allowed to modify an existing flow.
		 * We accept NLM_F_CREATE in place of the intended NLM_F_EXCL
		 * because Generic Netlink treats the latter as a dump
		 * request.  We also accept NLM_F_EXCL in case that bug ever
		 * gets fixed.
		 */
		if (unlikely(info->nlhdr->nlmsg_flags & (NLM_F_CREATE
							 | NLM_F_EXCL))) 
		{
			error = -EEXIST;
			goto err_unlock_ovs;
		}

		/* The flow identifier has to be the same for flow updates.
		 * Look for any overlapping flow.
		 */
		if (unlikely(!ovs_flow_cmp(flow, &match))) 
		{
			if (ovs_identifier_is_key(&flow->id))
			{
				flow = ovs_flow_tbl_lookup_exact(&dp->table,
								 &match);
			}
			else /* UFID matches but key is different */
			{
				flow = NULL;
			}

			if (!flow) 
			{
				error = -ENOENT;
				goto err_unlock_ovs;
			}
		}
		/* Update actions. */
		old_acts = ovsl_dereference(flow->sf_acts);
		rcu_assign_pointer(flow->sf_acts, acts);

		if (unlikely(reply))
		{
			error = ovs_flow_cmd_fill_info(flow,
						       ovs_header->dp_ifindex,
						       reply, info->snd_portid,
						       info->snd_seq, 0,
						       OVS_FLOW_CMD_NEW,
						       ufid_flags);
			BUG_ON(error < 0);
		}

		ovs_unlock();

		ovs_nla_free_flow_actions_rcu(old_acts);
		ovs_flow_free(new_flow, false);
	}

	if (reply)
	{
		ovs_notify(&dp_flow_genl_family, &ovs_dp_flow_multicast_group, reply, info);
	}
	
	return 0;

err_unlock_ovs:
	ovs_unlock();
	kfree_skb(reply);
err_kfree_acts:
	ovs_nla_free_flow_actions(acts);
err_kfree_flow:
	ovs_flow_free(new_flow, false);
error:
	return error;
}

/*******************************************************************************
 函数名称  :	get_flow_actions
 功能描述  :	获取流的动作
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
******************************************************************************/
/* Factor out action copy to avoid "Wframe-larger-than=1024" warning. */
static struct sw_flow_actions *get_flow_actions(struct net *net,
						const struct nlattr *a,
						const struct sw_flow_key *key,
						const struct sw_flow_mask *mask,
						bool log)
{
	struct sw_flow_actions *acts;
	struct sw_flow_key masked_key;
	int error;

	ovs_flow_mask_key(&masked_key, key, true, mask);
	error = ovs_nla_copy_actions(net, a, &masked_key, &acts, log);
	if (error) {
		OVS_NLERR(log,
			  "Actions may not be safe on all matching packets");
		return ERR_PTR(error);
	}

	return acts;
}

/* Factor out match-init and action-copy to avoid
 * "Wframe-larger-than=1024" warning. Because mask is only
 * used to get actions, we new a function to save some
 * stack space.
 *
 * If there are not key and action attrs, we return 0
 * directly. In the case, the caller will also not use the
 * match as before. If there is action attr, we try to get
 * actions and save them to *acts. Before returning from
 * the function, we reset the match->mask pointer. Because
 * we should not to return match object with dangling reference
 * to mask.
 * */
static int ovs_nla_init_match_and_action(struct net *net,
					 struct sw_flow_match *match,
					 struct sw_flow_key *key,
					 struct nlattr **a,
					 struct sw_flow_actions **acts,
					 bool log)
{
	struct sw_flow_mask mask;
	int error = 0;

	if (a[OVS_FLOW_ATTR_KEY]) {
		ovs_match_init(match, key, true, &mask);
		error = ovs_nla_get_match(net, match, a[OVS_FLOW_ATTR_KEY],
					  a[OVS_FLOW_ATTR_MASK], log);
		if (error)
			goto error;
	}

	if (a[OVS_FLOW_ATTR_ACTIONS]) {
		if (!a[OVS_FLOW_ATTR_KEY]) {
			OVS_NLERR(log,
				  "Flow key attribute not present in set flow.");
			error = -EINVAL;
			goto error;
		}

		*acts = get_flow_actions(net, a[OVS_FLOW_ATTR_ACTIONS], key,
					 &mask, log);
		if (IS_ERR(*acts)) {
			error = PTR_ERR(*acts);
			goto error;
		}
	}

	/* On success, error is 0. */
error:
	match->mask = NULL;
	return error;
}

/*******************************************************************************
 函数名称  :	ovs_flow_cmd_set
 功能描述  :	流设置
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static int ovs_flow_cmd_set(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sw_flow_key key;
	struct sw_flow *flow;
	struct sk_buff *reply = NULL;
	struct datapath *dp;
	struct sw_flow_actions *old_acts = NULL, *acts = NULL;
	struct sw_flow_match match;
	struct sw_flow_id sfid;
	u32 ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);
	int error = 0;
	bool log = !a[OVS_FLOW_ATTR_PROBE];
	bool ufid_present;

	ufid_present = ovs_nla_get_ufid(&sfid, a[OVS_FLOW_ATTR_UFID], log);
	if (!a[OVS_FLOW_ATTR_KEY] && !ufid_present) {
		OVS_NLERR(log,
			  "Flow set message rejected, Key attribute missing.");
		return -EINVAL;
	}

	/*初始化匹配与回调函数*/
	error = ovs_nla_init_match_and_action(net, &match, &key, a,
					      &acts, log);
	if (error)
		goto error;

	if (acts) {
		/* Can allocate before locking if have acts. */

		/*申请消息结构*/
		reply = ovs_flow_cmd_alloc_info(acts, &sfid, info, false,
						ufid_flags);
		if (IS_ERR(reply)) {
			error = PTR_ERR(reply);
			goto err_kfree_acts;
		}
	}

	ovs_lock();
	dp = get_dp(net, ovs_header->dp_ifindex);
	if (unlikely(!dp)) {
		error = -ENODEV;
		goto err_unlock_ovs;
	}
	/* Check that the flow exists. */
	if (ufid_present)
		flow = ovs_flow_tbl_lookup_ufid(&dp->table, &sfid);
	else
		flow = ovs_flow_tbl_lookup_exact(&dp->table, &match);
	if (unlikely(!flow)) {
		error = -ENOENT;
		goto err_unlock_ovs;
	}

	/* Update actions, if present. */
	if (likely(acts)) {
		old_acts = ovsl_dereference(flow->sf_acts);
		rcu_assign_pointer(flow->sf_acts, acts);

		if (unlikely(reply)) {
			error = ovs_flow_cmd_fill_info(flow,
						       ovs_header->dp_ifindex,
						       reply, info->snd_portid,
						       info->snd_seq, 0,
						       OVS_FLOW_CMD_NEW,
						       ufid_flags);
			BUG_ON(error < 0);
		}
	} else {
		/* Could not alloc without acts before locking. */
		reply = ovs_flow_cmd_build_info(flow, ovs_header->dp_ifindex,
						info, OVS_FLOW_CMD_NEW, false,
						ufid_flags);

		if (unlikely(IS_ERR(reply))) {
			error = PTR_ERR(reply);
			goto err_unlock_ovs;
		}
	}

	/* Clear stats. */
	if (a[OVS_FLOW_ATTR_CLEAR])
		ovs_flow_stats_clear(flow);
	ovs_unlock();

	if (reply)
		ovs_notify(&dp_flow_genl_family, &ovs_dp_flow_multicast_group, reply, info);
	if (old_acts)
		ovs_nla_free_flow_actions_rcu(old_acts);

	return 0;

err_unlock_ovs:
	ovs_unlock();
	kfree_skb(reply);
err_kfree_acts:
	ovs_nla_free_flow_actions(acts);
error:
	return error;
}

static int ovs_flow_cmd_get(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct net *net = sock_net(skb->sk);
	struct sw_flow_key key;
	struct sk_buff *reply;
	struct sw_flow *flow;
	struct datapath *dp;
	struct sw_flow_match match;
	struct sw_flow_id ufid;
	u32 ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);
	int err = 0;
	bool log = !a[OVS_FLOW_ATTR_PROBE];
	bool ufid_present;

	ufid_present = ovs_nla_get_ufid(&ufid, a[OVS_FLOW_ATTR_UFID], log);
	if (a[OVS_FLOW_ATTR_KEY]) {
		ovs_match_init(&match, &key, true, NULL);
		err = ovs_nla_get_match(net, &match, a[OVS_FLOW_ATTR_KEY], NULL,
					log);
	} else if (!ufid_present) {
		OVS_NLERR(log,
			  "Flow get message rejected, Key attribute missing.");
		err = -EINVAL;
	}
	if (err)
		return err;

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		err = -ENODEV;
		goto unlock;
	}

	if (ufid_present)
		flow = ovs_flow_tbl_lookup_ufid(&dp->table, &ufid);
	else
		flow = ovs_flow_tbl_lookup_exact(&dp->table, &match);
	if (!flow) {
		err = -ENOENT;
		goto unlock;
	}

	reply = ovs_flow_cmd_build_info(flow, ovs_header->dp_ifindex, info,
					OVS_FLOW_CMD_NEW, true, ufid_flags);
	if (IS_ERR(reply)) {
		err = PTR_ERR(reply);
		goto unlock;
	}

	ovs_unlock();
	return genlmsg_reply(reply, info);
unlock:
	ovs_unlock();
	return err;
}

static int ovs_flow_cmd_del(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct net *net = sock_net(skb->sk);
	struct sw_flow_key key;
	struct sk_buff *reply;
	struct sw_flow *flow = NULL;
	struct datapath *dp;
	struct sw_flow_match match;
	struct sw_flow_id ufid;
	u32 ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);
	int err;
	bool log = !a[OVS_FLOW_ATTR_PROBE];
	bool ufid_present;

	ufid_present = ovs_nla_get_ufid(&ufid, a[OVS_FLOW_ATTR_UFID], log);
	if (a[OVS_FLOW_ATTR_KEY]) {
		ovs_match_init(&match, &key, true, NULL);
		err = ovs_nla_get_match(net, &match, a[OVS_FLOW_ATTR_KEY],
					NULL, log);
		if (unlikely(err))
			return err;
	}

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (unlikely(!dp)) {
		err = -ENODEV;
		goto unlock;
	}

	if (unlikely(!a[OVS_FLOW_ATTR_KEY] && !ufid_present)) {
		err = ovs_flow_tbl_flush(&dp->table);
		goto unlock;
	}

	if (ufid_present)
		flow = ovs_flow_tbl_lookup_ufid(&dp->table, &ufid);
	else
		flow = ovs_flow_tbl_lookup_exact(&dp->table, &match);
	if (unlikely(!flow)) {
		err = -ENOENT;
		goto unlock;
	}

	ovs_flow_tbl_remove(&dp->table, flow);
	ovs_unlock();

	reply = ovs_flow_cmd_alloc_info(rcu_dereference_raw(flow->sf_acts),
					&flow->id, info, false, ufid_flags);

	if (likely(reply)) {
		if (likely(!IS_ERR(reply))) {
			rcu_read_lock();	/*To keep RCU checker happy. */
			err = ovs_flow_cmd_fill_info(flow, ovs_header->dp_ifindex,
						     reply, info->snd_portid,
						     info->snd_seq, 0,
						     OVS_FLOW_CMD_DEL,
						     ufid_flags);
			rcu_read_unlock();
			BUG_ON(err < 0);
			ovs_notify(&dp_flow_genl_family, &ovs_dp_flow_multicast_group, reply, info);
		} else {
			genl_set_err(&dp_flow_genl_family, sock_net(skb->sk), 0,
				     GROUP_ID(&ovs_dp_flow_multicast_group), PTR_ERR(reply));

		}
	}

	ovs_flow_free(flow, true);
	return 0;
unlock:
	ovs_unlock();
	return err;
}

static int ovs_flow_cmd_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct nlattr *a[__OVS_FLOW_ATTR_MAX];
	struct ovs_header *ovs_header = genlmsg_data(nlmsg_data(cb->nlh));
	struct table_instance *ti;
	struct datapath *dp;
	u32 ufid_flags;
	int err;

	err = genlmsg_parse(cb->nlh, &dp_flow_genl_family, a,
			    OVS_FLOW_ATTR_MAX, flow_policy, NULL);
	if (err)
		return err;
	ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);

	rcu_read_lock();
	dp = get_dp_rcu(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		rcu_read_unlock();
		return -ENODEV;
	}

	ti = rcu_dereference(dp->table.ti);
	for (;;) {
		struct sw_flow *flow;
		u32 bucket, obj;

		bucket = cb->args[0];
		obj = cb->args[1];
		flow = ovs_flow_tbl_dump_next(ti, &bucket, &obj);
		if (!flow)
			break;

		if (ovs_flow_cmd_fill_info(flow, ovs_header->dp_ifindex, skb,
					   NETLINK_CB(cb->skb).portid,
					   cb->nlh->nlmsg_seq, NLM_F_MULTI,
					   OVS_FLOW_CMD_NEW, ufid_flags) < 0)
			break;

		cb->args[0] = bucket;
		cb->args[1] = obj;
	}
	rcu_read_unlock();
	return skb->len;
}

static const struct nla_policy flow_policy[OVS_FLOW_ATTR_MAX + 1] = {
	[OVS_FLOW_ATTR_KEY] = { .type = NLA_NESTED },
	[OVS_FLOW_ATTR_MASK] = { .type = NLA_NESTED },
	[OVS_FLOW_ATTR_ACTIONS] = { .type = NLA_NESTED },
	[OVS_FLOW_ATTR_CLEAR] = { .type = NLA_FLAG },
	[OVS_FLOW_ATTR_PROBE] = { .type = NLA_FLAG },
	[OVS_FLOW_ATTR_UFID] = { .type = NLA_UNSPEC, .len = 1 },
	[OVS_FLOW_ATTR_UFID_FLAGS] = { .type = NLA_U32 },
};

/*流全局操作函数,对flow流表的操作*/
static struct genl_ops dp_flow_genl_ops[] = 
{
	{ .cmd = OVS_FLOW_CMD_NEW,
	  .flags = GENL_UNS_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_new
	},
	{ .cmd = OVS_FLOW_CMD_DEL,
	  .flags = GENL_UNS_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_del
	},
	{ .cmd = OVS_FLOW_CMD_GET,
	  .flags = 0,		    /* OK for unprivileged users. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_get,
	  .dumpit = ovs_flow_cmd_dump
	},
	{ .cmd = OVS_FLOW_CMD_SET,
	  .flags = GENL_UNS_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_set,
	},
};

/*流全局*/
static struct genl_family dp_flow_genl_family __ro_after_init = 
{
	.hdrsize      = sizeof(struct ovs_header),
	.name 	      = OVS_FLOW_FAMILY,
	.version      = OVS_FLOW_VERSION,
	.maxattr      = OVS_FLOW_ATTR_MAX,
	.netnsok      = true,
	.parallel_ops = true,
	.ops 	      = dp_flow_genl_ops,
	.n_ops 	      = ARRAY_SIZE(dp_flow_genl_ops),
	.mcgrps       = &ovs_dp_flow_multicast_group,
	.n_mcgrps 	  = 1,
	.module       = THIS_MODULE,
};


/*******************************************************************************
 函数名称  :	ovs_dp_cmd_msg_size
 功能描述  :	网桥消息size计算
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static size_t ovs_dp_cmd_msg_size(void)
{
	size_t msgsize = NLMSG_ALIGN(sizeof(struct ovs_header));

	msgsize += nla_total_size(IFNAMSIZ);

	/*网桥流量统计size*/
	msgsize += nla_total_size_64bit(sizeof(struct ovs_dp_stats));

	/*网桥mega流量统计size*/
	msgsize += nla_total_size_64bit(sizeof(struct ovs_dp_megaflow_stats));

	/*用户特征size*/
	msgsize += nla_total_size(sizeof(u32)); /* OVS_DP_ATTR_USER_FEATURES */

	return msgsize;
}

/* Called with ovs_mutex. */
/*******************************************************************************
 函数名称  :	ovs_dp_cmd_fill_info
 功能描述  :	填充netlink消息
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static int ovs_dp_cmd_fill_info(struct datapath *dp, struct sk_buff *skb,
				u32 portid, u32 seq, u32 flags, u8 cmd)
{
	struct ovs_header *ovs_header;
	struct ovs_dp_stats dp_stats;
	struct ovs_dp_megaflow_stats dp_megaflow_stats;
	int err;

	/*填充netlink消息头*/
	ovs_header = genlmsg_put(skb, portid, seq, &dp_datapath_genl_family,
				   flags, cmd);
	if (!ovs_header)
		goto error;

	ovs_header->dp_ifindex = get_dpifindex(dp);

	err = nla_put_string(skb, OVS_DP_ATTR_NAME, ovs_dp_name(dp));
	if (err)
		goto nla_put_failure;

	/*获取网桥上流量与megaflow流量*/
	get_dp_stats(dp, &dp_stats, &dp_megaflow_stats);
	if (nla_put_64bit(skb, OVS_DP_ATTR_STATS, sizeof(struct ovs_dp_stats),
			  &dp_stats, OVS_DP_ATTR_PAD))
		goto nla_put_failure;

	if (nla_put_64bit(skb, OVS_DP_ATTR_MEGAFLOW_STATS,
			  sizeof(struct ovs_dp_megaflow_stats),
			  &dp_megaflow_stats, OVS_DP_ATTR_PAD))
		goto nla_put_failure;

	if (nla_put_u32(skb, OVS_DP_ATTR_USER_FEATURES, dp->user_features))
		goto nla_put_failure;

	/*发送netlink消息*/
	genlmsg_end(skb, ovs_header);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, ovs_header);
error:
	return -EMSGSIZE;
}


/*******************************************************************************
 函数名称  :	ovs_dp_cmd_alloc_info
 功能描述  :	消息发送到用户空间缓冲申请
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static struct sk_buff *ovs_dp_cmd_alloc_info(void)
{
	return genlmsg_new(ovs_dp_cmd_msg_size(), GFP_KERNEL);
}

/* Called with rcu_read_lock or ovs_mutex. */
/*******************************************************************************
 函数名称  :	lookup_datapath
 功能描述  :	查询网桥
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static struct datapath *lookup_datapath(struct net *net,
					const struct ovs_header *ovs_header,
					struct nlattr *a[OVS_DP_ATTR_MAX + 1])
{
	struct datapath *dp;

	/*获取net上的网桥*/
	if (!a[OVS_DP_ATTR_NAME])
	{
		dp = get_dp(net, ovs_header->dp_ifindex);
	}
	else
	{
		struct vport *vport;

		/*查询虚拟端口获取网桥*/
		vport = ovs_vport_locate(net, nla_data(a[OVS_DP_ATTR_NAME]));
		dp = vport && vport->port_no == OVSP_LOCAL ? vport->dp : NULL;
	}

	return dp ? dp : ERR_PTR(-ENODEV);
}

/*******************************************************************************
 函数名称  :	ovs_dp_reset_user_features
 功能描述  :	重设用户特征
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static void ovs_dp_reset_user_features(struct sk_buff *skb, struct genl_info *info)
{
	struct datapath *dp;

	/*查找网桥*/
	dp = lookup_datapath(sock_net(skb->sk), info->userhdr, info->attrs);
	if (IS_ERR(dp))
		return;

	WARN(dp->user_features, "Dropping previously announced user features\n");
	dp->user_features = 0;
}

static void ovs_dp_change(struct datapath *dp, struct nlattr *a[])
{
	if (a[OVS_DP_ATTR_USER_FEATURES])
		dp->user_features = nla_get_u32(a[OVS_DP_ATTR_USER_FEATURES]);
}

/*******************************************************************************
 函数名称  :	ovs_dp_cmd_new
 功能描述  :	网桥创建
 输入参数  :    info--netlink信息
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static int ovs_dp_cmd_new(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;          /*netlink数据部分*/
	struct vport_parms parms;
	struct sk_buff *reply;
	struct datapath *dp;
	struct vport *vport;
	struct ovs_net *ovs_net;
	int err, i;

	/**/
	err = -EINVAL;
	if (!a[OVS_DP_ATTR_NAME] || !a[OVS_DP_ATTR_UPCALL_PID])
		goto err;

	/*netlink消息传递缓冲区申请*/
	reply = ovs_dp_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	err = -ENOMEM;

	/*网桥结构申请*/
	dp = kzalloc(sizeof(*dp), GFP_KERNEL);
	if (dp == NULL)
		goto err_free_reply;

	/*网桥net赋值，报文的net赋值给网桥net*/
	ovs_dp_set_net(dp, sock_net(skb->sk));

	/* Allocate table. */
	/*网桥流表申请*/
	err = ovs_flow_tbl_init(&dp->table);
	if (err)
		goto err_free_dp;

	/*申请每CPU流量*/
	dp->stats_percpu = netdev_alloc_pcpu_stats(struct dp_stats_percpu);
	if (!dp->stats_percpu) {
		err = -ENOMEM;
		goto err_destroy_table;
	}

	/*1024个端口链表*/
	dp->ports = kmalloc(DP_VPORT_HASH_BUCKETS * sizeof(struct hlist_head),
			    GFP_KERNEL);
	if (!dp->ports)
	{
		err = -ENOMEM;
		goto err_destroy_percpu;
	}

	/*网桥上1024 个虚拟端口链表初始化*/
	for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++)
		INIT_HLIST_HEAD(&dp->ports[i]);

	/*1024个meter链表申请初始化*/
	err = ovs_meters_init(dp);
	if (err)
		goto err_destroy_ports_array;

	/* Set up our datapath device. */
	/*netlink参数*/
	parms.name = nla_data(a[OVS_DP_ATTR_NAME]);
	parms.type = OVS_VPORT_TYPE_INTERNAL;
	parms.options = NULL;
	parms.dp = dp;
	parms.port_no = OVSP_LOCAL;
	parms.upcall_portids = a[OVS_DP_ATTR_UPCALL_PID];

	/*网桥使用特征获取*/
	ovs_dp_change(dp, a);

	/* So far only local changes have been made, now need the lock. */
	ovs_lock();

	/*自带新端口，创建新端口*/
	vport = new_vport(&parms);
	if (IS_ERR(vport)) 
	{
		err = PTR_ERR(vport);
		if (err == -EBUSY)
		{
			err = -EEXIST;
		}
		
		if (err == -EEXIST) 
		{
			/* An outdated user space instance that does not understand
			 * the concept of user_features has attempted to create a new
			 * datapath and is likely to reuse it. Drop all user features.
			 */
			if (info->genlhdr->version < OVS_DP_VER_FEATURES)
			{	/*重设使用特征*/
				ovs_dp_reset_user_features(skb, info);
			}
		}

		goto err_destroy_meters;
	}

	/*netlink信息填充*/
	err = ovs_dp_cmd_fill_info(dp, reply, info->snd_portid, info->snd_seq, 0, OVS_DP_CMD_NEW);
	BUG_ON(err < 0);

	/*网桥添加到net下网桥链*/
	ovs_net = net_generic(ovs_dp_get_net(dp), ovs_net_id);
	list_add_tail_rcu(&dp->list_node, &ovs_net->dps);

	ovs_unlock();

	/*添加事件提醒*/
	ovs_notify(&dp_datapath_genl_family, &ovs_dp_datapath_multicast_group, reply, info);
	return 0;

err_destroy_meters:
	ovs_unlock();
	ovs_meters_exit(dp);
err_destroy_ports_array:
	kfree(dp->ports);
err_destroy_percpu:
	free_percpu(dp->stats_percpu);
err_destroy_table:
	ovs_flow_tbl_destroy(&dp->table);
err_free_dp:
	kfree(dp);
err_free_reply:
	kfree_skb(reply);
err:
	return err;
}

/* Called with ovs_mutex. */
/*******************************************************************************
 函数名称  :	__dp_destroy
 功能描述  :	网桥销毁
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static void __dp_destroy(struct datapath *dp)
{
	int i;

	/*遍历网桥虚拟端口链*/
	for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++) {
		struct vport *vport;
		struct hlist_node *n;

		/*删除虚拟端口*/
		hlist_for_each_entry_safe(vport, n, &dp->ports[i], dp_hash_node)
			if (vport->port_no != OVSP_LOCAL)
				ovs_dp_detach_port(vport);
	}

	list_del_rcu(&dp->list_node);

	/* OVSP_LOCAL is datapath internal port. We need to make sure that
	 * all ports in datapath are destroyed first before freeing datapath.
	 */
	 
	/*分离虚拟端口*/
	ovs_dp_detach_port(ovs_vport_ovsl(dp, OVSP_LOCAL));

	/* RCU destroy the flow table */
	call_rcu(&dp->rcu, destroy_dp_rcu);
}

/*******************************************************************************
 函数名称  :	ovs_dp_cmd_del
 功能描述  :	网桥创建
 输入参数  :	info--netlink信息
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static int ovs_dp_cmd_del(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply;
	struct datapath *dp;
	int err;

	/*netlink信息结构申请*/
	reply = ovs_dp_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	ovs_lock();

	/*net链获取网桥*/
	dp = lookup_datapath(sock_net(skb->sk), info->userhdr, info->attrs);
	err = PTR_ERR(dp);
	if (IS_ERR(dp))
		goto err_unlock_free;

	/*填充netlink消息*/
	err = ovs_dp_cmd_fill_info(dp, reply, info->snd_portid,
				   info->snd_seq, 0, OVS_DP_CMD_DEL);
	BUG_ON(err < 0);

	/*消耗网桥*/
	__dp_destroy(dp);
	ovs_unlock();

	ovs_notify(&dp_datapath_genl_family, &ovs_dp_datapath_multicast_group, reply, info);
	return 0;

err_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

/*******************************************************************************
 函数名称  :	ovs_dp_cmd_set
 功能描述  :	网桥设置
 输入参数  :	info--netlink信息
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static int ovs_dp_cmd_set(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply;
	struct datapath *dp;
	int err;

	reply = ovs_dp_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	ovs_lock();

	/*查询网桥*/
	dp = lookup_datapath(sock_net(skb->sk), info->userhdr, info->attrs);
	err = PTR_ERR(dp);
	if (IS_ERR(dp))
		goto err_unlock_free;

	ovs_dp_change(dp, info->attrs);

	/*填充netlink消息*/
	err = ovs_dp_cmd_fill_info(dp, reply, info->snd_portid,
				   info->snd_seq, 0, OVS_DP_CMD_NEW);
	BUG_ON(err < 0);

	ovs_unlock();

	ovs_notify(&dp_datapath_genl_family, &ovs_dp_datapath_multicast_group, reply, info);
	return 0;

err_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

/*******************************************************************************
 函数名称  :	ovs_dp_cmd_get
 功能描述  :	获取网桥
 输入参数  :	info--netlink信息
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static int ovs_dp_cmd_get(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply;
	struct datapath *dp;
	int err;

	/*申请netlink消息*/
	reply = ovs_dp_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	ovs_lock();

	/*查询网桥*/
	dp = lookup_datapath(sock_net(skb->sk), info->userhdr, info->attrs);
	if (IS_ERR(dp)) {
		err = PTR_ERR(dp);
		goto err_unlock_free;
	}

	/*填充netlink消息*/
	err = ovs_dp_cmd_fill_info(dp, reply, info->snd_portid,
				   info->snd_seq, 0, OVS_DP_CMD_NEW);
	BUG_ON(err < 0);
	ovs_unlock();

	/**/
	return genlmsg_reply(reply, info);

err_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

/*******************************************************************************
 函数名称  :	ovs_dp_cmd_dump
 功能描述  :	网桥删除命令
 输入参数  :	info--netlink信息
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static int ovs_dp_cmd_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct ovs_net *ovs_net = net_generic(sock_net(skb->sk), ovs_net_id);
	struct datapath *dp;
	int skip = cb->args[0];
	int i = 0;

	ovs_lock();

	/*遍历网桥*/
	list_for_each_entry(dp, &ovs_net->dps, list_node) {

		/*网桥new命令*/
		if (i >= skip &&
		    ovs_dp_cmd_fill_info(dp, skb, NETLINK_CB(cb->skb).portid,
					 cb->nlh->nlmsg_seq, NLM_F_MULTI,
					 OVS_DP_CMD_NEW) < 0)
			break;
		i++;
	}
	ovs_unlock();

	cb->args[0] = i;

	return skb->len;
}

/*网桥策略*/
static const struct nla_policy datapath_policy[OVS_DP_ATTR_MAX + 1] = 
{
	[OVS_DP_ATTR_NAME] = { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
	[OVS_DP_ATTR_UPCALL_PID] = { .type = NLA_U32 },
	[OVS_DP_ATTR_USER_FEATURES] = { .type = NLA_U32 },
};

/*网桥netlink操作函数*/
static struct genl_ops dp_datapath_genl_ops[] = {
	{ .cmd = OVS_DP_CMD_NEW,
	  .flags = GENL_UNS_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = datapath_policy,
	  .doit = ovs_dp_cmd_new
	},
	{ .cmd = OVS_DP_CMD_DEL,
	  .flags = GENL_UNS_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = datapath_policy,
	  .doit = ovs_dp_cmd_del
	},
	{ .cmd = OVS_DP_CMD_GET,
	  .flags = 0,		    /* OK for unprivileged users. */
	  .policy = datapath_policy,
	  .doit = ovs_dp_cmd_get,
	  .dumpit = ovs_dp_cmd_dump
	},
	{ .cmd = OVS_DP_CMD_SET,
	  .flags = GENL_UNS_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = datapath_policy,
	  .doit = ovs_dp_cmd_set,
	},
};

/*netlink协议族信息及操作函数*/
static struct genl_family dp_datapath_genl_family __ro_after_init = {
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_DATAPATH_FAMILY,
	.version = OVS_DATAPATH_VERSION,
	.maxattr = OVS_DP_ATTR_MAX,
	.netnsok = true,
	.parallel_ops = true,
	.ops = dp_datapath_genl_ops,
	.n_ops = ARRAY_SIZE(dp_datapath_genl_ops),
	.mcgrps = &ovs_dp_datapath_multicast_group,
	.n_mcgrps = 1,
	.module = THIS_MODULE,
};

/*******************************************************************************
 函数名称  :	ovs_vport_cmd_build_info
 功能描述  :	查询虚拟端口
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
/* Called with ovs_mutex or RCU read lock. */
static int ovs_vport_cmd_fill_info(struct vport *vport, struct sk_buff *skb,
				   struct net *net, u32 portid, u32 seq,
				   u32 flags, u8 cmd)
{
	struct ovs_header *ovs_header;
	struct ovs_vport_stats vport_stats;
	int err;

	/*netlink填充消息头*/
	ovs_header = genlmsg_put(skb, portid, seq, &dp_vport_genl_family,
				 flags, cmd);
	if (!ovs_header)
		return -EMSGSIZE;

	/*网桥index*/
	ovs_header->dp_ifindex = get_dpifindex(vport->dp);

	if (nla_put_u32(skb, OVS_VPORT_ATTR_PORT_NO, vport->port_no) ||
	    nla_put_u32(skb, OVS_VPORT_ATTR_TYPE, vport->ops->type) ||
	    nla_put_string(skb, OVS_VPORT_ATTR_NAME,
			   ovs_vport_name(vport)) ||
	    nla_put_u32(skb, OVS_VPORT_ATTR_IFINDEX, vport->dev->ifindex))
		goto nla_put_failure;

#ifdef HAVE_PEERNET2ID_ALLOC
	if (!net_eq(net, dev_net(vport->dev))) {
		int id = peernet2id_alloc(net, dev_net(vport->dev));

		if (nla_put_s32(skb, OVS_VPORT_ATTR_NETNSID, id))
			goto nla_put_failure;
	}

#endif

	/*获取流量*/
	ovs_vport_get_stats(vport, &vport_stats);
	if (nla_put_64bit(skb, OVS_VPORT_ATTR_STATS,
			  sizeof(struct ovs_vport_stats), &vport_stats,
			  OVS_VPORT_ATTR_PAD))
		goto nla_put_failure;

	/*获取netlink upcall ID*/
	if (ovs_vport_get_upcall_portids(vport, skb))
		goto nla_put_failure;

	/*获取虚拟端口操作函数*/
	err = ovs_vport_get_options(vport, skb);
	if (err == -EMSGSIZE)
		goto error;

	genlmsg_end(skb, ovs_header);
	return 0;

nla_put_failure:
	err = -EMSGSIZE;
error:
	genlmsg_cancel(skb, ovs_header);
	return err;
}

static struct sk_buff *ovs_vport_cmd_alloc_info(void)
{
	return nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
}

/*******************************************************************************
 函数名称  :	ovs_vport_cmd_build_info
 功能描述  :	查询虚拟端口
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
/* Called with ovs_mutex, only via ovs_dp_notify_wq(). */
struct sk_buff *ovs_vport_cmd_build_info(struct vport *vport, struct net *net,
					 u32 portid, u32 seq, u8 cmd)
{
	struct sk_buff *skb;
	int retval;

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	/*虚拟端口填充命令行*/
	retval = ovs_vport_cmd_fill_info(vport, skb, net, portid, seq, 0, cmd);
	BUG_ON(retval < 0);

	return skb;
}
/*******************************************************************************
 函数名称  :	lookup_vport
 功能描述  :	查询虚拟端口
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
/* Called with ovs_mutex or RCU read lock. */
static struct vport *lookup_vport(struct net *net,
				  const struct ovs_header *ovs_header,
				  struct nlattr *a[OVS_VPORT_ATTR_MAX + 1])
{
	struct datapath *dp;
	struct vport *vport;

	if (a[OVS_VPORT_ATTR_IFINDEX])
	{
		return ERR_PTR(-EOPNOTSUPP);
	}
	
	if (a[OVS_VPORT_ATTR_NAME]) 
	{
		vport = ovs_vport_locate(net, nla_data(a[OVS_VPORT_ATTR_NAME]));
		if (!vport)
			return ERR_PTR(-ENODEV);
		if (ovs_header->dp_ifindex &&
		    ovs_header->dp_ifindex != get_dpifindex(vport->dp))
			return ERR_PTR(-ENODEV);
		return vport;
	}
	else if (a[OVS_VPORT_ATTR_PORT_NO]) 
	{
		u32 port_no = nla_get_u32(a[OVS_VPORT_ATTR_PORT_NO]);

		if (port_no >= DP_MAX_PORTS)
			return ERR_PTR(-EFBIG);

		dp = get_dp(net, ovs_header->dp_ifindex);
		if (!dp)
			return ERR_PTR(-ENODEV);

		vport = ovs_vport_ovsl_rcu(dp, port_no);
		if (!vport)
			return ERR_PTR(-ENODEV);
		return vport;
	}
	else
	{
		return ERR_PTR(-EINVAL);
	}

}

/* Called with ovs_mutex */
/*******************************************************************************
 函数名称  :	update_headroom
 功能描述  :	新建vport
 输入参数  :	skb---报文skb_buff
				info---netlink使用
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static void update_headroom(struct datapath *dp)
{
	unsigned dev_headroom, max_headroom = 0;
	struct net_device *dev;
	struct vport *vport;
	int i;

	/*遍历1024虚拟端口链，获取dev设备获取最大dev_headroom*/
	for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++) {
		hlist_for_each_entry_rcu(vport, &dp->ports[i], dp_hash_node) {
			dev = vport->dev;
			dev_headroom = netdev_get_fwd_headroom(dev);
			if (dev_headroom > max_headroom)
				max_headroom = dev_headroom;
		}
	}

	/*设置headroom 赋值*/
	dp->max_headroom = max_headroom;
	for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++)
		hlist_for_each_entry_rcu(vport, &dp->ports[i], dp_hash_node)
			netdev_set_rx_headroom(vport->dev, max_headroom);
}


/*******************************************************************************
 函数名称  :	ovs_vport_cmd_new
 功能描述  :	新建vport
 输入参数  :    skb---报文skb_buff
 				info---netlink使用
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static int ovs_vport_cmd_new(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct vport_parms parms;
	struct sk_buff *reply;
	struct vport *vport;
	struct datapath *dp;
	u32 port_no;
	int err;

	/*netlink的 name type upcall id ifindex 没设置则非法*/
	if (!a[OVS_VPORT_ATTR_NAME] || !a[OVS_VPORT_ATTR_TYPE] ||
	    !a[OVS_VPORT_ATTR_UPCALL_PID])
		return -EINVAL;
	if (a[OVS_VPORT_ATTR_IFINDEX])
		return -EOPNOTSUPP;

	/*获取netlink端口号*/
	port_no = a[OVS_VPORT_ATTR_PORT_NO]
		? nla_get_u32(a[OVS_VPORT_ATTR_PORT_NO]) : 0;
	if (port_no >= DP_MAX_PORTS)
		return -EFBIG;

	/*获取netlink消息体*/
	reply = ovs_vport_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	ovs_lock();
restart:

	/*从skb上的net获取网桥*/
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	err = -ENODEV;
	if (!dp)
		goto exit_unlock_free;

	if (port_no) 
	{	
		/*获取虚拟端口*/
		vport = ovs_vport_ovsl(dp, port_no);
		err = -EBUSY;
		if (vport)
			goto exit_unlock_free;
	} 
	else 
	{
		/*遍历获取虚拟端口*/
		for (port_no = 1; ; port_no++) 
		{
			if (port_no >= DP_MAX_PORTS) 
			{
				err = -EFBIG;
				goto exit_unlock_free;
			}
			vport = ovs_vport_ovsl(dp, port_no);
			if (!vport)
			{
				break;
			}
		}
	}

	/*填充虚拟端口新建参数*/
	parms.name           = nla_data(a[OVS_VPORT_ATTR_NAME]);
	parms.type           = nla_get_u32(a[OVS_VPORT_ATTR_TYPE]);
	parms.options        = a[OVS_VPORT_ATTR_OPTIONS];
	parms.dp             = dp;
	parms.port_no 		 = port_no;
	parms.upcall_portids = a[OVS_VPORT_ATTR_UPCALL_PID];

	/*新建虚拟端口*/
	vport = new_vport(&parms);
	err = PTR_ERR(vport);
	if (IS_ERR(vport)) 
	{
		/*虚拟端口新建错误重新建立*/
		if (err == -EAGAIN)
			goto restart;
		goto exit_unlock_free;
	}

	/*虚拟端口填充到网桥*/
	err = ovs_vport_cmd_fill_info(vport, reply, genl_info_net(info),
				      info->snd_portid, info->snd_seq, 0,
				      OVS_VPORT_CMD_NEW);
	BUG_ON(err < 0);

	/*获取并设置headroom*/
	if (netdev_get_fwd_headroom(vport->dev) > dp->max_headroom)
		update_headroom(dp);
	else
		netdev_set_rx_headroom(vport->dev, dp->max_headroom);

	ovs_unlock();

	/*虚拟端口*/
	ovs_notify(&dp_vport_genl_family, &ovs_dp_vport_multicast_group, reply, info);
	return 0;

exit_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

/*******************************************************************************
 函数名称  :	ovs_vport_cmd_set
 功能描述  :	设置vport
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static int ovs_vport_cmd_set(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct sk_buff *reply;
	struct vport *vport;
	int err;

	reply = ovs_vport_cmd_alloc_info();
	if (!reply)
	{
		return -ENOMEM;
	}
	
	ovs_lock();

	/*虚拟端口*/
	vport = lookup_vport(sock_net(skb->sk), info->userhdr, a);
	err = PTR_ERR(vport);
	if (IS_ERR(vport))
	{
		goto exit_unlock_free;
	}
	
	if (a[OVS_VPORT_ATTR_TYPE] &&
	    nla_get_u32(a[OVS_VPORT_ATTR_TYPE]) != vport->ops->type) 
	{
		err = -EINVAL;
		goto exit_unlock_free;
	}

	if (a[OVS_VPORT_ATTR_OPTIONS]) 
	{
		err = ovs_vport_set_options(vport, a[OVS_VPORT_ATTR_OPTIONS]);
		if (err)
		{
			goto exit_unlock_free;
		}
	}

	if (a[OVS_VPORT_ATTR_UPCALL_PID]) 
	{
		struct nlattr *ids = a[OVS_VPORT_ATTR_UPCALL_PID];

		err = ovs_vport_set_upcall_portids(vport, ids);
		if (err)
		{
			goto exit_unlock_free;
		}
	}

	err = ovs_vport_cmd_fill_info(vport, reply, genl_info_net(info),
				      info->snd_portid, info->snd_seq, 0,
				      OVS_VPORT_CMD_NEW);
	BUG_ON(err < 0);
	ovs_unlock();

	ovs_notify(&dp_vport_genl_family, &ovs_dp_vport_multicast_group, reply, info);
	return 0;

exit_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

/*******************************************************************************
 函数名称  :    ovs_vport_cmd_del
 功能描述  :    删除端口
 输入参数  :  
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static int ovs_vport_cmd_del(struct sk_buff *skb, struct genl_info *info)
{
	bool must_update_headroom = false;
	struct nlattr **a = info->attrs;
	struct sk_buff *reply;
	struct datapath *dp;
	struct vport *vport;
	int err;

	reply = ovs_vport_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	ovs_lock();
	vport = lookup_vport(sock_net(skb->sk), info->userhdr, a);
	err = PTR_ERR(vport);
	if (IS_ERR(vport))
		goto exit_unlock_free;

	if (vport->port_no == OVSP_LOCAL) {
		err = -EINVAL;
		goto exit_unlock_free;
	}

	err = ovs_vport_cmd_fill_info(vport, reply, genl_info_net(info),
				      info->snd_portid, info->snd_seq, 0,
				      OVS_VPORT_CMD_DEL);
	BUG_ON(err < 0);

	/* the vport deletion may trigger dp headroom update */
	dp = vport->dp;
	if (netdev_get_fwd_headroom(vport->dev) == dp->max_headroom)
		must_update_headroom = true;
	netdev_reset_rx_headroom(vport->dev);
	ovs_dp_detach_port(vport);

	if (must_update_headroom)
		update_headroom(dp);

	ovs_unlock();

	ovs_notify(&dp_vport_genl_family, &ovs_dp_vport_multicast_group, reply, info);
	return 0;

exit_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

/*******************************************************************************
 函数名称  :	ovs_vport_cmd_get
 功能描述  :	新建vport
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static int ovs_vport_cmd_get(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sk_buff *reply;
	struct vport *vport;
	int err;

	reply = ovs_vport_cmd_alloc_info();
	if (!reply)
	{
		return -ENOMEM;
	}
	
	rcu_read_lock();
	vport = lookup_vport(sock_net(skb->sk), ovs_header, a);
	err = PTR_ERR(vport);
	if (IS_ERR(vport))
	{
		goto exit_unlock_free;
	}
	err = ovs_vport_cmd_fill_info(vport, reply, genl_info_net(info),
				      info->snd_portid, info->snd_seq, 0,
				      OVS_VPORT_CMD_NEW);
	BUG_ON(err < 0);
	rcu_read_unlock();

	return genlmsg_reply(reply, info);

exit_unlock_free:
	rcu_read_unlock();
	kfree_skb(reply);
	return err;
}

/*******************************************************************************
 函数名称  :	ovs_vport_cmd_dump
 功能描述  :	虚拟端口命令销毁
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static int ovs_vport_cmd_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct ovs_header *ovs_header = genlmsg_data(nlmsg_data(cb->nlh));
	struct datapath *dp;
	int bucket = cb->args[0], skip = cb->args[1];
	int i, j = 0;

	rcu_read_lock();

	/*网桥*/
	dp = get_dp_rcu(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		rcu_read_unlock();
		return -ENODEV;
	}

	/*遍历网桥虚拟端口链*/
	for (i = bucket; i < DP_VPORT_HASH_BUCKETS; i++) {
		struct vport *vport;

		j = 0;

		/*遍历链表上虚拟端口填充信息*/
		hlist_for_each_entry_rcu(vport, &dp->ports[i], dp_hash_node) {
			if (j >= skip &&
			    ovs_vport_cmd_fill_info(vport, skb,
						    sock_net(skb->sk),
						    NETLINK_CB(cb->skb).portid,
						    cb->nlh->nlmsg_seq,
						    NLM_F_MULTI,
						    OVS_VPORT_CMD_NEW) < 0)
				goto out;

			j++;
		}
		skip = 0;
	}
out:
	rcu_read_unlock();

	cb->args[0] = i;
	cb->args[1] = j;

	return skb->len;
}

static const struct nla_policy vport_policy[OVS_VPORT_ATTR_MAX + 1] = {
	[OVS_VPORT_ATTR_NAME] = { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
	[OVS_VPORT_ATTR_STATS] = { .len = sizeof(struct ovs_vport_stats) },
	[OVS_VPORT_ATTR_PORT_NO] = { .type = NLA_U32 },
	[OVS_VPORT_ATTR_TYPE] = { .type = NLA_U32 },
	[OVS_VPORT_ATTR_UPCALL_PID] = { .type = NLA_U32 },
	[OVS_VPORT_ATTR_OPTIONS] = { .type = NLA_NESTED },
	[OVS_VPORT_ATTR_IFINDEX] = { .type = NLA_U32 },
	[OVS_VPORT_ATTR_NETNSID] = { .type = NLA_S32 },
};

/*虚拟端口操作函数*/
static struct genl_ops dp_vport_genl_ops[] = 
{
	{ .cmd = OVS_VPORT_CMD_NEW,
	  .flags = GENL_UNS_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = vport_policy,
	  .doit = ovs_vport_cmd_new
	},
	{ .cmd = OVS_VPORT_CMD_DEL,
	  .flags = GENL_UNS_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = vport_policy,
	  .doit = ovs_vport_cmd_del
	},
	{ .cmd = OVS_VPORT_CMD_GET,
	  .flags = 0,		    /* OK for unprivileged users. */
	  .policy = vport_policy,
	  .doit = ovs_vport_cmd_get,
	  .dumpit = ovs_vport_cmd_dump
	},
	{ .cmd = OVS_VPORT_CMD_SET,
	  .flags = GENL_UNS_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = vport_policy,
	  .doit = ovs_vport_cmd_set,
	},
};

struct genl_family dp_vport_genl_family __ro_after_init = {
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_VPORT_FAMILY,
	.version = OVS_VPORT_VERSION,
	.maxattr = OVS_VPORT_ATTR_MAX,
	.netnsok = true,
	.parallel_ops = true,
	.ops = dp_vport_genl_ops,
	.n_ops = ARRAY_SIZE(dp_vport_genl_ops),
	.mcgrps = &ovs_dp_vport_multicast_group,
	.n_mcgrps = 1,
	.module = THIS_MODULE,
};

/*dp的genl_family，datapath、vport、flow、packet、meter协议族*/
static struct genl_family *dp_genl_families[] = 
{
	&dp_datapath_genl_family,
	&dp_vport_genl_family,
	&dp_flow_genl_family,
	&dp_packet_genl_family,
	&dp_meter_genl_family,
#if	IS_ENABLED(CONFIG_NETFILTER_CONNCOUNT)
	&dp_ct_limit_genl_family,
#endif
};

static void dp_unregister_genl(int n_families)
{
	int i;

	for (i = 0; i < n_families; i++)
	{
		genl_unregister_family(dp_genl_families[i]);
	}
}


/*******************************************************************************
 函数名称  :	dp_register_genl
 功能描述  :	注册
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static int __init dp_register_genl(void)
{
	int err;
	int i;

	/*遍历数组个数注册协议族*/
	for (i = 0; i < ARRAY_SIZE(dp_genl_families); i++) 
	{
		err = genl_register_family(dp_genl_families[i]);
		if (err)
		{
			goto error;
		}
	}

	return 0;

error:
	dp_unregister_genl(i);
	return err;
}

/*******************************************************************************
 函数名称  :	ovs_init_net
 功能描述  :	初始化网络
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static int __net_init ovs_init_net(struct net *net)
{
	struct ovs_net *ovs_net = net_generic(net, ovs_net_id);

	INIT_LIST_HEAD(&ovs_net->dps);
	INIT_WORK(&ovs_net->dp_notify_work, ovs_dp_notify_wq);

	/*分片初始化*/
	ovs_netns_frags_init(net);
	ovs_netns_frags6_init(net);

	/*控制端初始化*/
	return ovs_ct_init(net);
}


/*******************************************************************************
 函数名称  :	list_vports_from_net
 功能描述  :	列出虚拟端口
 输入参数  :  
 输出参数  :	
 返 回 值  :	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	:	
 修改日期	:	
*******************************************************************************/
static void __net_exit list_vports_from_net(struct net *net, struct net *dnet,
					    struct list_head *head)
{
	struct ovs_net *ovs_net = net_generic(net, ovs_net_id);
	struct datapath *dp;

	/*遍历net上的网桥*/
	list_for_each_entry(dp, &ovs_net->dps, list_node) {
		int i;

		/*遍历1024个虚拟端口链*/
		for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++) {
			struct vport *vport;

			/*遍历虚拟端口链上端口*/
			hlist_for_each_entry(vport, &dp->ports[i], dp_hash_node) {

				if (vport->ops->type != OVS_VPORT_TYPE_INTERNAL)
					continue;

				if (dev_net(vport->dev) == dnet)
					list_add(&vport->detach_list, head);
			}
		}
	}
}

static void __net_exit ovs_exit_net(struct net *dnet)
{
	struct datapath *dp, *dp_next;
	struct ovs_net *ovs_net = net_generic(dnet, ovs_net_id);
	struct vport *vport, *vport_next;
	struct net *net;
	LIST_HEAD(head);

	ovs_netns_frags6_exit(dnet);
	ovs_netns_frags_exit(dnet);
	ovs_ct_exit(dnet);
	ovs_lock();
	list_for_each_entry_safe(dp, dp_next, &ovs_net->dps, list_node)
		__dp_destroy(dp);

#ifdef HAVE_NET_RWSEM
	down_read(&net_rwsem);
#else
	rtnl_lock();
#endif
	for_each_net(net)
		list_vports_from_net(net, dnet, &head);
#ifdef HAVE_NET_RWSEM
	up_read(&net_rwsem);
#else
	rtnl_unlock();
#endif

	/* Detach all vports from given namespace. */
	list_for_each_entry_safe(vport, vport_next, &head, detach_list) {
		list_del(&vport->detach_list);
		ovs_dp_detach_port(vport);
	}

	ovs_unlock();

	cancel_work_sync(&ovs_net->dp_notify_work);
}

/*net操作函数初始化*/
static struct pernet_operations ovs_net_ops = 
{
	.init = ovs_init_net,
	.exit = ovs_exit_net,
	.id   = &ovs_net_id,
	.size = sizeof(struct ovs_net),
};

/*******************************************************************************
 函数名称  :    dp_init
 功能描述  :    数据交换平台初始化
 				注册netlink
 				包含对datapath的操作
 				对虚拟端口vport的操作
 输入参数  :  
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static int __init dp_init(void)
{
	int err;

	BUILD_BUG_ON(sizeof(struct ovs_skb_cb) > FIELD_SIZEOF(struct sk_buff, cb));

	pr_info("Open vSwitch switching datapath %s\n", VERSION);

	/*注册报文offload回调函数*/
	ovs_nsh_init();

	/*初始化action_fifos空间*/
	err = action_fifos_init();
	if (err)
	{
		goto error;
	}

	/*与用户态sdn controller通信netlink初始化,注册netlink操作函数和虚拟端口操作函数*/
	err = ovs_internal_dev_rtnl_link_register();
	if (err)
	{
		goto error_action_fifos_exit;
	}
	
	/*初始化flow模块，申请 flow_cache和 flow_stats_cache*/
	err = ovs_flow_init();
	if (err)
	{
		goto error_unreg_rtnl_link;
	}
	
	/*初始化vport，分配哈希节点空间，vport 数据结构初始化，申请dev_table 1024个虚拟端口链表头*/
	err = ovs_vport_init();
	if (err)
	{
		goto error_flow_exit;
	}
	
	/*注册ovs网络空间类型，注册网络名字空间设备，net操作函数注册*/
	err = register_pernet_device(&ovs_net_ops);
	if (err)
	{
		goto error_vport_exit;
	}

	/*平台初始化*/
	err = compat_init();
	if (err)
	{
		goto error_netns_exit;
	}
	
	/*注册设备通知事件，ovs_dp_device_notifier事件提醒链挂入*/
	err = register_netdevice_notifier(&ovs_dp_device_notifier);
	if (err)
	{
		goto error_compat_exit;
	}

	/*虚拟端口net操作函数注册到虚拟端口操作函数全局链*/
	err = ovs_netdev_init();
	if (err)
	{
		goto error_unreg_notifier;
	}
	
	/*dp_register_genl 初始化 dp 相关的 netlink 的 family和ops*/
	/* 注册netlink处理函数*/
	err = dp_register_genl();
	if (err < 0)
	{
		goto error_unreg_netdev;
	}
	
	return 0;

error_unreg_netdev:
	ovs_netdev_exit();
error_unreg_notifier:
	unregister_netdevice_notifier(&ovs_dp_device_notifier);
error_compat_exit:
	compat_exit();
error_netns_exit:
	unregister_pernet_device(&ovs_net_ops);
error_vport_exit:
	ovs_vport_exit();
error_flow_exit:
	ovs_flow_exit();
error_unreg_rtnl_link:
	ovs_internal_dev_rtnl_link_unregister();
error_action_fifos_exit:
	action_fifos_exit();
error:
	ovs_nsh_cleanup();
	return err;
}

static void dp_cleanup(void)
{
	dp_unregister_genl(ARRAY_SIZE(dp_genl_families));
	ovs_netdev_exit();
	unregister_netdevice_notifier(&ovs_dp_device_notifier);
	compat_exit();
	unregister_pernet_device(&ovs_net_ops);
	rcu_barrier();
	ovs_vport_exit();
	ovs_flow_exit();
	ovs_internal_dev_rtnl_link_unregister();
	action_fifos_exit();
	ovs_nsh_cleanup();
}

/*交换机内核模块初始化*/
module_init(dp_init);
module_exit(dp_cleanup);

MODULE_DESCRIPTION("Open vSwitch switching datapath");
MODULE_LICENSE("GPL");
MODULE_VERSION(VERSION);
MODULE_ALIAS_GENL_FAMILY(OVS_DATAPATH_FAMILY);
MODULE_ALIAS_GENL_FAMILY(OVS_VPORT_FAMILY);
MODULE_ALIAS_GENL_FAMILY(OVS_FLOW_FAMILY);
MODULE_ALIAS_GENL_FAMILY(OVS_PACKET_FAMILY);
MODULE_ALIAS_GENL_FAMILY(OVS_METER_FAMILY);
MODULE_ALIAS_GENL_FAMILY(OVS_CT_LIMIT_FAMILY);
