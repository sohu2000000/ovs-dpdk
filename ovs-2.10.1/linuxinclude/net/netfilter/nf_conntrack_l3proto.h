/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C)2003,2004 USAGI/WIDE Project
 *
 * Header for use in defining a given L3 protocol for connection tracking.
 *
 * Author:
 *	Yasuyuki Kozakai @USAGI	<yasuyuki.kozakai@toshiba.co.jp>
 *
 * Derived from include/netfilter_ipv4/ip_conntrack_protocol.h
 */

#ifndef _NF_CONNTRACK_L3PROTO_H
#define _NF_CONNTRACK_L3PROTO_H
#include <linux/netlink.h>
#include <net/netlink.h>
#include <linux/seq_file.h>
#include <net/netfilter/nf_conntrack.h>

/*三层协议填充处理函数，arp ip icmp*/
struct nf_conntrack_l3proto {
	/* L3 Protocol Family number. ex) PF_INET */
	u_int16_t l3proto;								/*三层协议类型*/

	/* size of tuple nlattr, fills a hole */
	u16 nla_size;

	/*
	 * Try to fill in the third arg: nhoff is offset of l3 proto
         * hdr.  Return true if possible.
	 */
	bool (*pkt_to_tuple)(const struct sk_buff *skb, unsigned int nhoff,		/*报文转出tuple*/
			     struct nf_conntrack_tuple *tuple);

	/*
	 * Invert the per-proto part of the tuple: ie. turn xmit into reply.
	 * Some packets can't be inverted: return 0 in that case.
	 */
	bool (*invert_tuple)(struct nf_conntrack_tuple *inverse,				/*报文反向 tuple*/
			     const struct nf_conntrack_tuple *orig);

	/*
	 * Called before tracking. 
	 *	*dataoff: offset of protocol header (TCP, UDP,...) in skb
	 *	*protonum: protocol number
	 */
	int (*get_l4proto)(const struct sk_buff *skb, unsigned int nhoff,		/*获取4层协议*/
			   unsigned int *dataoff, u_int8_t *protonum);

#if IS_ENABLED(CONFIG_NF_CT_NETLINK)
	int (*tuple_to_nlattr)(struct sk_buff *skb,
			       const struct nf_conntrack_tuple *t);
	int (*nlattr_to_tuple)(struct nlattr *tb[],
			       struct nf_conntrack_tuple *t);
	
	const struct nla_policy *nla_policy;
#endif

	/* Called when netns wants to use connection tracking */
	int (*net_ns_get)(struct net *);
	void (*net_ns_put)(struct net *);

	/* Module (if any) which this is connected to. */
	struct module *me;
};

/*nf_ct_l3protos[]数组中的每个元素都赋值为nf_conntrack_l3proto_generic，
即不区分L3协议的处理函数，后续的初始化会为不同的L3协议赋上相应的值*/
/*L3相关函数*/
extern struct nf_conntrack_l3proto __rcu *nf_ct_l3protos[NFPROTO_NUMPROTO];

/* Protocol global registration. */
int nf_ct_l3proto_register(const struct nf_conntrack_l3proto *proto);
void nf_ct_l3proto_unregister(const struct nf_conntrack_l3proto *proto);

const struct nf_conntrack_l3proto *nf_ct_l3proto_find_get(u_int16_t l3proto);

/* Existing built-in protocols */
/*3层协议原始注册结构*/
extern struct nf_conntrack_l3proto nf_conntrack_l3proto_generic;


/*******************************************************************************
 函数名称 :  __nf_ct_l3proto_find
 功能描述 :  报文处理入口
 输入参数 :  
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static inline struct nf_conntrack_l3proto *
__nf_ct_l3proto_find(u_int16_t l3proto)
{
	/*其他三层协议返回默认值*/
	if (unlikely(l3proto >= NFPROTO_NUMPROTO))
		return &nf_conntrack_l3proto_generic;

	/*返回3层协议注册的对应结构*/
	return rcu_dereference(nf_ct_l3protos[l3proto]);
}

#endif /*_NF_CONNTRACK_L3PROTO_H*/
