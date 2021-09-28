
/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2004 Netfilter Core Team <coreteam@netfilter.org>
 * (C) 2006-2012 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/types.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/sysctl.h>
#include <net/route.h>
#include <net/ip.h>

#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/netfilter/ipv4/nf_conntrack_ipv4.h>
#include <net/netfilter/nf_nat_helper.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <net/netfilter/nf_log.h>

static int conntrack4_net_id __read_mostly;
static DEFINE_MUTEX(register_ipv4_hooks);

struct conntrack4_net {
	unsigned int users;
};


/*******************************************************************************
 函数名称 :  ipv4_pkt_to_tuple
 功能描述 :  获取skb源目IP填充tuple
 输入参数 :  skb---skb报文
 			 nhoff---skb数据部分偏移
 			 tuple---存储获取的tuple
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static bool ipv4_pkt_to_tuple(const struct sk_buff *skb, unsigned int nhoff,
			      struct nf_conntrack_tuple *tuple)
{
	/*从IP头获src dst 存入touple*/
	const __be32 *ap;
	__be32 _addrs[2];

	/*skb 数据部分偏过IP头*/
	ap = skb_header_pointer(skb, nhoff + offsetof(struct iphdr, saddr),
				sizeof(u_int32_t) * 2, _addrs);
	if (ap == NULL)
		return false;

	/*填充源、目IP*/
	tuple->src.u3.ip = ap[0];
	tuple->dst.u3.ip = ap[1];

	return true;
}


/*******************************************************************************
 函数名称 :  ipv4_invert_tuple
 功能描述 :  构建三层反向tuple
 输入参数 :  orig---正向tuple
 			 tuple---反向tuple
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static bool ipv4_invert_tuple(struct nf_conntrack_tuple *tuple,
			      const struct nf_conntrack_tuple *orig)
{
	
	/*地址相反*/
	tuple->src.u3.ip = orig->dst.u3.ip;
	
	tuple->dst.u3.ip = orig->src.u3.ip;

	return true;
}


/*******************************************************************************
 函数名称 :  ipv4_get_l4proto
 功能描述 :  获取4层头偏移起始位置与协议号
 输入参数 :  skb---skb报文
 			 nhoff---偏移
 			 dataoff---数据部分偏移
 			 protonum---4层协议号
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static int ipv4_get_l4proto(const struct sk_buff *skb, unsigned int nhoff, unsigned int *dataoff, u_int8_t *protonum)
{
	const struct iphdr *iph;
	struct iphdr _iph;

	/* 获取ip头 */
	iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
	if (iph == NULL)
		return -NF_ACCEPT;

	/* Conntrack defragments packets, we might still see fragments
	 * inside ICMP packets though. */

	/*偏移值*/
	if (iph->frag_off & htons(IP_OFFSET))
		return -NF_ACCEPT;

	/*4层偏移与协议号*/
	*dataoff = nhoff + (iph->ihl << 2);
	*protonum = iph->protocol;

	/* Check bogus IP headers */
	/*非法*/
	if (*dataoff > skb->len) 
	{
		pr_debug("nf_conntrack_ipv4: bogus IPv4 packet: "
			 "nhoff %u, ihl %u, skblen %u\n",
			 nhoff, iph->ihl << 2, skb->len);
		return -NF_ACCEPT;
	}

	return NF_ACCEPT;
}


/*******************************************************************************
 函数名称 :  ipv4_helper
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
static unsigned int ipv4_helper(void *priv,
				struct sk_buff *skb,
				const struct nf_hook_state *state)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	const struct nf_conn_help *help;
	const struct nf_conntrack_helper *helper;

	/* This is where we call the helper: as the packet goes out. */
	/* 获取skb关联的nf_conn */
	ct = nf_ct_get(skb, &ctinfo);

	/* 未关联，或者是 已建立连接的关联连接的响应 */
	if (!ct || ctinfo == IP_CT_RELATED_REPLY)
		return NF_ACCEPT;

	/* 获取help扩展 */
	help = nfct_help(ct);
	if (!help)
		return NF_ACCEPT;

	/* rcu_read_lock()ed by nf_hook_thresh */
	/* 获得helper */
	helper = rcu_dereference(help->helper);

	/* 没有扩展 */
	if (!helper)
		return NF_ACCEPT;

	/* 执行扩展的help函数 */
	return helper->help(skb, skb_network_offset(skb) + ip_hdrlen(skb), ct, ctinfo);
}

/*******************************************************************************
 函数名称 :  ipv4_confirm
 功能描述 :  完成对连接的确认，并且将连接按照方向加入到对应的hash表中；

 			 挂载在NF_IP_POST_ROUTING和NF_IP_LOCAL_IN点上。
 			 该函数主要功能是确认一个链接。对于一个新链接，
 			 在ipv4_conntrack_in()函数中只是创建了struct nf_conn结构，
 			 但并没有将该结构挂载到链接跟踪的Hash表中，
 			 因为此时还不能确定该链接是否会被NF_IP_FORWARD点上的钩子函数过滤掉，
 			 所以将挂载到Hash表的工作放到了ipv4_confirm()函数中。
 			 同时，子链接的helper功能也是在该函数中实现的
 输入参数 :  
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static unsigned int ipv4_confirm(void *priv,
				 struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

	/*获取skb关联的ct，ct结构从下面获得: (struct nf_conn *)skb->nfct; */
	ct = nf_ct_get(skb, &ctinfo);
	
	/* skb没有关联的ct，或者是回应方向报文，不需确认，只有original方向确认，因为过其他hook点时有可能drop*/
	if (!ct || ctinfo == IP_CT_RELATED_REPLY)
		goto out;

	/* adjust seqs for loopback traffic only in outgoing direction */
	 /* 有调整序号标记，且不是环回包，调整序号 */
	 if (test_bit(IPS_SEQ_ADJUST_BIT, &ct->status) && !nf_is_loopback_packet(skb)) 
	 {
		if (!nf_ct_seq_adjust(skb, ct, ctinfo, ip_hdrlen(skb))) 
		{
			NF_CT_STAT_INC_ATOMIC(nf_ct_net(ct), drop);
			
			return NF_DROP;
		}
	}
out:
	/* We've seen it coming out the other side: confirm it */
	/*新建链接跟踪确认*/
	return nf_conntrack_confirm(skb);
}


/*******************************************************************************
 函数名称 :  ipv4_conntrack_in
 功能描述 :  ipv4链接跟踪入口
 输入参数 :  
 			 priv---私有数据
 			 skb---skb报文
 			 state---hook的状态
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static unsigned int ipv4_conntrack_in(void *priv,
				      struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	/*入口*/
	return nf_conntrack_in(state->net, PF_INET, state->hook, skb);
}

static unsigned int ipv4_conntrack_local(void *priv,
					 struct sk_buff *skb,
					 const struct nf_hook_state *state)
{
	if (ip_is_fragment(ip_hdr(skb))) { /* IP_NODEFRAG setsockopt set */
		enum ip_conntrack_info ctinfo;
		struct nf_conn *tmpl;

		tmpl = nf_ct_get(skb, &ctinfo);
		if (tmpl && nf_ct_is_template(tmpl)) {
			/* when skipping ct, clear templates to avoid fooling
			 * later targets/matches
			 */
			skb->_nfct = 0;
			nf_ct_put(tmpl);
		}
		return NF_ACCEPT;
	}

	return nf_conntrack_in(state->net, PF_INET, state->hook, skb);
}

/* Connection tracking may drop packets, but never alters them, so
   make it the first hook. */

/*contrack _in helper confirm 等钩子函数的注册*/
static const struct nf_hook_ops ipv4_conntrack_ops[] = 
{
	{
		/*刚进入netfilter框架在第一个PREROUTEING链上建立连接跟踪*/
		.hook		= ipv4_conntrack_in,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK,
	},
	{
	    /*本机产生的数据包在OUT链上建立连接跟踪*/
		.hook		= ipv4_conntrack_local,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP_PRI_CONNTRACK,
	},
	{
		/*数据包最后出去在POSTROUTING链上连接跟踪确认*/
		.hook		= ipv4_helper,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK_HELPER,
	},
	{
		/*出口去confirm*/
		.hook		= ipv4_confirm,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK_CONFIRM,
	},
	{
		/*在LOCAL_IN链进入本机的数据连接跟踪确认*/
		.hook		= ipv4_helper,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_CONNTRACK_HELPER,
	},
	{
		/*确认链接，链接节点挂入哈希表*/
		.hook		= ipv4_confirm,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_CONNTRACK_CONFIRM,
	},
};

/* Fast function for those who don't want to parse /proc (and I don't
   blame them). */
/* Reversing the socket's dst/src point of view gives us the reply
   mapping. */
static int
getorigdst(struct sock *sk, int optval, void __user *user, int *len)
{
	const struct inet_sock *inet = inet_sk(sk);
	const struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;

	memset(&tuple, 0, sizeof(tuple));

	lock_sock(sk);
	tuple.src.u3.ip = inet->inet_rcv_saddr;
	tuple.src.u.tcp.port = inet->inet_sport;
	tuple.dst.u3.ip = inet->inet_daddr;
	tuple.dst.u.tcp.port = inet->inet_dport;
	tuple.src.l3num = PF_INET;
	tuple.dst.protonum = sk->sk_protocol;
	release_sock(sk);

	/* We only do TCP and SCTP at the moment: is there a better way? */
	if (tuple.dst.protonum != IPPROTO_TCP &&
	    tuple.dst.protonum != IPPROTO_SCTP) {
		pr_debug("SO_ORIGINAL_DST: Not a TCP/SCTP socket\n");
		return -ENOPROTOOPT;
	}

	if ((unsigned int) *len < sizeof(struct sockaddr_in)) {
		pr_debug("SO_ORIGINAL_DST: len %d not %zu\n",
			 *len, sizeof(struct sockaddr_in));
		return -EINVAL;
	}

	h = nf_conntrack_find_get(sock_net(sk), &nf_ct_zone_dflt, &tuple);
	if (h) {
		struct sockaddr_in sin;
		struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);

		sin.sin_family = AF_INET;
		sin.sin_port = ct->tuplehash[IP_CT_DIR_ORIGINAL]
			.tuple.dst.u.tcp.port;
		sin.sin_addr.s_addr = ct->tuplehash[IP_CT_DIR_ORIGINAL]
			.tuple.dst.u3.ip;
		memset(sin.sin_zero, 0, sizeof(sin.sin_zero));

		pr_debug("SO_ORIGINAL_DST: %pI4 %u\n",
			 &sin.sin_addr.s_addr, ntohs(sin.sin_port));
		nf_ct_put(ct);
		if (copy_to_user(user, &sin, sizeof(sin)) != 0)
			return -EFAULT;
		else
			return 0;
	}
	pr_debug("SO_ORIGINAL_DST: Can't find %pI4/%u-%pI4/%u.\n",
		 &tuple.src.u3.ip, ntohs(tuple.src.u.tcp.port),
		 &tuple.dst.u3.ip, ntohs(tuple.dst.u.tcp.port));
	return -ENOENT;
}

#if IS_ENABLED(CONFIG_NF_CT_NETLINK)

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

static int ipv4_tuple_to_nlattr(struct sk_buff *skb,
				const struct nf_conntrack_tuple *tuple)
{
	/* 填充tuple的源目的地址到netlink */
	if (nla_put_in_addr(skb, CTA_IP_V4_SRC, tuple->src.u3.ip) ||
	    nla_put_in_addr(skb, CTA_IP_V4_DST, tuple->dst.u3.ip))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -1;
}

static const struct nla_policy ipv4_nla_policy[CTA_IP_MAX+1] = {
	[CTA_IP_V4_SRC]	= { .type = NLA_U32 },
	[CTA_IP_V4_DST]	= { .type = NLA_U32 },
};

static int ipv4_nlattr_to_tuple(struct nlattr *tb[],
				struct nf_conntrack_tuple *t)
{
	if (!tb[CTA_IP_V4_SRC] || !tb[CTA_IP_V4_DST])
		return -EINVAL;

	t->src.u3.ip = nla_get_in_addr(tb[CTA_IP_V4_SRC]);
	t->dst.u3.ip = nla_get_in_addr(tb[CTA_IP_V4_DST]);

	return 0;
}
#endif

static struct nf_sockopt_ops so_getorigdst = {
	.pf		= PF_INET,
	.get_optmin	= SO_ORIGINAL_DST,
	.get_optmax	= SO_ORIGINAL_DST+1,
	.get		= getorigdst,
	.owner		= THIS_MODULE,
};

static int ipv4_hooks_register(struct net *net)
{
	struct conntrack4_net *cnet = net_generic(net, conntrack4_net_id);
	int err = 0;

	mutex_lock(&register_ipv4_hooks);

	cnet->users++;
	if (cnet->users > 1)
		goto out_unlock;

	 /* defrag钩子函数注册 */
	err = nf_defrag_ipv4_enable(net);
	if (err) {
		cnet->users = 0;
		goto out_unlock;
	}

	/* defrag钩子函数注册 */
	err = nf_register_net_hooks(net, ipv4_conntrack_ops,
				    ARRAY_SIZE(ipv4_conntrack_ops));

	if (err)
		cnet->users = 0;
 out_unlock:
	mutex_unlock(&register_ipv4_hooks);
	return err;
}

static void ipv4_hooks_unregister(struct net *net)
{
	struct conntrack4_net *cnet = net_generic(net, conntrack4_net_id);

	mutex_lock(&register_ipv4_hooks);
	if (cnet->users && (--cnet->users == 0))
		nf_unregister_net_hooks(net, ipv4_conntrack_ops,
					ARRAY_SIZE(ipv4_conntrack_ops));
	mutex_unlock(&register_ipv4_hooks);
}

/*L3 钩子和函数*/
const struct nf_conntrack_l3proto nf_conntrack_l3proto_ipv4 = {
	.l3proto	 = PF_INET,
	.pkt_to_tuple	 = ipv4_pkt_to_tuple,
	.invert_tuple	 = ipv4_invert_tuple,
	.get_l4proto	 = ipv4_get_l4proto,
#if IS_ENABLED(CONFIG_NF_CT_NETLINK)
	.tuple_to_nlattr = ipv4_tuple_to_nlattr,
	.nlattr_to_tuple = ipv4_nlattr_to_tuple,
	.nla_policy	 = ipv4_nla_policy,
	.nla_size	 = NLA_ALIGN(NLA_HDRLEN + sizeof(u32)) + /* CTA_IP_V4_SRC */
			   NLA_ALIGN(NLA_HDRLEN + sizeof(u32)),  /* CTA_IP_V4_DST */
#endif
	.net_ns_get	 = ipv4_hooks_register,
	.net_ns_put	 = ipv4_hooks_unregister,
	.me		 = THIS_MODULE,
};

module_param_call(hashsize, nf_conntrack_set_hashsize, param_get_uint,
		  &nf_conntrack_htable_size, 0600);

MODULE_ALIAS("nf_conntrack-" __stringify(AF_INET));
MODULE_ALIAS("ip_conntrack");
MODULE_LICENSE("GPL");

/*各协议的四层钩子函数注册*/
/* 注册tcp4、udp4和icmp三个L4协议到全局的二维数组nf_ct_protos[][]*/
static const struct nf_conntrack_l4proto * const builtin_l4proto4[] = {
	&nf_conntrack_l4proto_tcp4,
	&nf_conntrack_l4proto_udp4,
	&nf_conntrack_l4proto_icmp,
#ifdef CONFIG_NF_CT_PROTO_DCCP
	&nf_conntrack_l4proto_dccp4,
#endif
#ifdef CONFIG_NF_CT_PROTO_SCTP
	&nf_conntrack_l4proto_sctp4,
#endif
#ifdef CONFIG_NF_CT_PROTO_UDPLITE
	&nf_conntrack_l4proto_udplite4,
#endif
};

/*******************************************************************************
 函数名称 :  ipv4_net_init
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
static int ipv4_net_init(struct net *net)
{
	/*
	注册了和 IPv4 相关的几个 4 层 TCP、UDP、ICMP等协议
	3个l4proto与1个l3proto在pernet的初始化
	*/
	return nf_ct_l4proto_pernet_register(net, builtin_l4proto4,
					     ARRAY_SIZE(builtin_l4proto4));
}

static void ipv4_net_exit(struct net *net)
{
	nf_ct_l4proto_pernet_unregister(net, builtin_l4proto4,
					ARRAY_SIZE(builtin_l4proto4));
}

/*ipv4 操作函数*/
static struct pernet_operations ipv4_net_ops = {
	.init = ipv4_net_init,
	.exit = ipv4_net_exit,
	.id = &conntrack4_net_id,
	.size = sizeof(struct conntrack4_net),
};

/*******************************************************************************
 函数名称 :  nf_conntrack_l3proto_ipv4_init
 功能描述 :  三层协议及钩子函数注册
 输入参数 :  
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static int __init nf_conntrack_l3proto_ipv4_init(void)
{
	int ret = 0;

	need_conntrack();

#if IS_ENABLED(CONFIG_NF_CT_NETLINK)
	if (WARN_ON(nla_policy_len(ipv4_nla_policy, CTA_IP_MAX + 1) !=
	    nf_conntrack_l3proto_ipv4.nla_size))
		return -EINVAL;
#endif
	/*
	用户态与内核态交互通信的方法sockopt，写法也简单.
	缺点就是使用 copy_from_user()/copy_to_user()完成内核和用户的通信， 效率其实不高， 
	多用在传递控制 选项 信息，不适合做大量的数据传输
	*/
	/*初始化socket选项的get方法，可以通过getsockopt()来通过socket得到相应original方向的tuple*/
	ret = nf_register_sockopt(&so_getorigdst);
	if (ret < 0) {
		pr_err("Unable to register netfilter socket option\n");
		return ret;
	}

	/*调用ipv4_net_init 完成相关初始化，基础信息 tuple 钩子回调函数；*/
	ret = register_pernet_subsys(&ipv4_net_ops);
	if (ret < 0) {
		pr_err("nf_conntrack_ipv4: can't register pernet ops\n");
		goto cleanup_sockopt;
	}

	/* nf_conntrack_l4proto 不同协议相关初始化，基础信息 tuple 钩子回调函数；*/
	ret = nf_ct_l4proto_register(builtin_l4proto4,
				     ARRAY_SIZE(builtin_l4proto4));
	if (ret < 0)
		goto cleanup_pernet;

	/* nf_conntrack_l3proto ip相关初始化，基础信息 tuple 钩子回调函数；*/
	ret = nf_ct_l3proto_register(&nf_conntrack_l3proto_ipv4);
	if (ret < 0) {
		pr_err("nf_conntrack_ipv4: can't register ipv4 proto.\n");
		goto cleanup_l4proto;
	}

	return ret;

/*取消注册*/
cleanup_l4proto:
	nf_ct_l4proto_unregister(builtin_l4proto4,
				 ARRAY_SIZE(builtin_l4proto4));
 cleanup_pernet:
	unregister_pernet_subsys(&ipv4_net_ops);
 cleanup_sockopt:
	nf_unregister_sockopt(&so_getorigdst);
	return ret;
}

static void __exit nf_conntrack_l3proto_ipv4_fini(void)
{
	synchronize_net();
	nf_ct_l3proto_unregister(&nf_conntrack_l3proto_ipv4);
	nf_ct_l4proto_unregister(builtin_l4proto4,
				 ARRAY_SIZE(builtin_l4proto4));
	unregister_pernet_subsys(&ipv4_net_ops);
	nf_unregister_sockopt(&so_getorigdst);
}

module_init(nf_conntrack_l3proto_ipv4_init);
module_exit(nf_conntrack_l3proto_ipv4_fini);
