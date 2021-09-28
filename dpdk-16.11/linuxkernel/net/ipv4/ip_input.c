/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) module.
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <alan@lxorguk.ukuu.org.uk>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *
 *
 * Fixes:
 *		Alan Cox	:	Commented a couple of minor bits of surplus code
 *		Alan Cox	:	Undefining IP_FORWARD doesn't include the code
 *					(just stops a compiler warning).
 *		Alan Cox	:	Frames with >=MAX_ROUTE record routes, strict routes or loose routes
 *					are junked rather than corrupting things.
 *		Alan Cox	:	Frames to bad broadcast subnets are dumped
 *					We used to process them non broadcast and
 *					boy could that cause havoc.
 *		Alan Cox	:	ip_forward sets the free flag on the
 *					new frame it queues. Still crap because
 *					it copies the frame but at least it
 *					doesn't eat memory too.
 *		Alan Cox	:	Generic queue code and memory fixes.
 *		Fred Van Kempen :	IP fragment support (borrowed from NET2E)
 *		Gerhard Koerting:	Forward fragmented frames correctly.
 *		Gerhard Koerting: 	Fixes to my fix of the above 8-).
 *		Gerhard Koerting:	IP interface addressing fix.
 *		Linus Torvalds	:	More robustness checks
 *		Alan Cox	:	Even more checks: Still not as robust as it ought to be
 *		Alan Cox	:	Save IP header pointer for later
 *		Alan Cox	:	ip option setting
 *		Alan Cox	:	Use ip_tos/ip_ttl settings
 *		Alan Cox	:	Fragmentation bogosity removed
 *					(Thanks to Mark.Bush@prg.ox.ac.uk)
 *		Dmitry Gorodchanin :	Send of a raw packet crash fix.
 *		Alan Cox	:	Silly ip bug when an overlength
 *					fragment turns up. Now frees the
 *					queue.
 *		Linus Torvalds/ :	Memory leakage on fragmentation
 *		Alan Cox	:	handling.
 *		Gerhard Koerting:	Forwarding uses IP priority hints
 *		Teemu Rantanen	:	Fragment problems.
 *		Alan Cox	:	General cleanup, comments and reformat
 *		Alan Cox	:	SNMP statistics
 *		Alan Cox	:	BSD address rule semantics. Also see
 *					UDP as there is a nasty checksum issue
 *					if you do things the wrong way.
 *		Alan Cox	:	Always defrag, moved IP_FORWARD to the config.in file
 *		Alan Cox	: 	IP options adjust sk->priority.
 *		Pedro Roque	:	Fix mtu/length error in ip_forward.
 *		Alan Cox	:	Avoid ip_chk_addr when possible.
 *	Richard Underwood	:	IP multicasting.
 *		Alan Cox	:	Cleaned up multicast handlers.
 *		Alan Cox	:	RAW sockets demultiplex in the BSD style.
 *		Gunther Mayer	:	Fix the SNMP reporting typo
 *		Alan Cox	:	Always in group 224.0.0.1
 *	Pauline Middelink	:	Fast ip_checksum update when forwarding
 *					Masquerading support.
 *		Alan Cox	:	Multicast loopback error for 224.0.0.1
 *		Alan Cox	:	IP_MULTICAST_LOOP option.
 *		Alan Cox	:	Use notifiers.
 *		Bjorn Ekwall	:	Removed ip_csum (from slhc.c too)
 *		Bjorn Ekwall	:	Moved ip_fast_csum to ip.h (inline!)
 *		Stefan Becker   :       Send out ICMP HOST REDIRECT
 *	Arnt Gulbrandsen	:	ip_build_xmit
 *		Alan Cox	:	Per socket routing cache
 *		Alan Cox	:	Fixed routing cache, added header cache.
 *		Alan Cox	:	Loopback didn't work right in original ip_build_xmit - fixed it.
 *		Alan Cox	:	Only send ICMP_REDIRECT if src/dest are the same net.
 *		Alan Cox	:	Incoming IP option handling.
 *		Alan Cox	:	Set saddr on raw output frames as per BSD.
 *		Alan Cox	:	Stopped broadcast source route explosions.
 *		Alan Cox	:	Can disable source routing
 *		Takeshi Sone    :	Masquerading didn't work.
 *	Dave Bonn,Alan Cox	:	Faster IP forwarding whenever possible.
 *		Alan Cox	:	Memory leaks, tramples, misc debugging.
 *		Alan Cox	:	Fixed multicast (by popular demand 8))
 *		Alan Cox	:	Fixed forwarding (by even more popular demand 8))
 *		Alan Cox	:	Fixed SNMP statistics [I think]
 *	Gerhard Koerting	:	IP fragmentation forwarding fix
 *		Alan Cox	:	Device lock against page fault.
 *		Alan Cox	:	IP_HDRINCL facility.
 *	Werner Almesberger	:	Zero fragment bug
 *		Alan Cox	:	RAW IP frame length bug
 *		Alan Cox	:	Outgoing firewall on build_xmit
 *		A.N.Kuznetsov	:	IP_OPTIONS support throughout the kernel
 *		Alan Cox	:	Multicast routing hooks
 *		Jos Vos		:	Do accounting *before* call_in_firewall
 *	Willy Konynenberg	:	Transparent proxying support
 *
 *
 *
 * To Fix:
 *		IP fragmentation wants rewriting cleanly. The RFC815 algorithm is much more efficient
 *		and could be made very efficient with the addition of some virtual memory hacks to permit
 *		the allocation of a buffer that can then be 'grown' by twiddling page tables.
 *		Output fragmentation wants updating along with the buffer management to use a single
 *		interleaved copy algorithm so that fragmenting has a one copy overhead. Actual packet
 *		output should probably do its own fragmentation at the UDP/RAW layer. TCP shouldn't cause
 *		fragmentation anyway.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#define pr_fmt(fmt) "IPv4: " fmt

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>

#include <linux/net.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/raw.h>
#include <net/checksum.h>
#include <net/inet_ecn.h>
#include <linux/netfilter_ipv4.h>
#include <net/xfrm.h>
#include <linux/mroute.h>
#include <linux/netlink.h>
#include <net/dst_metadata.h>

/*
 *	Process Router Attention IP option (RFC 2113)
 */
bool ip_call_ra_chain(struct sk_buff *skb)
{
	struct ip_ra_chain *ra;
	u8 protocol = ip_hdr(skb)->protocol;
	struct sock *last = NULL;
	struct net_device *dev = skb->dev;
	struct net *net = dev_net(dev);

	for (ra = rcu_dereference(net->ipv4.ra_chain); ra; ra = rcu_dereference(ra->next)) {
		struct sock *sk = ra->sk;

		/* If socket is bound to an interface, only report
		 * the packet if it came  from that interface.
		 */
		if (sk && inet_sk(sk)->inet_num == protocol &&
		    (!sk->sk_bound_dev_if ||
		     sk->sk_bound_dev_if == dev->ifindex)) {
			if (ip_is_fragment(ip_hdr(skb))) {
				if (ip_defrag(net, skb, IP_DEFRAG_CALL_RA_CHAIN))
					return true;
			}
			if (last) {
				struct sk_buff *skb2 = skb_clone(skb, GFP_ATOMIC);
				if (skb2)
					raw_rcv(last, skb2);
			}
			last = sk;
		}
	}

	if (last) {
		raw_rcv(last, skb);
		return true;
	}
	return false;
}

/*******************************************************************************
 函数名称 :  ip_local_deliver_finish
 功能描述 :  处理RAW IP，如果有配置安全策略，则进行IPsec安全检查。
			 根据IP报头的protocol字段，找到对应的L4协议(net_protocol)，
			 调用该协议的接收函数net_protocol->handler()
 输入参数 :  
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static int ip_local_deliver_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	/* 把skb->data指向L4协议头，更新skb->len */
	__skb_pull(skb, skb_network_header_len(skb));

	rcu_read_lock();
	{
		/* L4协议号 */
		int protocol = ip_hdr(skb)->protocol;
		const struct net_protocol *ipprot;
		int raw;

	resubmit:

		/* 处理RAW IP */
		/* 原始套接口，复制一个副本，输出到该套接口 *
		raw = raw_local_deliver(skb, protocol);

		/* 从inet_protos数组中取出对应的net_protocol元素，TCP的为tcp_protocol */
		/* 获取协议处理结构 */
		ipprot = rcu_dereference(inet_protos[protocol]);
		if (ipprot) {
			int ret;

			/* 如果需要检查IPsec安全策略 */
			if (!ipprot->no_policy) {
				if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					kfree_skb(skb);
					goto out;
				}
				nf_reset(skb);
			}
			/* 调用L4协议的处理函数，对于TCP，调用tcp_protocol->handler，为tcp_v4_rcv() */
			/* 协议上层收包处理函数 */
			ret = ipprot->handler(skb);
			if (ret < 0) {
				protocol = -ret;
				goto resubmit;
			}
			__IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
		}
		/* 没有协议接收该数据包 */
		else {
			/* 原始套接口未接收或接收异常 */
			if (!raw) {
				if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					__IP_INC_STATS(net, IPSTATS_MIB_INUNKNOWNPROTOS);
					/* 发送icmp */
					icmp_send(skb, ICMP_DEST_UNREACH,
						  ICMP_PROT_UNREACH, 0);
				}
				 /* 丢包 */
				kfree_skb(skb);
			}
			/* 原始套接口接收 */
			else {
				__IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
				/* 释放包 */
				consume_skb(skb);
			}
		}
	}
 out:
	rcu_read_unlock();

	return 0;
}

/*
 * 	Deliver IP Packets to the higher protocol layers.
 */
/*******************************************************************************
 函数名称 :  ip_local_deliver
 功能描述 :  收到的IP报文需要传递给更上层的协议去处理，
 			 但是如果收到的是IP分片的那么就需要在往上层传递之前先进行重组
 输入参数 :  
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
int ip_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */
	struct net *net = dev_net(skb->dev);

	//check if it is a fragment
	if (ip_is_fragment(ip_hdr(skb))) {
		//fragment recombination
		if (ip_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER))
			return 0;
	}

	/* 调用netfilter的NF_INET_LOCAL_IN的钩子函数，如果此数据包被钩子函数放行，则调用
		 * ip_local_deliver_finish()继续处理。
	*/
	return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN,
		       net, NULL, skb, skb->dev, NULL,
		       ip_local_deliver_finish);
}

static inline bool ip_rcv_options(struct sk_buff *skb)
{
	struct ip_options *opt;
	const struct iphdr *iph;
	struct net_device *dev = skb->dev;

	/* It looks as overkill, because not all
	   IP options require packet mangling.
	   But it is the easiest for now, especially taking
	   into account that combination of IP options
	   and running sniffer is extremely rare condition.
					      --ANK (980813)
	*/
	if (skb_cow(skb, skb_headroom(skb))) {
		__IP_INC_STATS(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	iph = ip_hdr(skb);
	opt = &(IPCB(skb)->opt);
	opt->optlen = iph->ihl*4 - sizeof(struct iphdr);

	if (ip_options_compile(dev_net(dev), opt, skb)) {
		__IP_INC_STATS(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
		goto drop;
	}

	if (unlikely(opt->srr)) {
		struct in_device *in_dev = __in_dev_get_rcu(dev);

		if (in_dev) {
			if (!IN_DEV_SOURCE_ROUTE(in_dev)) {
				if (IN_DEV_LOG_MARTIANS(in_dev))
					net_info_ratelimited("source route option %pI4 -> %pI4\n",
							     &iph->saddr,
							     &iph->daddr);
				goto drop;
			}
		}

		if (ip_options_rcv_srr(skb))
			goto drop;
	}

	return false;
drop:
	return true;
}

 /*******************************************************************************
 函数名称 :  ip_rcv_finish
 功能描述 :  调用ip_router_input函数，进入路由处理环节。
 			 会调用 ip_route_input ip_rcv route，
 			 决定该会被发到本机还是会被转发还是丢弃：

 			 执行完PRE_ROUTING上的钩子函数后，所有钩子都全部返回NF_ACCEPT后，数据包会交由ip_rcv_finish()函数。
			 这个函数主要功能是做路由选择
 输入参数 :  
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static int ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
	int (*edemux)(struct sk_buff *skb);
	struct net_device *dev = skb->dev;
	struct rtable *rt;
	int err;

	/* if ingress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	skb = l3mdev_ip_rcv(skb);
	if (!skb)
		return NET_RX_SUCCESS;

	/* 
			启用了early_demux
			skb路由缓存为空
			skb的sock为空
			不是分片包
	*/
	
	/*
     *  为数据包初始化虚拟路径缓存，它描述了数据包是如何在linux网络中传播的
     */
     //noted:通常从外界接收的数据包,skb->dst不会包含路由信息,暂时还不知道在何处会设置这个字段
     //ip_route_input函数会根据路由表设置路由信息
	if (net->ipv4.sysctl_ip_early_demux &&
	    !skb_dst(skb) &&
	    !skb->sk &&
	    !ip_is_fragment(iph)) {
		const struct net_protocol *ipprot;

		/* 找到上层协议 */
		int protocol = iph->protocol;

		/* 获取协议对应的prot */
		ipprot = rcu_dereference(inet_protos[protocol]);
		/* 找到early_demux函数，如tcp_v4_early_demux */
		if (ipprot && (edemux = READ_ONCE(ipprot->early_demux))) {
			/* 调用该函数，将路由信息缓存到skb->refdst */
			err = edemux(skb);
			if (unlikely(err))
				goto drop_error;
			/* must reload iph, skb->head might have changed */
			/* 重新取ip头 */
			iph = ip_hdr(skb);
		}
	}

	/*
	 *	Initialise the virtual path cache for the packet. It describes
	 *	how the packet travels inside Linux networking.
	 */
	/* 校验路由失败 */
	if (!skb_valid_dst(skb)) {
		/* 查路由 */
		err = ip_route_input_noref(skb, iph->daddr, iph->saddr,
					   iph->tos, dev);
		if (unlikely(err))
			goto drop_error;
	}

#ifdef CONFIG_IP_ROUTE_CLASSID
	if (unlikely(skb_dst(skb)->tclassid)) {
		struct ip_rt_acct *st = this_cpu_ptr(ip_rt_acct);
		u32 idx = skb_dst(skb)->tclassid;
		st[idx&0xFF].o_packets++;
		st[idx&0xFF].o_bytes += skb->len;
		st[(idx>>16)&0xFF].i_packets++;
		st[(idx>>16)&0xFF].i_bytes += skb->len;
	}
#endif

	/* 处理ip选项 */ 
	//如果IP头部大于20字节，则表示IP头部包含IP选项，需要进行选项处理
	if (iph->ihl > 5 && ip_rcv_options(skb))
		goto drop;

	/* 找到路由缓存项 */
	//noted: skb_rtable函数等同于skb_dst函数，获取skb->dst
	rt = skb_rtable(skb);
	if (rt->rt_type == RTN_MULTICAST) {
		__IP_UPD_PO_STATS(net, IPSTATS_MIB_INMCAST, skb->len);
	} else if (rt->rt_type == RTN_BROADCAST) {
		__IP_UPD_PO_STATS(net, IPSTATS_MIB_INBCAST, skb->len);
	} else if (skb->pkt_type == PACKET_BROADCAST ||
		   skb->pkt_type == PACKET_MULTICAST) {
		struct in_device *in_dev = __in_dev_get_rcu(dev);

		/* RFC 1122 3.3.6:
		 *
		 *   When a host sends a datagram to a link-layer broadcast
		 *   address, the IP destination address MUST be a legal IP
		 *   broadcast or IP multicast address.
		 *
		 *   A host SHOULD silently discard a datagram that is received
		 *   via a link-layer broadcast (see Section 2.4) but does not
		 *   specify an IP multicast or broadcast destination address.
		 *
		 * This doesn't explicitly say L2 *broadcast*, but broadcast is
		 * in a way a form of multicast and the most common use case for
		 * this is 802.11 protecting against cross-station spoofing (the
		 * so-called "hole-196" attack) so do it for both.
		 */
		if (in_dev &&
		    IN_DEV_ORCONF(in_dev, DROP_UNICAST_IN_L2_MULTICAST))
			goto drop;
	}

	/* 调用路由项的input函数，可能为ip_local_deliver或者ip_forward */
	//noted: dst_input实际上会调用skb->dst->input(skb).input函数会根据路由信息设置为合适的
    //函数指针，如果是递交到本地的则为ip_local_deliver，若是转发则为ip_forward.
	return dst_input(skb);

drop:
	kfree_skb(skb);
	return NET_RX_DROP;

drop_error:
	if (err == -EXDEV)
		__NET_INC_STATS(net, LINUX_MIB_IPRPFILTER);
	goto drop;
}

/*
 * 	Main IP Receive routine.
 */
 /*******************************************************************************
 函数名称 :  ip_rcv
 功能描述 :  调用第三层协议的接收函数处理该skb包，进入第三层网络层处理
 			 首先会做包括checksum在内的各种检查，如果需要的话会做 IP defragment（分片合并），
 			 最终到达 ip_rcv_finish 函数
 输入参数 :  
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	const struct iphdr *iph;
	struct net *net;
	u32 len;

	/* When the interface is in promisc. mode, drop all the crap
	 * that it receives, do not try to analyse it.
	 */ 

	/* 
     * 当网卡处于混杂模式时，丢掉所有接收到的的垃圾数据，不要试图解析它
     */
     //noted: 其实也就是丢弃掉不是发往本地的数据包。网卡在混杂模式下会接收一切到达网卡的数据，不管目的地mac是否是本网卡
     //noted: 在调用ip_rcv之前，内核会将该数据包交给嗅探器，所以该函数仅丢弃该包
	 
	/* 混杂模式下，非本机包 */
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;

	/* 获取net */
	net = dev_net(dev);

	 //noted:该宏用于内核做一些统计,关于网络层snmp统计的信息，也可以通过netstat 指令看到这些统计值
	__IP_UPD_PO_STATS(net, IPSTATS_MIB_IN, skb->len);

	/* 检查skb共享 */
	//noted: ip_rcv是由netif_receive_skb函数调用，如果嗅探器或者其他的用户对数据包需要进
    //进行处理，则在调用ip_rcv之前，netif_receive_skb会增加skb的引用计数，既该引
    //用计数会大于1。若如此次，则skb_share_check会创建sk_buff的一份拷贝。
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb) {
		__IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
		goto out;
	}

	/* 测试是否可以取得ip头 */
	//noted:pskb_may_pull确保skb->data指向的内存包含的数据至少为IP头部大小，由于每个
    //IP数据包包括IP分片必须包含一个完整的IP头部。如果小于IP头部大小，则缺失
    //的部分将从数据分片中拷贝。这些分片保存在skb_shinfo(skb)->frags[]中。
	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto inhdr_error;

	/* 取ip头 */
	//noted: pskb_may_pull可能会调整skb中的指针，所以需要重新定义IP头部
	iph = ip_hdr(skb);

	/*
	 *	RFC1122: 3.2.1.2 MUST silently discard any IP frame that fails the checksum.
	 *
	 *	Is the datagram acceptable?
	 *
	 *	1.	Length at least the size of an ip header
	 *	2.	Version of 4
	 *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
	 *	4.	Doesn't have a bogus length
	 */

	/* 头部长度不足20 或者版本不是4 */
	/*
     *  RFC1122: 3.2.1.2 必须默默地放弃任何IP帧校验和失败.
     *
     *  数据报可接收?
     *
     *  1.  长度至少是一个ip报头的大小
     *  2.  版本4
     *  3.  校验和正确。(速度优化后,跳过回路校验和)
     *  4.  没有虚假的长度
     */
    //noted: 检测ip首部长度及协议版本
	if (iph->ihl < 5 || iph->version != 4)
		goto inhdr_error;

	BUILD_BUG_ON(IPSTATS_MIB_ECT1PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_1);
	BUILD_BUG_ON(IPSTATS_MIB_ECT0PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_0);
	BUILD_BUG_ON(IPSTATS_MIB_CEPKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_CE);
	__IP_ADD_STATS(net,
		       IPSTATS_MIB_NOECTPKTS + (iph->tos & INET_ECN_MASK),
		       max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

	/* 测试实际应取的ip头 */
	//noted: 确保IP完整的头部包括选项在内存中
	if (!pskb_may_pull(skb, iph->ihl*4))
		goto inhdr_error;

	/* 取ip头 */
	iph = ip_hdr(skb);

	/* 校验和错误 */
	//noted:验证IP头部的校验和
	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto csum_error;

	/* 取总长度 */
	len = ntohs(iph->tot_len);

	/* skb长度比ip包总长度小 */  
	//noted:检测ip报文长度是否小于skb->len
	if (skb->len < len) {
		__IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
		goto drop;
	}
	/* 比头部长度还小 */
	else if (len < (iph->ihl*4))
		goto inhdr_error;

	/* Our transport medium may have padded the buffer out. Now we know it
	 * is IP we can trim to the true length of the frame.
	 * Note this now means skb->len holds ntohs(iph->tot_len).
	 */

	/* 设置总长度为ip包的长度 */
	  /* 我们的传输介质可能填充缓冲区。现在我们知道这是 我们可以从此帧中削减的真实长度的ip帧
     * 注意现在意味着skb->len包括ntohs(iph->tot_len)
     */
	if (pskb_trim_rcsum(skb, len)) {
		__IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
		goto drop;
	}
	/* 取得传输层头部 */ 
	//noted: 设置tcp报头指针
	skb->transport_header = skb->network_header + iph->ihl*4;

	/* Remove any debris in the socket control block */
	/* 重置cb */
	 /* 删除任何套接字控制块碎片 */
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));

	/* 保存输入设备信息 */
	IPCB(skb)->iif = skb->skb_iif;

	/* Must drop socket now because of tproxy. */
	/* 因为tproxy，现在必须丢掉socket */
    //noted: tproxy是iptables的一附加控件，在mangle表的PREROUTING链中使用，不修改数据包包头，
    //直接把数据传递给一个本地socket(即不对数据包进行任何nat操作)。具体百度搜索tproxy
	skb_orphan(skb);

	/* 经过PRE_ROUTING钩子点 */
	//noted: 在做完基本的头校验等工作后，就交由NF_HOOK管理了
    //noted: NF_HOOK在做完PRE_ROUTING的筛选后，PRE_ROUTING点上注册的所有钩子都
    //返回NF_ACCEPT才会执行后面的ip_rcv_finish函数 ，然后继续执行路由等处理
    //如果是本地的就会交给更高层的协议进行处理，如果不是交由本地的就执行FORWARD
	return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING, net, NULL, skb, dev, NULL, ip_rcv_finish);

csum_error:
	__IP_INC_STATS(net, IPSTATS_MIB_CSUMERRORS);
inhdr_error:
	__IP_INC_STATS(net, IPSTATS_MIB_INHDRERRORS);
drop:
	kfree_skb(skb);
out:
	return NET_RX_DROP;
}
