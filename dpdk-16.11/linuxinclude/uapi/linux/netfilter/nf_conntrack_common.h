/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_NF_CONNTRACK_COMMON_H
#define _UAPI_NF_CONNTRACK_COMMON_H
/* Connection state tracking for netfilter.  This is separated from,
   but required by, the NAT layer; it can also be used by an iptables
   extension. */

/*Netfilter定义的各种连接状态*/

/* 一共5个状态，下面四个，加上IP_CT_RELATED + IP_CT_IS_REPLY */
/* 这些值是skb->nfctinfo使用的 */

enum ip_conntrack_info {
	/* Part of an established connection (either direction). */
	IP_CT_ESTABLISHED,               /*表示连接建立，双向都有包通过时设置

	/* Like NEW, but related to an existing connection, or ICMP error
	   (in either direction). */
	IP_CT_RELATED,                    /*表示一个与其它连接关联的新建连接，本链接是子链接，当前数据包是ORIGINAL方向*/
									  /* 已建立连接的关联连接，或者是ICMP错误(任一方向) */

	/* Started a new connection to track (only
           IP_CT_DIR_ORIGINAL); may be a retransmission. */
	IP_CT_NEW,               /*表示一个新建连接，只有ORIGINAL方向，还没有REPLY方向*/ /* 开始一个新连接; 可能是重传 */

	/* >= this indicates reply direction */
	IP_CT_IS_REPLY,           /* 这个状态一般不单独使用，通常以下面两种方式使用 */

	IP_CT_ESTABLISHED_REPLY = IP_CT_ESTABLISHED + IP_CT_IS_REPLY,	  /* 表示这个数据包对应的连接在两个方向都有数据包通过，
																		并且这是REPLY应答方向数据包。但它表示不了这是第几个数据包，
																		也说明不了这个CT是否是子连接。*/

	
	IP_CT_RELATED_REPLY = IP_CT_RELATED + IP_CT_IS_REPLY,			 /* 这个状态仅在nf_conntrack_attach()函数中设置，用于本机返回REJECT，
																		例如返回一个ICMP目的不可达报文， 或返回一个reset报文。
																		它表示不了这是第几个数据包。*/
	/* No NEW in reply direction. */

	/* Number of distinct IP_CT types. */
	IP_CT_NUMBER,									/* 可表示状态的总数 */ /* IP_CT类型的数量 */

	/* only for userspace compatibility */
#ifndef __KERNEL__
	IP_CT_NEW_REPLY = IP_CT_NUMBER,
#else
	IP_CT_UNTRACKED = 7,							/*不需要建立链接跟踪*/
#endif
};

#define NF_CT_STATE_INVALID_BIT			(1 << 0)
#define NF_CT_STATE_BIT(ctinfo)			(1 << ((ctinfo) % IP_CT_IS_REPLY + 1))
#define NF_CT_STATE_UNTRACKED_BIT		(1 << 6)

/* Bitset representing status of connection. */


/* 这些值是ct->status使用的，链接的状态，是否已建立*/
enum ip_conntrack_status {
	/* It's an expected connection: bit 0 set.  This bit never changed */
	IPS_EXPECTED_BIT = 0,						/* 表示该连接是个子连接 */
	IPS_EXPECTED = (1 << IPS_EXPECTED_BIT),		/*表示一个期望连接*/

	/* We've seen packets both ways: bit 1 set.  Can be set, not unset. */
	IPS_SEEN_REPLY_BIT = 1,                     /* 表示该连接上双方向上都有数据包了，表示一个双向的连接*/
	IPS_SEEN_REPLY = (1 << IPS_SEEN_REPLY_BIT),

	/* Conntrack should never be early-expired. */
	IPS_ASSURED_BIT = 2,						 /* TCP：在三次握手建立完连接后即设定该标志。
													UDP：如果在该连接上的两个方向都有数据包通过，
                                                    再有数据包在该连接上通过时，就设定该标志
                                                    CMP：不设置该标志 
                                                    表示这个连接即使发生超时也不能提早被删除*/
	IPS_ASSURED = (1 << IPS_ASSURED_BIT),

	/* Connection is confirmed: originating packet has left box */
	IPS_CONFIRMED_BIT = 3,						/* 表示该连接已被添加到net->ct.hash表中 */
	IPS_CONFIRMED = (1 << IPS_CONFIRMED_BIT),	/*表示这个连接已经被确认*/

	/* Connection needs src nat in orig dir.  This bit never changed. */
	IPS_SRC_NAT_BIT = 4,						/*在POSTROUTING处，当替换reply tuple完成时, 设置该标记 */
	IPS_SRC_NAT = (1 << IPS_SRC_NAT_BIT),

	/* Connection needs dst nat in orig dir.  This bit never changed. */
	IPS_DST_NAT_BIT = 5,						/* 在PREROUTING处，当替换reply tuple完成时, 设置该标记 */
	IPS_DST_NAT = (1 << IPS_DST_NAT_BIT),

	/* Both together. */
	IPS_NAT_MASK = (IPS_DST_NAT | IPS_SRC_NAT),

	/* Connection needs TCP sequence adjusted. */
	IPS_SEQ_ADJUST_BIT = 6,
	IPS_SEQ_ADJUST = (1 << IPS_SEQ_ADJUST_BIT),

	/* NAT initialization bits. */
	IPS_SRC_NAT_DONE_BIT = 7,						   /* 在POSTROUTING处，已被SNAT处理，并被加入到bysource链中，设置该标记 */
	IPS_SRC_NAT_DONE = (1 << IPS_SRC_NAT_DONE_BIT),

	IPS_DST_NAT_DONE_BIT = 8,						   /* 在PREROUTING处，已被DNAT处理，并被加入到bysource链中，设置该标记 */
	IPS_DST_NAT_DONE = (1 << IPS_DST_NAT_DONE_BIT),

	/* Both together */
	IPS_NAT_DONE_MASK = (IPS_DST_NAT_DONE | IPS_SRC_NAT_DONE),

	/* Connection is dying (removed from lists), can not be unset. */
	IPS_DYING_BIT = 9,									/* 表示该连接正在被释放，内核通过该标志保证正在被释放的ct不会被其它地方再次引用。
														有了这个标志，当某个连接要被删除时，即使它还在net->ct.hash中，也不会再次被引用。*/
	IPS_DYING = (1 << IPS_DYING_BIT),

	/* Connection has fixed timeout. */
	IPS_FIXED_TIMEOUT_BIT = 10,							/* 固定连接超时时间，这将不根据状态修改连接超时时间。
														通过函数nf_ct_refresh_acct()修改超时时间时检查该标志。 */
	IPS_FIXED_TIMEOUT = (1 << IPS_FIXED_TIMEOUT_BIT),

	/* Conntrack is a template */
	IPS_TEMPLATE_BIT = 11,								/* 由CT target进行设置
														   （这个target只能用在raw表中，用于为数据包构建指定ct，并打上该标志），
														   用于表明这个ct是由CT target创建的 */
	IPS_TEMPLATE = (1 << IPS_TEMPLATE_BIT),

	/* Conntrack is a fake untracked entry.  Obsolete and not used anymore */
	IPS_UNTRACKED_BIT = 12,
	IPS_UNTRACKED = (1 << IPS_UNTRACKED_BIT),

	/* Conntrack got a helper explicitly attached via CT target. */
	IPS_HELPER_BIT = 13,
	IPS_HELPER = (1 << IPS_HELPER_BIT),

	/* Conntrack has been offloaded to flow table. */
	IPS_OFFLOAD_BIT = 14,
	IPS_OFFLOAD = (1 << IPS_OFFLOAD_BIT),

	/* Be careful here, modifying these bits can make things messy,
	 * so don't let users modify them directly.
	 */
	IPS_UNCHANGEABLE_MASK = (IPS_NAT_DONE_MASK | IPS_NAT_MASK |
				 IPS_EXPECTED | IPS_CONFIRMED | IPS_DYING |
				 IPS_SEQ_ADJUST | IPS_TEMPLATE | IPS_OFFLOAD),

	__IPS_MAX_BIT = 14,
};

/* Connection tracking event types */

/*时间通知机制*/
enum ip_conntrack_events {
	IPCT_NEW,		/* new conntrack */
	IPCT_RELATED,		/* related conntrack */
	IPCT_DESTROY,		/* destroyed conntrack */
	IPCT_REPLY,		/* connection has seen two-way traffic */
	IPCT_ASSURED,		/* connection status has changed to assured */
	IPCT_PROTOINFO,		/* protocol information has changed */
	IPCT_HELPER,		/* new helper has been set */
	IPCT_MARK,		/* new mark has been set */
	IPCT_SEQADJ,		/* sequence adjustment has changed */
	IPCT_NATSEQADJ = IPCT_SEQADJ,
	IPCT_SECMARK,		/* new security mark has been set */
	IPCT_LABEL,		/* new connlabel has been set */
	IPCT_SYNPROXY,		/* synproxy has been set */
#ifdef __KERNEL__
	__IPCT_MAX
#endif
};

enum ip_conntrack_expect_events {
	IPEXP_NEW,		/* new expectation */
	IPEXP_DESTROY,		/* destroyed expectation */
};

/* expectation flags */
#define NF_CT_EXPECT_PERMANENT		0x1
#define NF_CT_EXPECT_INACTIVE		0x2
#define NF_CT_EXPECT_USERSPACE		0x4


#endif /* _UAPI_NF_CONNTRACK_COMMON_H */
