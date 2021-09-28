/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NETNS_CONNTRACK_H
#define __NETNS_CONNTRACK_H

#include <linux/list.h>
#include <linux/list_nulls.h>
#include <linux/atomic.h>
#include <linux/workqueue.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#ifdef CONFIG_NF_CT_PROTO_DCCP
#include <linux/netfilter/nf_conntrack_dccp.h>
#endif
#ifdef CONFIG_NF_CT_PROTO_SCTP
#include <linux/netfilter/nf_conntrack_sctp.h>
#endif
#include <linux/seqlock.h>

struct ctl_table_header;
struct nf_conntrack_ecache;

/*sysctl */
struct nf_proto_net {
#ifdef CONFIG_SYSCTL
	struct ctl_table_header *ctl_table_header;
	struct ctl_table        *ctl_table;
#endif
	unsigned int		users;
};

struct nf_generic_net {
	struct nf_proto_net pn;
	unsigned int timeout;
};

/*namespace的tcp信息*/
struct nf_tcp_net {
	struct nf_proto_net pn;
	unsigned int timeouts[TCP_CONNTRACK_TIMEOUT_MAX];
	unsigned int tcp_loose;
	unsigned int tcp_be_liberal;
	unsigned int tcp_max_retrans;
};

enum udp_conntrack {
	UDP_CT_UNREPLIED,
	UDP_CT_REPLIED,
	UDP_CT_MAX
};

struct nf_udp_net {
	struct nf_proto_net pn;
	unsigned int timeouts[UDP_CT_MAX];
};

struct nf_icmp_net {
	struct nf_proto_net pn;
	unsigned int timeout;
};

#ifdef CONFIG_NF_CT_PROTO_DCCP
struct nf_dccp_net {
	struct nf_proto_net pn;
	int dccp_loose;
	unsigned int dccp_timeout[CT_DCCP_MAX + 1];
};
#endif

#ifdef CONFIG_NF_CT_PROTO_SCTP
struct nf_sctp_net {
	struct nf_proto_net pn;
	unsigned int timeouts[SCTP_CONNTRACK_MAX];
};
#endif

/*三层*/
struct nf_ip_net {
	struct nf_generic_net   generic;
	struct nf_tcp_net	tcp;
	struct nf_udp_net	udp;
	struct nf_icmp_net	icmp;
	struct nf_icmp_net	icmpv6;
#ifdef CONFIG_NF_CT_PROTO_DCCP
	struct nf_dccp_net	dccp;
#endif
#ifdef CONFIG_NF_CT_PROTO_SCTP
	struct nf_sctp_net	sctp;
#endif
};

/*每CPU ct结构*/
struct ct_pcpu {
	spinlock_t		lock;
	/* 对于一个链接的第一个包，在init_conntrack()函数中会将该包original方向的tuple结构挂入该链，
	这是因为在此时还不确定该链接会不会被后续的规则过滤掉，
	如果被过滤掉就没有必要挂入正式的链接跟踪表。
	在ipv4_confirm()函数中，会将unconfirmed链中的tuple拆掉，
	然后再将original方向和reply方向的tuple挂入到正式的链接跟踪表中，即init_net.ct.hash中，
	这是因为到达ipv4_confirm()函数时，应经在钩子NF_IP_POST_ROUTING处了，已经通过了前面的filter表。 
	通过cat  /proc/net/nf_conntrack显示连接，是不会显示该链中的连接的。
	但总的连接个数（net->ct.count）包含该链中的连接。
	当注销l3proto、l4proto、helper、nat等资源或在应用层删除所有连接（conntrack -F）时，
	除了释放confirmed连接（在net->ct.hash中的连接）的资源，
	还要释放unconfirmed连接（即在该链中的连接）的资源。*/
	struct hlist_nulls_head unconfirmed;		/*只有单向包时，链接节点放这个链*/


	/* 释放连接时，通告DESTROY事件失败的ct被放入该链中，并设置定时器，等待下次通告。 
	通过cat  /proc/net/nf_conntrack显示连接，是不会显示该链中的连接的。
	但总的连接个数（net->ct.count）包含该链中的连接。
	当注销连接跟踪模块时，同时要清除正再等待被释放的连接（即该链中的连接）*/
	struct hlist_nulls_head dying;				/*已老化，待删除链*/
};

/*命名空间中的一套数据结构
net是本地CPU的网络命名空间，在单CPU系统中就是全局变量init_net*/
struct netns_ct {
	atomic_t		count;				/* 当前连接表中连接的个数 */
	unsigned int		expect_count;	/* nf_conntrack_helper创建的期待子连接nf_conntrack_expect项的个数 */
#ifdef CONFIG_NF_CONNTRACK_EVENTS
	struct delayed_work ecache_dwork;
	bool ecache_dwork_pending;
#endif

/*sysctl 命令相关*/
#ifdef CONFIG_SYSCTL
	struct ctl_table_header	*sysctl_header;
	struct ctl_table_header	*acct_sysctl_header;
	struct ctl_table_header	*tstamp_sysctl_header;
	struct ctl_table_header	*event_sysctl_header;
	struct ctl_table_header	*helper_sysctl_header;
#endif

	unsigned int		sysctl_log_invalid; /* Log invalid packets */
	int			sysctl_events; 					/* 是否开启连接事件通告功能 */
	int			sysctl_acct;				/* 是否开启每个连接数据包统计功能 */
	int			sysctl_auto_assign_helper;
	bool			auto_assign_helper_warned;
	int			sysctl_tstamp;
	int			sysctl_checksum;

	struct ct_pcpu __percpu *pcpu_lists;						  /*每CPU 链接相关链表*/
	struct ip_conntrack_stat __percpu *stat;					 /* 每CPU连接跟踪过程中的一些状态统计，为了减少锁 */
	struct nf_ct_event_notifier __rcu *nf_conntrack_event_cb;
	struct nf_exp_event_notifier __rcu *nf_expect_event_cb;
	struct nf_ip_net	nf_ct_proto;
#if defined(CONFIG_NF_CONNTRACK_LABELS)
	unsigned int		labels_used;
#endif
};
#endif
