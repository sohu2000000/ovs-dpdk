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

/*namespace��tcp��Ϣ*/
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

/*����*/
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

/*ÿCPU ct�ṹ*/
struct ct_pcpu {
	spinlock_t		lock;
	/* ����һ�����ӵĵ�һ��������init_conntrack()�����лὫ�ð�original�����tuple�ṹ���������
	������Ϊ�ڴ�ʱ����ȷ�������ӻ᲻�ᱻ�����Ĺ�����˵���
	��������˵���û�б�Ҫ������ʽ�����Ӹ��ٱ�
	��ipv4_confirm()�����У��Ὣunconfirmed���е�tuple�����
	Ȼ���ٽ�original�����reply�����tuple���뵽��ʽ�����Ӹ��ٱ��У���init_net.ct.hash�У�
	������Ϊ����ipv4_confirm()����ʱ��Ӧ���ڹ���NF_IP_POST_ROUTING���ˣ��Ѿ�ͨ����ǰ���filter�� 
	ͨ��cat  /proc/net/nf_conntrack��ʾ���ӣ��ǲ�����ʾ�����е����ӵġ�
	���ܵ����Ӹ�����net->ct.count�����������е����ӡ�
	��ע��l3proto��l4proto��helper��nat����Դ����Ӧ�ò�ɾ���������ӣ�conntrack -F��ʱ��
	�����ͷ�confirmed���ӣ���net->ct.hash�е����ӣ�����Դ��
	��Ҫ�ͷ�unconfirmed���ӣ����ڸ����е����ӣ�����Դ��*/
	struct hlist_nulls_head unconfirmed;		/*ֻ�е����ʱ�����ӽڵ�������*/


	/* �ͷ�����ʱ��ͨ��DESTROY�¼�ʧ�ܵ�ct����������У������ö�ʱ�����ȴ��´�ͨ�档 
	ͨ��cat  /proc/net/nf_conntrack��ʾ���ӣ��ǲ�����ʾ�����е����ӵġ�
	���ܵ����Ӹ�����net->ct.count�����������е����ӡ�
	��ע�����Ӹ���ģ��ʱ��ͬʱҪ������ٵȴ����ͷŵ����ӣ��������е����ӣ�*/
	struct hlist_nulls_head dying;				/*���ϻ�����ɾ����*/
};

/*�����ռ��е�һ�����ݽṹ
net�Ǳ���CPU�����������ռ䣬�ڵ�CPUϵͳ�о���ȫ�ֱ���init_net*/
struct netns_ct {
	atomic_t		count;				/* ��ǰ���ӱ������ӵĸ��� */
	unsigned int		expect_count;	/* nf_conntrack_helper�������ڴ�������nf_conntrack_expect��ĸ��� */
#ifdef CONFIG_NF_CONNTRACK_EVENTS
	struct delayed_work ecache_dwork;
	bool ecache_dwork_pending;
#endif

/*sysctl �������*/
#ifdef CONFIG_SYSCTL
	struct ctl_table_header	*sysctl_header;
	struct ctl_table_header	*acct_sysctl_header;
	struct ctl_table_header	*tstamp_sysctl_header;
	struct ctl_table_header	*event_sysctl_header;
	struct ctl_table_header	*helper_sysctl_header;
#endif

	unsigned int		sysctl_log_invalid; /* Log invalid packets */
	int			sysctl_events; 					/* �Ƿ��������¼�ͨ�湦�� */
	int			sysctl_acct;				/* �Ƿ���ÿ���������ݰ�ͳ�ƹ��� */
	int			sysctl_auto_assign_helper;
	bool			auto_assign_helper_warned;
	int			sysctl_tstamp;
	int			sysctl_checksum;

	struct ct_pcpu __percpu *pcpu_lists;						  /*ÿCPU �����������*/
	struct ip_conntrack_stat __percpu *stat;					 /* ÿCPU���Ӹ��ٹ����е�һЩ״̬ͳ�ƣ�Ϊ�˼����� */
	struct nf_ct_event_notifier __rcu *nf_conntrack_event_cb;
	struct nf_exp_event_notifier __rcu *nf_expect_event_cb;
	struct nf_ip_net	nf_ct_proto;
#if defined(CONFIG_NF_CONNTRACK_LABELS)
	unsigned int		labels_used;
#endif
};
#endif
