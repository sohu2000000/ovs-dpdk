/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_NF_CONNTRACK_TCP_H
#define _UAPI_NF_CONNTRACK_TCP_H
/* TCP tracking. */

#include <linux/types.h>

/* This is exposed to userspace (ctnetlink) */

/*tcp���Ӹ��ŵ�״̬*/
enum tcp_conntrack {
	TCP_CONNTRACK_NONE,			/*��ʼ״̬*/
	TCP_CONNTRACK_SYN_SENT,		/*����syn���ģ�nfconntrack������syn����*/
	TCP_CONNTRACK_SYN_RECV,		/*nf conntrack������syn-ack*/
	TCP_CONNTRACK_ESTABLISHED,	/*���ӽ���ȷ��*/
	TCP_CONNTRACK_FIN_WAIT,		/*����fin���ݰ�*/
	TCP_CONNTRACK_CLOSE_WAIT,	/*����FIN֮��*/
	TCP_CONNTRACK_LAST_ACK,		/*��󿴵���ack*/
	TCP_CONNTRACK_TIME_WAIT,	
	TCP_CONNTRACK_CLOSE,		/*�ر�����*/
	TCP_CONNTRACK_LISTEN,		/* obsolete */
#define TCP_CONNTRACK_SYN_SENT2	TCP_CONNTRACK_LISTEN
	TCP_CONNTRACK_MAX,
	TCP_CONNTRACK_IGNORE,
	TCP_CONNTRACK_RETRANS,
	TCP_CONNTRACK_UNACK,
	TCP_CONNTRACK_TIMEOUT_MAX
};

/* Window scaling is advertised by the sender */

/*�������ڱ������߸�֪*/
#define IP_CT_TCP_FLAG_WINDOW_SCALE		0x01

/* SACK is permitted by the sender */
/*sack�����Ͷ�����*/
#define IP_CT_TCP_FLAG_SACK_PERM		0x02

/* This sender sent FIN first */

/*�����߷���fin����*/
#define IP_CT_TCP_FLAG_CLOSE_INIT		0x04

/* Be liberal in window checking */

/*�������ڼ���Ƕ�����*/
#define IP_CT_TCP_FLAG_BE_LIBERAL		0x08

/* Has unacknowledged data */

/*����δ֪����*/
#define IP_CT_TCP_FLAG_DATA_UNACKNOWLEDGED	0x10

/* The field td_maxack has been set */
#define IP_CT_TCP_FLAG_MAXACK_SET		0x20

/* Marks possibility for expected RFC5961 challenge ACK */
#define IP_CT_EXP_CHALLENGE_ACK 		0x40

/* Simultaneous open initialized */
#define IP_CT_TCP_SIMULTANEOUS_OPEN		0x80

struct nf_ct_tcp_flags {
	__u8 flags;
	__u8 mask;
};


#endif /* _UAPI_NF_CONNTRACK_TCP_H */
