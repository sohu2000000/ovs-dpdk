/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_NF_CONNTRACK_TCP_H
#define _UAPI_NF_CONNTRACK_TCP_H
/* TCP tracking. */

#include <linux/types.h>

/* This is exposed to userspace (ctnetlink) */

/*tcp链接跟着的状态*/
enum tcp_conntrack {
	TCP_CONNTRACK_NONE,			/*初始状态*/
	TCP_CONNTRACK_SYN_SENT,		/*发了syn报文，nfconntrack看到了syn报文*/
	TCP_CONNTRACK_SYN_RECV,		/*nf conntrack看到了syn-ack*/
	TCP_CONNTRACK_ESTABLISHED,	/*链接建立确认*/
	TCP_CONNTRACK_FIN_WAIT,		/*看到fin数据包*/
	TCP_CONNTRACK_CLOSE_WAIT,	/*看到FIN之后*/
	TCP_CONNTRACK_LAST_ACK,		/*最后看到的ack*/
	TCP_CONNTRACK_TIME_WAIT,	
	TCP_CONNTRACK_CLOSE,		/*关闭链接*/
	TCP_CONNTRACK_LISTEN,		/* obsolete */
#define TCP_CONNTRACK_SYN_SENT2	TCP_CONNTRACK_LISTEN
	TCP_CONNTRACK_MAX,
	TCP_CONNTRACK_IGNORE,
	TCP_CONNTRACK_RETRANS,
	TCP_CONNTRACK_UNACK,
	TCP_CONNTRACK_TIMEOUT_MAX
};

/* Window scaling is advertised by the sender */

/*滑动窗口被发送者告知*/
#define IP_CT_TCP_FLAG_WINDOW_SCALE		0x01

/* SACK is permitted by the sender */
/*sack被发送端允许*/
#define IP_CT_TCP_FLAG_SACK_PERM		0x02

/* This sender sent FIN first */

/*发送者发了fin报文*/
#define IP_CT_TCP_FLAG_CLOSE_INIT		0x04

/* Be liberal in window checking */

/*滑动窗口检查是独立的*/
#define IP_CT_TCP_FLAG_BE_LIBERAL		0x08

/* Has unacknowledged data */

/*存在未知数据*/
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
