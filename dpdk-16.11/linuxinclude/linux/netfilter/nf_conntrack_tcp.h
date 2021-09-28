/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NF_CONNTRACK_TCP_H
#define _NF_CONNTRACK_TCP_H

#include <uapi/linux/netfilter/nf_conntrack_tcp.h>

/*ip_ct_tcp_state*/
struct ip_ct_tcp_state {
	u_int32_t	td_end;		/* max of seq + len */										/*序列号和报文长度之和最大值*/
	u_int32_t	td_maxend;	/* max of ack + max(win, 1) */								/*ack+滑动窗口最大值*/
	u_int32_t	td_maxwin;	/* max(win) */												/*滑动窗口最大值*/
	u_int32_t	td_maxack;	/* max of ack */											/*ack最大值*/
	u_int8_t	td_scale;	/* window scale factor */					
	u_int8_t	flags;		/* per direction options */									/*每方向选项*/
};

/*记录一个连接TCP状态*/
struct ip_ct_tcp {
	struct ip_ct_tcp_state seen[2];	/* connection parameters per direction */			/*链接参数，正反向*/
	u_int8_t	state;		/* state of the connection (enum tcp_conntrack) */			/*ct链接状态*/
	/* For detecting stale connections */
	u_int8_t	last_dir;	/* Direction of the last packet (enum ip_conntrack_dir) */	/*上一个包的方向*/
	u_int8_t	retrans;	/* Number of retransmitted packets */						/*重发的包数*/
	u_int8_t	last_index;	/* Index of the last packet */								/*上一个包的tcp flag*/
	u_int32_t	last_seq;	/* Last sequence number seen in dir */						/*本方向上一个报文序列号*/
	u_int32_t	last_ack;	/* Last sequence number seen in opposite dir */				/*反方向上一个报文序的列号*/
	u_int32_t	last_end;	/* Last seq + len */									    /*上一个报文的序列号加len*/
	u_int16_t	last_win;	/* Last window advertisement seen in dir */					/*本方向上一个报文的窗口*/
	/* For SYN packets while we may be out-of-sync */
	u_int8_t	last_wscale;	/* Last window scaling factor seen */					/*设置的最后一个window*/		
	u_int8_t	last_flags;	/* Last flags set */										/*设置的最后一个flag*/
};

#endif /* _NF_CONNTRACK_TCP_H */
