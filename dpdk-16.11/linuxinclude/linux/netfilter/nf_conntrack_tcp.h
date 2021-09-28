/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NF_CONNTRACK_TCP_H
#define _NF_CONNTRACK_TCP_H

#include <uapi/linux/netfilter/nf_conntrack_tcp.h>

/*ip_ct_tcp_state*/
struct ip_ct_tcp_state {
	u_int32_t	td_end;		/* max of seq + len */										/*���кźͱ��ĳ���֮�����ֵ*/
	u_int32_t	td_maxend;	/* max of ack + max(win, 1) */								/*ack+�����������ֵ*/
	u_int32_t	td_maxwin;	/* max(win) */												/*�����������ֵ*/
	u_int32_t	td_maxack;	/* max of ack */											/*ack���ֵ*/
	u_int8_t	td_scale;	/* window scale factor */					
	u_int8_t	flags;		/* per direction options */									/*ÿ����ѡ��*/
};

/*��¼һ������TCP״̬*/
struct ip_ct_tcp {
	struct ip_ct_tcp_state seen[2];	/* connection parameters per direction */			/*���Ӳ�����������*/
	u_int8_t	state;		/* state of the connection (enum tcp_conntrack) */			/*ct����״̬*/
	/* For detecting stale connections */
	u_int8_t	last_dir;	/* Direction of the last packet (enum ip_conntrack_dir) */	/*��һ�����ķ���*/
	u_int8_t	retrans;	/* Number of retransmitted packets */						/*�ط��İ���*/
	u_int8_t	last_index;	/* Index of the last packet */								/*��һ������tcp flag*/
	u_int32_t	last_seq;	/* Last sequence number seen in dir */						/*��������һ���������к�*/
	u_int32_t	last_ack;	/* Last sequence number seen in opposite dir */				/*��������һ����������к�*/
	u_int32_t	last_end;	/* Last seq + len */									    /*��һ�����ĵ����кż�len*/
	u_int16_t	last_win;	/* Last window advertisement seen in dir */					/*��������һ�����ĵĴ���*/
	/* For SYN packets while we may be out-of-sync */
	u_int8_t	last_wscale;	/* Last window scaling factor seen */					/*���õ����һ��window*/		
	u_int8_t	last_flags;	/* Last flags set */										/*���õ����һ��flag*/
};

#endif /* _NF_CONNTRACK_TCP_H */
