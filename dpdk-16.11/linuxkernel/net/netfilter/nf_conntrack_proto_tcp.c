/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2004 Netfilter Core Team <coreteam@netfilter.org>
 * (C) 2002-2013 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 * (C) 2006-2012 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/types.h>
#include <linux/timer.h>
#include <linux/module.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/ipv6.h>
#include <net/ip6_checksum.h>
#include <asm/unaligned.h>

#include <net/tcp.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/netfilter/nf_conntrack_synproxy.h>
#include <net/netfilter/nf_log.h>
#include <net/netfilter/ipv4/nf_conntrack_ipv4.h>
#include <net/netfilter/ipv6/nf_conntrack_ipv6.h>

/* "Be conservative in what you do,
    be liberal in what you accept from others."
    If it's non-zero, we mark only out of window RST segments as INVALID. */
static int nf_ct_tcp_be_liberal __read_mostly = 0;

/* If it is set to zero, we disable picking up already established
   connections. */
static int nf_ct_tcp_loose __read_mostly = 1;

/* Max number of the retransmitted packets without receiving an (acceptable)
   ACK from the destination. If this number is reached, a shorter timer
   will be started. */
static int nf_ct_tcp_max_retrans __read_mostly = 3;

  /* FIXME: Examine ipfilter's timeouts and conntrack transitions more
     closely.  They're more complex. --RR */

static const char *const tcp_conntrack_names[] = {
	"NONE",
	"SYN_SENT",
	"SYN_RECV",
	"ESTABLISHED",
	"FIN_WAIT",
	"CLOSE_WAIT",
	"LAST_ACK",
	"TIME_WAIT",
	"CLOSE",
	"SYN_SENT2",
};

#define SECS * HZ
#define MINS * 60 SECS
#define HOURS * 60 MINS
#define DAYS * 24 HOURS

/*tcp不同状态老化时间*/
static const unsigned int tcp_timeouts[TCP_CONNTRACK_TIMEOUT_MAX] = {
	[TCP_CONNTRACK_SYN_SENT]	= 2 MINS,		/*SYN等待2分钟*/
	[TCP_CONNTRACK_SYN_RECV]	= 60 SECS,
	[TCP_CONNTRACK_ESTABLISHED]	= 5 DAYS,		/*链接维持5天*/
	[TCP_CONNTRACK_FIN_WAIT]	= 2 MINS,
	[TCP_CONNTRACK_CLOSE_WAIT]	= 60 SECS,
	[TCP_CONNTRACK_LAST_ACK]	= 30 SECS,
	[TCP_CONNTRACK_TIME_WAIT]	= 2 MINS,
	[TCP_CONNTRACK_CLOSE]		= 10 SECS,
	[TCP_CONNTRACK_SYN_SENT2]	= 2 MINS,
/* RFC1122 says the R2 limit should be at least 100 seconds.
   Linux uses 15 packets as limit, which corresponds
   to ~13-30min depending on RTO. */
	[TCP_CONNTRACK_RETRANS]		= 5 MINS,		/*重传5分钟*/
	[TCP_CONNTRACK_UNACK]		= 5 MINS,
};

#define sNO TCP_CONNTRACK_NONE
#define sSS TCP_CONNTRACK_SYN_SENT
#define sSR TCP_CONNTRACK_SYN_RECV
#define sES TCP_CONNTRACK_ESTABLISHED
#define sFW TCP_CONNTRACK_FIN_WAIT
#define sCW TCP_CONNTRACK_CLOSE_WAIT
#define sLA TCP_CONNTRACK_LAST_ACK
#define sTW TCP_CONNTRACK_TIME_WAIT
#define sCL TCP_CONNTRACK_CLOSE
#define sS2 TCP_CONNTRACK_SYN_SENT2
#define sIV TCP_CONNTRACK_MAX
#define sIG TCP_CONNTRACK_IGNORE

/* What TCP flags are set from RST/SYN/FIN/ACK. */

/*tcp设置位*/
enum tcp_bit_set {
	TCP_SYN_SET,		/*syn标记位*/
	TCP_SYNACK_SET,		/*syn-ack标记位*/
	TCP_FIN_SET,	    /*FIN标记位*/
	TCP_ACK_SET,		/*ack标记位*/
	TCP_RST_SET,		/*rst标记位*/
	TCP_NONE_SET,		/*非tcp标记位*/
};

/*
 * The TCP state transition table needs a few words...
 *
 * We are the man in the middle. All the packets go through us
 * but might get lost in transit to the destination.
 * It is assumed that the destinations can't receive segments
 * we haven't seen.
 *
 * The checked segment is in window, but our windows are *not*
 * equivalent with the ones of the sender/receiver. We always
 * try to guess the state of the current sender.
 *
 * The meaning of the states are:
 *
 * NONE:	initial state
 * SYN_SENT:	SYN-only packet seen
 * SYN_SENT2:	SYN-only packet seen from reply dir, simultaneous open
 * SYN_RECV:	SYN-ACK packet seen
 * ESTABLISHED:	ACK packet seen
 * FIN_WAIT:	FIN packet seen
 * CLOSE_WAIT:	ACK seen (after FIN)
 * LAST_ACK:	FIN seen (after FIN)
 * TIME_WAIT:	last ACK seen
 * CLOSE:	closed connection (RST)
 *
 * Packets marked as IGNORED (sIG):
 *	if they may be either invalid or valid
 *	and the receiver may send back a connection
 *	closing RST or a SYN/ACK.
 *
 * Packets marked as INVALID (sIV):
 *	if we regard them as truly invalid packets
 */
static const u8 tcp_conntracks[2][6][TCP_CONNTRACK_MAX] = {
	{
/* ORIGINAL */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*syn*/	   { sSS, sSS, sIG, sIG, sIG, sIG, sIG, sSS, sSS, sS2 },
/*
 *	sNO -> sSS	Initialize a new connection
 *	sSS -> sSS	Retransmitted SYN
 *	sS2 -> sS2	Late retransmitted SYN
 *	sSR -> sIG
 *	sES -> sIG	Error: SYNs in window outside the SYN_SENT state
 *			are errors. Receiver will reply with RST
 *			and close the connection.
 *			Or we are not in sync and hold a dead connection.
 *	sFW -> sIG
 *	sCW -> sIG
 *	sLA -> sIG
 *	sTW -> sSS	Reopened connection (RFC 1122).
 *	sCL -> sSS
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*synack*/ { sIV, sIV, sSR, sIV, sIV, sIV, sIV, sIV, sIV, sSR },
/*
 *	sNO -> sIV	Too late and no reason to do anything
 *	sSS -> sIV	Client can't send SYN and then SYN/ACK
 *	sS2 -> sSR	SYN/ACK sent to SYN2 in simultaneous open
 *	sSR -> sSR	Late retransmitted SYN/ACK in simultaneous open
 *	sES -> sIV	Invalid SYN/ACK packets sent by the client
 *	sFW -> sIV
 *	sCW -> sIV
 *	sLA -> sIV
 *	sTW -> sIV
 *	sCL -> sIV
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*fin*/    { sIV, sIV, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sIV },
/*
 *	sNO -> sIV	Too late and no reason to do anything...
 *	sSS -> sIV	Client migth not send FIN in this state:
 *			we enforce waiting for a SYN/ACK reply first.
 *	sS2 -> sIV
 *	sSR -> sFW	Close started.
 *	sES -> sFW
 *	sFW -> sLA	FIN seen in both directions, waiting for
 *			the last ACK.
 *			Migth be a retransmitted FIN as well...
 *	sCW -> sLA
 *	sLA -> sLA	Retransmitted FIN. Remain in the same state.
 *	sTW -> sTW
 *	sCL -> sCL
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*ack*/	   { sES, sIV, sES, sES, sCW, sCW, sTW, sTW, sCL, sIV },
/*
 *	sNO -> sES	Assumed.
 *	sSS -> sIV	ACK is invalid: we haven't seen a SYN/ACK yet.
 *	sS2 -> sIV
 *	sSR -> sES	Established state is reached.
 *	sES -> sES	:-)
 *	sFW -> sCW	Normal close request answered by ACK.
 *	sCW -> sCW
 *	sLA -> sTW	Last ACK detected (RFC5961 challenged)
 *	sTW -> sTW	Retransmitted last ACK. Remain in the same state.
 *	sCL -> sCL
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*rst*/    { sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL },
/*none*/   { sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV }
	},
	{
/* REPLY */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*syn*/	   { sIV, sS2, sIV, sIV, sIV, sIV, sIV, sSS, sIV, sS2 },
/*
 *	sNO -> sIV	Never reached.
 *	sSS -> sS2	Simultaneous open
 *	sS2 -> sS2	Retransmitted simultaneous SYN
 *	sSR -> sIV	Invalid SYN packets sent by the server
 *	sES -> sIV
 *	sFW -> sIV
 *	sCW -> sIV
 *	sLA -> sIV
 *	sTW -> sSS	Reopened connection, but server may have switched role
 *	sCL -> sIV
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*synack*/ { sIV, sSR, sIG, sIG, sIG, sIG, sIG, sIG, sIG, sSR },
/*
 *	sSS -> sSR	Standard open.
 *	sS2 -> sSR	Simultaneous open
 *	sSR -> sIG	Retransmitted SYN/ACK, ignore it.
 *	sES -> sIG	Late retransmitted SYN/ACK?
 *	sFW -> sIG	Might be SYN/ACK answering ignored SYN
 *	sCW -> sIG
 *	sLA -> sIG
 *	sTW -> sIG
 *	sCL -> sIG
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*fin*/    { sIV, sIV, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sIV },
/*
 *	sSS -> sIV	Server might not send FIN in this state.
 *	sS2 -> sIV
 *	sSR -> sFW	Close started.
 *	sES -> sFW
 *	sFW -> sLA	FIN seen in both directions.
 *	sCW -> sLA
 *	sLA -> sLA	Retransmitted FIN.
 *	sTW -> sTW
 *	sCL -> sCL
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*ack*/	   { sIV, sIG, sSR, sES, sCW, sCW, sTW, sTW, sCL, sIG },
/*
 *	sSS -> sIG	Might be a half-open connection.
 *	sS2 -> sIG
 *	sSR -> sSR	Might answer late resent SYN.
 *	sES -> sES	:-)
 *	sFW -> sCW	Normal close request answered by ACK.
 *	sCW -> sCW
 *	sLA -> sTW	Last ACK detected (RFC5961 challenged)
 *	sTW -> sTW	Retransmitted last ACK.
 *	sCL -> sCL
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*rst*/    { sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL },
/*none*/   { sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV }
	}
};

static inline struct nf_tcp_net *tcp_pernet(struct net *net)
{
	return &net->ct.nf_ct_proto.tcp;
}


/*******************************************************************************
 函数名称 :  tcp_pkt_to_tuple
 功能描述 :  skb源、目端口填充tuple
 输入参数 :  skb---skb报文
 			 dataoff---4层偏移
 			 net---namespace
 			 tuple---存储tuple
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static bool tcp_pkt_to_tuple(const struct sk_buff *skb, unsigned int dataoff,
			     struct net *net, struct nf_conntrack_tuple *tuple)
{
	const struct tcphdr *hp;
	struct tcphdr _hdr;

	/* Actually only need first 4 bytes to get ports. */
	/*偏过4层头到数据部分*/
	hp = skb_header_pointer(skb, dataoff, 4, &_hdr);
	if (hp == NULL)
		return false;

	/*源、目端口填充tuple*/
	tuple->src.u.tcp.port = hp->source;
	tuple->dst.u.tcp.port = hp->dest;

	return true;
}


/*******************************************************************************
 函数名称 :  tcp_invert_tuple
 功能描述 :  反向tuple端口构建
 输入参数 :  inverse---反向tuple
 			 orig---正向tuple
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static bool tcp_invert_tuple(struct nf_conntrack_tuple *tuple,
			     const struct nf_conntrack_tuple *orig)
{
	/*端口相反*/
	tuple->src.u.tcp.port = orig->dst.u.tcp.port;
	tuple->dst.u.tcp.port = orig->src.u.tcp.port;
	return true;
}

#ifdef CONFIG_NF_CONNTRACK_PROCFS
/* Print out the private part of the conntrack. */


/*******************************************************************************
 函数名称 :  tcp_print_conntrack
 功能描述 :  打印链接
 输入参数 :  
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static void tcp_print_conntrack(struct seq_file *s, struct nf_conn *ct)
{
	if (test_bit(IPS_OFFLOAD_BIT, &ct->status))
		return;

	seq_printf(s, "%s ", tcp_conntrack_names[ct->proto.tcp.state]);
}
#endif


/*******************************************************************************
 函数名称 :  get_conntrack_index
 功能描述 :  返回当前报文tcp flag
 输入参数 :  
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static unsigned int get_conntrack_index(const struct tcphdr *tcph)
{
	if (tcph->rst) return TCP_RST_SET;
	else if (tcph->syn) return (tcph->ack ? TCP_SYNACK_SET : TCP_SYN_SET);
	else if (tcph->fin) return TCP_FIN_SET;
	else if (tcph->ack) return TCP_ACK_SET;
	else return TCP_NONE_SET;
}

/* TCP connection tracking based on 'Real Stateful TCP Packet Filtering
   in IP Filter' by Guido van Rooij.

   http://www.sane.nl/events/sane2000/papers.html
   http://www.darkart.com/mirrors/www.obfuscation.org/ipf/

   The boundaries and the conditions are changed according to RFC793:
   the packet must intersect the window (i.e. segments may be
   after the right or before the left edge) and thus receivers may ACK
   segments after the right edge of the window.

	td_maxend = max(sack + max(win,1)) seen in reply packets
	td_maxwin = max(max(win, 1)) + (sack - ack) seen in sent packets
	td_maxwin += seq + len - sender.td_maxend
			if seq + len > sender.td_maxend
	td_end    = max(seq + len) seen in sent packets

   I.   Upper bound for valid data:	seq <= sender.td_maxend
   II.  Lower bound for valid data:	seq + len >= sender.td_end - receiver.td_maxwin
   III.	Upper bound for valid (s)ack:   sack <= receiver.td_end
   IV.	Lower bound for valid (s)ack:	sack >= receiver.td_end - MAXACKWINDOW

   where sack is the highest right edge of sack block found in the packet
   or ack in the case of packet without SACK option.

   The upper bound limit for a valid (s)ack is not ignored -
   we doesn't have to deal with fragments.
*/

static inline __u32 segment_seq_plus_len(__u32 seq,
					 size_t len,
					 unsigned int dataoff,
					 const struct tcphdr *tcph)
{
	/* XXX Should I use payload length field in IP/IPv6 header ?
	 * - YK */
	return (seq + len - dataoff - tcph->doff*4
		+ (tcph->syn ? 1 : 0) + (tcph->fin ? 1 : 0));
}

/* Fixme: what about big packets? */
#define MAXACKWINCONST			66000
#define MAXACKWINDOW(sender)						\
	((sender)->td_maxwin > MAXACKWINCONST ? (sender)->td_maxwin	\
					      : MAXACKWINCONST)

/*
 * Simplified tcp_parse_options routine from tcp_input.c
 */
<<<<<<< HEAD
/*******************************************************************************
 函数名称 :  tcp_options
 功能描述 :   tcp 选项设置
 输入参数 :  ct---nf_conn结构，一条链接跟踪项
=======

/*******************************************************************************
 函数名称 :  tcp_options
 功能描述 :  tcp选项填充
 输入参数 :  skb---当前报文为SYN报文
 			 dataoff---4层报文偏移
 			 tcph---4层头地址
 			 state--ct tcp状态
>>>>>>> f3ba9b758b1a5bbfb2b3e4bb581bb7fafcf5c88d
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
<<<<<<< HEAD
static void tcp_options(const struct sk_buff *skb,
			unsigned int dataoff,
			const struct tcphdr *tcph,
			struct ip_ct_tcp_state *state)
=======
static void tcp_options(const struct sk_buff *skb, unsigned int dataoff, const struct tcphdr *tcph, struct ip_ct_tcp_state *state)
>>>>>>> f3ba9b758b1a5bbfb2b3e4bb581bb7fafcf5c88d
{
	unsigned char buff[(15 * 4) - sizeof(struct tcphdr)];
	const unsigned char *ptr;

	/*数据部分长度*/
	int length = (tcph->doff*4) - sizeof(struct tcphdr);

	if (!length)
		return;

	/*四层数据部分*/
	ptr = skb_header_pointer(skb, dataoff + sizeof(struct tcphdr), length, buff);
	BUG_ON(ptr == NULL);

	/*清0*/
	state->td_scale = state->flags = 0;

	while (length > 0) 
	{
		/*操作码*/
		int opcode=*ptr++;
		int opsize;

		switch (opcode) 
		{
			/*选项的结束*/
			case TCPOPT_EOL:
				return;

			/*填充*/
			case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
				length--;
				continue;
			default:
			{
				if (length < 2)
					return;

				/*选项部分长度*/
				opsize=*ptr++;
				
				if (opsize < 2) /* "silly options" */
					return;
				
				if (opsize > length)
					return;	/* don't parse partial options */

				/*sack被发送端允许*/
				if (opcode == TCPOPT_SACK_PERM && opsize == TCPOLEN_SACK_PERM)
					/*ct状态置上允许SACK位*/
					state->flags |= IP_CT_TCP_FLAG_SACK_PERM;
				
				/*window 的大小为3*/
				else if (opcode == TCPOPT_WINDOW && opsize == TCPOLEN_WINDOW) 
				{
					state->td_scale = *(u_int8_t *)ptr;

					if (state->td_scale > TCP_MAX_WSCALE)
						state->td_scale = TCP_MAX_WSCALE;

					/*滑动窗口被发送者告知*/
					state->flags |= IP_CT_TCP_FLAG_WINDOW_SCALE;
				}

				/**/
				ptr += opsize - 2;

				/*4层数据部分长度减去选项*/
				length -= opsize;
			}
		}
	}
}


/*******************************************************************************
 函数名称 :  tcp_sack
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
static void tcp_sack(const struct sk_buff *skb, unsigned int dataoff,
                     const struct tcphdr *tcph, __u32 *sack)
{
	unsigned char buff[(15 * 4) - sizeof(struct tcphdr)];
	const unsigned char *ptr;
	int length = (tcph->doff*4) - sizeof(struct tcphdr);
	__u32 tmp;

	if (!length)
		return;

	ptr = skb_header_pointer(skb, dataoff + sizeof(struct tcphdr),
				 length, buff);
	BUG_ON(ptr == NULL);

	/* Fast path for timestamp-only option */
	if (length == TCPOLEN_TSTAMP_ALIGNED
	    && *(__be32 *)ptr == htonl((TCPOPT_NOP << 24)
				       | (TCPOPT_NOP << 16)
				       | (TCPOPT_TIMESTAMP << 8)
				       | TCPOLEN_TIMESTAMP))
		return;

	while (length > 0) {
		int opcode = *ptr++;
		int opsize, i;

		switch (opcode) {
		case TCPOPT_EOL:
			return;
		case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
			length--;
			continue;
		default:
			if (length < 2)
				return;
			opsize = *ptr++;
			if (opsize < 2) /* "silly options" */
				return;
			if (opsize > length)
				return;	/* don't parse partial options */

			if (opcode == TCPOPT_SACK
			    && opsize >= (TCPOLEN_SACK_BASE
					  + TCPOLEN_SACK_PERBLOCK)
			    && !((opsize - TCPOLEN_SACK_BASE)
				 % TCPOLEN_SACK_PERBLOCK)) {
				for (i = 0;
				     i < (opsize - TCPOLEN_SACK_BASE);
				     i += TCPOLEN_SACK_PERBLOCK) {
					tmp = get_unaligned_be32((__be32 *)(ptr+i)+1);

					if (after(tmp, *sack))
						*sack = tmp;
				}
				return;
			}
			ptr += opsize - 2;
			length -= opsize;
		}
	}
}


/*******************************************************************************
 函数名称 :  tcp_in_window
 功能描述 :  判断一个TCP包序列号和确认号是否在给定window范围内的函数是tcp_in_window�
 输入参数 :  SACK--允许确认不连续的tcp报文
 输出参数 :  ct---当前链接跟踪
 			 state---ct的tcp状态
 			 dir---方向 origin
 			 index---当前报文的tcp flag
 			 skb---当前报文skb
 			 dataoff---当前报文4层偏移
 			 tcph---tcp头
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static bool tcp_in_window(const struct nf_conn *ct, struct ip_ct_tcp *state, enum ip_conntrack_dir dir, 
			unsigned int index, const struct sk_buff *skb, unsigned int dataoff, const struct tcphdr *tcph)
{
	struct net *net = nf_ct_net(ct);
	
	struct nf_tcp_net *tn = tcp_pernet(net);

	/*发送方tcp_state*/
	struct ip_ct_tcp_state *sender = &state->seen[dir];

	/*接收方tcp_state*/
	struct ip_ct_tcp_state *receiver = &state->seen[!dir];

	/*original方向tuple*/
	const struct nf_conntrack_tuple *tuple = &ct->tuplehash[dir].tuple;
	
	__u32 seq, ack, sack, end, win, swin;
	
	s32 receiver_offset;
	
	bool res, in_recv_win;

	// 客户端发的第一个SYN包是到不了这个函数的,直接就接受了,
	// 是从连接的第2个包以后才进入本函数处理

	/*
	 * Get the required data from the packet.
	 */

	/*当前报文序列号*/
	seq = ntohl(tcph->seq);
	
	/*当前报文确认号*/
	ack = sack = ntohl(tcph->ack_seq);

	/*当前报文滑动窗口，sender的*/
	win = ntohs(tcph->window);

	/*本数据包结束序列号，本报文序号+报文长度*/
	end = segment_seq_plus_len(seq, skb->len, dataoff, tcph);

	/*tcp开启了SACK允许功能*/
	if (receiver->flags & IP_CT_TCP_FLAG_SACK_PERM)
		tcp_sack(skb, dataoff, tcph, &sack);

	/* Take into account NAT sequence number mangling */
	/*接收方支持SACK的话检查是否在TCP选项中有SACK*/
	receiver_offset = nf_ct_seq_offset(ct, !dir, ack - 1);

	/*ack 减去长度*/
	ack -= receiver_offset;

	/*sack 减去长度*/
	sack -= receiver_offset;

	pr_debug("tcp_in_window: START\n");
	pr_debug("tcp_in_window: ");
	nf_ct_dump_tuple(tuple);
	pr_debug("seq=%u ack=%u+(%d) sack=%u+(%d) win=%u end=%u\n", seq, ack, receiver_offset, sack, receiver_offset, win, end);
	pr_debug("tcp_in_window: sender end=%u maxend=%u maxwin=%u scale=%i "
		 "receiver end=%u maxend=%u maxwin=%u scale=%i\n",
		 sender->td_end, sender->td_maxend, sender->td_maxwin, sender->td_scale, 
		 receiver->td_end, receiver->td_maxend, receiver->td_maxwin, receiver->td_scale);

	/*发送端滑动窗口最大值*/
	if (sender->td_maxwin == 0) 
	{
		/*
		 * Initialize sender data.
		 */
		 
		/*报文为SYN报文，连接初始情况，服务器端*/
		if (tcph->syn) 
		{
			/*
			 * SYN-ACK in reply to a SYN
			 * or SYN from reply direction in simultaneous open.
			 */

			/*发送方序列号和报文长度之和最大值*/
			sender->td_end = sender->td_maxend = end;

			/*发送方滑动窗口最大值*/
			sender->td_maxwin = (win == 0 ? 1 : win);

			/*发送方检查TCP选项，判断接收方是否支持SACK和窗口扩大*/
			tcp_options(skb, dataoff, tcph, sender);
			/*
			 * RFC 1323:
			 * Both sides must send the Window Scale option
			 * to enable window scaling in either direction.
			 */
			 
			/*发送方滑动窗口被发送者告知*/
			if (!(sender->flags & IP_CT_TCP_FLAG_WINDOW_SCALE
			      && receiver->flags & IP_CT_TCP_FLAG_WINDOW_SCALE))

				/*不支持窗口扩大*/
				sender->td_scale = receiver->td_scale = 0;

			if (!tcph->ack)
				/* Simultaneous open */
			
				return true;
		} 
		else 
		{
			/*
			 * We are in the middle of a connection,
			 * its history is lost for us.
			 * Let's try to use the data from the packet.
			 */
			/*发送端 序列号和报文长度之和最大值*/
			sender->td_end = end;
			
			swin = win << sender->td_scale;

			/*发送方滑动窗口最大值*/
			sender->td_maxwin = (swin == 0 ? 1 : swin);

			/*序列号和报文长度之和最大值*/
			sender->td_maxend = end + sender->td_maxwin;
			/*
			 * We haven't seen traffic in the other direction yet
			 * but we have to tweak window tracking to pass III
			 * and IV until that happens.
			 */

			/*接收端滑动窗口最大值*/
			if (receiver->td_maxwin == 0)
				receiver->td_end = receiver->td_maxend = sack;
		}
	} 

	/*original方向看到了SYN报文、reply方向看到SYN ACK报文*/
	else if (((state->state == TCP_CONNTRACK_SYN_SENT && dir == IP_CT_DIR_ORIGINAL)
		   || (state->state == TCP_CONNTRACK_SYN_RECV && dir == IP_CT_DIR_REPLY))
		   && after(end, sender->td_end)) 
	{
		// 发送方重新发包
		/*
		 * RFC 793: "if a TCP is reinitialized ... then it need
		 * not wait at all; it must only be sure to use sequence
		 * numbers larger than those recently used."
		 */

		/*发送方 序列号和报文长度之和最大值*/
		sender->td_end = sender->td_maxend = end;

		/*发送方 滑动窗口最大值*/
		sender->td_maxwin = (win == 0 ? 1 : win);

		/*tcp选项设置*/
		tcp_options(skb, dataoff, tcph, sender);
	}

	/*非ACK包和RST包,将确认号置为接收方的结束序列号*/
	if (!(tcph->ack)) 
	{
		/*
		 * If there is no ACK, just pretend it was set and OK.
		 */
		ack = sack = receiver->td_end;
	} 
	else if (((tcp_flag_word(tcph) & (TCP_FLAG_ACK|TCP_FLAG_RST)) == (TCP_FLAG_ACK|TCP_FLAG_RST)) && (ack == 0)) 
	{
		/*
		 * Broken TCP stacks, that set ACK in RST packets as well
		 * with zero ack value.
		 */
		ack = sack = receiver->td_end;
	}

	/*无数据包或起始包*/
	if (tcph->rst && seq == 0 && state->state == TCP_CONNTRACK_SYN_SENT)
		/*
		 * RST sent answering SYN.
		 */
		 
		/*发送方序列号和报文长度之和最大值*/
		seq = end = sender->td_end;

	pr_debug("tcp_in_window: ");
	nf_ct_dump_tuple(tuple);
	pr_debug("seq=%u ack=%u+(%d) sack=%u+(%d) win=%u end=%u\n",
		 seq, ack, receiver_offset, sack, receiver_offset, win, end);
	pr_debug("tcp_in_window: sender end=%u maxend=%u maxwin=%u scale=%i "
		 "receiver end=%u maxend=%u maxwin=%u scale=%i\n",
		 sender->td_end, sender->td_maxend, sender->td_maxwin,
		 sender->td_scale,
		 receiver->td_end, receiver->td_maxend, receiver->td_maxwin,
		 receiver->td_scale);

	/* Is the ending sequence in the receive window (if available)? */

	/*在接手方窗口*/
	in_recv_win = !receiver->td_maxwin || after(end, sender->td_end - receiver->td_maxwin - 1);

	pr_debug("tcp_in_window: I=%i II=%i III=%i IV=%i\n",
		 before(seq, sender->td_maxend + 1),
		 (in_recv_win ? 1 : 0),
		 before(sack, receiver->td_end + 1),
		 after(sack, receiver->td_end - MAXACKWINDOW(sender) - 1));

	/*报文在tcp滑动窗口内*/
	if (before(seq, sender->td_maxend + 1) && in_recv_win 
		&& before(sack, receiver->td_end + 1) &&  after(sack, receiver->td_end - MAXACKWINDOW(sender) - 1)) 
	{
		/*
		 * Take into account window scaling (RFC 1323).
		 */

		/*非syn报文*/
		if (!tcph->syn)
		{
			win <<= sender->td_scale;
		}

		/*
		 * Update sender data.
		 */
		
		swin = win + (sack - ack);

		/*滑动窗口最大值*/
		if (sender->td_maxwin < swin)
			sender->td_maxwin = swin;

		/*超出了窗口*/
		if (after(end, sender->td_end)) 
		{
			sender->td_end = end;
			sender->flags |= IP_CT_TCP_FLAG_DATA_UNACKNOWLEDGED;
		}

		/*ack报文*/
		if (tcph->ack) 
		{
			/*发送方未设置ack*/
			if (!(sender->flags & IP_CT_TCP_FLAG_MAXACK_SET)) 
			{
				sender->td_maxack = ack;
				sender->flags |= IP_CT_TCP_FLAG_MAXACK_SET;
			} 
			else if (after(ack, sender->td_maxack))
			{
				/*ack最大值*/
				sender->td_maxack = ack;
			}
		}

		/*
		 * Update receiver data.
		 */

		/*窗口滑动*/
		if (receiver->td_maxwin != 0 && after(end, sender->td_maxend))
			receiver->td_maxwin += end - sender->td_maxend;

		/*窗口滑动*/
		if (after(sack + win, receiver->td_maxend - 1)) 
		{
			receiver->td_maxend = sack + win;

			if (win == 0)
				receiver->td_maxend++;
		}

		/*存在未知数据*/
		if (ack == receiver->td_end)
			receiver->flags &= ~IP_CT_TCP_FLAG_DATA_UNACKNOWLEDGED;

		/*
		 * Check retransmissions.
		 */

		/*判断是否是重发包*/
		if (index == TCP_ACK_SET) 
		{
			/*校验这些值*/
			if (state->last_dir == dir
			    && state->last_seq == seq
			    && state->last_ack == ack
			    && state->last_end == end
			    && state->last_win == win)
			{
				/*重发的包数++*/
				state->retrans++;
			}
			else 
			{
				/*tcp状态赋值*/
				state->last_dir = dir;
				state->last_seq = seq;
				state->last_ack = ack;
				state->last_end = end;
				state->last_win = win;
				state->retrans = 0;
			}
		}
		
		res = true;
	}
	else 
	{
		res = false;

		/*对非法包的缺省策略,0拒绝,非0接受.该参数可通过/proc文件系统设置*/
		if (sender->flags & IP_CT_TCP_FLAG_BE_LIBERAL || tn->tcp_be_liberal)
			res = true;
		
		if (!res) 
		{
			nf_ct_l4proto_log_invalid(skb, ct,
			"%s",
			before(seq, sender->td_maxend + 1) ?
			in_recv_win ?
			before(sack, receiver->td_end + 1) ?
			after(sack, receiver->td_end - MAXACKWINDOW(sender) - 1) ? "BUG"
			: "ACK is under the lower bound (possible overly delayed ACK)"
			: "ACK is over the upper bound (ACKed data not seen yet)"
			: "SEQ is under the lower bound (already ACKed data retransmitted)"
			: "SEQ is over the upper bound (over the window of the receiver)");
		}
	}

	pr_debug("tcp_in_window: res=%u sender end=%u maxend=%u maxwin=%u "
		 "receiver end=%u maxend=%u maxwin=%u\n",
		 res, sender->td_end, sender->td_maxend, sender->td_maxwin,
		 receiver->td_end, receiver->td_maxend, receiver->td_maxwin);

	return res;
}

/* table of valid flag combinations - PUSH, ECE and CWR are always valid */
static const u8 tcp_valid_flags[(TCPHDR_FIN|TCPHDR_SYN|TCPHDR_RST|TCPHDR_ACK|
				 TCPHDR_URG) + 1] =
{
	[TCPHDR_SYN]				= 1,
	[TCPHDR_SYN|TCPHDR_URG]			= 1,
	[TCPHDR_SYN|TCPHDR_ACK]			= 1,
	[TCPHDR_RST]				= 1,
	[TCPHDR_RST|TCPHDR_ACK]			= 1,
	[TCPHDR_FIN|TCPHDR_ACK]			= 1,
	[TCPHDR_FIN|TCPHDR_ACK|TCPHDR_URG]	= 1,
	[TCPHDR_ACK]				= 1,
	[TCPHDR_ACK|TCPHDR_URG]			= 1,
};

static void tcp_error_log(const struct sk_buff *skb, struct net *net,
			  u8 pf, const char *msg)
{
	nf_l4proto_log_invalid(skb, net, pf, IPPROTO_TCP, "%s", msg);
}

/* Protect conntrack agaist broken packets. Code taken from ipt_unclean.c.  */

/*******************************************************************************
 函数名称 :  tcp_error
 功能描述 :  主要检查了tcp报文头的完整性，校验和的正确性以及 flag的有效性
 输入参数 :  
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static int tcp_error(struct net *net, struct nf_conn *tmpl, struct sk_buff *skb,
		     unsigned int dataoff,
		     u_int8_t pf,
		     unsigned int hooknum)
{
	const struct tcphdr *th;
	struct tcphdr _tcph;
	unsigned int tcplen = skb->len - dataoff;
	u_int8_t tcpflags;

	/* Smaller that minimal TCP header? */

	/*tcp 包头*/
	th = skb_header_pointer(skb, dataoff, sizeof(_tcph), &_tcph);
	if (th == NULL) 
	{
		tcp_error_log(skb, net, pf, "short packet");
		return -NF_ACCEPT;
	}

	/* Not whole TCP header or malformed packet */

	/*长度有误*/
	if (th->doff*4 < sizeof(struct tcphdr) || tcplen < th->doff*4) 
	{
		tcp_error_log(skb, net, pf, "truncated packet");
		return -NF_ACCEPT;
	}

	/* Checksum invalid? Ignore.
	 * We skip checking packets on the outgoing path
	 * because the checksum is assumed to be correct.
	 */
	/* FIXME: Source route IP option packets --RR */
	if (net->ct.sysctl_checksum 
		&& hooknum == NF_INET_PRE_ROUTING
		&& nf_checksum(skb, hooknum, dataoff, IPPROTO_TCP, pf)) 
	{
		tcp_error_log(skb, net, pf, "bad checksum");
		return -NF_ACCEPT;
	}

	/* Check TCP flags. */
	tcpflags = (tcp_flag_byte(th) & ~(TCPHDR_ECE|TCPHDR_CWR|TCPHDR_PSH));
	if (!tcp_valid_flags[tcpflags]) 
	{
		tcp_error_log(skb, net, pf, "invalid tcp flag combination");
		return -NF_ACCEPT;
	}

	return NF_ACCEPT;
}


/*******************************************************************************
 函数名称 :  tcp_get_timeouts
 功能描述 :  获取超时时间
 输入参数 :  
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static unsigned int *tcp_get_timeouts(struct net *net)
{
	return tcp_pernet(net)->timeouts;
}

/* Returns verdict for packet, or -1 for invalid. */

/*******************************************************************************
 函数名称 :  nf_conntrack_init_net
 功能描述 :  通过连接当前的状态，到达的新报文，得到连接新的状态并进行更新，
 			 其实就是一次查询，输入是方向+报文信息+旧状态，输出是新状态
 输入参数 :  ct---nf_conn
 			 skb---skb报文
 			 dataoff---4层数据部分开始
 			 ctinfo---链接状态值
 			 timeouts---超时时间
 			 
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static int tcp_packet(struct nf_conn *ct, const struct sk_buff *skb, unsigned int dataoff, enum ip_conntrack_info ctinfo, unsigned int *timeouts)
{
	/*获取ct 关联的namespace*/
	struct net *net = nf_ct_net(ct);

	/*tcp net*/
	struct nf_tcp_net *tn = tcp_pernet(net);
	
	struct nf_conntrack_tuple *tuple;

	enum tcp_conntrack new_state, old_state;
	enum ip_conntrack_dir dir;

	const struct tcphdr *th;

	struct tcphdr _tcph;

	unsigned long timeout;

	unsigned int index;

	/*tcp头*/
	th = skb_header_pointer(skb, dataoff, sizeof(_tcph), &_tcph);
	BUG_ON(th == NULL);

	spin_lock_bh(&ct->lock);

	/*tcp协议链接跟踪旧的状态*/
	old_state = ct->proto.tcp.state;

	/*链接的方向*/
	dir = CTINFO2DIR(ctinfo);

	/*返回当前报文tcp flag*/
	index = get_conntrack_index(th);

	/*计算出tcp链接的新状态*/
	new_state = tcp_conntracks[dir][index][old_state];

	/*获取链接对应方向的tuple值*/
	tuple = &ct->tuplehash[dir].tuple;

	/*新状态转换*/
	switch (new_state) 
	{
		/*当前报文为SYN报文，新状态为SYN_SENT*/
		case TCP_CONNTRACK_SYN_SENT:
		{
			/*tcp协议的状态小于4次挥手，为什么，旧状态必须为非交互状态*/
			if (old_state < TCP_CONNTRACK_TIME_WAIT)
				break;
			
			/* RFC 1122: "When a connection is closed actively,
			 * it MUST linger in TIME-WAIT state for a time 2xMSL
			 * (Maximum Segment Lifetime). However, it MAY accept
			 * a new SYN from the remote TCP to reopen the connection
			 * directly from TIME-WAIT state, if..."
			 * We ignore the conditions because we are in the
			 * TIME-WAIT state anyway.
			 *
			 * Handle aborted connections: we and the server
			 * think there is an existing connection but the client
			 * aborts it and starts a new one.
			 */

			/*重新链接，则丢弃本syn报文，删除ct，为什么*/
			/*正反向flag设置了IP_CT_TCP_FLAG_CLOSE_INIT 或 最后一个报文为dir方向、或最后一个报文为TCP_RST_SET*/
			if (

				/*2个方向旧的tcp flag存在设置了FIN 报文*/
				((ct->proto.tcp.seen[dir].flags | ct->proto.tcp.seen[!dir].flags) & IP_CT_TCP_FLAG_CLOSE_INIT)

				/*最后一个包的方向是origin方向*/
				|| (ct->proto.tcp.last_dir == dir

				/*最后一个包是reset报文*/
				&& ct->proto.tcp.last_index == TCP_RST_SET)
			   ) 
			{
				/* Attempt to reopen a closed/aborted connection.
				 * Delete this connection and look up again. */

				
				spin_unlock_bh(&ct->lock);

				/* Only repeat if we can actually remove the timer.
				 * Destruction may already be in progress in process
				 * context and we must give it a chance to terminate.
				 */
				
				if (nf_ct_kill(ct))
					return -NF_REPEAT;

				/*这种情况drop掉这个SYN报文*/
				return NF_DROP;
			}
			/* Fall through */
		}

		/*当前报文为SYNACK报文、新状态改为TCP_CONNTRACK_SYN_RECV，这些报文都是忽略tcp链接跟踪标记宏*/
		case TCP_CONNTRACK_IGNORE:
		{
			/* Ignored packets:
			 *
			 * Our connection entry may be out of sync, so ignore
			 * packets which may signal the real connection between
			 * the client and the server.
			 *
			 * a) SYN in ORIGINAL
			 * b) SYN/ACK in REPLY
			 * c) ACK in reply direction after initial SYN in original.
			 *
			 * If the ignored packet is invalid, the receiver will send
			 * a RST we'll catch below.
			 */

			/*当前是reply方向的syn ack 报文、上一个报文为SYN报文、序列号加len校验合法*/
			if (index == TCP_SYNACK_SET
			    && ct->proto.tcp.last_index == TCP_SYN_SET
			    && ct->proto.tcp.last_dir != dir
			    && ntohl(th->ack_seq) == ct->proto.tcp.last_end) 
			{
				/* b) This SYN/ACK acknowledges a SYN that we earlier
				 * ignored as invalid. This means that the client and
				 * the server are both in sync, while the firewall is
				 * not. We get in sync from the previously annotated
				 * values.
				 */

				/*设置旧状态为发了SYN报文状态*/
				/*nf状态SYN_SENT改为SYN_RECV*/
				old_state = TCP_CONNTRACK_SYN_SENT;
				new_state = TCP_CONNTRACK_SYN_RECV;

				/*更新当前方向(reply)的tcp状态*/
				/*记录上一个报文的序列号和报文长度之和最大值*/
				ct->proto.tcp.seen[ct->proto.tcp.last_dir].td_end = ct->proto.tcp.last_end;

				/*记录上一个报文 ack+滑动窗口最大值*/
				ct->proto.tcp.seen[ct->proto.tcp.last_dir].td_maxend = ct->proto.tcp.last_end;

				/*记录上一个报文的窗口值*/
				ct->proto.tcp.seen[ct->proto.tcp.last_dir].td_maxwin = ct->proto.tcp.last_win == 0 ? 1 : ct->proto.tcp.last_win;
				
				ct->proto.tcp.seen[ct->proto.tcp.last_dir].td_scale = ct->proto.tcp.last_wscale;

				/*设置的最后一个flag*/
				ct->proto.tcp.last_flags &= ~IP_CT_EXP_CHALLENGE_ACK;

				/*记录上一个报文的tcp flag*/
				ct->proto.tcp.seen[ct->proto.tcp.last_dir].flags = ct->proto.tcp.last_flags;

				/*本方向记录的数据清掉*/
				memset(&ct->proto.tcp.seen[dir], 0, sizeof(struct ip_ct_tcp_state));
				
				break;
			}

			/*当前报文的tcp flag 赋值给tcp结构*/
			ct->proto.tcp.last_index = index;

			/*当前报文的方向赋值给tcp结构*/
			ct->proto.tcp.last_dir = dir;

			/*记录当前报文的序列号到tcp结构*/
			ct->proto.tcp.last_seq = ntohl(th->seq);

			/*当前报文的序列号加len记录到tcp结构*/
			ct->proto.tcp.last_end = segment_seq_plus_len(ntohl(th->seq), skb->len, dataoff, th);

			/*当前报文的tcp滑动窗口记录到tcp结构*/
			ct->proto.tcp.last_win = ntohs(th->window);

			/* a) This is a SYN in ORIGINAL. The client and the server
			 * may be in sync but we are not. In that case, we annotate
			 * the TCP options and let the packet go through. If it is a
			 * valid SYN packet, the server will reply with a SYN/ACK, and
			 * then we'll get in sync. Otherwise, the server potentially
			 * responds with a challenge ACK if implementing RFC5961.
			 */

			/*当前报文为syn报文、original方向*/
			if (index == TCP_SYN_SET && dir == IP_CT_DIR_ORIGINAL) 
			{
				struct ip_ct_tcp_state seen = {};

				/*清空tcp记录的tcp flag、last_wscale*/
				ct->proto.tcp.last_flags = ct->proto.tcp.last_wscale = 0;

				/*获取tcp选项，赋值给ct*/
				tcp_options(skb, dataoff, th, &seen);

				/*滑动窗口被发送者告知*/
				if (seen.flags & IP_CT_TCP_FLAG_WINDOW_SCALE) 
				{
					/*赋值tcp flag、last_wscale*//*滑动窗口被发送者告知*/
					ct->proto.tcp.last_flags |= IP_CT_TCP_FLAG_WINDOW_SCALE;
					ct->proto.tcp.last_wscale = seen.td_scale;
				}

				/*sack被发送端允许*/
				if (seen.flags & IP_CT_TCP_FLAG_SACK_PERM) 
				{
					/*赋值tcp flag*//*sack被发送端允许*/
					ct->proto.tcp.last_flags |= IP_CT_TCP_FLAG_SACK_PERM;
				}
				
				/* Mark the potential for RFC5961 challenge ACK,
				 * this pose a special problem for LAST_ACK state
				 * as ACK is intrepretated as ACKing last FIN.
				 */

				/*赋值tcp flag*/
				if (old_state == TCP_CONNTRACK_LAST_ACK)
					ct->proto.tcp.last_flags |= IP_CT_EXP_CHALLENGE_ACK;
			}

			spin_unlock_bh(&ct->lock);

			nf_ct_l4proto_log_invalid(skb, ct, "invalid packet ignored in "
						  "state %s ", tcp_conntrack_names[old_state]);

			return NF_ACCEPT;

		}
		/*新状态为最大值*/
		/*ACK报文*/
		case TCP_CONNTRACK_MAX:
		{
			/* Special case for SYN proxy: when the SYN to the server or
			 * the SYN/ACK from the server is lost, the client may transmit
			 * a keep-alive packet while in SYN_SENT state. This needs to
			 * be associated with the original conntrack entry in order to
			 * generate a new SYN with the correct sequence number.
			 */

			/*syn报文、双向*/
			if (
				/*syn 代理*/
				nfct_synproxy(ct) 
				
				/*旧状态为nf 看到了 syn*/
				&& old_state == TCP_CONNTRACK_SYN_SENT 

				/*当前为ack报文*/
				&& index == TCP_ACK_SET

				/*方向为origin方向*/
				&& dir == IP_CT_DIR_ORIGINAL 

				/*最后一个报文为origin方向，origin方向回的最后一个ack*/	
				&& ct->proto.tcp.last_dir == IP_CT_DIR_ORIGINAL 

				/*序列号和报文长度之和最大值校验*/
				&& ct->proto.tcp.seen[dir].td_end - 1 == ntohl(th->seq)
				) 
			{
				pr_debug("nf_ct_tcp: SYN proxy client keep alive\n");
				spin_unlock_bh(&ct->lock);
				return NF_ACCEPT;
			}

			/* Invalid packet */
			pr_debug("nf_ct_tcp: Invalid dir=%i index=%u ostate=%u\n", dir, get_conntrack_index(th), old_state);
			spin_unlock_bh(&ct->lock);
			nf_ct_l4proto_log_invalid(skb, ct, "invalid state");
			
			return -NF_ACCEPT;
		}
		/*新状态为见到了FIN报文，当前报文为第一个FIN报文*/
		/*tcp conntrack*/
		/*4次挥手的ACK报文*/
		case TCP_CONNTRACK_TIME_WAIT:
		{
			/* RFC5961 compliance cause stack to send "challenge-ACK"
			 * e.g. in response to spurious SYNs.  Conntrack MUST
			 * not believe this ACK is acking last FIN.
			 */

			//
			if (
				/*旧状态看到了第二个FIN*/
				old_state == TCP_CONNTRACK_LAST_ACK 

				/*当前报文为ack*/
				&& index == TCP_ACK_SET 

				/*方向为reply方向*/
				&& ct->proto.tcp.last_dir != dir 

				/*当前ct见到的最后一个报文为syn报文*/
				&& ct->proto.tcp.last_index == TCP_SYN_SET 
				&& (ct->proto.tcp.last_flags & IP_CT_EXP_CHALLENGE_ACK)
				) 
			{
				/* Detected RFC5961 challenge ACK */
				/*上一个报文标记取消IP_CT_EXP_CHALLENGE_ACK*/
				ct->proto.tcp.last_flags &= ~IP_CT_EXP_CHALLENGE_ACK;
				spin_unlock_bh(&ct->lock);
				nf_ct_l4proto_log_invalid(skb, ct, "challenge-ack ignored");

				return NF_ACCEPT; /* Don't change state */
			}
			break;
		}	
		/*syn报文发送*/
		case TCP_CONNTRACK_SYN_SENT2:
		{
			/* tcp_conntracks table is not smart enough to handle
			 * simultaneous open.
			 */
			ct->proto.tcp.last_flags |= IP_CT_TCP_SIMULTANEOUS_OPEN;
			break;
		}
		/*新状态为nf 见到了回应的syn ack报文*/
		case TCP_CONNTRACK_SYN_RECV:
		{
			if (
				/*reply方向*/
				dir == IP_CT_DIR_REPLY 

				/*当前报文设置了ACK*/
				&& index == TCP_ACK_SET 

				/*打开了模拟模式*/
				&& ct->proto.tcp.last_flags & IP_CT_TCP_SIMULTANEOUS_OPEN
			   )
			    {
			   		/*新状态转换为建立了链接*/
					new_state = TCP_CONNTRACK_ESTABLISHED;
				}
			
			break;
		}
		/*tcp跟踪关闭、当前报文为rst报文*/
		case TCP_CONNTRACK_CLOSE:
		{
			/*报文为rst报文*/
			if (index == TCP_RST_SET
			    && (ct->proto.tcp.seen[!dir].flags & IP_CT_TCP_FLAG_MAXACK_SET)
			    && before(ntohl(th->seq), ct->proto.tcp.seen[!dir].td_maxack)) 
			{
				/* Invalid RST  */
				spin_unlock_bh(&ct->lock);
				
				nf_ct_l4proto_log_invalid(skb, ct, "invalid rst");


				/*非法rst丢弃*/
				return -NF_ACCEPT;
			}

			/*当前报文为rst报文、为回应方向、上一个报文为SYN报文、链接已建立过、ACK标记也设置了*/
			if (index == TCP_RST_SET
			    && ((test_bit(IPS_SEEN_REPLY_BIT, &ct->status)
				&& ct->proto.tcp.last_index == TCP_SYN_SET)
				|| (!test_bit(IPS_ASSURED_BIT, &ct->status)
				&& ct->proto.tcp.last_index == TCP_ACK_SET))
			    && ntohl(th->ack_seq) == ct->proto.tcp.last_end) 
			{
				/* RST sent to invalid SYN or ACK we had let through
				 * at a) and c) above:
				 *
				 * a) SYN was in window then
				 * c) we hold a half-open connection.
				 *
				 * Delete our connection entry.
				 * We skip window checking, because packet might ACK
				 * segments we ignored. */

				/*tcp在window校验*/
				goto in_window;
			}
			
		}
		/* Just fall through */
		default:
		{
			/* Keep compilers happy. */
			break;
		}
	}

	/*判断一个TCP包序列号和确认号是否在给定window范围内*/
	if (!tcp_in_window(ct, &ct->proto.tcp, dir, index, skb, dataoff, th)) 
	{
		spin_unlock_bh(&ct->lock);
		
		return -NF_ACCEPT;
	}

in_window:
	
	/* From now on we have got in-window packets */

	/*窗口内的报文*/
	/*更新赋值记录的上一个包的flag 与方向*/
	ct->proto.tcp.last_index = index;
	ct->proto.tcp.last_dir = dir;

	pr_debug("tcp_conntracks: ");
	nf_ct_dump_tuple(tuple);

	pr_debug("syn=%i ack=%i fin=%i rst=%i old=%i new=%i\n",(th->syn ? 1 : 0), (th->ack ? 1 : 0), (th->fin ? 1 : 0), (th->rst ? 1 : 0), old_state, new_state);

	/*新的ct tcp状态*/
	ct->proto.tcp.state = new_state;

	/*状态改为要关闭、ct状态修改为要关闭*/
	if (old_state != new_state && new_state == TCP_CONNTRACK_FIN_WAIT)
		ct->proto.tcp.seen[dir].flags |= IP_CT_TCP_FLAG_CLOSE_INIT;

	/*不同类型的老化时间获取*/
	if (ct->proto.tcp.retrans >= tn->tcp_max_retrans && timeouts[new_state] > timeouts[TCP_CONNTRACK_RETRANS])
		timeout = timeouts[TCP_CONNTRACK_RETRANS];
	else if ((ct->proto.tcp.seen[0].flags | ct->proto.tcp.seen[1].flags) & IP_CT_TCP_FLAG_DATA_UNACKNOWLEDGED && timeouts[new_state] > timeouts[TCP_CONNTRACK_UNACK])
		timeout = timeouts[TCP_CONNTRACK_UNACK];
	else if (ct->proto.tcp.last_win == 0 && timeouts[new_state] > timeouts[TCP_CONNTRACK_RETRANS])
		timeout = timeouts[TCP_CONNTRACK_RETRANS];
	else
		timeout = timeouts[new_state];
	
	spin_unlock_bh(&ct->lock);

	/*cache修改*/
	if (new_state != old_state)
		nf_conntrack_event_cache(IPCT_PROTOINFO, ct);

	/*original方向检查到了IPS_SEEN_REPLY_BIT、回应方向有数据*/
	if (!test_bit(IPS_SEEN_REPLY_BIT, &ct->status)) 
	{
		/* If only reply is a RST, we can consider ourselves not to
		   have an established connection: this is a fairly common
		   problem case, so we can delete the conntrack
		   immediately.  --RR */

		/*rst报文*/
		if (th->rst) 
		{
			nf_ct_kill_acct(ct, ctinfo, skb);
			return NF_ACCEPT;
		}
		/* ESTABLISHED without SEEN_REPLY, i.e. mid-connection
		 * pickup with loose=1. Avoid large ESTABLISHED timeout.
		 */

		
		if (new_state == TCP_CONNTRACK_ESTABLISHED && timeout > timeouts[TCP_CONNTRACK_UNACK])
			timeout = timeouts[TCP_CONNTRACK_UNACK];
	} 

	/*双向链接已建立、旧状态为SYN_RECV或已建立链接、且新状态为已建立链接TCP_CONNTRACK_ESTABLISHED*/
	else if (!test_bit(IPS_ASSURED_BIT, &ct->status)
		   && (old_state == TCP_CONNTRACK_SYN_RECV || old_state == TCP_CONNTRACK_ESTABLISHED)
		   && new_state == TCP_CONNTRACK_ESTABLISHED) 
	{
		/* Set ASSURED if we see see valid ack in ESTABLISHED
		   after SYN_RECV or a valid answer for a picked up
		   connection. */

		/*双向都看到了数据*/
		set_bit(IPS_ASSURED_BIT, &ct->status);

		
		nf_conntrack_event_cache(IPCT_ASSURED, ct);
	}

	/*刷新链接超时老化时间*/
	nf_ct_refresh_acct(ct, ctinfo, skb, timeout);

	return NF_ACCEPT;
	
}

/* Called when a new connection for this protocol found. */

/*******************************************************************************
 函数名称 :  tcp_new
 功能描述 :   tcp报文相关设置
 			  1.L4层字段如window, ack等字段赋给ct->proto.tcp.seen[0],新建立的连接才调这里，所以不用给reply方向的ct->proto.tcp.seen[1]赋值 
			  2.设置TCP的状态ct->proto.tcp.state=TCP_CONNTRACK_NONE(新建)
			  3.将ct->tuplehash加入到了 net->ct.unconfirmed，未确认链接
 输入参数 :  ct---nf_conn结构，新建的一条链接跟踪项
 			 skb---skb报文
 			 dataoff---四层数据部分偏移
 			 timeouts---超时时间
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static bool tcp_new(struct nf_conn *ct, const struct sk_buff *skb, unsigned int dataoff, unsigned int *timeouts)
{
	enum tcp_conntrack new_state;
	const struct tcphdr *th;
	struct tcphdr _tcph;

	/*链接跟踪对应的net namespace*/
	struct net *net = nf_ct_net(ct);

	/*namespace的tcp信息*/
	struct nf_tcp_net *tn = tcp_pernet(net);

	/*nf记录的客户端方向 tcp的状态*/
	const struct ip_ct_tcp_state *sender = &ct->proto.tcp.seen[0];

	/*nf记录的 服务端方向tcp的状态*/
	const struct ip_ct_tcp_state *receiver = &ct->proto.tcp.seen[1];

	/*tcp头*/
	th = skb_header_pointer(skb, dataoff, sizeof(_tcph), &_tcph);
	BUG_ON(th == NULL);

	/* Don't need lock here: this conntrack not in circulation yet */


	/*根据当前报文的tcp flag 转出的nf tcp新状态*/
	new_state = tcp_conntracks[0][get_conntrack_index(th)][TCP_CONNTRACK_NONE];

	/* Invalid: delete conntrack */
	/*非法新状态，新建ct失败*/
	if (new_state >= TCP_CONNTRACK_MAX) 
	{
		pr_debug("nf_ct_tcp: invalid new deleting.\n");
		
		return false;
	}


	/*当前为SYN报文，syn报文已发，nf新状态为TCP_CONNTRACK_SYN_SENT*/
	if (new_state == TCP_CONNTRACK_SYN_SENT) 
	{
		/*清除tcp 状态标记*/
		memset(&ct->proto.tcp, 0, sizeof(ct->proto.tcp));

		/* SYN packet，origin方向填充*/
		/*记录当前SYN报文序列号和报文长度之和最大值*/
		ct->proto.tcp.seen[0].td_end = segment_seq_plus_len(ntohl(th->seq), skb->len, dataoff, th);

		/*记录SYN报文 tcp窗口宽度*/
		ct->proto.tcp.seen[0].td_maxwin = ntohs(th->window);

		/*若SYN报文窗口宽度为0设为1*/
		if (ct->proto.tcp.seen[0].td_maxwin == 0)
			ct->proto.tcp.seen[0].td_maxwin = 1;

		/*ack+滑动窗口最大值 = 序列号+报文长度*/
		/*记录SYN报文 ack+滑动窗口最大值*/
		ct->proto.tcp.seen[0].td_maxend = ct->proto.tcp.seen[0].td_end;

		/*tcp选项填充*/
		tcp_options(skb, dataoff, th, &ct->proto.tcp.seen[0]);
	}
	else if (tn->tcp_loose == 0)
	{
		/*不再跟踪链接*/
		/* Don't try to pick up connections. */
		return false;
	}
	else 
	{
		/*其他报文*/
		memset(&ct->proto.tcp, 0, sizeof(ct->proto.tcp));
		/*
		 * We are in the middle of a connection,
		 * its history is lost for us.
		 * Let's try to use the data from the packet.
		 */
		 
		/*填充*/
		/*序列号和报文长度之和最大值*/
		ct->proto.tcp.seen[0].td_end = segment_seq_plus_len(ntohl(th->seq), skb->len, dataoff, th);

		/*滑动窗口最大值*/

		ct->proto.tcp.seen[0].td_maxwin = ntohs(th->window);

		/*若窗口宽度为0设为1*/
		if (ct->proto.tcp.seen[0].td_maxwin == 0)
			ct->proto.tcp.seen[0].td_maxwin = 1;
		/*ack+滑动窗口最大值*/
		ct->proto.tcp.seen[0].td_maxend = ct->proto.tcp.seen[0].td_end + ct->proto.tcp.seen[0].td_maxwin;

		/* We assume SACK and liberal window checking to handle
		 * window scaling */

		/*每方向动作，sack被发送端允许，滑动窗口检查是独立的*/
		ct->proto.tcp.seen[0].flags = ct->proto.tcp.seen[1].flags = IP_CT_TCP_FLAG_SACK_PERM |  IP_CT_TCP_FLAG_BE_LIBERAL;
	}

	/* tcp_packet will set them */
	/*最后一个包的index tcp flag*/

	ct->proto.tcp.last_index = TCP_NONE_SET;

	pr_debug("tcp_new: sender end=%u maxend=%u maxwin=%u scale=%i "
		 "receiver end=%u maxend=%u maxwin=%u scale=%i\n",
		 sender->td_end, sender->td_maxend, sender->td_maxwin,
		 sender->td_scale,
		 receiver->td_end, receiver->td_maxend, receiver->td_maxwin,
		 receiver->td_scale);
	
	return true;
}

static bool tcp_can_early_drop(const struct nf_conn *ct)
{
	switch (ct->proto.tcp.state) {
	case TCP_CONNTRACK_FIN_WAIT:
	case TCP_CONNTRACK_LAST_ACK:
	case TCP_CONNTRACK_TIME_WAIT:
	case TCP_CONNTRACK_CLOSE:
	case TCP_CONNTRACK_CLOSE_WAIT:
		return true;
	default:
		break;
	}

	return false;
}

#if IS_ENABLED(CONFIG_NF_CT_NETLINK)

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

static int tcp_to_nlattr(struct sk_buff *skb, struct nlattr *nla,
			 struct nf_conn *ct)
{
	struct nlattr *nest_parms;
	struct nf_ct_tcp_flags tmp = {};

	spin_lock_bh(&ct->lock);
	nest_parms = nla_nest_start(skb, CTA_PROTOINFO_TCP | NLA_F_NESTED);
	if (!nest_parms)
		goto nla_put_failure;

	if (nla_put_u8(skb, CTA_PROTOINFO_TCP_STATE, ct->proto.tcp.state) ||
	    nla_put_u8(skb, CTA_PROTOINFO_TCP_WSCALE_ORIGINAL,
		       ct->proto.tcp.seen[0].td_scale) ||
	    nla_put_u8(skb, CTA_PROTOINFO_TCP_WSCALE_REPLY,
		       ct->proto.tcp.seen[1].td_scale))
		goto nla_put_failure;

	tmp.flags = ct->proto.tcp.seen[0].flags;
	if (nla_put(skb, CTA_PROTOINFO_TCP_FLAGS_ORIGINAL,
		    sizeof(struct nf_ct_tcp_flags), &tmp))
		goto nla_put_failure;

	tmp.flags = ct->proto.tcp.seen[1].flags;
	if (nla_put(skb, CTA_PROTOINFO_TCP_FLAGS_REPLY,
		    sizeof(struct nf_ct_tcp_flags), &tmp))
		goto nla_put_failure;
	spin_unlock_bh(&ct->lock);

	nla_nest_end(skb, nest_parms);

	return 0;

nla_put_failure:
	spin_unlock_bh(&ct->lock);
	return -1;
}

static const struct nla_policy tcp_nla_policy[CTA_PROTOINFO_TCP_MAX+1] = {
	[CTA_PROTOINFO_TCP_STATE]	    = { .type = NLA_U8 },
	[CTA_PROTOINFO_TCP_WSCALE_ORIGINAL] = { .type = NLA_U8 },
	[CTA_PROTOINFO_TCP_WSCALE_REPLY]    = { .type = NLA_U8 },
	[CTA_PROTOINFO_TCP_FLAGS_ORIGINAL]  = { .len = sizeof(struct nf_ct_tcp_flags) },
	[CTA_PROTOINFO_TCP_FLAGS_REPLY]	    = { .len =  sizeof(struct nf_ct_tcp_flags) },
};

#define TCP_NLATTR_SIZE	( \
	NLA_ALIGN(NLA_HDRLEN + 1) + \
	NLA_ALIGN(NLA_HDRLEN + 1) + \
	NLA_ALIGN(NLA_HDRLEN + sizeof(sizeof(struct nf_ct_tcp_flags))) + \
	NLA_ALIGN(NLA_HDRLEN + sizeof(sizeof(struct nf_ct_tcp_flags))))

static int nlattr_to_tcp(struct nlattr *cda[], struct nf_conn *ct)
{
	struct nlattr *pattr = cda[CTA_PROTOINFO_TCP];
	struct nlattr *tb[CTA_PROTOINFO_TCP_MAX+1];
	int err;

	/* updates could not contain anything about the private
	 * protocol info, in that case skip the parsing */
	if (!pattr)
		return 0;

	err = nla_parse_nested(tb, CTA_PROTOINFO_TCP_MAX, pattr,
			       tcp_nla_policy, NULL);
	if (err < 0)
		return err;

	if (tb[CTA_PROTOINFO_TCP_STATE] &&
	    nla_get_u8(tb[CTA_PROTOINFO_TCP_STATE]) >= TCP_CONNTRACK_MAX)
		return -EINVAL;

	spin_lock_bh(&ct->lock);
	if (tb[CTA_PROTOINFO_TCP_STATE])
		ct->proto.tcp.state = nla_get_u8(tb[CTA_PROTOINFO_TCP_STATE]);

	if (tb[CTA_PROTOINFO_TCP_FLAGS_ORIGINAL]) {
		struct nf_ct_tcp_flags *attr =
			nla_data(tb[CTA_PROTOINFO_TCP_FLAGS_ORIGINAL]);
		ct->proto.tcp.seen[0].flags &= ~attr->mask;
		ct->proto.tcp.seen[0].flags |= attr->flags & attr->mask;
	}

	if (tb[CTA_PROTOINFO_TCP_FLAGS_REPLY]) {
		struct nf_ct_tcp_flags *attr =
			nla_data(tb[CTA_PROTOINFO_TCP_FLAGS_REPLY]);
		ct->proto.tcp.seen[1].flags &= ~attr->mask;
		ct->proto.tcp.seen[1].flags |= attr->flags & attr->mask;
	}

	if (tb[CTA_PROTOINFO_TCP_WSCALE_ORIGINAL] &&
	    tb[CTA_PROTOINFO_TCP_WSCALE_REPLY] &&
	    ct->proto.tcp.seen[0].flags & IP_CT_TCP_FLAG_WINDOW_SCALE &&
	    ct->proto.tcp.seen[1].flags & IP_CT_TCP_FLAG_WINDOW_SCALE) {
		ct->proto.tcp.seen[0].td_scale =
			nla_get_u8(tb[CTA_PROTOINFO_TCP_WSCALE_ORIGINAL]);
		ct->proto.tcp.seen[1].td_scale =
			nla_get_u8(tb[CTA_PROTOINFO_TCP_WSCALE_REPLY]);
	}
	spin_unlock_bh(&ct->lock);

	return 0;
}

static unsigned int tcp_nlattr_tuple_size(void)
{
	static unsigned int size __read_mostly;

	if (!size)
		size = nla_policy_len(nf_ct_port_nla_policy, CTA_PROTO_MAX + 1);

	return size;
}
#endif

#if IS_ENABLED(CONFIG_NF_CT_NETLINK_TIMEOUT)

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_cttimeout.h>

static int tcp_timeout_nlattr_to_obj(struct nlattr *tb[],
				     struct net *net, void *data)
{
	unsigned int *timeouts = data;
	struct nf_tcp_net *tn = tcp_pernet(net);
	int i;

	/* set default TCP timeouts. */
	for (i=0; i<TCP_CONNTRACK_TIMEOUT_MAX; i++)
		timeouts[i] = tn->timeouts[i];

	if (tb[CTA_TIMEOUT_TCP_SYN_SENT]) {
		timeouts[TCP_CONNTRACK_SYN_SENT] =
			ntohl(nla_get_be32(tb[CTA_TIMEOUT_TCP_SYN_SENT]))*HZ;
	}
	if (tb[CTA_TIMEOUT_TCP_SYN_RECV]) {
		timeouts[TCP_CONNTRACK_SYN_RECV] =
			ntohl(nla_get_be32(tb[CTA_TIMEOUT_TCP_SYN_RECV]))*HZ;
	}
	if (tb[CTA_TIMEOUT_TCP_ESTABLISHED]) {
		timeouts[TCP_CONNTRACK_ESTABLISHED] =
			ntohl(nla_get_be32(tb[CTA_TIMEOUT_TCP_ESTABLISHED]))*HZ;
	}
	if (tb[CTA_TIMEOUT_TCP_FIN_WAIT]) {
		timeouts[TCP_CONNTRACK_FIN_WAIT] =
			ntohl(nla_get_be32(tb[CTA_TIMEOUT_TCP_FIN_WAIT]))*HZ;
	}
	if (tb[CTA_TIMEOUT_TCP_CLOSE_WAIT]) {
		timeouts[TCP_CONNTRACK_CLOSE_WAIT] =
			ntohl(nla_get_be32(tb[CTA_TIMEOUT_TCP_CLOSE_WAIT]))*HZ;
	}
	if (tb[CTA_TIMEOUT_TCP_LAST_ACK]) {
		timeouts[TCP_CONNTRACK_LAST_ACK] =
			ntohl(nla_get_be32(tb[CTA_TIMEOUT_TCP_LAST_ACK]))*HZ;
	}
	if (tb[CTA_TIMEOUT_TCP_TIME_WAIT]) {
		timeouts[TCP_CONNTRACK_TIME_WAIT] =
			ntohl(nla_get_be32(tb[CTA_TIMEOUT_TCP_TIME_WAIT]))*HZ;
	}
	if (tb[CTA_TIMEOUT_TCP_CLOSE]) {
		timeouts[TCP_CONNTRACK_CLOSE] =
			ntohl(nla_get_be32(tb[CTA_TIMEOUT_TCP_CLOSE]))*HZ;
	}
	if (tb[CTA_TIMEOUT_TCP_SYN_SENT2]) {
		timeouts[TCP_CONNTRACK_SYN_SENT2] =
			ntohl(nla_get_be32(tb[CTA_TIMEOUT_TCP_SYN_SENT2]))*HZ;
	}
	if (tb[CTA_TIMEOUT_TCP_RETRANS]) {
		timeouts[TCP_CONNTRACK_RETRANS] =
			ntohl(nla_get_be32(tb[CTA_TIMEOUT_TCP_RETRANS]))*HZ;
	}
	if (tb[CTA_TIMEOUT_TCP_UNACK]) {
		timeouts[TCP_CONNTRACK_UNACK] =
			ntohl(nla_get_be32(tb[CTA_TIMEOUT_TCP_UNACK]))*HZ;
	}
	return 0;
}

static int
tcp_timeout_obj_to_nlattr(struct sk_buff *skb, const void *data)
{
	const unsigned int *timeouts = data;

	if (nla_put_be32(skb, CTA_TIMEOUT_TCP_SYN_SENT,
			htonl(timeouts[TCP_CONNTRACK_SYN_SENT] / HZ)) ||
	    nla_put_be32(skb, CTA_TIMEOUT_TCP_SYN_RECV,
			 htonl(timeouts[TCP_CONNTRACK_SYN_RECV] / HZ)) ||
	    nla_put_be32(skb, CTA_TIMEOUT_TCP_ESTABLISHED,
			 htonl(timeouts[TCP_CONNTRACK_ESTABLISHED] / HZ)) ||
	    nla_put_be32(skb, CTA_TIMEOUT_TCP_FIN_WAIT,
			 htonl(timeouts[TCP_CONNTRACK_FIN_WAIT] / HZ)) ||
	    nla_put_be32(skb, CTA_TIMEOUT_TCP_CLOSE_WAIT,
			 htonl(timeouts[TCP_CONNTRACK_CLOSE_WAIT] / HZ)) ||
	    nla_put_be32(skb, CTA_TIMEOUT_TCP_LAST_ACK,
			 htonl(timeouts[TCP_CONNTRACK_LAST_ACK] / HZ)) ||
	    nla_put_be32(skb, CTA_TIMEOUT_TCP_TIME_WAIT,
			 htonl(timeouts[TCP_CONNTRACK_TIME_WAIT] / HZ)) ||
	    nla_put_be32(skb, CTA_TIMEOUT_TCP_CLOSE,
			 htonl(timeouts[TCP_CONNTRACK_CLOSE] / HZ)) ||
	    nla_put_be32(skb, CTA_TIMEOUT_TCP_SYN_SENT2,
			 htonl(timeouts[TCP_CONNTRACK_SYN_SENT2] / HZ)) ||
	    nla_put_be32(skb, CTA_TIMEOUT_TCP_RETRANS,
			 htonl(timeouts[TCP_CONNTRACK_RETRANS] / HZ)) ||
	    nla_put_be32(skb, CTA_TIMEOUT_TCP_UNACK,
			 htonl(timeouts[TCP_CONNTRACK_UNACK] / HZ)))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -ENOSPC;
}

static const struct nla_policy tcp_timeout_nla_policy[CTA_TIMEOUT_TCP_MAX+1] = {
	[CTA_TIMEOUT_TCP_SYN_SENT]	= { .type = NLA_U32 },
	[CTA_TIMEOUT_TCP_SYN_RECV]	= { .type = NLA_U32 },
	[CTA_TIMEOUT_TCP_ESTABLISHED]	= { .type = NLA_U32 },
	[CTA_TIMEOUT_TCP_FIN_WAIT]	= { .type = NLA_U32 },
	[CTA_TIMEOUT_TCP_CLOSE_WAIT]	= { .type = NLA_U32 },
	[CTA_TIMEOUT_TCP_LAST_ACK]	= { .type = NLA_U32 },
	[CTA_TIMEOUT_TCP_TIME_WAIT]	= { .type = NLA_U32 },
	[CTA_TIMEOUT_TCP_CLOSE]		= { .type = NLA_U32 },
	[CTA_TIMEOUT_TCP_SYN_SENT2]	= { .type = NLA_U32 },
	[CTA_TIMEOUT_TCP_RETRANS]	= { .type = NLA_U32 },
	[CTA_TIMEOUT_TCP_UNACK]		= { .type = NLA_U32 },
};
#endif /* CONFIG_NF_CT_NETLINK_TIMEOUT */

#ifdef CONFIG_SYSCTL
static struct ctl_table tcp_sysctl_table[] = {
	{
		.procname	= "nf_conntrack_tcp_timeout_syn_sent",
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "nf_conntrack_tcp_timeout_syn_recv",
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "nf_conntrack_tcp_timeout_established",
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "nf_conntrack_tcp_timeout_fin_wait",
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "nf_conntrack_tcp_timeout_close_wait",
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "nf_conntrack_tcp_timeout_last_ack",
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "nf_conntrack_tcp_timeout_time_wait",
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "nf_conntrack_tcp_timeout_close",
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "nf_conntrack_tcp_timeout_max_retrans",
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "nf_conntrack_tcp_timeout_unacknowledged",
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "nf_conntrack_tcp_loose",
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname       = "nf_conntrack_tcp_be_liberal",
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
	{
		.procname	= "nf_conntrack_tcp_max_retrans",
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ }
};
#endif /* CONFIG_SYSCTL */

static int tcp_kmemdup_sysctl_table(struct nf_proto_net *pn,
				    struct nf_tcp_net *tn)
{
#ifdef CONFIG_SYSCTL
	if (pn->ctl_table)
		return 0;

	pn->ctl_table = kmemdup(tcp_sysctl_table,
				sizeof(tcp_sysctl_table),
				GFP_KERNEL);
	if (!pn->ctl_table)
		return -ENOMEM;

	pn->ctl_table[0].data = &tn->timeouts[TCP_CONNTRACK_SYN_SENT];
	pn->ctl_table[1].data = &tn->timeouts[TCP_CONNTRACK_SYN_RECV];
	pn->ctl_table[2].data = &tn->timeouts[TCP_CONNTRACK_ESTABLISHED];
	pn->ctl_table[3].data = &tn->timeouts[TCP_CONNTRACK_FIN_WAIT];
	pn->ctl_table[4].data = &tn->timeouts[TCP_CONNTRACK_CLOSE_WAIT];
	pn->ctl_table[5].data = &tn->timeouts[TCP_CONNTRACK_LAST_ACK];
	pn->ctl_table[6].data = &tn->timeouts[TCP_CONNTRACK_TIME_WAIT];
	pn->ctl_table[7].data = &tn->timeouts[TCP_CONNTRACK_CLOSE];
	pn->ctl_table[8].data = &tn->timeouts[TCP_CONNTRACK_RETRANS];
	pn->ctl_table[9].data = &tn->timeouts[TCP_CONNTRACK_UNACK];
	pn->ctl_table[10].data = &tn->tcp_loose;
	pn->ctl_table[11].data = &tn->tcp_be_liberal;
	pn->ctl_table[12].data = &tn->tcp_max_retrans;
#endif
	return 0;
}

static int tcp_init_net(struct net *net, u_int16_t proto)
{
	struct nf_tcp_net *tn = tcp_pernet(net);
	struct nf_proto_net *pn = &tn->pn;

	if (!pn->users) {
		int i;

		for (i = 0; i < TCP_CONNTRACK_TIMEOUT_MAX; i++)
			tn->timeouts[i] = tcp_timeouts[i];

		tn->tcp_loose = nf_ct_tcp_loose;
		tn->tcp_be_liberal = nf_ct_tcp_be_liberal;
		tn->tcp_max_retrans = nf_ct_tcp_max_retrans;
	}

	return tcp_kmemdup_sysctl_table(pn, tn);
}

static struct nf_proto_net *tcp_get_net_proto(struct net *net)
{
	return &net->ct.nf_ct_proto.tcp.pn;
}

/*tcp相关钩子函数注册*/
const struct nf_conntrack_l4proto nf_conntrack_l4proto_tcp4 =
{
	.l3proto		= PF_INET,
	.l4proto 		= IPPROTO_TCP,
	.pkt_to_tuple 		= tcp_pkt_to_tuple,
	.invert_tuple 		= tcp_invert_tuple,

/*proc相关*/
#ifdef CONFIG_NF_CONNTRACK_PROCFS
	.print_conntrack 	= tcp_print_conntrack,
#endif
	.packet 		= tcp_packet,
	.get_timeouts		= tcp_get_timeouts,
	.new 			= tcp_new,
	.error			= tcp_error,
	.can_early_drop		= tcp_can_early_drop,

/*netlink相关*/
#if IS_ENABLED(CONFIG_NF_CT_NETLINK)
	.to_nlattr		= tcp_to_nlattr,
	.from_nlattr		= nlattr_to_tcp,
	.tuple_to_nlattr	= nf_ct_port_tuple_to_nlattr,
	.nlattr_to_tuple	= nf_ct_port_nlattr_to_tuple,
	.nlattr_tuple_size	= tcp_nlattr_tuple_size,
	.nlattr_size		= TCP_NLATTR_SIZE,
	.nla_policy		= nf_ct_port_nla_policy,
#endif


#if IS_ENABLED(CONFIG_NF_CT_NETLINK_TIMEOUT)
	.ctnl_timeout		= {
		.nlattr_to_obj	= tcp_timeout_nlattr_to_obj,
		.obj_to_nlattr	= tcp_timeout_obj_to_nlattr,
		.nlattr_max	= CTA_TIMEOUT_TCP_MAX,
		.obj_size	= sizeof(unsigned int) *
					TCP_CONNTRACK_TIMEOUT_MAX,
		.nla_policy	= tcp_timeout_nla_policy,
	},
#endif /* CONFIG_NF_CT_NETLINK_TIMEOUT */
	.init_net		= tcp_init_net,
	.get_net_proto		= tcp_get_net_proto,
};



EXPORT_SYMBOL_GPL(nf_conntrack_l4proto_tcp4);

const struct nf_conntrack_l4proto nf_conntrack_l4proto_tcp6 =
{
	.l3proto		= PF_INET6,
	.l4proto 		= IPPROTO_TCP,
	.pkt_to_tuple 		= tcp_pkt_to_tuple,
	.invert_tuple 		= tcp_invert_tuple,
#ifdef CONFIG_NF_CONNTRACK_PROCFS
	.print_conntrack 	= tcp_print_conntrack,
#endif
	.packet 		= tcp_packet,
	.get_timeouts		= tcp_get_timeouts,
	.new 			= tcp_new,
	.error			= tcp_error,
	.can_early_drop		= tcp_can_early_drop,
#if IS_ENABLED(CONFIG_NF_CT_NETLINK)
	.nlattr_size		= TCP_NLATTR_SIZE,
	.to_nlattr		= tcp_to_nlattr,
	.from_nlattr		= nlattr_to_tcp,
	.tuple_to_nlattr	= nf_ct_port_tuple_to_nlattr,
	.nlattr_to_tuple	= nf_ct_port_nlattr_to_tuple,
	.nlattr_tuple_size	= tcp_nlattr_tuple_size,
	.nla_policy		= nf_ct_port_nla_policy,
#endif
#if IS_ENABLED(CONFIG_NF_CT_NETLINK_TIMEOUT)
	.ctnl_timeout		= {
		.nlattr_to_obj	= tcp_timeout_nlattr_to_obj,
		.obj_to_nlattr	= tcp_timeout_obj_to_nlattr,
		.nlattr_max	= CTA_TIMEOUT_TCP_MAX,
		.obj_size	= sizeof(unsigned int) *
					TCP_CONNTRACK_TIMEOUT_MAX,
		.nla_policy	= tcp_timeout_nla_policy,
	},
#endif /* CONFIG_NF_CT_NETLINK_TIMEOUT */
	.init_net		= tcp_init_net,
	.get_net_proto		= tcp_get_net_proto,
};
EXPORT_SYMBOL_GPL(nf_conntrack_l4proto_tcp6);
