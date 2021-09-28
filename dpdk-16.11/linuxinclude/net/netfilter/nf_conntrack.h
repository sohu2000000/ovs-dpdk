/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Connection state tracking for netfilter.  This is separated from,
 * but required by, the (future) NAT layer; it can also be used by an iptables
 * extension.
 *
 * 16 Dec 2003: Yasuyuki Kozakai @USAGI <yasuyuki.kozakai@toshiba.co.jp>
 *	- generalize L3 protocol dependent part.
 *
 * Derived from include/linux/netfiter_ipv4/ip_conntrack.h
 */

#ifndef _NF_CONNTRACK_H
#define _NF_CONNTRACK_H

#include <linux/netfilter/nf_conntrack_common.h>

#include <linux/bitops.h>
#include <linux/compiler.h>
#include <linux/atomic.h>

#include <linux/netfilter/nf_conntrack_tcp.h>
#include <linux/netfilter/nf_conntrack_dccp.h>
#include <linux/netfilter/nf_conntrack_sctp.h>
#include <linux/netfilter/nf_conntrack_proto_gre.h>
#include <net/netfilter/ipv6/nf_conntrack_icmpv6.h>

#include <net/netfilter/nf_conntrack_tuple.h>

/* per conntrack: protocol private data */
/*协议特有的用来表示连接跟踪的信息*/
union nf_conntrack_proto {
	/* insert conntrack proto private data here */
	struct nf_ct_dccp dccp;
	struct ip_ct_sctp sctp;
	struct ip_ct_tcp tcp;			/*链接跟踪私有数据tcp协议*/
	struct nf_ct_gre gre;
	unsigned int tmpl_padto;
};

union nf_conntrack_expect_proto {
	/* insert expect proto private data here */
};

#include <linux/types.h>
#include <linux/skbuff.h>

#include <net/netfilter/ipv4/nf_conntrack_ipv4.h>
#include <net/netfilter/ipv6/nf_conntrack_ipv6.h>

/*连接跟踪项的抽象*/
struct nf_conn {
	/* Usage count in here is 1 for hash table, 1 per skb,
	 * plus 1 for any connection(s) we are `master' for
	 *
	 * Hint, SKB address this struct and refcnt via skb->_nfct and
	 * helpers nf_conntrack_get() and nf_conntrack_put().
	 * Helper nf_ct_put() equals nf_conntrack_put() by dec refcnt,
	 * beware nf_ct_get() is different and don't inc refcnt.
	 */
	struct nf_conntrack ct_general; /*连接跟踪的引用计数及指向销毁一个连接跟踪项的函数指针,该连接记录被引用的次数*/

	spinlock_t	lock;
	u16		cpu;

#ifdef CONFIG_NF_CONNTRACK_ZONES
	struct nf_conntrack_zone zone;   /*zone 相关*/
#endif
	/* XXX should I move this to the tail ? - Y.K */
	/* These are my tuples; original and reply */
	struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];  /*nf_conntrack_tuple_hash{}类型的数组，大小为2。
																tuplehash[0]表示一条数据流“初始”方向上的连接情况，
																tuplehash[1]表示该数据流“应答”方向的响应情况。*/

	/* Have we seen traffic both ways yet? (bitset) */
	unsigned long status;			/*该连接的连接状态,数据连接的状态，是一个比特位图 enum ip_conntrack_status */

	/* jiffies32 when this ct is considered dead */
	u32 timeout;					/*连接垃圾回收定时器  连接跟踪的超时时间 */
									/*不同协议的每条连接都有默认超时时间，
									  如果在超过了该时间且没有属于某条连接的数据包来刷新该连接跟踪记录，
									  那么会调用这种协议类型提供的超时函数*/

	possible_net_t ct_net;			/*net结构指针*/

#if IS_ENABLED(CONFIG_NF_NAT)
	struct hlist_node	nat_bysource;  /*链首*/
#endif
	/* all members below initialized via memset */
	u8 __nfct_init_offset[0];

	/* If we were expected by an expectation, this will be it */
	struct nf_conn *master;			 /*将一个预期的连接分配给现有的连接，也就是说本连接是这个master的一个预期连接*/ 
									 /* 如果该连接是某个连接的子连接，则master指向它的主连接 */
									  /*如果该连接有期望连接，则该值统计期望连接的个数,	
									  指向另外一个ip_conntrack{}。一般用于期望连接场景。
									  即如果当前连接是另外某条连接的期望连接的话，那么该成员就指向那条我们所属的主连接*/

/*用于防火墙的mark，通过iptables的mark模块，能够实现对数据流打mark的功 能*/
#if defined(CONFIG_NF_CONNTRACK_MARK)
	u_int32_t mark;
#endif

#ifdef CONFIG_NF_CONNTRACK_SECMARK
	u_int32_t secmark;
#endif

	/* Extensions */
	struct nf_ct_ext *ext;					/*扩展使用,helper扩展功能，指向扩展结构，该结构中包含一些基于连接的功能扩展处理函数，tftp扩展处理函数*/

	/* Storage reserved for other modules, must be the last member */
	union nf_conntrack_proto proto;			/*每链接协议私有数据*//*存储特定协议的连接跟踪信息 也就是不同协议实现连接跟踪的额外参数 */
	 										
};


/*******************************************************************************
 函数名称 :  nf_ct_tuplehash_to_ctrack
 功能描述 :  根据tuple节点获取tuple所属的nf_conn结构
 输入参数 :  hash---tuple节点
 			 
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static inline struct nf_conn *
nf_ct_tuplehash_to_ctrack(const struct nf_conntrack_tuple_hash *hash)
{
	/*根据tuple节点获取tuple所属的nf_conn结构*/
	return container_of(hash, struct nf_conn, tuplehash[hash->tuple.dst.dir]);
}

static inline u_int16_t nf_ct_l3num(const struct nf_conn *ct)
{
	return ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num;
}

static inline u_int8_t nf_ct_protonum(const struct nf_conn *ct)
{
	return ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum;
}

#define nf_ct_tuple(ct, dir) (&(ct)->tuplehash[dir].tuple)

/* get master conntrack via master expectation */
#define master_ct(conntr) (conntr->master)

extern struct net init_net;

static inline struct net *nf_ct_net(const struct nf_conn *ct)
{
	return read_pnet(&ct->ct_net);
}

/* Alter reply tuple (maybe alter helper). */
void nf_conntrack_alter_reply(struct nf_conn *ct,
			      const struct nf_conntrack_tuple *newreply);

/* Is this tuple taken? (ignoring any belonging to the given
   conntrack). */
int nf_conntrack_tuple_taken(const struct nf_conntrack_tuple *tuple,
			     const struct nf_conn *ignored_conntrack);

#define NFCT_INFOMASK	7UL
#define NFCT_PTRMASK	~(NFCT_INFOMASK)

/* Return conntrack_info and tuple hash for given skb. */

/*******************************************************************************
 函数名称 :  nf_ct_get
 功能描述 :  报文处理入口
 输入参数 :  skb---当前的报文
 			 ctinfo---ct的状态位图
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static inline struct nf_conn *
nf_ct_get(const struct sk_buff *skb, enum ip_conntrack_info *ctinfo)
{
	/*获取报文关联的链接状态值*/
	*ctinfo = skb->_nfct & NFCT_INFOMASK;

	return (struct nf_conn *)(skb->_nfct & NFCT_PTRMASK);
}

/* decrement reference count on a conntrack */

/*******************************************************************************
 函数名称 :  nf_conntrack_init_net
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
static inline void nf_ct_put(struct nf_conn *ct)
{
	WARN_ON(!ct);

	/*引用清除*/
	nf_conntrack_put(&ct->ct_general);
}

/* Protocol module loading */
int nf_ct_l3proto_try_module_get(unsigned short l3proto);
void nf_ct_l3proto_module_put(unsigned short l3proto);

/* load module; enable/disable conntrack in this namespace */
int nf_ct_netns_get(struct net *net, u8 nfproto);
void nf_ct_netns_put(struct net *net, u8 nfproto);

/*
 * Allocate a hashtable of hlist_head (if nulls == 0),
 * or hlist_nulls_head (if nulls == 1)
 */
void *nf_ct_alloc_hashtable(unsigned int *sizep, int nulls);

void nf_ct_free_hashtable(void *hash, unsigned int size);

int nf_conntrack_hash_check_insert(struct nf_conn *ct);
bool nf_ct_delete(struct nf_conn *ct, u32 pid, int report);

bool nf_ct_get_tuplepr(const struct sk_buff *skb, unsigned int nhoff,
		       u_int16_t l3num, struct net *net,
		       struct nf_conntrack_tuple *tuple);
bool nf_ct_invert_tuplepr(struct nf_conntrack_tuple *inverse,
			  const struct nf_conntrack_tuple *orig);

void __nf_ct_refresh_acct(struct nf_conn *ct, enum ip_conntrack_info ctinfo,
			  const struct sk_buff *skb,
			  unsigned long extra_jiffies, int do_acct);

/* Refresh conntrack for this many jiffies and do accounting */

/*******************************************************************************
 函数名称 :  nf_ct_refresh_acct
 功能描述 :  报文处理入口
 输入参数 :  ct--要刷新的链接
 			 extra_jiffies---老化时间
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static inline void nf_ct_refresh_acct(struct nf_conn *ct, enum ip_conntrack_info ctinfo, const struct sk_buff *skb, unsigned long extra_jiffies)
{
	__nf_ct_refresh_acct(ct, ctinfo, skb, extra_jiffies, 1);
}

/* Refresh conntrack for this many jiffies */
static inline void nf_ct_refresh(struct nf_conn *ct,
				 const struct sk_buff *skb,
				 unsigned long extra_jiffies)
{
	__nf_ct_refresh_acct(ct, 0, skb, extra_jiffies, 0);
}

/* kill conntrack and do accounting */
bool nf_ct_kill_acct(struct nf_conn *ct, enum ip_conntrack_info ctinfo,
		     const struct sk_buff *skb);

/* kill conntrack without accounting */

static inline bool nf_ct_kill(struct nf_conn *ct)
{
	return nf_ct_delete(ct, 0, 0);
}

/* Set all unconfirmed conntrack as dying */
void nf_ct_unconfirmed_destroy(struct net *);

/* Iterate over all conntracks: if iter returns true, it's deleted. */
void nf_ct_iterate_cleanup_net(struct net *net,
			       int (*iter)(struct nf_conn *i, void *data),
			       void *data, u32 portid, int report);

/* also set unconfirmed conntracks as dying. Only use in module exit path. */
void nf_ct_iterate_destroy(int (*iter)(struct nf_conn *i, void *data),
			   void *data);

struct nf_conntrack_zone;

void nf_conntrack_free(struct nf_conn *ct);
struct nf_conn *nf_conntrack_alloc(struct net *net,
				   const struct nf_conntrack_zone *zone,
				   const struct nf_conntrack_tuple *orig,
				   const struct nf_conntrack_tuple *repl,
				   gfp_t gfp);

static inline int nf_ct_is_template(const struct nf_conn *ct)
{
	return test_bit(IPS_TEMPLATE_BIT, &ct->status);
}

/* It's confirmed if it is, or has been in the hash table. */
static inline int nf_ct_is_confirmed(const struct nf_conn *ct)
{
	return test_bit(IPS_CONFIRMED_BIT, &ct->status);
}

static inline int nf_ct_is_dying(const struct nf_conn *ct)
{
	/*超时老化标记*/
	return test_bit(IPS_DYING_BIT, &ct->status);
}

/* Packet is received from loopback */
static inline bool nf_is_loopback_packet(const struct sk_buff *skb)
{
	return skb->dev && skb->skb_iif && skb->dev->flags & IFF_LOOPBACK;
}

#define nfct_time_stamp ((u32)(jiffies))

/* jiffies until ct expires, 0 if already expired */
static inline unsigned long nf_ct_expires(const struct nf_conn *ct)
{
	s32 timeout = ct->timeout - nfct_time_stamp;

	return timeout > 0 ? timeout : 0;
}

static inline bool nf_ct_is_expired(const struct nf_conn *ct)
{
	return (__s32)(ct->timeout - nfct_time_stamp) <= 0;
}

/* use after obtaining a reference count */

/*******************************************************************************
 函数名称 :  nf_ct_should_gc
 功能描述 :  ct 已超时、ct已经确认链接、ct未挂入dying链表
 输入参数 :  
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static inline bool nf_ct_should_gc(const struct nf_conn *ct)
{
	return nf_ct_is_expired(ct) /*ct 已超时*/
			&& nf_ct_is_confirmed(ct)  /*ct已经确认链接*/
			&& !nf_ct_is_dying(ct);	   /*ct未挂入dying链表*/
}

struct kernel_param;

int nf_conntrack_set_hashsize(const char *val, const struct kernel_param *kp);
int nf_conntrack_hash_resize(unsigned int hashsize);

/*链接跟踪哈希表首地址*/
extern struct hlist_nulls_head *nf_conntrack_hash;

/*初始化htable_size 哈希桶个数*/
extern unsigned int nf_conntrack_htable_size;
extern seqcount_t nf_conntrack_generation;
extern unsigned int nf_conntrack_max;

/* must be called with rcu read lock held */

/*******************************************************************************
 函数名称 :  nf_conntrack_get_ht
 功能描述 :  获取哈希表地址、size
 输入参数 :  
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static inline void
nf_conntrack_get_ht(struct hlist_nulls_head **hash, unsigned int *hsize)
{
	struct hlist_nulls_head *hptr;
	unsigned int sequence, hsz;

	do {
		sequence = read_seqcount_begin(&nf_conntrack_generation);

		/*哈希表size*/
		hsz = nf_conntrack_htable_size;

		/*哈希表地址*/
		hptr = nf_conntrack_hash;
	} while (read_seqcount_retry(&nf_conntrack_generation, sequence));

	*hash = hptr;
	*hsize = hsz;
}

struct nf_conn *nf_ct_tmpl_alloc(struct net *net,
				 const struct nf_conntrack_zone *zone,
				 gfp_t flags);
void nf_ct_tmpl_free(struct nf_conn *tmpl);


/*******************************************************************************
 函数名称 :  nf_ct_set
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
static inline void
nf_ct_set(struct sk_buff *skb, struct nf_conn *ct, enum ip_conntrack_info info)
{
	/* 这里取的地址，由于ct_general是ct的第一个成员，所以skb->nfct保存的是ct的地址。 */
	/* ct的状态 */
	skb->_nfct = (unsigned long)ct | info;
}

#define NF_CT_STAT_INC(net, count)	  __this_cpu_inc((net)->ct.stat->count)
#define NF_CT_STAT_INC_ATOMIC(net, count) this_cpu_inc((net)->ct.stat->count)
#define NF_CT_STAT_ADD_ATOMIC(net, count, v) this_cpu_add((net)->ct.stat->count, (v))

#define MODULE_ALIAS_NFCT_HELPER(helper) \
        MODULE_ALIAS("nfct-helper-" helper)

#endif /* _NF_CONNTRACK_H */
