/* SPDX-License-Identifier: GPL-2.0 */
/*
 * connection tracking expectations.
 */

#ifndef _NF_CONNTRACK_EXPECT_H
#define _NF_CONNTRACK_EXPECT_H

#include <linux/refcount.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_zones.h>

extern unsigned int nf_ct_expect_hsize;
extern unsigned int nf_ct_expect_max;
extern struct hlist_head *nf_ct_expect_hash;/*期望链接哈希表*/


/*期望链接实例*/
struct nf_conntrack_expect {
	/* Conntrack expectation list member */
	struct hlist_node lnode;						/*期望链接链*///同属一个master连接的期望连接被组织到一个链表中，见struct nf_conn_help定义

	/* Hash member */
	struct hlist_node hnode;						/*全局期望链接哈希链*/

	/* We expect this tuple, with the following mask */
	struct nf_conntrack_tuple tuple;				//期望连接跟踪信息块能够匹配的skb，不带server端口的五元组，单向tuple
	struct nf_conntrack_tuple_mask mask;

	/* Function to call after setup and insertion */
	void (*expectfn)(struct nf_conn *new, struct nf_conntrack_expect *this); /*回调函数*///当期望连接到来时，会调用该函数，该回调函数是可选的做NAT等

	/* Helper to assign to new connection */
	struct nf_conntrack_helper *helper;				/*用到的注册的helper结构，这里是tftp结构*///指向识别出该期望连接的helper

	/* The conntrack of the master connection */
	struct nf_conn *master;							/*指向的master链接*/

	/* Timer function; deletes the expectation. */
	struct timer_list timeout;						/*老化删除期望链接*///和普通的连接类似，每个期望连接也有有效定时器，定时器超时则会从系统中删除该期望连接

	/* Usage count. */
	refcount_t use;									/*期望链接引用计数*/

	/* Flags */
	unsigned int flags;

	/* Expectation class */
	unsigned int class;

#ifdef CONFIG_NF_NAT_NEEDED
	union nf_inet_addr saved_addr;
	/* This is the original per-proto part, used to map the
	 * expected connection the way the recipient expects. */
	union nf_conntrack_man_proto saved_proto;
	/* Direction relative to the master connection. */
	enum ip_conntrack_dir dir;
#endif

	struct rcu_head rcu;
};

static inline struct net *nf_ct_exp_net(struct nf_conntrack_expect *exp)
{
	return nf_ct_net(exp->master);
}

#define NF_CT_EXP_POLICY_NAME_LEN	16

struct nf_conntrack_expect_policy {
	unsigned int	max_expected;				/*允许最大的期望链接数*/
	unsigned int	timeout;					 /*超时老化时间*/
	char		name[NF_CT_EXP_POLICY_NAME_LEN];
};

#define NF_CT_EXPECT_CLASS_DEFAULT	0
#define NF_CT_EXPECT_MAX_CNT		255

int nf_conntrack_expect_pernet_init(struct net *net);
void nf_conntrack_expect_pernet_fini(struct net *net);

int nf_conntrack_expect_init(void);
void nf_conntrack_expect_fini(void);

struct nf_conntrack_expect *
__nf_ct_expect_find(struct net *net,
		    const struct nf_conntrack_zone *zone,
		    const struct nf_conntrack_tuple *tuple);

struct nf_conntrack_expect *
nf_ct_expect_find_get(struct net *net,
		      const struct nf_conntrack_zone *zone,
		      const struct nf_conntrack_tuple *tuple);

struct nf_conntrack_expect *
nf_ct_find_expectation(struct net *net,
		       const struct nf_conntrack_zone *zone,
		       const struct nf_conntrack_tuple *tuple);

void nf_ct_unlink_expect_report(struct nf_conntrack_expect *exp,
				u32 portid, int report);
static inline void nf_ct_unlink_expect(struct nf_conntrack_expect *exp)
{
	nf_ct_unlink_expect_report(exp, 0, 0);
}

void nf_ct_remove_expectations(struct nf_conn *ct);
void nf_ct_unexpect_related(struct nf_conntrack_expect *exp);
bool nf_ct_remove_expect(struct nf_conntrack_expect *exp);

void nf_ct_expect_iterate_destroy(bool (*iter)(struct nf_conntrack_expect *e, void *data), void *data);
void nf_ct_expect_iterate_net(struct net *net,
			      bool (*iter)(struct nf_conntrack_expect *e, void *data),
                              void *data, u32 portid, int report);

/* Allocate space for an expectation: this is mandatory before calling
   nf_ct_expect_related.  You will have to call put afterwards. */
struct nf_conntrack_expect *nf_ct_expect_alloc(struct nf_conn *me);
void nf_ct_expect_init(struct nf_conntrack_expect *, unsigned int, u_int8_t,
		       const union nf_inet_addr *,
		       const union nf_inet_addr *,
		       u_int8_t, const __be16 *, const __be16 *);
void nf_ct_expect_put(struct nf_conntrack_expect *exp);
int nf_ct_expect_related_report(struct nf_conntrack_expect *expect, 
				u32 portid, int report);
static inline int nf_ct_expect_related(struct nf_conntrack_expect *expect)
{
	return nf_ct_expect_related_report(expect, 0, 0);
}

#endif /*_NF_CONNTRACK_EXPECT_H*/

