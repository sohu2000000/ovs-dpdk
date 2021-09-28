/* (C) 2001-2002 Magnus Boden <mb@ozaba.mine.nu>
 * (C) 2006-2012 Patrick McHardy <kaber@trash.net>
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/netfilter.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <linux/netfilter/nf_conntrack_tftp.h>

MODULE_AUTHOR("Magnus Boden <mb@ozaba.mine.nu>");
MODULE_DESCRIPTION("TFTP connection tracking helper");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ip_conntrack_tftp");
MODULE_ALIAS_NFCT_HELPER("tftp");

#define MAX_PORTS 8
static unsigned short ports[MAX_PORTS];
static unsigned int ports_c;
module_param_array(ports, ushort, &ports_c, 0400);
MODULE_PARM_DESC(ports, "Port numbers of TFTP servers");


unsigned int (*nf_nat_tftp_hook)(struct sk_buff *skb,
				 enum ip_conntrack_info ctinfo,
				 struct nf_conntrack_expect *exp) __read_mostly;


EXPORT_SYMBOL_GPL(nf_nat_tftp_hook);


/*******************************************************************************
 函数名称 :  tftp_help
 功能描述 :  生成期望链接 插入全局期望链接哈希表nf_ct_expect_hash、插入struct nf_conn_help结构的链表
 
 			 在普通的conntrack条目基础上增加一个expect conntrack（期望连接）来记录这个连接上的额外信息。
 			 1.   根据数据包的ct初始化一个expect连接，由于help函数是在ipv4_confirm()时调用的，所以ct是存在的。 			 
			 2.   如果ct做了NAT，就调用nf_nat_tftp指向的函数，这里它指向nf_nat_tftp.c中的help()函数。
			 3.tftp处理tftp read/write request的时候会进入这个函数
 
 输入参数 :  skb---数据链接首包
 			 ct---控制链接ct
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static int tftp_help(struct sk_buff *skb,
		     unsigned int protoff,
		     struct nf_conn *ct,
		     enum ip_conntrack_info ctinfo)
{
	const struct tftphdr *tfh;
	struct tftphdr _tftph;
	struct nf_conntrack_expect *exp;
	struct nf_conntrack_tuple *tuple;
	unsigned int ret = NF_ACCEPT;
	typeof(nf_nat_tftp_hook) nf_nat_tftp;

	/* 获得tftp首部 */
	tfh = skb_header_pointer(skb, protoff + sizeof(struct udphdr), sizeof(_tftph), &_tftph);
	if (tfh == NULL)
		return NF_ACCEPT;

	/* 从tftp首部中获得操作码，tftp请求（读或写）只能从client到server */
	switch (ntohs(tfh->opcode)) 
	{
		/* read请求 */
		case TFTP_OPCODE_READ:

		/* write请求 */
		case TFTP_OPCODE_WRITE:
			/* RRQ and WRQ works the same way */
			nf_ct_dump_tuple(&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
			nf_ct_dump_tuple(&ct->tuplehash[IP_CT_DIR_REPLY].tuple);

			/* 
				在nf_ct_expect_cache上分配一个expect连接，同时赋两个值：
				exp->master = ct,
				exp->use = 1。 被主链接引用
			*/

			/*slab申请一个期望链接expect，master指向当前链接控制链接*/
			exp = nf_ct_expect_alloc(ct);
			if (exp == NULL)
			{
				nf_ct_helper_log(skb, ct, "cannot alloc expectation");

				/*未申请成功则丢包*/
				return NF_DROP;
			}
			
			/*获取主链接的reply方向tuple， 根据ct初始化expect */
			tuple = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;

			/*期望链接初始化，地址与端口赋值*/
			nf_ct_expect_init(exp, NF_CT_EXPECT_CLASS_DEFAULT, nf_ct_l3num(ct), &tuple->src.u3, &tuple->dst.u3, IPPROTO_UDP, NULL, &tuple->dst.u.udp.port);

			pr_debug("expect: ");


			nf_ct_dump_tuple(&exp->tuple);

			/* 指向help() -- nf_nat_tftp.c */
			nf_nat_tftp = rcu_dereference(nf_nat_tftp_hook);

			/* 数据包需要走NAT时，if成立，局域网传输则else成立。 */
			if (nf_nat_tftp && ct->status & IPS_NAT_MASK)
				ret = nf_nat_tftp(skb, ctinfo, exp);

			/* 插入struct nf_conn_help结构的链表以及全局的期望连接链表nf_ct_expect_hash中 */
			else if (nf_ct_expect_related(exp) != 0) 
			{
				nf_ct_helper_log(skb, ct, "cannot add expectation");
				ret = NF_DROP;
			}

			/*释放slab内存*/
			nf_ct_expect_put(exp);

			break;

		/* 数据 */
		case TFTP_OPCODE_DATA:

		/* 数据的ACK */
		case TFTP_OPCODE_ACK:
			pr_debug("Data/ACK opcode\n");
			break;
		case TFTP_OPCODE_ERROR:
			pr_debug("Error opcode\n");
			break;
		default:
			pr_debug("Unknown opcode\n");
		}
	return ret;
}

/*tftp的helper*/
static struct nf_conntrack_helper tftp[MAX_PORTS * 2] __read_mostly;


/*tftp 期望链接策略*/
static const struct nf_conntrack_expect_policy tftp_exp_policy = {
	.max_expected	= 1,  /*tftp最大期望链接个数1*/
	.timeout	= 5 * 60, /*期望链接超时时间5分钟*/
};

static void nf_conntrack_tftp_fini(void)
{
	nf_conntrack_helpers_unregister(tftp, ports_c * 2);
}


/*******************************************************************************
 函数名称 :  nf_conntrack_tftp_init
 功能描述 :  1.对nf_conntrack_helper结构体的tuple进行了部分初始化
 			 2.注册了help函数为tftp_help()
 			 3.初始化了一个conntrack helper方法，并将其注册到helper extension的链表
 输入参数 :  
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static int __init nf_conntrack_tftp_init(void)
{
	int i, ret;

	NF_CT_HELPER_BUILD_BUG_ON(0);

	if (ports_c == 0)
		ports[ports_c++] = TFTP_PORT;  /*69端口*/

	for (i = 0; i < ports_c; i++) 
	{
		/*v4 初始化conntrack helper方法, tuple部分赋值，固定参数协议,helper函数为tftp_help，处理tftp read/write request的时候会进入这个函数*/
		nf_ct_helper_init(&tftp[2 * i], AF_INET, IPPROTO_UDP, "tftp", TFTP_PORT, ports[i], i, &tftp_exp_policy, 0, tftp_help, NULL, THIS_MODULE);

		/*v6*/
		nf_ct_helper_init(&tftp[2 * i + 1], AF_INET6, IPPROTO_UDP, "tftp", TFTP_PORT, ports[i], i, &tftp_exp_policy, 0, tftp_help, NULL, THIS_MODULE);
	}

	/*注册到tftp helper 到链表*/
	ret = nf_conntrack_helpers_register(tftp, ports_c * 2);
	if (ret < 0) 
	{
		pr_err("failed to register helpers\n");
		return ret;
	}
	
	return 0;
}

module_init(nf_conntrack_tftp_init);
module_exit(nf_conntrack_tftp_fini);
