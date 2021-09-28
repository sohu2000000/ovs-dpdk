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
 �������� :  tftp_help
 �������� :  ������������ ����ȫ���������ӹ�ϣ��nf_ct_expect_hash������struct nf_conn_help�ṹ������
 
 			 ����ͨ��conntrack��Ŀ����������һ��expect conntrack���������ӣ�����¼��������ϵĶ�����Ϣ��
 			 1.   �������ݰ���ct��ʼ��һ��expect���ӣ�����help��������ipv4_confirm()ʱ���õģ�����ct�Ǵ��ڵġ� 			 
			 2.   ���ct����NAT���͵���nf_nat_tftpָ��ĺ�����������ָ��nf_nat_tftp.c�е�help()������
			 3.tftp����tftp read/write request��ʱ�������������
 
 ������� :  skb---���������װ�
 			 ct---��������ct
 ������� :  ��
 ����ֵ�� :  ��
 --------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸����� :  
 �޸�Ŀ�� :  
 �޸����� :  
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

	/* ���tftp�ײ� */
	tfh = skb_header_pointer(skb, protoff + sizeof(struct udphdr), sizeof(_tftph), &_tftph);
	if (tfh == NULL)
		return NF_ACCEPT;

	/* ��tftp�ײ��л�ò����룬tftp���󣨶���д��ֻ�ܴ�client��server */
	switch (ntohs(tfh->opcode)) 
	{
		/* read���� */
		case TFTP_OPCODE_READ:

		/* write���� */
		case TFTP_OPCODE_WRITE:
			/* RRQ and WRQ works the same way */
			nf_ct_dump_tuple(&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
			nf_ct_dump_tuple(&ct->tuplehash[IP_CT_DIR_REPLY].tuple);

			/* 
				��nf_ct_expect_cache�Ϸ���һ��expect���ӣ�ͬʱ������ֵ��
				exp->master = ct,
				exp->use = 1�� ������������
			*/

			/*slab����һ����������expect��masterָ��ǰ���ӿ�������*/
			exp = nf_ct_expect_alloc(ct);
			if (exp == NULL)
			{
				nf_ct_helper_log(skb, ct, "cannot alloc expectation");

				/*δ����ɹ��򶪰�*/
				return NF_DROP;
			}
			
			/*��ȡ�����ӵ�reply����tuple�� ����ct��ʼ��expect */
			tuple = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;

			/*�������ӳ�ʼ������ַ��˿ڸ�ֵ*/
			nf_ct_expect_init(exp, NF_CT_EXPECT_CLASS_DEFAULT, nf_ct_l3num(ct), &tuple->src.u3, &tuple->dst.u3, IPPROTO_UDP, NULL, &tuple->dst.u.udp.port);

			pr_debug("expect: ");


			nf_ct_dump_tuple(&exp->tuple);

			/* ָ��help() -- nf_nat_tftp.c */
			nf_nat_tftp = rcu_dereference(nf_nat_tftp_hook);

			/* ���ݰ���Ҫ��NATʱ��if������������������else������ */
			if (nf_nat_tftp && ct->status & IPS_NAT_MASK)
				ret = nf_nat_tftp(skb, ctinfo, exp);

			/* ����struct nf_conn_help�ṹ�������Լ�ȫ�ֵ�������������nf_ct_expect_hash�� */
			else if (nf_ct_expect_related(exp) != 0) 
			{
				nf_ct_helper_log(skb, ct, "cannot add expectation");
				ret = NF_DROP;
			}

			/*�ͷ�slab�ڴ�*/
			nf_ct_expect_put(exp);

			break;

		/* ���� */
		case TFTP_OPCODE_DATA:

		/* ���ݵ�ACK */
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

/*tftp��helper*/
static struct nf_conntrack_helper tftp[MAX_PORTS * 2] __read_mostly;


/*tftp �������Ӳ���*/
static const struct nf_conntrack_expect_policy tftp_exp_policy = {
	.max_expected	= 1,  /*tftp����������Ӹ���1*/
	.timeout	= 5 * 60, /*�������ӳ�ʱʱ��5����*/
};

static void nf_conntrack_tftp_fini(void)
{
	nf_conntrack_helpers_unregister(tftp, ports_c * 2);
}


/*******************************************************************************
 �������� :  nf_conntrack_tftp_init
 �������� :  1.��nf_conntrack_helper�ṹ���tuple�����˲��ֳ�ʼ��
 			 2.ע����help����Ϊtftp_help()
 			 3.��ʼ����һ��conntrack helper������������ע�ᵽhelper extension������
 ������� :  
 ������� :  ��
 ����ֵ�� :  ��
 --------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸����� :  
 �޸�Ŀ�� :  
 �޸����� :  
*******************************************************************************/
static int __init nf_conntrack_tftp_init(void)
{
	int i, ret;

	NF_CT_HELPER_BUILD_BUG_ON(0);

	if (ports_c == 0)
		ports[ports_c++] = TFTP_PORT;  /*69�˿�*/

	for (i = 0; i < ports_c; i++) 
	{
		/*v4 ��ʼ��conntrack helper����, tuple���ָ�ֵ���̶�����Э��,helper����Ϊtftp_help������tftp read/write request��ʱ�������������*/
		nf_ct_helper_init(&tftp[2 * i], AF_INET, IPPROTO_UDP, "tftp", TFTP_PORT, ports[i], i, &tftp_exp_policy, 0, tftp_help, NULL, THIS_MODULE);

		/*v6*/
		nf_ct_helper_init(&tftp[2 * i + 1], AF_INET6, IPPROTO_UDP, "tftp", TFTP_PORT, ports[i], i, &tftp_exp_policy, 0, tftp_help, NULL, THIS_MODULE);
	}

	/*ע�ᵽtftp helper ������*/
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
