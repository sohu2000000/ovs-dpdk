/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NF_CONNTRACK_ZONES_H
#define _NF_CONNTRACK_ZONES_H

#include <linux/netfilter/nf_conntrack_zones_common.h>

#if IS_ENABLED(CONFIG_NF_CONNTRACK)
#include <net/netfilter/nf_conntrack_extend.h>

static inline const struct nf_conntrack_zone *
nf_ct_zone(const struct nf_conn *ct)
{
#ifdef CONFIG_NF_CONNTRACK_ZONES
	return &ct->zone;
#else
	return &nf_ct_zone_dflt;
#endif
}


/*******************************************************************************
 函数名称 :  nf_ct_zone_init
 功能描述 :  初始化skb属于的zone
 输入参数 :  zone---zone
 			 id---
 			 dir--
 			 
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static inline const struct nf_conntrack_zone *
nf_ct_zone_init(struct nf_conntrack_zone *zone, u16 id, u8 dir, u8 flags)
{
	zone->id = id;
	zone->flags = flags;
	zone->dir = dir;

	return zone;
}


/*******************************************************************************
 函数名称 :  nf_conntrack_init_net
 功能描述 :  报文处理入口
 输入参数 :  tmpl---skb管理的链接
 			 skb---skb报文
 			 tmp---nf conntrack zone
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static inline const struct nf_conntrack_zone *
nf_ct_zone_tmpl(const struct nf_conn *tmpl, const struct sk_buff *skb,
		struct nf_conntrack_zone *tmp)
{
#ifdef CONFIG_NF_CONNTRACK_ZONES
	if (!tmpl)
		return &nf_ct_zone_dflt;

	if (tmpl->zone.flags & NF_CT_FLAG_MARK)
		return nf_ct_zone_init(tmp, skb->mark, tmpl->zone.dir, 0);
#endif

	return nf_ct_zone(tmpl);
}


/*******************************************************************************
 函数名称 :  nf_ct_zone_add
 功能描述 :  zone信息赋值给nf_conn
 输入参数 :  
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static inline void nf_ct_zone_add(struct nf_conn *ct,
				  const struct nf_conntrack_zone *zone)
{
#ifdef CONFIG_NF_CONNTRACK_ZONES
	ct->zone = *zone;
#endif
}

static inline bool nf_ct_zone_matches_dir(const struct nf_conntrack_zone *zone,
					  enum ip_conntrack_dir dir)
{
	return zone->dir & (1 << dir);
}

static inline u16 nf_ct_zone_id(const struct nf_conntrack_zone *zone,
				enum ip_conntrack_dir dir)
{
#ifdef CONFIG_NF_CONNTRACK_ZONES
	return nf_ct_zone_matches_dir(zone, dir) ?
	       zone->id : NF_CT_DEFAULT_ZONE_ID;
#else
	return NF_CT_DEFAULT_ZONE_ID;
#endif
}

static inline bool nf_ct_zone_equal(const struct nf_conn *a,
				    const struct nf_conntrack_zone *b,
				    enum ip_conntrack_dir dir)
{
#ifdef CONFIG_NF_CONNTRACK_ZONES
	return nf_ct_zone_id(nf_ct_zone(a), dir) ==
	       nf_ct_zone_id(b, dir);
#else
	return true;
#endif
}

static inline bool nf_ct_zone_equal_any(const struct nf_conn *a,
					const struct nf_conntrack_zone *b)
{
#ifdef CONFIG_NF_CONNTRACK_ZONES
	return nf_ct_zone(a)->id == b->id;
#else
	return true;
#endif
}
#endif /* IS_ENABLED(CONFIG_NF_CONNTRACK) */
#endif /* _NF_CONNTRACK_ZONES_H */
