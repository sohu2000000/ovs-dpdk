/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   Copyright 2014 6WIND S.A.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <inttypes.h>
#include <errno.h>
#include <ctype.h>
#include <sys/queue.h>

#include <rte_debug.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_hexdump.h>
#include <rte_errno.h>
#include <rte_memcpy.h>

/*
 * ctrlmbuf constructor, given as a callback function to
 * rte_mempool_create()
 */
void
rte_ctrlmbuf_init(struct rte_mempool *mp,
		__attribute__((unused)) void *opaque_arg,
		void *_m,
		__attribute__((unused)) unsigned i)
{
	struct rte_mbuf *m = _m;
	rte_pktmbuf_init(mp, opaque_arg, _m, i);
	m->ol_flags |= CTRL_MBUF_FLAG;
}

/*
 * pktmbuf pool constructor, given as a callback function to
 * rte_mempool_create()
 */
/*******************************************************
  函数名:		rte_pktmbuf_pool_init
  功能描述: 	校验设置内存池elt_size是否合法
  参数描述: 	mp---内存池地址
				opaque_arg---记录mbuf单元的dataroom长度和priv长度

  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
void rte_pktmbuf_pool_init(struct rte_mempool *mem_pool, void *opaque_arg)
{
	struct rte_pktmbuf_pool_private *user_mbp_priv, *mem_pool_pkt_mbuf_priv;
	struct rte_pktmbuf_pool_private default_mbp_priv;
	uint16_t room_size;

	/*单报文elem长度校验*/
	RTE_ASSERT(mem_pool->elt_size >= sizeof(struct rte_mbuf));

	/* if no structure is provided, assume no mbuf private area */
	user_mbp_priv = opaque_arg;
	
	if (user_mbp_priv == NULL) 
	{
		default_mbp_priv.mbuf_priv_size = 0;

		/*内存池的报文长度规格 /*单个报文size rte_mbuf + prive + dataroom*/
		if (mem_pool->elt_size > sizeof(struct rte_mbuf))
		{
			/*dataroom的size*/
			room_size = mem_pool->elt_size - sizeof(struct rte_mbuf);
		}
		else
		{
			room_size = 0;
		}
		
		default_mbp_priv.mbuf_data_room_size = room_size;
		user_mbp_priv = &default_mbp_priv;
	}

	/*elem size 足够长，private 当前是0*/
	RTE_ASSERT(mem_pool->elt_size >= sizeof(struct rte_mbuf) + user_mbp_priv->mbuf_data_room_size + user_mbp_priv->mbuf_priv_size);

	/*偏过mempool头+128逻辑核cache地址，存储priv*/
	mem_pool_pkt_mbuf_priv = rte_mempool_get_priv(mem_pool);

	/*长度信息赋值给cache,user_mbp_priv->mbuf_data_room_size = dataroom*/
	//user_mbp_priv->mbuf_priv_size = 0;
	/*长度信息拷贝到mp 最尾部，4字节*/
	memcpy(mem_pool_pkt_mbuf_priv, user_mbp_priv, sizeof(*mem_pool_pkt_mbuf_priv));
}

/*
 * pktmbuf constructor, given as a callback function to
 * rte_mempool_create().
 * Set the fields of a packet mbuf to their default values.
 */

/*******************************************************
  函数名:		rte_pktmbuf_init
  功能描述: 	elt_list链表mbuf初始化，内存清0
  参数描述: 	mp---内存池地址
				opaque_arg---记录mbuf单元的dataroom长度和priv长度

  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
void
rte_pktmbuf_init(struct rte_mempool *mp,
		 __attribute__((unused)) void *opaque_arg,
		 void *_m,
		 __attribute__((unused)) unsigned i)
{
	struct rte_mbuf *m = _m;
	uint32_t mbuf_size, buf_len, priv_size;

	/*获取mbuf prive 长度*/
	priv_size = rte_pktmbuf_priv_size(mp);

	/*mbuf长度*/
	mbuf_size = sizeof(struct rte_mbuf) + priv_size;

	/*数据部分的长度 mbuf_data_room_size*/
	buf_len = rte_pktmbuf_data_room_size(mp);

	/*长度校验*/
	RTE_ASSERT(RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) == priv_size);
	RTE_ASSERT(mp->elt_size >= mbuf_size);
	RTE_ASSERT(buf_len <= UINT16_MAX);

	/*elt元素size清0*/
	memset(m, 0, mp->elt_size);

	/* start of buffer is after mbuf structure and priv data */
	m->priv_size = priv_size;

	/*buf 起始地址 m + mbufsize偏移*/
	m->buf_addr = (char *)m + mbuf_size;
	m->buf_physaddr = rte_mempool_virt2phy(mp, m) + mbuf_size;
	m->buf_len = (uint16_t)buf_len;

	/* keep some headroom between start of buffer and data */
	m->data_off = RTE_MIN(RTE_PKTMBUF_HEADROOM, (uint16_t)m->buf_len);

	/* init some constant fields */
	m->pool = mp;
	m->nb_segs = 1;
	m->port = 0xff;
}

/* helper to create a mbuf pool */
/*******************************************************
  函数名:		rte_pktmbuf_pool_create
  功能描述: 	1.申请128个逻辑核cache结构sizeof(struct rte_mempool_cache)，挂250个mbuf obj
  				2.申请所有mbuf 内存切成mbuf 入队，多生产者多消费者
  				
  				内存池创建，做成mbuf，放入队列
  参数描述: 	name---内存池名字,"MBUF_POOL"
  				n---所有端口(nb_ports个端口x8191个mbuf)mbuf总数
  				cache_size---每逻辑核使用的mbuf cache，优先从这里拿mbuf，用完了再从内存池拿
  				priv_size---私有内存大小，目前为0
  				data_room_size---数据空间大小，mbuf 数据部分默认大小，2176，单个mbuf 数据部分 size
  				socket_id---socket id，在哪个socket上拿的内存
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
struct rte_mempool *rte_pktmbuf_pool_create(const char *name, unsigned mbuf_num, unsigned cache_size, uint16_t priv_size, uint16_t data_room_size, int socket_id)
{
	struct rte_mempool *mem_pool;

	/*对mbuf长度的描述*/
	struct rte_pktmbuf_pool_private mbp_priv;

	unsigned pkt_mbuf_size;

	int ret;

	/*private长度是否8字节对齐*/
	if (RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) != priv_size)
	{
		RTE_LOG(ERR, MBUF, "mbuf priv_size=%u is not aligned\n",priv_size);
		rte_errno = EINVAL;
		return NULL;
	}

	/*一个报文描述内存大小，mbuf+data数据部分+私有数据部分，rte_mbuf+数据部分data_room_size=2176*/
	/*rte_mbuf + prive_size + dataroom*/
	pkt_mbuf_size = sizeof(struct rte_mbuf) + (unsigned)priv_size + (unsigned)data_room_size;

	/*mbuf长度描述结构*/
	mbp_priv.mbuf_data_room_size = data_room_size;	     //2176数据部分
	mbp_priv.mbuf_priv_size      = priv_size;            //0

	/*创建内存池128个每逻辑核cache (sizeof(struct rte_mempool_cache))，cache下挂mbuf*/
	/*elem地址*/            /*rte_mbuf + prive_size + dataroom*//*cache_size逻辑核cache使用 250*/
	mem_pool = rte_mempool_create_empty(name, mbuf_num, pkt_mbuf_size, cache_size, sizeof(struct rte_pktmbuf_pool_private), socket_id, 0);
	if (mem_pool == NULL)                                                 /*dataroom长度与private长度描述结构*/
	{
		return NULL;
	}
	
	/*设置mbuf mempool的操作函数，默认操作函数为ring_mp_mc，多生产者多消费者*/
	ret = rte_mempool_set_ops_byname(mem_pool, RTE_MBUF_DEFAULT_MEMPOOL_OPS, NULL);
	if (ret != 0) 
	{
		RTE_LOG(ERR, MBUF, "error setting mempool handler\n");
		rte_mempool_free(mem_pool);
		rte_errno = -ret;
		return NULL;
	}

	/*mbuf 数据长度描述，描述单个报文，赋值给mp*/
	/*dataroom private 长度信息拷贝到mp尾部*/
	rte_pktmbuf_pool_init(mem_pool, &mbp_priv);

	/*1.申请所有端口mbuf内存之和按页做成elt 单个报文对象挂链到elt_list*/
	/*2.按页做成mbuf obj 挂链且入ring队列*/
	/*3.所有端口 mbuf内存申请，挂载mempool的elt链*/
	ret = rte_mempool_populate_default(mem_pool);
	if (ret < 0) 
	{
		rte_mempool_free(mem_pool);
		rte_errno = -ret;
		return NULL;
	}

	/*对elt_list链的mbuf对象初始化，内存清0，记录物理地址等*/
	rte_mempool_obj_iter(mem_pool, rte_pktmbuf_init, NULL);

	return mem_pool;
}

/* do some sanity checks on a mbuf: panic if it fails */

/*******************************************************
  函数名:		rte_mbuf_sanity_check
  功能描述: 	逻辑核线程函数
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
void
rte_mbuf_sanity_check(const struct rte_mbuf *mbuf, int is_header)
{
	const struct rte_mbuf *m_seg;
	unsigned nb_segs;

	/*mbuf内存池地址检查等*/
	if (mbuf == NULL)
		rte_panic("mbuf is NULL\n");

	/* generic checks */
	if (mbuf->pool == NULL)
		rte_panic("bad mbuf pool\n");
	
	if (mbuf->buf_physaddr == 0)
		rte_panic("bad phys addr\n");

	if (mbuf->buf_addr == NULL)
		rte_panic("bad virt addr\n");

	/**/
	uint16_t cnt = rte_mbuf_refcnt_read(mbuf);
	if ((cnt == 0) || (cnt == UINT16_MAX))
		rte_panic("bad ref cnt\n");

	/* nothing to check for sub-segments */
	if (is_header == 0)
		return;

	/*内存段个数*/
	nb_segs = mbuf->nb_segs;
	
	m_seg = mbuf;

	while (m_seg && nb_segs != 0) 
	{
		m_seg = m_seg->next;
		nb_segs--;
	}
	
	if (nb_segs != 0)
		rte_panic("bad nb_segs\n");
}

/* dump a mbuf on console */
void
rte_pktmbuf_dump(FILE *f, const struct rte_mbuf *m, unsigned dump_len)
{
	unsigned int len;
	unsigned nb_segs;

	__rte_mbuf_sanity_check(m, 1);

	fprintf(f, "dump mbuf at %p, phys=%"PRIx64", buf_len=%u\n",
	       m, (uint64_t)m->buf_physaddr, (unsigned)m->buf_len);
	fprintf(f, "  pkt_len=%"PRIu32", ol_flags=%"PRIx64", nb_segs=%u, "
	       "in_port=%u\n", m->pkt_len, m->ol_flags,
	       (unsigned)m->nb_segs, (unsigned)m->port);
	nb_segs = m->nb_segs;

	while (m && nb_segs != 0) {
		__rte_mbuf_sanity_check(m, 0);

		fprintf(f, "  segment at %p, data=%p, data_len=%u\n",
			m, rte_pktmbuf_mtod(m, void *), (unsigned)m->data_len);
		len = dump_len;
		if (len > m->data_len)
			len = m->data_len;
		if (len != 0)
			rte_hexdump(f, NULL, rte_pktmbuf_mtod(m, void *), len);
		dump_len -= len;
		m = m->next;
		nb_segs --;
	}
}

/* read len data bytes in a mbuf at specified offset (internal) */
const void *__rte_pktmbuf_read(const struct rte_mbuf *m, uint32_t off,
	uint32_t len, void *buf)
{
	const struct rte_mbuf *seg = m;
	uint32_t buf_off = 0, copy_len;

	if (off + len > rte_pktmbuf_pkt_len(m))
		return NULL;

	while (off >= rte_pktmbuf_data_len(seg)) {
		off -= rte_pktmbuf_data_len(seg);
		seg = seg->next;
	}

	if (off + len <= rte_pktmbuf_data_len(seg))
		return rte_pktmbuf_mtod_offset(seg, char *, off);

	/* rare case: header is split among several segments */
	while (len > 0) {
		copy_len = rte_pktmbuf_data_len(seg) - off;
		if (copy_len > len)
			copy_len = len;
		rte_memcpy((char *)buf + buf_off,
			rte_pktmbuf_mtod_offset(seg, char *, off), copy_len);
		off = 0;
		buf_off += copy_len;
		len -= copy_len;
		seg = seg->next;
	}

	return buf;
}

/*
 * Get the name of a RX offload flag. Must be kept synchronized with flag
 * definitions in rte_mbuf.h.
 */
const char *rte_get_rx_ol_flag_name(uint64_t mask)
{
	switch (mask) {
	case PKT_RX_VLAN_PKT: return "PKT_RX_VLAN_PKT";
	case PKT_RX_RSS_HASH: return "PKT_RX_RSS_HASH";
	case PKT_RX_FDIR: return "PKT_RX_FDIR";
	case PKT_RX_L4_CKSUM_BAD: return "PKT_RX_L4_CKSUM_BAD";
	case PKT_RX_L4_CKSUM_GOOD: return "PKT_RX_L4_CKSUM_GOOD";
	case PKT_RX_L4_CKSUM_NONE: return "PKT_RX_L4_CKSUM_NONE";
	case PKT_RX_IP_CKSUM_BAD: return "PKT_RX_IP_CKSUM_BAD";
	case PKT_RX_IP_CKSUM_GOOD: return "PKT_RX_IP_CKSUM_GOOD";
	case PKT_RX_IP_CKSUM_NONE: return "PKT_RX_IP_CKSUM_NONE";
	case PKT_RX_EIP_CKSUM_BAD: return "PKT_RX_EIP_CKSUM_BAD";
	case PKT_RX_VLAN_STRIPPED: return "PKT_RX_VLAN_STRIPPED";
	case PKT_RX_IEEE1588_PTP: return "PKT_RX_IEEE1588_PTP";
	case PKT_RX_IEEE1588_TMST: return "PKT_RX_IEEE1588_TMST";
	case PKT_RX_QINQ_STRIPPED: return "PKT_RX_QINQ_STRIPPED";
	case PKT_RX_LRO: return "PKT_RX_LRO";
	default: return NULL;
	}
}

struct flag_mask {
	uint64_t flag;
	uint64_t mask;
	const char *default_name;
};

/* write the list of rx ol flags in buffer buf */
int
rte_get_rx_ol_flag_list(uint64_t mask, char *buf, size_t buflen)
{
	const struct flag_mask rx_flags[] = {
		{ PKT_RX_VLAN_PKT, PKT_RX_VLAN_PKT, NULL },
		{ PKT_RX_RSS_HASH, PKT_RX_RSS_HASH, NULL },
		{ PKT_RX_FDIR, PKT_RX_FDIR, NULL },
		{ PKT_RX_L4_CKSUM_BAD, PKT_RX_L4_CKSUM_MASK, NULL },
		{ PKT_RX_L4_CKSUM_GOOD, PKT_RX_L4_CKSUM_MASK, NULL },
		{ PKT_RX_L4_CKSUM_NONE, PKT_RX_L4_CKSUM_MASK, NULL },
		{ PKT_RX_L4_CKSUM_UNKNOWN, PKT_RX_L4_CKSUM_MASK,
		  "PKT_RX_L4_CKSUM_UNKNOWN" },
		{ PKT_RX_IP_CKSUM_BAD, PKT_RX_IP_CKSUM_MASK, NULL },
		{ PKT_RX_IP_CKSUM_GOOD, PKT_RX_IP_CKSUM_MASK, NULL },
		{ PKT_RX_IP_CKSUM_NONE, PKT_RX_IP_CKSUM_MASK, NULL },
		{ PKT_RX_IP_CKSUM_UNKNOWN, PKT_RX_IP_CKSUM_MASK,
		  "PKT_RX_IP_CKSUM_UNKNOWN" },
		{ PKT_RX_EIP_CKSUM_BAD, PKT_RX_EIP_CKSUM_BAD, NULL },
		{ PKT_RX_VLAN_STRIPPED, PKT_RX_VLAN_STRIPPED, NULL },
		{ PKT_RX_IEEE1588_PTP, PKT_RX_IEEE1588_PTP, NULL },
		{ PKT_RX_IEEE1588_TMST, PKT_RX_IEEE1588_TMST, NULL },
		{ PKT_RX_QINQ_STRIPPED, PKT_RX_QINQ_STRIPPED, NULL },
		{ PKT_RX_LRO, PKT_RX_LRO, NULL },
	};
	const char *name;
	unsigned int i;
	int ret;

	if (buflen == 0)
		return -1;

	buf[0] = '\0';
	for (i = 0; i < RTE_DIM(rx_flags); i++) {
		if ((mask & rx_flags[i].mask) != rx_flags[i].flag)
			continue;
		name = rte_get_rx_ol_flag_name(rx_flags[i].flag);
		if (name == NULL)
			name = rx_flags[i].default_name;
		ret = snprintf(buf, buflen, "%s ", name);
		if (ret < 0)
			return -1;
		if ((size_t)ret >= buflen)
			return -1;
		buf += ret;
		buflen -= ret;
	}

	return 0;
}

/*
 * Get the name of a TX offload flag. Must be kept synchronized with flag
 * definitions in rte_mbuf.h.
 */
const char *rte_get_tx_ol_flag_name(uint64_t mask)
{
	switch (mask) {
	case PKT_TX_VLAN_PKT: return "PKT_TX_VLAN_PKT";
	case PKT_TX_IP_CKSUM: return "PKT_TX_IP_CKSUM";
	case PKT_TX_TCP_CKSUM: return "PKT_TX_TCP_CKSUM";
	case PKT_TX_SCTP_CKSUM: return "PKT_TX_SCTP_CKSUM";
	case PKT_TX_UDP_CKSUM: return "PKT_TX_UDP_CKSUM";
	case PKT_TX_IEEE1588_TMST: return "PKT_TX_IEEE1588_TMST";
	case PKT_TX_TCP_SEG: return "PKT_TX_TCP_SEG";
	case PKT_TX_IPV4: return "PKT_TX_IPV4";
	case PKT_TX_IPV6: return "PKT_TX_IPV6";
	case PKT_TX_OUTER_IP_CKSUM: return "PKT_TX_OUTER_IP_CKSUM";
	case PKT_TX_OUTER_IPV4: return "PKT_TX_OUTER_IPV4";
	case PKT_TX_OUTER_IPV6: return "PKT_TX_OUTER_IPV6";
	case PKT_TX_TUNNEL_VXLAN: return "PKT_TX_TUNNEL_VXLAN";
	case PKT_TX_TUNNEL_GRE: return "PKT_TX_TUNNEL_GRE";
	case PKT_TX_TUNNEL_IPIP: return "PKT_TX_TUNNEL_IPIP";
	case PKT_TX_TUNNEL_GENEVE: return "PKT_TX_TUNNEL_GENEVE";
	default: return NULL;
	}
}

/* write the list of tx ol flags in buffer buf */
int
rte_get_tx_ol_flag_list(uint64_t mask, char *buf, size_t buflen)
{
	const struct flag_mask tx_flags[] = {
		{ PKT_TX_VLAN_PKT, PKT_TX_VLAN_PKT, NULL },
		{ PKT_TX_IP_CKSUM, PKT_TX_IP_CKSUM, NULL },
		{ PKT_TX_TCP_CKSUM, PKT_TX_L4_MASK, NULL },
		{ PKT_TX_SCTP_CKSUM, PKT_TX_L4_MASK, NULL },
		{ PKT_TX_UDP_CKSUM, PKT_TX_L4_MASK, NULL },
		{ PKT_TX_L4_NO_CKSUM, PKT_TX_L4_MASK, "PKT_TX_L4_NO_CKSUM" },
		{ PKT_TX_IEEE1588_TMST, PKT_TX_IEEE1588_TMST, NULL },
		{ PKT_TX_TCP_SEG, PKT_TX_TCP_SEG, NULL },
		{ PKT_TX_IPV4, PKT_TX_IPV4, NULL },
		{ PKT_TX_IPV6, PKT_TX_IPV6, NULL },
		{ PKT_TX_OUTER_IP_CKSUM, PKT_TX_OUTER_IP_CKSUM, NULL },
		{ PKT_TX_OUTER_IPV4, PKT_TX_OUTER_IPV4, NULL },
		{ PKT_TX_OUTER_IPV6, PKT_TX_OUTER_IPV6, NULL },
		{ PKT_TX_TUNNEL_VXLAN, PKT_TX_TUNNEL_MASK,
		  "PKT_TX_TUNNEL_NONE" },
		{ PKT_TX_TUNNEL_GRE, PKT_TX_TUNNEL_MASK,
		  "PKT_TX_TUNNEL_NONE" },
		{ PKT_TX_TUNNEL_IPIP, PKT_TX_TUNNEL_MASK,
		  "PKT_TX_TUNNEL_NONE" },
		{ PKT_TX_TUNNEL_GENEVE, PKT_TX_TUNNEL_MASK,
		  "PKT_TX_TUNNEL_NONE" },
	};
	const char *name;
	unsigned int i;
	int ret;

	if (buflen == 0)
		return -1;

	buf[0] = '\0';
	for (i = 0; i < RTE_DIM(tx_flags); i++) {
		if ((mask & tx_flags[i].mask) != tx_flags[i].flag)
			continue;
		name = rte_get_tx_ol_flag_name(tx_flags[i].flag);
		if (name == NULL)
			name = tx_flags[i].default_name;
		ret = snprintf(buf, buflen, "%s ", name);
		if (ret < 0)
			return -1;
		if ((size_t)ret >= buflen)
			return -1;
		buf += ret;
		buflen -= ret;
	}

	return 0;
}
