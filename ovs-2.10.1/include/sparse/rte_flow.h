/*-
 *   BSD LICENSE
 *
 *   Copyright 2016 6WIND S.A.
 *   Copyright 2016 Mellanox.
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
 *     * Neither the name of 6WIND S.A. nor the names of its
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

#ifndef __CHECKER__
#error "Use this header only with sparse.  It is not a correct implementation."
#endif

#ifndef RTE_FLOW_H_
#define RTE_FLOW_H_

/**
 * @file
 * RTE generic flow API
 *
 * This interface provides the ability to program packet matching and
 * associated actions in hardware through flow rules.
 */

#include <rte_arp.h>
#include <rte_ether.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_sctp.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_byteorder.h>
#include <rte_esp.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Flow rule attributes.
 *
 * Priorities are set on two levels: per group and per rule within groups.
 *
 * Lower values denote higher priority, the highest priority for both levels
 * is 0, so that a rule with priority 0 in group 8 is always matched after a
 * rule with priority 8 in group 0.
 *
 * Although optional, applications are encouraged to group similar rules as
 * much as possible to fully take advantage of hardware capabilities
 * (e.g. optimized matching) and work around limitations (e.g. a single
 * pattern type possibly allowed in a given group).
 *
 * Group and priority levels are arbitrary and up to the application, they
 * do not need to be contiguous nor start from 0, however the maximum number
 * varies between devices and may be affected by existing flow rules.
 *
 * If a packet is matched by several rules of a given group for a given
 * priority level, the outcome is undefined. It can take any path, may be
 * duplicated or even cause unrecoverable errors.
 *
 * Note that support for more than a single group and priority level is not
 * guaranteed.
 *
 * Flow rules can apply to inbound and/or outbound traffic (ingress/egress).
 *
 * Several pattern items and actions are valid and can be used in both
 * directions. Those valid for only one direction are described as such.
 *
 * At least one direction must be specified.
 *
 * Specifying both directions at once for a given rule is not recommended
 * but may be valid in a few cases (e.g. shared counter).
 */
struct rte_flow_attr {
	uint32_t group; /**< Priority group. */
	uint32_t priority; /**< Priority level within group. */
	uint32_t ingress:1; /**< Rule applies to ingress traffic. */
	uint32_t egress:1; /**< Rule applies to egress traffic. */
	uint32_t reserved:30; /**< Reserved, must be zero. */
};

/**
 * Matching pattern item types.
 *
 * Pattern items fall in two categories:
 *
 * - Matching protocol headers and packet data (ANY, RAW, ETH, VLAN, IPV4,
 *   IPV6, ICMP, UDP, TCP, SCTP, VXLAN and so on), usually associated with a
 *   specification structure. These must be stacked in the same order as the
 *   protocol layers to match, starting from the lowest.
 *
 * - Matching meta-data or affecting pattern processing (END, VOID, INVERT,
 *   PF, VF, PORT and so on), often without a specification structure. Since
 *   they do not match packet contents, these can be specified anywhere
 *   within item lists without affecting others.
 *
 * See the description of individual types for more information. Those
 * marked with [META] fall into the second category.
 */
enum rte_flow_item_type {
	/**
	 * [META]
	 *
	 * End marker for item lists. Prevents further processing of items,
	 * thereby ending the pattern.
	 *
	 * No associated specification structure.
	 */
	RTE_FLOW_ITEM_TYPE_END,

	/**
	 * [META]
	 *
	 * Used as a placeholder for convenience. It is ignored and simply
	 * discarded by PMDs.
	 *
	 * No associated specification structure.
	 */
	RTE_FLOW_ITEM_TYPE_VOID,

	/**
	 * [META]
	 *
	 * Inverted matching, i.e. process packets that do not match the
	 * pattern.
	 *
	 * No associated specification structure.
	 */
	RTE_FLOW_ITEM_TYPE_INVERT,

	/**
	 * Matches any protocol in place of the current layer, a single ANY
	 * may also stand for several protocol layers.
	 *
	 * See struct rte_flow_item_any.
	 */
	RTE_FLOW_ITEM_TYPE_ANY,

	/**
	 * [META]
	 *
	 * Matches packets addressed to the physical function of the device.
	 *
	 * If the underlying device function differs from the one that would
	 * normally receive the matched traffic, specifying this item
	 * prevents it from reaching that device unless the flow rule
	 * contains a PF action. Packets are not duplicated between device
	 * instances by default.
	 *
	 * No associated specification structure.
	 */
	RTE_FLOW_ITEM_TYPE_PF,

	/**
	 * [META]
	 *
	 * Matches packets addressed to a virtual function ID of the device.
	 *
	 * If the underlying device function differs from the one that would
	 * normally receive the matched traffic, specifying this item
	 * prevents it from reaching that device unless the flow rule
	 * contains a VF action. Packets are not duplicated between device
	 * instances by default.
	 *
	 * See struct rte_flow_item_vf.
	 */
	RTE_FLOW_ITEM_TYPE_VF,

	/**
	 * [META]
	 *
	 * Matches packets coming from the specified physical port of the
	 * underlying device.
	 *
	 * The first PORT item overrides the physical port normally
	 * associated with the specified DPDK input port (port_id). This
	 * item can be provided several times to match additional physical
	 * ports.
	 *
	 * See struct rte_flow_item_port.
	 */
	RTE_FLOW_ITEM_TYPE_PORT,

	/**
	 * Matches a byte string of a given length at a given offset.
	 *
	 * See struct rte_flow_item_raw.
	 */
	RTE_FLOW_ITEM_TYPE_RAW,

	/**
	 * Matches an Ethernet header.
	 *
	 * See struct rte_flow_item_eth.
	 */
	RTE_FLOW_ITEM_TYPE_ETH,					/*rte flow eth ????*/

	/**
	 * Matches an 802.1Q/ad VLAN tag.
	 *
	 * See struct rte_flow_item_vlan.
	 */
	RTE_FLOW_ITEM_TYPE_VLAN,

	/**
	 * Matches an IPv4 header.
	 *
	 * See struct rte_flow_item_ipv4.
	 */
	RTE_FLOW_ITEM_TYPE_IPV4,

	/**
	 * Matches an IPv6 header.
	 *
	 * See struct rte_flow_item_ipv6.
	 */
	RTE_FLOW_ITEM_TYPE_IPV6,

	/**
	 * Matches an ICMP header.
	 *
	 * See struct rte_flow_item_icmp.
	 */
	RTE_FLOW_ITEM_TYPE_ICMP,

	/**
	 * Matches a UDP header.
	 *
	 * See struct rte_flow_item_udp.
	 */
	RTE_FLOW_ITEM_TYPE_UDP,

	/**
	 * Matches a TCP header.
	 *
	 * See struct rte_flow_item_tcp.
	 */
	RTE_FLOW_ITEM_TYPE_TCP,

	/**
	 * Matches a SCTP header.
	 *
	 * See struct rte_flow_item_sctp.
	 */
	RTE_FLOW_ITEM_TYPE_SCTP,

	/**
	 * Matches a VXLAN header.
	 *
	 * See struct rte_flow_item_vxlan.
	 */
	RTE_FLOW_ITEM_TYPE_VXLAN,

	/**
	 * Matches a E_TAG header.
	 *
	 * See struct rte_flow_item_e_tag.
	 */
	RTE_FLOW_ITEM_TYPE_E_TAG,

	/**
	 * Matches a NVGRE header.
	 *
	 * See struct rte_flow_item_nvgre.
	 */
	RTE_FLOW_ITEM_TYPE_NVGRE,

	/**
	 * Matches a MPLS header.
	 *
	 * See struct rte_flow_item_mpls.
	 */
	RTE_FLOW_ITEM_TYPE_MPLS,

	/**
	 * Matches a GRE header.
	 *
	 * See struct rte_flow_item_gre.
	 */
	RTE_FLOW_ITEM_TYPE_GRE,

	/**
	 * [META]
	 *
	 * Fuzzy pattern match, expect faster than default.
	 *
	 * This is for device that support fuzzy matching option.
	 * Usually a fuzzy matching is fast but the cost is accuracy.
	 *
	 * See struct rte_flow_item_fuzzy.
	 */
	RTE_FLOW_ITEM_TYPE_FUZZY,

	/**
	 * Matches a GTP header.
	 *
	 * Configure flow for GTP packets.
	 *
	 * See struct rte_flow_item_gtp.
	 */
	RTE_FLOW_ITEM_TYPE_GTP,

	/**
	 * Matches a GTP header.
	 *
	 * Configure flow for GTP-C packets.
	 *
	 * See struct rte_flow_item_gtp.
	 */
	RTE_FLOW_ITEM_TYPE_GTPC,

	/**
	 * Matches a GTP header.
	 *
	 * Configure flow for GTP-U packets.
	 *
	 * See struct rte_flow_item_gtp.
	 */
	RTE_FLOW_ITEM_TYPE_GTPU,

	/**
	 * Matches a ESP header.
	 *
	 * See struct rte_flow_item_esp.
	 */
	RTE_FLOW_ITEM_TYPE_ESP,
};

/**
 * RTE_FLOW_ITEM_TYPE_ANY
 *
 * Matches any protocol in place of the current layer, a single ANY may also
 * stand for several protocol layers.
 *
 * This is usually specified as the first pattern item when looking for a
 * protocol anywhere in a packet.
 *
 * A zeroed mask stands for any number of layers.
 */
struct rte_flow_item_any {
	uint32_t num; /**< Number of layers covered. */
};

/** Default mask for RTE_FLOW_ITEM_TYPE_ANY. */
#ifndef __cplusplus
static const struct rte_flow_item_any rte_flow_item_any_mask = {
	.num = 0x00000000,
};
#endif

/**
 * RTE_FLOW_ITEM_TYPE_VF
 *
 * Matches packets addressed to a virtual function ID of the device.
 *
 * If the underlying device function differs from the one that would
 * normally receive the matched traffic, specifying this item prevents it
 * from reaching that device unless the flow rule contains a VF
 * action. Packets are not duplicated between device instances by default.
 *
 * - Likely to return an error or never match any traffic if this causes a
 *   VF device to match traffic addressed to a different VF.
 * - Can be specified multiple times to match traffic addressed to several
 *   VF IDs.
 * - Can be combined with a PF item to match both PF and VF traffic.
 *
 * A zeroed mask can be used to match any VF ID.
 */
struct rte_flow_item_vf {
	uint32_t id; /**< Destination VF ID. */
};

/** Default mask for RTE_FLOW_ITEM_TYPE_VF. */
#ifndef __cplusplus
static const struct rte_flow_item_vf rte_flow_item_vf_mask = {
	.id = 0x00000000,
};
#endif

/**
 * RTE_FLOW_ITEM_TYPE_PORT
 *
 * Matches packets coming from the specified physical port of the underlying
 * device.
 *
 * The first PORT item overrides the physical port normally associated with
 * the specified DPDK input port (port_id). This item can be provided
 * several times to match additional physical ports.
 *
 * Note that physical ports are not necessarily tied to DPDK input ports
 * (port_id) when those are not under DPDK control. Possible values are
 * specific to each device, they are not necessarily indexed from zero and
 * may not be contiguous.
 *
 * As a device property, the list of allowed values as well as the value
 * associated with a port_id should be retrieved by other means.
 *
 * A zeroed mask can be used to match any port index.
 */
struct rte_flow_item_port {
	uint32_t index; /**< Physical port index. */
};

/** Default mask for RTE_FLOW_ITEM_TYPE_PORT. */
#ifndef __cplusplus
static const struct rte_flow_item_port rte_flow_item_port_mask = {
	.index = 0x00000000,
};
#endif

/**
 * RTE_FLOW_ITEM_TYPE_RAW
 *
 * Matches a byte string of a given length at a given offset.
 *
 * Offset is either absolute (using the start of the packet) or relative to
 * the end of the previous matched item in the stack, in which case negative
 * values are allowed.
 *
 * If search is enabled, offset is used as the starting point. The search
 * area can be delimited by setting limit to a nonzero value, which is the
 * maximum number of bytes after offset where the pattern may start.
 *
 * Matching a zero-length pattern is allowed, doing so resets the relative
 * offset for subsequent items.
 *
 * This type does not support ranges (struct rte_flow_item.last).
 */
struct rte_flow_item_raw {
	uint32_t relative:1; /**< Look for pattern after the previous item. */
	uint32_t search:1; /**< Search pattern from offset (see also limit). */
	uint32_t reserved:30; /**< Reserved, must be set to zero. */
	int32_t offset; /**< Absolute or relative offset for pattern. */
	uint16_t limit; /**< Search area limit for start of pattern. */
	uint16_t length; /**< Pattern length. */
	uint8_t pattern[]; /**< Byte string to look for. */
};

/** Default mask for RTE_FLOW_ITEM_TYPE_RAW. */
#ifndef __cplusplus
static const struct rte_flow_item_raw rte_flow_item_raw_mask = {
	.relative = 1,
	.search = 1,
	.reserved = 0x3fffffff,
	.offset = 0xffffffff,
	.limit = 0xffff,
	.length = 0xffff,
};
#endif

/**
 * RTE_FLOW_ITEM_TYPE_ETH
 *
 * Matches an Ethernet header.
 */

/*rte flow eth mask*/
struct rte_flow_item_eth {
	struct ether_addr dst; /**< Destination MAC. */		/*????mac*/
	struct ether_addr src; /**< Source MAC. */			/*??mac*/
	rte_be16_t type; /**< EtherType. */					/*ether type*/
};

/** Default mask for RTE_FLOW_ITEM_TYPE_ETH. */
#ifndef __cplusplus
static const struct rte_flow_item_eth rte_flow_item_eth_mask = {
	.dst.addr_bytes = "\xff\xff\xff\xff\xff\xff",
	.src.addr_bytes = "\xff\xff\xff\xff\xff\xff",
	.type = RTE_BE16(0x0000),
};
#endif

/**
 * RTE_FLOW_ITEM_TYPE_VLAN
 *
 * Matches an 802.1Q/ad VLAN tag.
 *
 * This type normally follows either RTE_FLOW_ITEM_TYPE_ETH or
 * RTE_FLOW_ITEM_TYPE_VLAN.
 */
struct rte_flow_item_vlan {
	rte_be16_t tpid; /**< Tag protocol identifier. */
	rte_be16_t tci; /**< Tag control information. */
};

/** Default mask for RTE_FLOW_ITEM_TYPE_VLAN. */
#ifndef __cplusplus
static const struct rte_flow_item_vlan rte_flow_item_vlan_mask = {
	.tpid = RTE_BE16(0x0000),
	.tci = RTE_BE16(0xffff),
};
#endif

/**
 * RTE_FLOW_ITEM_TYPE_IPV4
 *
 * Matches an IPv4 header.
 *
 * Note: IPv4 options are handled by dedicated pattern items.
 */
struct rte_flow_item_ipv4 {
	struct ipv4_hdr hdr; /**< IPv4 header definition. */
};

/** Default mask for RTE_FLOW_ITEM_TYPE_IPV4. */
#ifndef __cplusplus
static const struct rte_flow_item_ipv4 rte_flow_item_ipv4_mask = {
	.hdr = {
		.src_addr = RTE_BE32(0xffffffff),
		.dst_addr = RTE_BE32(0xffffffff),
	},
};
#endif

/**
 * RTE_FLOW_ITEM_TYPE_IPV6.
 *
 * Matches an IPv6 header.
 *
 * Note: IPv6 options are handled by dedicated pattern items.
 */
struct rte_flow_item_ipv6 {
	struct ipv6_hdr hdr; /**< IPv6 header definition. */
};

/** Default mask for RTE_FLOW_ITEM_TYPE_IPV6. */
#ifndef __cplusplus
static const struct rte_flow_item_ipv6 rte_flow_item_ipv6_mask = {
	.hdr = {
		.src_addr =
			"\xff\xff\xff\xff\xff\xff\xff\xff"
			"\xff\xff\xff\xff\xff\xff\xff\xff",
		.dst_addr =
			"\xff\xff\xff\xff\xff\xff\xff\xff"
			"\xff\xff\xff\xff\xff\xff\xff\xff",
	},
};
#endif

/**
 * RTE_FLOW_ITEM_TYPE_ICMP.
 *
 * Matches an ICMP header.
 */
struct rte_flow_item_icmp {
	struct icmp_hdr hdr; /**< ICMP header definition. */
};

/** Default mask for RTE_FLOW_ITEM_TYPE_ICMP. */
#ifndef __cplusplus
static const struct rte_flow_item_icmp rte_flow_item_icmp_mask = {
	.hdr = {
		.icmp_type = 0xff,
		.icmp_code = 0xff,
	},
};
#endif

/**
 * RTE_FLOW_ITEM_TYPE_UDP.
 *
 * Matches a UDP header.
 */
struct rte_flow_item_udp {
	struct udp_hdr hdr; /**< UDP header definition. */
};

/** Default mask for RTE_FLOW_ITEM_TYPE_UDP. */
#ifndef __cplusplus
static const struct rte_flow_item_udp rte_flow_item_udp_mask = {
	.hdr = {
		.src_port = RTE_BE16(0xffff),
		.dst_port = RTE_BE16(0xffff),
	},
};
#endif

/**
 * RTE_FLOW_ITEM_TYPE_TCP.
 *
 * Matches a TCP header.
 */
struct rte_flow_item_tcp {
	struct tcp_hdr hdr; /**< TCP header definition. */
};

/** Default mask for RTE_FLOW_ITEM_TYPE_TCP. */
#ifndef __cplusplus
static const struct rte_flow_item_tcp rte_flow_item_tcp_mask = {
	.hdr = {
		.src_port = RTE_BE16(0xffff),
		.dst_port = RTE_BE16(0xffff),
	},
};
#endif

/**
 * RTE_FLOW_ITEM_TYPE_SCTP.
 *
 * Matches a SCTP header.
 */
struct rte_flow_item_sctp {
	struct sctp_hdr hdr; /**< SCTP header definition. */
};

/** Default mask for RTE_FLOW_ITEM_TYPE_SCTP. */
#ifndef __cplusplus
static const struct rte_flow_item_sctp rte_flow_item_sctp_mask = {
	.hdr = {
		.src_port = RTE_BE16(0xffff),
		.dst_port = RTE_BE16(0xffff),
	},
};
#endif

/**
 * RTE_FLOW_ITEM_TYPE_VXLAN.
 *
 * Matches a VXLAN header (RFC 7348).
 */
struct rte_flow_item_vxlan {
	uint8_t flags; /**< Normally 0x08 (I flag). */
	uint8_t rsvd0[3]; /**< Reserved, normally 0x000000. */
	uint8_t vni[3]; /**< VXLAN identifier. */
	uint8_t rsvd1; /**< Reserved, normally 0x00. */
};

/** Default mask for RTE_FLOW_ITEM_TYPE_VXLAN. */
#ifndef __cplusplus
static const struct rte_flow_item_vxlan rte_flow_item_vxlan_mask = {
	.vni = "\xff\xff\xff",
};
#endif

/**
 * RTE_FLOW_ITEM_TYPE_E_TAG.
 *
 * Matches a E-tag header.
 */
struct rte_flow_item_e_tag {
	rte_be16_t tpid; /**< Tag protocol identifier (0x893F). */
	/**
	 * E-Tag control information (E-TCI).
	 * E-PCP (3b), E-DEI (1b), ingress E-CID base (12b).
	 */
	rte_be16_t epcp_edei_in_ecid_b;
	/** Reserved (2b), GRP (2b), E-CID base (12b). */
	rte_be16_t rsvd_grp_ecid_b;
	uint8_t in_ecid_e; /**< Ingress E-CID ext. */
	uint8_t ecid_e; /**< E-CID ext. */
};

/** Default mask for RTE_FLOW_ITEM_TYPE_E_TAG. */
#ifndef __cplusplus
static const struct rte_flow_item_e_tag rte_flow_item_e_tag_mask = {
	.rsvd_grp_ecid_b = RTE_BE16(0x3fff),
};
#endif

/**
 * RTE_FLOW_ITEM_TYPE_NVGRE.
 *
 * Matches a NVGRE header.
 */
struct rte_flow_item_nvgre {
	/**
	 * Checksum (1b), undefined (1b), key bit (1b), sequence number (1b),
	 * reserved 0 (9b), version (3b).
	 *
	 * c_k_s_rsvd0_ver must have value 0x2000 according to RFC 7637.
	 */
	rte_be16_t c_k_s_rsvd0_ver;
	rte_be16_t protocol; /**< Protocol type (0x6558). */
	uint8_t tni[3]; /**< Virtual subnet ID. */
	uint8_t flow_id; /**< Flow ID. */
};

/** Default mask for RTE_FLOW_ITEM_TYPE_NVGRE. */
#ifndef __cplusplus
static const struct rte_flow_item_nvgre rte_flow_item_nvgre_mask = {
	.tni = "\xff\xff\xff",
};
#endif

/**
 * RTE_FLOW_ITEM_TYPE_MPLS.
 *
 * Matches a MPLS header.
 */
struct rte_flow_item_mpls {
	/**
	 * Label (20b), TC (3b), Bottom of Stack (1b).
	 */
	uint8_t label_tc_s[3];
	uint8_t ttl; /** Time-to-Live. */
};

/** Default mask for RTE_FLOW_ITEM_TYPE_MPLS. */
#ifndef __cplusplus
static const struct rte_flow_item_mpls rte_flow_item_mpls_mask = {
	.label_tc_s = "\xff\xff\xf0",
};
#endif

/**
 * RTE_FLOW_ITEM_TYPE_GRE.
 *
 * Matches a GRE header.
 */
struct rte_flow_item_gre {
	/**
	 * Checksum (1b), reserved 0 (12b), version (3b).
	 * Refer to RFC 2784.
	 */
	rte_be16_t c_rsvd0_ver;
	rte_be16_t protocol; /**< Protocol type. */
};

/** Default mask for RTE_FLOW_ITEM_TYPE_GRE. */
#ifndef __cplusplus
static const struct rte_flow_item_gre rte_flow_item_gre_mask = {
	.protocol = RTE_BE16(0xffff),
};
#endif

/**
 * RTE_FLOW_ITEM_TYPE_FUZZY
 *
 * Fuzzy pattern match, expect faster than default.
 *
 * This is for device that support fuzzy match option.
 * Usually a fuzzy match is fast but the cost is accuracy.
 * i.e. Signature Match only match pattern's hash value, but it is
 * possible two different patterns have the same hash value.
 *
 * Matching accuracy level can be configure by threshold.
 * Driver can divide the range of threshold and map to different
 * accuracy levels that device support.
 *
 * Threshold 0 means perfect match (no fuzziness), while threshold
 * 0xffffffff means fuzziest match.
 */
struct rte_flow_item_fuzzy {
	uint32_t thresh; /**< Accuracy threshold. */
};

/** Default mask for RTE_FLOW_ITEM_TYPE_FUZZY. */
#ifndef __cplusplus
static const struct rte_flow_item_fuzzy rte_flow_item_fuzzy_mask = {
	.thresh = 0xffffffff,
};
#endif

/**
 * RTE_FLOW_ITEM_TYPE_GTP.
 *
 * Matches a GTPv1 header.
 */
struct rte_flow_item_gtp {
	/**
	 * Version (3b), protocol type (1b), reserved (1b),
	 * Extension header flag (1b),
	 * Sequence number flag (1b),
	 * N-PDU number flag (1b).
	 */
	uint8_t v_pt_rsv_flags;
	uint8_t msg_type; /**< Message type. */
	rte_be16_t msg_len; /**< Message length. */
	rte_be32_t teid; /**< Tunnel endpoint identifier. */
};

/** Default mask for RTE_FLOW_ITEM_TYPE_GTP. */
#ifndef __cplusplus
static const struct rte_flow_item_gtp rte_flow_item_gtp_mask = {
	.teid = RTE_BE32(0xffffffff),
};
#endif

/**
 * RTE_FLOW_ITEM_TYPE_ESP
 *
 * Matches an ESP header.
 */
struct rte_flow_item_esp {
	struct esp_hdr hdr; /**< ESP header definition. */
};

/** Default mask for RTE_FLOW_ITEM_TYPE_ESP. */
#ifndef __cplusplus
static const struct rte_flow_item_esp rte_flow_item_esp_mask = {
	.hdr = {
		.spi = OVS_BE32_MAX,
	},
};
#endif

/**
 * Matching pattern item definition.
 *
 * A pattern is formed by stacking items starting from the lowest protocol
 * layer to match. This stacking restriction does not apply to meta items
 * which can be placed anywhere in the stack without affecting the meaning
 * of the resulting pattern.
 *
 * Patterns are terminated by END items.
 *
 * The spec field should be a valid pointer to a structure of the related
 * item type. It may remain unspecified (NULL) in many cases to request
 * broad (nonspecific) matching. In such cases, last and mask must also be
 * set to NULL.
 *
 * Optionally, last can point to a structure of the same type to define an
 * inclusive range. This is mostly supported by integer and address fields,
 * may cause errors otherwise. Fields that do not support ranges must be set
 * to 0 or to the same value as the corresponding fields in spec.
 *
 * Only the fields defined to nonzero values in the default masks (see
 * rte_flow_item_{name}_mask constants) are considered relevant by
 * default. This can be overridden by providing a mask structure of the
 * same type with applicable bits set to one. It can also be used to
 * partially filter out specific fields (e.g. as an alternate mean to match
 * ranges of IP addresses).
 *
 * Mask is a simple bit-mask applied before interpreting the contents of
 * spec and last, which may yield unexpected results if not used
 * carefully. For example, if for an IPv4 address field, spec provides
 * 10.1.2.3, last provides 10.3.4.5 and mask provides 255.255.0.0, the
 * effective range becomes 10.1.0.0 to 10.3.255.255.
 */
 
struct rte_flow_item {
	enum rte_flow_item_type type; /**< Item type. */
	const void *spec; /**< Pointer to item specification structure. */
	const void *last; /**< Defines an inclusive range (spec to last). */
	const void *mask; /**< Bit-mask applied to spec and last. */
};

/**
 * Action types.
 *
 * Each possible action is represented by a type. Some have associated
 * configuration structures. Several actions combined in a list can be
 * affected to a flow rule. That list is not ordered.
 *
 * They fall in three categories:
 *
 * - Terminating actions (such as QUEUE, DROP, RSS, PF, VF) that prevent
 *   processing matched packets by subsequent flow rules, unless overridden
 *   with PASSTHRU.
 *
 * - Non terminating actions (PASSTHRU, DUP) that leave matched packets up
 *   for additional processing by subsequent flow rules.
 *
 * - Other non terminating meta actions that do not affect the fate of
 *   packets (END, VOID, MARK, FLAG, COUNT).
 *
 * When several actions are combined in a flow rule, they should all have
 * different types (e.g. dropping a packet twice is not possible).
 *
 * Only the last action of a given type is taken into account. PMDs still
 * perform error checking on the entire list.
 *
 * Note that PASSTHRU is the only action able to override a terminating
 * rule.
 */
enum rte_flow_action_type {
	/**
	 * [META]
	 *
	 * End marker for action lists. Prevents further processing of
	 * actions, thereby ending the list.
	 *
	 * No associated configuration structure.
	 */
	RTE_FLOW_ACTION_TYPE_END,

	/**
	 * [META]
	 *
	 * Used as a placeholder for convenience. It is ignored and simply
	 * discarded by PMDs.
	 *
	 * No associated configuration structure.
	 */
	RTE_FLOW_ACTION_TYPE_VOID,

	/**
	 * Leaves packets up for additional processing by subsequent flow
	 * rules. This is the default when a rule does not contain a
	 * terminating action, but can be specified to force a rule to
	 * become non-terminating.
	 *
	 * No associated configuration structure.
	 */
	RTE_FLOW_ACTION_TYPE_PASSTHRU,

	/**
	 * [META]
	 *
	 * Attaches an integer value to packets and sets PKT_RX_FDIR and
	 * PKT_RX_FDIR_ID mbuf flags.
	 *
	 * See struct rte_flow_action_mark.
	 */
	RTE_FLOW_ACTION_TYPE_MARK,

	/**
	 * [META]
	 *
	 * Flags packets. Similar to MARK without a specific value; only
	 * sets the PKT_RX_FDIR mbuf flag.
	 *
	 * No associated configuration structure.
	 */
	RTE_FLOW_ACTION_TYPE_FLAG,

	/**
	 * Assigns packets to a given queue index.
	 *
	 * See struct rte_flow_action_queue.
	 */
	RTE_FLOW_ACTION_TYPE_QUEUE,

	/**
	 * Drops packets.
	 *
	 * PASSTHRU overrides this action if both are specified.
	 *
	 * No associated configuration structure.
	 */
	RTE_FLOW_ACTION_TYPE_DROP,

	/**
	 * [META]
	 *
	 * Enables counters for this rule.
	 *
	 * These counters can be retrieved and reset through rte_flow_query(),
	 * see struct rte_flow_query_count.
	 *
	 * No associated configuration structure.
	 */
	RTE_FLOW_ACTION_TYPE_COUNT,

	/**
	 * Duplicates packets to a given queue index.
	 *
	 * This is normally combined with QUEUE, however when used alone, it
	 * is actually similar to QUEUE + PASSTHRU.
	 *
	 * See struct rte_flow_action_dup.
	 */
	RTE_FLOW_ACTION_TYPE_DUP,

	/**
	 * Similar to QUEUE, except RSS is additionally performed on packets
	 * to spread them among several queues according to the provided
	 * parameters.
	 *
	 * See struct rte_flow_action_rss.
	 */
	RTE_FLOW_ACTION_TYPE_RSS,

	/**
	 * Redirects packets to the physical function (PF) of the current
	 * device.
	 *
	 * No associated configuration structure.
	 */
	RTE_FLOW_ACTION_TYPE_PF,

	/**
	 * Redirects packets to the virtual function (VF) of the current
	 * device with the specified ID.
	 *
	 * See struct rte_flow_action_vf.
	 */
	RTE_FLOW_ACTION_TYPE_VF,

	/**
	 * Traffic metering and policing (MTR).
	 *
	 * See struct rte_flow_action_meter.
	 * See file rte_mtr.h for MTR object configuration.
	 */
	RTE_FLOW_ACTION_TYPE_METER,

	/**
	 * Redirects packets to security engine of current device for security
	 * processing as specified by security session.
	 *
	 * See struct rte_flow_action_security.
	 */
	RTE_FLOW_ACTION_TYPE_SECURITY
};

/**
 * RTE_FLOW_ACTION_TYPE_MARK
 *
 * Attaches an integer value to packets and sets PKT_RX_FDIR and
 * PKT_RX_FDIR_ID mbuf flags.
 *
 * This value is arbitrary and application-defined. Maximum allowed value
 * depends on the underlying implementation. It is returned in the
 * hash.fdir.hi mbuf field.
 */
struct rte_flow_action_mark {
	uint32_t id; /**< Integer value to return with packets. */
};

/**
 * RTE_FLOW_ACTION_TYPE_QUEUE
 *
 * Assign packets to a given queue index.
 *
 * Terminating by default.
 */
struct rte_flow_action_queue {
	uint16_t index; /**< Queue index to use. */
};

/**
 * RTE_FLOW_ACTION_TYPE_COUNT (query)
 *
 * Query structure to retrieve and reset flow rule counters.
 */
struct rte_flow_query_count {
	uint32_t reset:1; /**< Reset counters after query [in]. */
	uint32_t hits_set:1; /**< hits field is set [out]. */
	uint32_t bytes_set:1; /**< bytes field is set [out]. */
	uint32_t reserved:29; /**< Reserved, must be zero [in, out]. */
	uint64_t hits; /**< Number of hits for this rule [out]. */
	uint64_t bytes; /**< Number of bytes through this rule [out]. */
};

/**
 * RTE_FLOW_ACTION_TYPE_DUP
 *
 * Duplicates packets to a given queue index.
 *
 * This is normally combined with QUEUE, however when used alone, it is
 * actually similar to QUEUE + PASSTHRU.
 *
 * Non-terminating by default.
 */
struct rte_flow_action_dup {
	uint16_t index; /**< Queue index to duplicate packets to. */
};

/**
 * RTE_FLOW_ACTION_TYPE_RSS
 *
 * Similar to QUEUE, except RSS is additionally performed on packets to
 * spread them among several queues according to the provided parameters.
 *
 * Note: RSS hash result is stored in the hash.rss mbuf field which overlaps
 * hash.fdir.lo. Since the MARK action sets the hash.fdir.hi field only,
 * both can be requested simultaneously.
 *
 * Terminating by default.
 */
struct rte_flow_action_rss {
	const struct rte_eth_rss_conf *rss_conf; /**< RSS parameters. */
	uint16_t num; /**< Number of entries in queue[]. */
	uint16_t queue[]; /**< Queues indices to use. */
};

/**
 * RTE_FLOW_ACTION_TYPE_VF
 *
 * Redirects packets to a virtual function (VF) of the current device.
 *
 * Packets matched by a VF pattern item can be redirected to their original
 * VF ID instead of the specified one. This parameter may not be available
 * and is not guaranteed to work properly if the VF part is matched by a
 * prior flow rule or if packets are not addressed to a VF in the first
 * place.
 *
 * Terminating by default.
 */
struct rte_flow_action_vf {
	uint32_t original:1; /**< Use original VF ID if possible. */
	uint32_t reserved:31; /**< Reserved, must be zero. */
	uint32_t id; /**< VF ID to redirect packets to. */
};

/**
 * RTE_FLOW_ACTION_TYPE_METER
 *
 * Traffic metering and policing (MTR).
 *
 * Packets matched by items of this type can be either dropped or passed to the
 * next item with their color set by the MTR object.
 *
 * Non-terminating by default.
 */
struct rte_flow_action_meter {
	uint32_t mtr_id; /**< MTR object ID created with rte_mtr_create(). */			/*meter ????action*/
};

/**
 * RTE_FLOW_ACTION_TYPE_SECURITY
 *
 * Perform the security action on flows matched by the pattern items
 * according to the configuration of the security session.
 *
 * This action modifies the payload of matched flows. For INLINE_CRYPTO, the
 * security protocol headers and IV are fully provided by the application as
 * specified in the flow pattern. The payload of matching packets is
 * encrypted on egress, and decrypted and authenticated on ingress.
 * For INLINE_PROTOCOL, the security protocol is fully offloaded to HW,
 * providing full encapsulation and decapsulation of packets in security
 * protocols. The flow pattern specifies both the outer security header fields
 * and the inner packet fields. The security session specified in the action
 * must match the pattern parameters.
 *
 * The security session specified in the action must be created on the same
 * port as the flow action that is being specified.
 *
 * The ingress/egress flow attribute should match that specified in the
 * security session if the security session supports the definition of the
 * direction.
 *
 * Multiple flows can be configured to use the same security session.
 *
 * Non-terminating by default.
 */
struct rte_flow_action_security {
	void *security_session; /**< Pointer to security session structure. */
};

/**
 * Definition of a single action.
 *
 * A list of actions is terminated by a END action.
 *
 * For simple actions without a configuration structure, conf remains NULL.
 */
struct rte_flow_action {
	enum rte_flow_action_type type; /**< Action type. */
	const void *conf; /**< Pointer to action configuration structure. */
};

/**
 * Opaque type returned after successfully creating a flow.
 *
 * This handle can be used to manage and query the related flow (e.g. to
 * destroy it or retrieve counters).
 */
struct rte_flow;

/**
 * Verbose error types.
 *
 * Most of them provide the type of the object referenced by struct
 * rte_flow_error.cause.
 */
enum rte_flow_error_type {
	RTE_FLOW_ERROR_TYPE_NONE, /**< No error. */
	RTE_FLOW_ERROR_TYPE_UNSPECIFIED, /**< Cause unspecified. */
	RTE_FLOW_ERROR_TYPE_HANDLE, /**< Flow rule (handle). */
	RTE_FLOW_ERROR_TYPE_ATTR_GROUP, /**< Group field. */
	RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY, /**< Priority field. */
	RTE_FLOW_ERROR_TYPE_ATTR_INGRESS, /**< Ingress field. */
	RTE_FLOW_ERROR_TYPE_ATTR_EGRESS, /**< Egress field. */
	RTE_FLOW_ERROR_TYPE_ATTR, /**< Attributes structure. */
	RTE_FLOW_ERROR_TYPE_ITEM_NUM, /**< Pattern length. */
	RTE_FLOW_ERROR_TYPE_ITEM, /**< Specific pattern item. */
	RTE_FLOW_ERROR_TYPE_ACTION_NUM, /**< Number of actions. */
	RTE_FLOW_ERROR_TYPE_ACTION, /**< Specific action. */
};

/**
 * Verbose error structure definition.
 *
 * This object is normally allocated by applications and set by PMDs, the
 * message points to a constant string which does not need to be freed by
 * the application, however its pointer can be considered valid only as long
 * as its associated DPDK port remains configured. Closing the underlying
 * device or unloading the PMD invalidates it.
 *
 * Both cause and message may be NULL regardless of the error type.
 */
struct rte_flow_error {
	enum rte_flow_error_type type; /**< Cause field and error types. */
	const void *cause; /**< Object responsible for the error. */
	const char *message; /**< Human-readable error message. */
};

/**
 * Check whether a flow rule can be created on a given port.
 *
 * The flow rule is validated for correctness and whether it could be accepted
 * by the device given sufficient resources. The rule is checked against the
 * current device mode and queue configuration. The flow rule may also
 * optionally be validated against existing flow rules and device resources.
 * This function has no effect on the target device.
 *
 * The returned value is guaranteed to remain valid only as long as no
 * successful calls to rte_flow_create() or rte_flow_destroy() are made in
 * the meantime and no device parameter affecting flow rules in any way are
 * modified, due to possible collisions or resource limitations (although in
 * such cases EINVAL should not be returned).
 *
 * @param port_id
 *   Port identifier of Ethernet device.
 * @param[in] attr
 *   Flow rule attributes.
 * @param[in] pattern
 *   Pattern specification (list terminated by the END pattern item).
 * @param[in] actions
 *   Associated actions (list terminated by the END action).
 * @param[out] error
 *   Perform verbose error reporting if not NULL. PMDs initialize this
 *   structure in case of error only.
 *
 * @return
 *   0 if flow rule is valid and can be created. A negative errno value
 *   otherwise (rte_errno is also set), the following errors are defined:
 *
 *   -ENOSYS: underlying device does not support this functionality.
 *
 *   -EINVAL: unknown or invalid rule specification.
 *
 *   -ENOTSUP: valid but unsupported rule specification (e.g. partial
 *   bit-masks are unsupported).
 *
 *   -EEXIST: collision with an existing rule. Only returned if device
 *   supports flow rule collision checking and there was a flow rule
 *   collision. Not receiving this return code is no guarantee that creating
 *   the rule will not fail due to a collision.
 *
 *   -ENOMEM: not enough memory to execute the function, or if the device
 *   supports resource validation, resource limitation on the device.
 *
 *   -EBUSY: action cannot be performed due to busy device resources, may
 *   succeed if the affected queues or even the entire port are in a stopped
 *   state (see rte_eth_dev_rx_queue_stop() and rte_eth_dev_stop()).
 */
int
rte_flow_validate(uint16_t port_id,
		  const struct rte_flow_attr *attr,
		  const struct rte_flow_item pattern[],
		  const struct rte_flow_action actions[],
		  struct rte_flow_error *error);

/**
 * Create a flow rule on a given port.
 *
 * @param port_id
 *   Port identifier of Ethernet device.
 * @param[in] attr
 *   Flow rule attributes.
 * @param[in] pattern
 *   Pattern specification (list terminated by the END pattern item).
 * @param[in] actions
 *   Associated actions (list terminated by the END action).
 * @param[out] error
 *   Perform verbose error reporting if not NULL. PMDs initialize this
 *   structure in case of error only.
 *
 * @return
 *   A valid handle in case of success, NULL otherwise and rte_errno is set
 *   to the positive version of one of the error codes defined for
 *   rte_flow_validate().
 */

/*******************************************************************************
 ????????  :    rte_flow_create
 ????????  :    rte flow ????
 ????????  :  	port_id---????in_port
 				attr---??????????
 				pattern---rte flow match
 				actions---rte flow action
 				error---rte flow??????????
 ????????  :	
 ?? ?? ??  : 	??
--------------------------------------------------------------------------------
 ???????????????? :
 ????????	:	
 ????????	: 	
 ????????	:	
*******************************************************************************/
struct rte_flow *
rte_flow_create(uint16_t port_id,
		const struct rte_flow_attr *attr,
		const struct rte_flow_item pattern[],
		const struct rte_flow_action actions[],
		struct rte_flow_error *error);

/**
 * Destroy a flow rule on a given port.
 *
 * Failure to destroy a flow rule handle may occur when other flow rules
 * depend on it, and destroying it would result in an inconsistent state.
 *
 * This function is only guaranteed to succeed if handles are destroyed in
 * reverse order of their creation.
 *
 * @param port_id
 *   Port identifier of Ethernet device.
 * @param flow
 *   Flow rule handle to destroy.
 * @param[out] error
 *   Perform verbose error reporting if not NULL. PMDs initialize this
 *   structure in case of error only.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */

/*******************************************************************************
 ????????  :    netdev_dpdk_destroy_rte_flow
 ????????  :    ???? rte flow ??????flow??????????????????????
 ????????  :  	port_id flow??in_port 
 				rte_flow---rte flow
 ????????  :	
 ?? ?? ??  : 	??
--------------------------------------------------------------------------------
 ???????????????? :
 ????????	:	
 ????????	: 	
 ????????	:	
*******************************************************************************/
int
rte_flow_destroy(uint16_t port_id,
		 struct rte_flow *flow,
		 struct rte_flow_error *error);

/**
 * Destroy all flow rules associated with a port.
 *
 * In the unlikely event of failure, handles are still considered destroyed
 * and no longer valid but the port must be assumed to be in an inconsistent
 * state.
 *
 * @param port_id
 *   Port identifier of Ethernet device.
 * @param[out] error
 *   Perform verbose error reporting if not NULL. PMDs initialize this
 *   structure in case of error only.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
rte_flow_flush(uint16_t port_id,
	       struct rte_flow_error *error);

/**
 * Query an existing flow rule.
 *
 * This function allows retrieving flow-specific data such as counters.
 * Data is gathered by special actions which must be present in the flow
 * rule definition.
 *
 * \see RTE_FLOW_ACTION_TYPE_COUNT
 *
 * @param port_id
 *   Port identifier of Ethernet device.
 * @param flow
 *   Flow rule handle to query.
 * @param action
 *   Action type to query.
 * @param[in, out] data
 *   Pointer to storage for the associated query data type.
 * @param[out] error
 *   Perform verbose error reporting if not NULL. PMDs initialize this
 *   structure in case of error only.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
rte_flow_query(uint16_t port_id,
	       struct rte_flow *flow,
	       enum rte_flow_action_type action,
	       void *data,
	       struct rte_flow_error *error);

/**
 * Restrict ingress traffic to the defined flow rules.
 *
 * Isolated mode guarantees that all ingress traffic comes from defined flow
 * rules only (current and future).
 *
 * Besides making ingress more deterministic, it allows PMDs to safely reuse
 * resources otherwise assigned to handle the remaining traffic, such as
 * global RSS configuration settings, VLAN filters, MAC address entries,
 * legacy filter API rules and so on in order to expand the set of possible
 * flow rule types.
 *
 * Calling this function as soon as possible after device initialization,
 * ideally before the first call to rte_eth_dev_configure(), is recommended
 * to avoid possible failures due to conflicting settings.
 *
 * Once effective, leaving isolated mode may not be possible depending on
 * PMD implementation.
 *
 * Additionally, the following functionality has no effect on the underlying
 * port and may return errors such as ENOTSUP ("not supported"):
 *
 * - Toggling promiscuous mode.
 * - Toggling allmulticast mode.
 * - Configuring MAC addresses.
 * - Configuring multicast addresses.
 * - Configuring VLAN filters.
 * - Configuring Rx filters through the legacy API (e.g. FDIR).
 * - Configuring global RSS settings.
 *
 * @param port_id
 *   Port identifier of Ethernet device.
 * @param set
 *   Nonzero to enter isolated mode, attempt to leave it otherwise.
 * @param[out] error
 *   Perform verbose error reporting if not NULL. PMDs initialize this
 *   structure in case of error only.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
rte_flow_isolate(uint16_t port_id, int set, struct rte_flow_error *error);

/**
 * Initialize flow error structure.
 *
 * @param[out] error
 *   Pointer to flow error structure (may be NULL).
 * @param code
 *   Related error code (rte_errno).
 * @param type
 *   Cause field and error types.
 * @param cause
 *   Object responsible for the error.
 * @param message
 *   Human-readable error message.
 *
 * @return
 *   Negative error code (errno value) and rte_errno is set.
 */
int
rte_flow_error_set(struct rte_flow_error *error,
		   int code,
		   enum rte_flow_error_type type,
		   const void *cause,
		   const char *message);

/**
 * Generic flow representation.
 *
 * This form is sufficient to describe an rte_flow independently from any
 * PMD implementation and allows for replayability and identification.
 */
struct rte_flow_desc {
	size_t size; /**< Allocated space including data[]. */
	struct rte_flow_attr attr; /**< Attributes. */
	struct rte_flow_item *items; /**< Items. */
	struct rte_flow_action *actions; /**< Actions. */
	uint8_t data[]; /**< Storage for items/actions. */
};

/**
 * Copy an rte_flow rule description.
 *
 * @param[in] fd
 *   Flow rule description.
 * @param[in] len
 *   Total size of allocated data for the flow description.
 * @param[in] attr
 *   Flow rule attributes.
 * @param[in] items
 *   Pattern specification (list terminated by the END pattern item).
 * @param[in] actions
 *   Associated actions (list terminated by the END action).
 *
 * @return
 *   If len is greater or equal to the size of the flow, the total size of the
 *   flow description and its data.
 *   If len is lower than the size of the flow, the number of bytes that would
 *   have been written to desc had it been sufficient. Nothing is written.
 */
size_t
rte_flow_copy(struct rte_flow_desc *fd, size_t len,
	      const struct rte_flow_attr *attr,
	      const struct rte_flow_item *items,
	      const struct rte_flow_action *actions);

#ifdef __cplusplus
}
#endif

#endif /* RTE_FLOW_H_ */
