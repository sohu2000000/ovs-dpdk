/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_NF_CONNTRACK_COMMON_H
#define _UAPI_NF_CONNTRACK_COMMON_H
/* Connection state tracking for netfilter.  This is separated from,
   but required by, the NAT layer; it can also be used by an iptables
   extension. */

/*Netfilter¶¨ÒåµÄ¸÷ÖÖÁ¬½Ó×´Ì¬*/

/* Ò»¹²5¸ö×´Ì¬£¬ÏÂÃæËÄ¸ö£¬¼ÓÉÏIP_CT_RELATED + IP_CT_IS_REPLY */
/* ÕâĞ©ÖµÊÇskb->nfctinfoÊ¹ÓÃµÄ */

enum ip_conntrack_info {
	/* Part of an established connection (either direction). */
	IP_CT_ESTABLISHED,               /*±íÊ¾Á¬½Ó½¨Á¢£¬Ë«Ïò¶¼ÓĞ°üÍ¨¹ıÊ±ÉèÖÃ

	/* Like NEW, but related to an existing connection, or ICMP error
	   (in either direction). */
	IP_CT_RELATED,                    /*±íÊ¾Ò»¸öÓëÆäËüÁ¬½Ó¹ØÁªµÄĞÂ½¨Á¬½Ó£¬ÊÇ×ÓÁ´½Ó£¬µ±Ç°Êı¾İ°üÊÇORIGINAL·½Ïò*/

	/* Started a new connection to track (only
           IP_CT_DIR_ORIGINAL); may be a retransmission. */
	IP_CT_NEW,               /*±íÊ¾Ò»¸öĞÂ½¨Á¬½Ó£¬Ö»ÓĞORIGINAL·½Ïò£¬»¹Ã»ÓĞREPLY·½Ïò*/

	/* >= this indicates reply direction */
	IP_CT_IS_REPLY,           /* Õâ¸ö×´Ì¬Ò»°ã²»µ¥¶ÀÊ¹ÓÃ£¬Í¨³£ÒÔÏÂÃæÁ½ÖÖ·½Ê½Ê¹ÓÃ */

	IP_CT_ESTABLISHED_REPLY = IP_CT_ESTABLISHED + IP_CT_IS_REPLY,	  /* ±íÊ¾Õâ¸öÊı¾İ°ü¶ÔÓ¦µÄÁ¬½ÓÔÚÁ½¸ö·½Ïò¶¼ÓĞÊı¾İ°üÍ¨¹ı£¬
																		²¢ÇÒÕâÊÇREPLYÓ¦´ğ·½ÏòÊı¾İ°ü¡£µ«Ëü±íÊ¾²»ÁËÕâÊÇµÚ¼¸¸öÊı¾İ°ü£¬
																		Ò²ËµÃ÷²»ÁËÕâ¸öCTÊÇ·ñÊÇ×ÓÁ¬½Ó¡£*/

	
	IP_CT_RELATED_REPLY = IP_CT_RELATED + IP_CT_IS_REPLY,			 /* Õâ¸ö×´Ì¬½öÔÚnf_conntrack_attach()º¯ÊıÖĞÉèÖÃ£¬ÓÃÓÚ±¾»ú·µ»ØREJECT£¬
																		ÀıÈç·µ»ØÒ»¸öICMPÄ¿µÄ²»¿É´ï±¨ÎÄ£¬ »ò·µ»ØÒ»¸öreset±¨ÎÄ¡£
																		Ëü±íÊ¾²»ÁËÕâÊÇµÚ¼¸¸öÊı¾İ°ü¡£*/
	/* No NEW in reply direction. */

	/* Number of distinct IP_CT types. */
	IP_CT_NUMBER,									/* ¿É±íÊ¾×´Ì¬µÄ×ÜÊı */

	/* only for userspace compatibility */
#ifndef __KERNEL__
	IP_CT_NEW_REPLY = IP_CT_NUMBER,
#else
	IP_CT_UNTRACKED = 7,							/*²»ĞèÒª½¨Á¢Á´½Ó¸ú×Ù*/
#endif
};

#define NF_CT_STATE_INVALID_BIT			(1 << 0)
#define NF_CT_STATE_BIT(ctinfo)			(1 << ((ctinfo) % IP_CT_IS_REPLY + 1))
#define NF_CT_STATE_UNTRACKED_BIT		(1 << 6)

/* Bitset representing status of connection. */


/* ÕâĞ©ÖµÊÇct->statusÊ¹ÓÃµÄ£¬Á´½ÓµÄ×´Ì¬£¬ÊÇ·ñÒÑ½¨Á¢*/
enum ip_conntrack_status {
	/* It's an expected connection: bit 0 set.  This bit never changed */
	IPS_EXPECTED_BIT = 0,						/* ±íÊ¾¸ÃÁ¬½ÓÊÇ¸ö×ÓÁ¬½Ó */
	IPS_EXPECTED = (1 << IPS_EXPECTED_BIT),

	/* We've seen packets both ways: bit 1 set.  Can be set, not unset. */
	IPS_SEEN_REPLY_BIT = 1,                     /* ±íÊ¾¸ÃÁ¬½ÓÉÏË«·½ÏòÉÏ¶¼ÓĞÊı¾İ°üÁË */
	IPS_SEEN_REPLY = (1 << IPS_SEEN_REPLY_BIT),

	/* Conntrack should never be early-expired. */
	IPS_ASSURED_BIT = 2,						 /* TCP£ºÔÚÈı´ÎÎÕÊÖ½¨Á¢ÍêÁ¬½Óºó¼´Éè¶¨¸Ã±êÖ¾¡£
													UDP£ºÈç¹ûÔÚ¸ÃÁ¬½ÓÉÏµÄÁ½¸ö·½Ïò¶¼ÓĞÊı¾İ°üÍ¨¹ı£¬
                                                    ÔòÔÙÓĞÊı¾İ°üÔÚ¸ÃÁ¬½ÓÉÏÍ¨¹ıÊ±£¬¾ÍÉè¶¨¸Ã±êÖ¾¡
                                                    CMP£º²»ÉèÖÃ¸Ã±êÖ¾ */
	IPS_ASSURED = (1 << IPS_ASSURED_BIT),

	/* Connection is confirmed: originating packet has left box */
	IPS_CONFIRMED_BIT = 3,						/* ±íÊ¾¸ÃÁ¬½ÓÒÑ±»Ìí¼Óµ½net->ct.hash±íÖĞ */
	IPS_CONFIRMED = (1 << IPS_CONFIRMED_BIT),

	/* Connection needs src nat in orig dir.  This bit never changed. */
	IPS_SRC_NAT_BIT = 4,						/*ÔÚPOSTROUTING´¦£¬µ±Ìæ»»reply tupleÍê³ÉÊ±, ÉèÖÃ¸Ã±ê¼Ç */
	IPS_SRC_NAT = (1 << IPS_SRC_NAT_BIT),

	/* Connection needs dst nat in orig dir.  This bit never changed. */
	IPS_DST_NAT_BIT = 5,						/* ÔÚPREROUTING´¦£¬µ±Ìæ»»reply tupleÍê³ÉÊ±, ÉèÖÃ¸Ã±ê¼Ç */
	IPS_DST_NAT = (1 << IPS_DST_NAT_BIT),

	/* Both together. */
	IPS_NAT_MASK = (IPS_DST_NAT | IPS_SRC_NAT),

	/* Connection needs TCP sequence adjusted. */
	IPS_SEQ_ADJUST_BIT = 6,
	IPS_SEQ_ADJUST = (1 << IPS_SEQ_ADJUST_BIT),

	/* NAT initialization bits. */
	IPS_SRC_NAT_DONE_BIT = 7,						   /* ÔÚPOSTROUTING´¦£¬ÒÑ±»SNAT´¦Àí£¬²¢±»¼ÓÈëµ½bysourceÁ´ÖĞ£¬ÉèÖÃ¸Ã±ê¼Ç */
	IPS_SRC_NAT_DONE = (1 << IPS_SRC_NAT_DONE_BIT),

	IPS_DST_NAT_DONE_BIT = 8,						   /* ÔÚPREROUTING´¦£¬ÒÑ±»DNAT´¦Àí£¬²¢±»¼ÓÈëµ½bysourceÁ´ÖĞ£¬ÉèÖÃ¸Ã±ê¼Ç */
	IPS_DST_NAT_DONE = (1 << IPS_DST_NAT_DONE_BIT),

	/* Both together */
	IPS_NAT_DONE_MASK = (IPS_DST_NAT_DONE | IPS_SRC_NAT_DONE),

	/* Connection is dying (removed from lists), can not be unset. */
	IPS_DYING_BIT = 9,									/* ±íÊ¾¸ÃÁ¬½ÓÕıÔÚ±»ÊÍ·Å£¬ÄÚºËÍ¨¹ı¸Ã±êÖ¾±£Ö¤ÕıÔÚ±»ÊÍ·ÅµÄct²»»á±»ÆäËüµØ·½ÔÙ´ÎÒıÓÃ¡£
														ÓĞÁËÕâ¸ö±êÖ¾£¬µ±Ä³¸öÁ¬½ÓÒª±»É¾³ıÊ±£¬¼´Ê¹Ëü»¹ÔÚnet->ct.hashÖĞ£¬Ò²²»»áÔÙ´Î±»ÒıÓÃ¡£*/
	IPS_DYING = (1 << IPS_DYING_BIT),

	/* Connection has fixed timeout. */
	IPS_FIXED_TIMEOUT_BIT = 10,							/* ¹Ì¶¨Á¬½Ó³¬Ê±Ê±¼ä£¬Õâ½«²»¸ù¾İ×´Ì¬ĞŞ¸ÄÁ¬½Ó³¬Ê±Ê±¼ä¡£
														Í¨¹ıº¯Êınf_ct_refresh_acct()ĞŞ¸Ä³¬Ê±Ê±¼äÊ±¼ì²é¸Ã±êÖ¾¡£ */
	IPS_FIXED_TIMEOUT = (1 << IPS_FIXED_TIMEOUT_BIT),

	/* Conntrack is a template */
	IPS_TEMPLATE_BIT = 11,								/* ÓÉCT target½øĞĞÉèÖÃ£¨Õâ¸ötargetÖ»ÄÜÓÃÔÚraw±íÖĞ£¬ÓÃÓÚÎªÊı¾İ°ü¹¹½¨Ö¸¶¨ct£¬
															²¢´òÉÏ¸Ã±êÖ¾£©£¬ÓÃÓÚ±íÃ÷Õâ¸öctÊÇÓÉCT target´´½¨µÄ */
	IPS_TEMPLATE = (1 << IPS_TEMPLATE_BIT),

	/* Conntrack is a fake untracked entry.  Obsolete and not used anymore */
	IPS_UNTRACKED_BIT = 12,
	IPS_UNTRACKED = (1 << IPS_UNTRACKED_BIT),

	/* Conntrack got a helper explicitly attached via CT target. */
	IPS_HELPER_BIT = 13,
	IPS_HELPER = (1 << IPS_HELPER_BIT),

	/* Conntrack has been offloaded to flow table. */
	IPS_OFFLOAD_BIT = 14,
	IPS_OFFLOAD = (1 << IPS_OFFLOAD_BIT),

	/* Be careful here, modifying these bits can make things messy,
	 * so don't let users modify them directly.
	 */
	IPS_UNCHANGEABLE_MASK = (IPS_NAT_DONE_MASK | IPS_NAT_MASK |
				 IPS_EXPECTED | IPS_CONFIRMED | IPS_DYING |
				 IPS_SEQ_ADJUST | IPS_TEMPLATE | IPS_OFFLOAD),

	__IPS_MAX_BIT = 14,
};

/* Connection tracking event types */
enum ip_conntrack_events {
	IPCT_NEW,		/* new conntrack */
	IPCT_RELATED,		/* related conntrack */
	IPCT_DESTROY,		/* destroyed conntrack */
	IPCT_REPLY,		/* connection has seen two-way traffic */
	IPCT_ASSURED,		/* connection status has changed to assured */
	IPCT_PROTOINFO,		/* protocol information has changed */
	IPCT_HELPER,		/* new helper has been set */
	IPCT_MARK,		/* new mark has been set */
	IPCT_SEQADJ,		/* sequence adjustment has changed */
	IPCT_NATSEQADJ = IPCT_SEQADJ,
	IPCT_SECMARK,		/* new security mark has been set */
	IPCT_LABEL,		/* new connlabel has been set */
	IPCT_SYNPROXY,		/* synproxy has been set */
#ifdef __KERNEL__
	__IPCT_MAX
#endif
};

enum ip_conntrack_expect_events {
	IPEXP_NEW,		/* new expectation */
	IPEXP_DESTROY,		/* destroyed expectation */
};

/* expectation flags */
#define NF_CT_EXPECT_PERMANENT		0x1
#define NF_CT_EXPECT_INACTIVE		0x2
#define NF_CT_EXPECT_USERSPACE		0x4


#endif /* _UAPI_NF_CONNTRACK_COMMON_H */
