/*
 * Copyright (c) 2007-2015 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#ifndef VPORT_H
#define VPORT_H 1

#include <linux/if_tunnel.h>
#include <linux/list.h>
#include <linux/netlink.h>
#include <linux/openvswitch.h>
#include <linux/reciprocal_div.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/u64_stats_sync.h>

#include "datapath.h"

struct vport;
struct vport_parms;

/* The following definitions are for users of the vport subsytem: */

int ovs_vport_init(void);
void ovs_vport_exit(void);

struct vport *ovs_vport_add(const struct vport_parms *);
void ovs_vport_del(struct vport *);

struct vport *ovs_vport_locate(const struct net *net, const char *name);

void ovs_vport_get_stats(struct vport *, struct ovs_vport_stats *);

int ovs_vport_set_options(struct vport *, struct nlattr *options);
int ovs_vport_get_options(const struct vport *, struct sk_buff *);

int ovs_vport_set_upcall_portids(struct vport *, const struct nlattr *pids);
int ovs_vport_get_upcall_portids(const struct vport *, struct sk_buff *);
u32 ovs_vport_find_upcall_portid(const struct vport *, struct sk_buff *);

/**
 * struct vport_portids - array of netlink portids of a vport.
 *                        must be protected by rcu.
 * @rn_ids: The reciprocal value of @n_ids.
 * @rcu: RCU callback head for deferred destruction.
 * @n_ids: Size of @ids array.
 * @ids: Array storing the Netlink socket pids to be used for packets received
 * on this port that miss the flow table.
 */

/*虚拟端口*/
struct vport_portids 
{
	struct reciprocal_value rn_ids;  /*ids的反值*/
	struct rcu_head rcu;             /*rcu锁*/
	u32 n_ids;
	u32 ids[];                       /**/
};

/**
 * struct vport - one port within a datapath
 * @dev: Pointer to net_device.
 * @dp: Datapath to which this port belongs.
 * @upcall_portids: RCU protected 'struct vport_portids'.
 * @port_no: Index into @dp's @ports array.
 * @hash_node: Element in @dev_table hash table in vport.c.
 * @dp_hash_node: Element in @datapath->ports hash table in datapath.c.
 * @ops: Class structure.
 * @detach_list: list used for detaching vport in net-exit call.
 * @rcu: RCU callback head for deferred destruction.
 */

/*虚拟端口*/
struct vport
{
	struct net_device *dev;                           /*网络设备*/
	struct datapath	*dp;                              /*端口所属网桥*/
	struct vport_portids __rcu *upcall_portids;       /*用户态netlink时使用的ID,Netlink端口收到的数据包时使用的端口id*/
	u16 port_no;                                      /*端口号*/

	struct hlist_node hash_node;                      /*虚拟端口哈希节点指针,有next和prev前驱后继指针*/
	struct hlist_node dp_hash_node;                   /*记录网桥哈希链表头*/
	const struct vport_ops *ops;                      /*端口操作函数*/

	struct list_head detach_list;                     /*销毁链*/
	struct rcu_head rcu;                              /*rcu锁*/
};

/**
 * struct vport_parms - parameters for creating a new vport
 *
 * @name: New vport's name.
 * @type: New vport's type.
 * @options: %OVS_VPORT_ATTR_OPTIONS attribute from Netlink message, %NULL if
 * none was supplied.
 * @dp: New vport's datapath.
 * @port_no: New vport's port number.
 */

/*虚拟端口创建时参数*/
struct vport_parms 
{
	const char *name;                  /*端口name*/
	enum ovs_vport_type type;          /*端口类型*/
	struct nlattr *options;            /*netlink使用选项，Netlink消息中得到的OVS_VPORT_ATTR_OPTIONS属性*/

	/* For ovs_vport_alloc(). */
	struct datapath *dp;               /*所属网桥*/
	u16 port_no;                       /*端口号*/
	struct nlattr *upcall_portids;     /*netlink通信端口ID*/
};

/**
 * struct vport_ops - definition of a type of virtual port
 *
 * @type: %OVS_VPORT_TYPE_* value for this type of virtual port.
 * @create: Create a new vport configured as specified.  On success returns
 * a new vport allocated with ovs_vport_alloc(), otherwise an ERR_PTR() value.
 * @destroy: Destroys a vport.  Must call vport_free() on the vport but not
 * before an RCU grace period has elapsed.
 * @set_options: Modify the configuration of an existing vport.  May be %NULL
 * if modification is not supported.
 * @get_options: Appends vport-specific attributes for the configuration of an
 * existing vport to a &struct sk_buff.  May be %NULL for a vport that does not
 * have any configuration.
 * @send: Send a packet on the device.
 * zero for dropped packets or negative for error.
 */

/*虚拟端口操作函数*/
struct vport_ops 
{
	enum ovs_vport_type type;                                                /*虚拟端口类型*/

	/* Called with ovs_mutex. */
	struct vport *(*create)(const struct vport_parms *);                     /*端口创建*/
	void (*destroy)(struct vport *);                                         /*端口销毁*/

	int (*set_options)(struct vport *, struct nlattr *);                     /*设置、得到端口option*/
	int (*get_options)(const struct vport *, struct sk_buff *);

	netdev_tx_t (*send)(struct sk_buff *skb);                                /*端口发包接口*/
#ifndef USE_UPSTREAM_TUNNEL
	int  (*fill_metadata_dst)(struct net_device *dev, struct sk_buff *skb);  /*填充数据*/
#endif
	struct module *owner;                                                    /*所属模块*/
	struct list_head list;                                                   /*端口链表*/
};

struct vport *ovs_vport_alloc(int priv_size, const struct vport_ops *,
			      const struct vport_parms *);
void ovs_vport_free(struct vport *);

#define VPORT_ALIGN 8

/**
 *	vport_priv - access private data area of vport
 *
 * @vport: vport to access
 *
 * If a nonzero size was passed in priv_size of vport_alloc() a private data
 * area was allocated on creation.  This allows that area to be accessed and
 * used for any purpose needed by the vport implementer.
 */
static inline void *vport_priv(const struct vport *vport)
{
	return (u8 *)(uintptr_t)vport + ALIGN(sizeof(struct vport), VPORT_ALIGN);
}

/**
 *	vport_from_priv - lookup vport from private data pointer
 *
 * @priv: Start of private data area.
 *
 * It is sometimes useful to translate from a pointer to the private data
 * area to the vport, such as in the case where the private data pointer is
 * the result of a hash table lookup.  @priv must point to the start of the
 * private data area.
 */
static inline struct vport *vport_from_priv(void *priv)
{
	return (struct vport *)((u8 *)priv - ALIGN(sizeof(struct vport), VPORT_ALIGN));
}

int ovs_vport_receive(struct vport *, struct sk_buff *,
		      const struct ip_tunnel_info *);

static inline const char *ovs_vport_name(struct vport *vport)
{
	return vport->dev->name;
}

int __ovs_vport_ops_register(struct vport_ops *ops);
#define ovs_vport_ops_register(ops)		\
	({					\
		(ops)->owner = THIS_MODULE;	\
		__ovs_vport_ops_register(ops);	\
	})

void ovs_vport_ops_unregister(struct vport_ops *ops);
void ovs_vport_send(struct vport *vport, struct sk_buff *skb, u8 mac_proto);

#endif /* vport.h */
