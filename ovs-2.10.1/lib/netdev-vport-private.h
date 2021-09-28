/*
 * Copyright (c) 2010, 2011, 2013, 2015 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NETDEV_VPORT_PRIVATE_H
#define NETDEV_VPORT_PRAVITE_H 1

#include <stdbool.h>
#include <stddef.h>
#include "compiler.h"
#include "netdev.h"
#include "netdev-provider.h"
#include "ovs-thread.h"

struct netdev_vport {
    struct netdev up;

    /* Protects all members below. */
    struct ovs_mutex mutex;

    struct eth_addr etheraddr;
    struct netdev_stats stats;

    /* Tunnels. */
    struct netdev_tunnel_config tnl_cfg;
    char egress_iface[IFNAMSIZ];
    bool carrier_status;

    /* Patch Ports. */
    char *peer;
};

int netdev_vport_construct(struct netdev *);

/*******************************************************************************
 函数名称  :    is_vport_class
 功能描述  :    emc流表删除
 输入参数  :  	class---
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static bool
is_vport_class(const struct netdev_class *class)
{
	/*虚拟端口构造类函数*/
    return class->construct == netdev_vport_construct;
}

/*******************************************************************************
 函数名称  :    netdev_vport_cast
 功能描述  :    emc流表删除
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline struct netdev_vport *
netdev_vport_cast(const struct netdev *netdev)
{
	/*虚拟端口类 assert 判断*/
    ovs_assert(is_vport_class(netdev_get_class(netdev)));

	/**/
    return CONTAINER_OF(netdev, struct netdev_vport, up);
}

#endif
