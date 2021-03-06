/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2016 RehiveTech. All rights reserved.
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
 *     * Neither the name of RehiveTech nor the names of its
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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/queue.h>

#include <rte_vdev.h>
#include <rte_common.h>

struct vdev_driver_list vdev_driver_list =
	TAILQ_HEAD_INITIALIZER(vdev_driver_list);               /*全局虚拟设备链表*/

/* register a driver */
void
rte_eal_vdrv_register(struct rte_vdev_driver *driver)
{
	TAILQ_INSERT_TAIL(&vdev_driver_list, driver, next);
	rte_eal_driver_register(&driver->driver);
}

/* unregister a driver */
void
rte_eal_vdrv_unregister(struct rte_vdev_driver *driver)
{
	rte_eal_driver_unregister(&driver->driver);
	TAILQ_REMOVE(&vdev_driver_list, driver, next);
}


/*******************************************************
  函数名:		rte_eal_vdev_init
  功能描述: 	虚拟设备初始化
  参数描述: 	name---设备name
                args---设备参数
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
int
rte_eal_vdev_init(const char *name, const char *args)
{
	struct rte_vdev_driver *driver;

	if (name == NULL)
	{
		return -EINVAL;
	}
	
	
	/*遍历dev_driver_list链表，执行网卡驱动对应的init的回调函数*/	
	TAILQ_FOREACH(driver, &vdev_driver_list, next)
	{
		/*
		 * search a driver prefix in virtual device name.
		 * For example, if the driver is pcap PMD, driver->name
		 * will be "net_pcap", but "name" will be "net_pcapN".
		 * So use strncmp to compare.
		 */

		/*匹配到设备返回探测结果*/
		if (!strncmp(driver->driver.name, name, strlen(driver->driver.name)))
		{
			/*e1000网卡为例，执行的init回调函数就是eth_igb_dev_init()函数*/
			return driver->probe(name, args);
		}
	}

	/* Give new names precedence over aliases. */
	/*虚拟设备链表，返回探测结果*/
	TAILQ_FOREACH(driver, &vdev_driver_list, next) 
	{
		if (driver->driver.alias && !strncmp(driver->driver.alias, name, strlen(driver->driver.alias)))
		{
			return driver->probe(name, args);
		}
	}

	RTE_LOG(ERR, EAL, "no driver found for %s\n", name);
	
	return -EINVAL;
}

int
rte_eal_vdev_uninit(const char *name)
{
	struct rte_vdev_driver *driver;

	if (name == NULL)
		return -EINVAL;

	TAILQ_FOREACH(driver, &vdev_driver_list, next) {
		/*
		 * search a driver prefix in virtual device name.
		 * For example, if the driver is pcap PMD, driver->name
		 * will be "net_pcap", but "name" will be "net_pcapN".
		 * So use strncmp to compare.
		 */
		if (!strncmp(driver->driver.name, name,
			     strlen(driver->driver.name)))
			return driver->remove(name);
	}

	RTE_LOG(ERR, EAL, "no driver found for %s\n", name);
	return -EINVAL;
}
