/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
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
/*   BSD LICENSE
 *
 *   Copyright 2013-2014 6WIND S.A.
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

#include <string.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/queue.h>
#include <sys/mman.h>

#include <rte_interrupts.h>
#include <rte_log.h>
#include <rte_pci.h>
#include <rte_per_lcore.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_string_fns.h>
#include <rte_common.h>
#include <rte_devargs.h>

#include "eal_private.h"

struct pci_driver_list pci_driver_list = TAILQ_HEAD_INITIALIZER(pci_driver_list);
struct pci_device_list pci_device_list = TAILQ_HEAD_INITIALIZER(pci_device_list);

#define SYSFS_PCI_DEVICES "/sys/bus/pci/devices"

/*******************************************************
  ������:		pci_get_sysfs_path
  ��������: 	���л�������ʼ�����
  ��������: 	
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
const char *pci_get_sysfs_path(void)
{
	const char *path = NULL;

	/*��ȡϵͳpci�豸·��*/
	path = getenv("SYSFS_PCI_DEVICES");
	if (path == NULL)
	{
		return SYSFS_PCI_DEVICES;
	}
	
	return path;
}


/*******************************************************
  ������:		pci_devargs_lookup
  ��������: 	pci�豸��������
  ��������: 	
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static struct rte_devargs *pci_devargs_lookup(struct rte_pci_device *dev)
{
	struct rte_devargs *devargs;

	/*�����豸�������������豸�Ĳ���*/
	TAILQ_FOREACH(devargs, &devargs_list, next) 
	{
		/*�豸�Ǻڰ���������*/
		if (devargs->type != RTE_DEVTYPE_BLACKLISTED_PCI
			&& devargs->type != RTE_DEVTYPE_WHITELISTED_PCI)
		{
			continue;
		}
		
		/*�Ƚ��豸��ַ�����豸�����Ƿ����*/
		if (!rte_eal_compare_pci_addr(&dev->addr, &devargs->pci.addr))
		{
			return devargs;
		}
	}
	
	return NULL;
}

/*******************************************************************************
 �������� :  pci_map_resource
 �������� :  pci��Դӳ��
 ������� :  requested_addr---ӳ�䵽������ռ���ʼ��ַ
 ������� :  ��
 ����ֵ�� :  ��
 --------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸����� :  
 �޸�Ŀ�� :  
 �޸����� :  
*******************************************************************************/
/* map a particular resource from a file */
void *
pci_map_resource(void *requested_addr, int fd, off_t offset, size_t size, int additional_flags)
{
	void *mapaddr;

	/* Map the PCI memory resource of device */
	/*ӳ���豸��pci��Դ*/
	mapaddr = mmap(requested_addr, size, PROT_READ | PROT_WRITE, MAP_SHARED | additional_flags, fd, offset);
	if (mapaddr == MAP_FAILED) 
	{
		RTE_LOG(ERR, EAL, "%s(): cannot mmap(%d, %p, 0x%lx, 0x%lx): %s (%p)\n", __func__,
			fd, requested_addr, (unsigned long)size, (unsigned long)offset, strerror(errno), mapaddr);
	}
	else
	{
		RTE_LOG(DEBUG, EAL, "  PCI memory mapped at %p\n", mapaddr);	
	}
	
	return mapaddr;
}

/*******************************************************************************
 �������� :  pci_unmap_resource
 �������� :  pci��Դȡ��ӳ��
 ������� :  
 ������� :  ��
 ����ֵ�� :  ��
 --------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸����� :  
 �޸�Ŀ�� :  
 �޸����� :  
*******************************************************************************/
/* unmap a particular resource */
void
pci_unmap_resource(void *requested_addr, size_t size)
{
	if (requested_addr == NULL)
		return;

	/* Unmap the PCI memory resource of device */
	if (munmap(requested_addr, size)) {
		RTE_LOG(ERR, EAL, "%s(): cannot munmap(%p, 0x%lx): %s\n",
			__func__, requested_addr, (unsigned long)size,
			strerror(errno));
	} else
		RTE_LOG(DEBUG, EAL, "  PCI memory unmapped at %p\n",
				requested_addr);
}

/*
 * If vendor/device ID match, call the probe() function of the
 * driver.
 */
 
/*******************************************************
  ������:		rte_eal_pci_probe_one_driver
  ��������: 	pci bar�Ĵ����洢��pci�洢�ռ��ַ��ӳ�䵽�ں˵�ַ�ռ䣬�˴���ӳ�䵽�û�̬
  ��������: 	dr---�豸������Ϣ
  				dev--pci�豸
  ����ֵ:
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static int rte_eal_pci_probe_one_driver(struct rte_pci_driver *dr, struct rte_pci_device *dev)
{
	int ret;
	const struct rte_pci_id *id_table;

	/*����������Ϣ���Ա��Ƿ���豸һ��*/
	/*ͨ���ȶ�PCI_ID��vendor_id��device_id��subsystem_vendor_id��subsystem_device_id
	  �ĸ��ֶ��ж�pci�豸��pci�����Ƿ�ƥ��
	*/
	for (id_table = dr->id_table; id_table->vendor_id != 0; id_table++) 
	{
		/* check if device's identifiers match the driver's ones */
		
		if (id_table->vendor_id != dev->id.vendor_id
			&& id_table->vendor_id != PCI_ANY_ID)
		{
			continue;
		}
		
		if (id_table->device_id != dev->id.device_id 
			&& id_table->device_id != PCI_ANY_ID)
		{
			continue;
		}

		if (id_table->subsystem_vendor_id != dev->id.subsystem_vendor_id
			&& id_table->subsystem_vendor_id != PCI_ANY_ID)
		{
			continue;
		}

		if (id_table->subsystem_device_id != dev->id.subsystem_device_id
			&& id_table->subsystem_device_id != PCI_ANY_ID)
		{
			continue;
		}
		
		if (id_table->class_id != dev->id.class_id 
			&& id_table->class_id != RTE_CLASS_ANY_ID)
		{
			continue;
		}

		struct rte_pci_addr *loc = &dev->addr;

		RTE_LOG(INFO, EAL, "PCI device "PCI_PRI_FMT" on NUMA socket %i\n",
				loc->domain, loc->bus, loc->devid, loc->function,dev->device.numa_node);

		/* no initialization when blacklisted, return without error */
		/*�豸Ϊ������ʱ*/
		if (dev->device.devargs != NULL 
			&& dev->device.devargs->type == RTE_DEVTYPE_BLACKLISTED_PCI)
		{
			RTE_LOG(INFO, EAL, "  Device is blacklisted, not initializing\n");
			return 1;
		}

		RTE_LOG(INFO, EAL, "  probe driver: %x:%x %s\n", dev->id.vendor_id, dev->id.device_id, dr->driver.name);

		/*pci �豸��Ҫӳ��*/
		if (dr->drv_flags & RTE_PCI_DRV_NEED_MAPPING) 
		{
			/* map resources for devices that use igb_uio */
			/*��pci��Դӳ�䵽uio�û�̬��Ϊ��PCI�豸����map resource*/
			/*��PCI�豸��PCI����ƥ��󣬵���pci_map_device()����Ϊ��PCI�豸����map resource��
			  ��pci bar�Ĵ����洢��pci�洢�ռ��ַ��ӳ�䵽�ں˵�ַ�ռ䣬�˴���ӳ�䵽�û�̬*/

			/*struct rte_mem_resource mem_resource[PCI_MAX_RESOURCE];��¼��ַ�ռ������ַ�������ַ*/
			ret = rte_eal_pci_map_device(dev);
			if (ret != 0)
			{
				return ret;
			}
			
		}
		else if (dr->drv_flags & RTE_PCI_DRV_FORCE_UNBIND
			&&	rte_eal_process_type() == RTE_PROC_PRIMARY)
		{
			/* unbind current driver */
			if (pci_unbind_kernel_driver(dev) < 0)
			{
				return -1;
			}
		}

		/* reference driver structure */
		/*������Ϣ�����豸��Ϣ*/
		dev->driver = dr;

		/* call the driver probe() function */
        /*�ֶ˿ں� ��prob��˳���0��ʼ ����ovsʹ��*/
		/*����ʹ�õ�������probe������rte_eth_dev_pci_probe*/
		ret = dr->probe(dr, dev);
		if (ret)
		{
			dev->driver = NULL;
		}
		
		return ret;
	}
	
	/* return positive value if driver doesn't support this device */
	return 1;
}

/*
 * If vendor/device ID match, call the remove() function of the
 * driver.
 */
static int
rte_eal_pci_detach_dev(struct rte_pci_driver *dr,
		struct rte_pci_device *dev)
{
	const struct rte_pci_id *id_table;

	if ((dr == NULL) || (dev == NULL))
		return -EINVAL;

	for (id_table = dr->id_table; id_table->vendor_id != 0; id_table++) {

		/* check if device's identifiers match the driver's ones */
		if (id_table->vendor_id != dev->id.vendor_id &&
				id_table->vendor_id != PCI_ANY_ID)
			continue;
		if (id_table->device_id != dev->id.device_id &&
				id_table->device_id != PCI_ANY_ID)
			continue;
		if (id_table->subsystem_vendor_id != dev->id.subsystem_vendor_id &&
				id_table->subsystem_vendor_id != PCI_ANY_ID)
			continue;
		if (id_table->subsystem_device_id != dev->id.subsystem_device_id &&
				id_table->subsystem_device_id != PCI_ANY_ID)
			continue;

		struct rte_pci_addr *loc = &dev->addr;

		RTE_LOG(DEBUG, EAL, "PCI device "PCI_PRI_FMT" on NUMA socket %i\n",
				loc->domain, loc->bus, loc->devid,
				loc->function, dev->device.numa_node);

		RTE_LOG(DEBUG, EAL, "  remove driver: %x:%x %s\n", dev->id.vendor_id,
				dev->id.device_id, dr->driver.name);

		if (dr->remove && (dr->remove(dev) < 0))
			return -1;	/* negative value is an error */

		/* clear driver structure */
		dev->driver = NULL;

		if (dr->drv_flags & RTE_PCI_DRV_NEED_MAPPING)
			/* unmap resources for devices that use igb_uio */
			rte_eal_pci_unmap_device(dev);

		return 0;
	}

	/* return positive value if driver doesn't support this device */
	return 1;
}

/*
 * If vendor/device ID match, call the probe() function of all
 * registered driver for the given device. Return -1 if initialization
 * failed, return 1 if no driver is found for this device.
 */

/*******************************************************
  ������:		pci_probe_all_drivers
  ��������: 	pci ��ַ�ռ�ӳ�䵽�û�̬����ӳ�䵽�ں�
  ��������: 	dev--pci�豸
  ����ֵ:
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static int
pci_probe_all_drivers(struct rte_pci_device *dev)
{
	struct rte_pci_driver *dr = NULL;
	int rc = 0;

	if (dev == NULL)
	{
		return -1;
	}
	
	/* Check if a driver is already loaded */

	/*����豸�����Ƿ����*/
	if (dev->driver != NULL)
	{
		return 0;
	}
	
	/*��������ȡpci�豸������Ϣ*/
	TAILQ_FOREACH(dr, &pci_driver_list, next)
	{
		/*pci bar�Ĵ����洢��pci�洢�ռ��ַ��ӳ�䵽�ں˵�ַ�ռ䣬�˴���ӳ�䵽�û�̬*/
		rc = rte_eal_pci_probe_one_driver(dr, dev);
		if (rc < 0)
		{
			/* negative value is an error */
			return -1;
		}
		
		if (rc > 0)
		{
			/* positive value means driver doesn't support it */
			continue;
		}
		
		return 0;
	}
	
	return 1;
}

/*
 * If vendor/device ID match, call the remove() function of all
 * registered driver for the given device. Return -1 if initialization
 * failed, return 1 if no driver is found for this device.
 */

/*******************************************************************************
 �������� :  igbuio_pci_irqhandler
 �������� :  �жϴ������
 ������� :  
 ������� :  ��
 ����ֵ�� :  ��
 --------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸����� :  
 �޸�Ŀ�� :  
 �޸����� :  
*******************************************************************************/
static int
pci_detach_all_drivers(struct rte_pci_device *dev)
{
	struct rte_pci_driver *dr = NULL;
	int rc = 0;

	if (dev == NULL)
		return -1;

	TAILQ_FOREACH(dr, &pci_driver_list, next) {
		rc = rte_eal_pci_detach_dev(dr, dev);
		if (rc < 0)
			/* negative value is an error */
			return -1;
		if (rc > 0)
			/* positive value means driver doesn't support it */
			continue;
		return 0;
	}
	return 1;
}

/*
 * Find the pci device specified by pci address, then invoke probe function of
 * the driver of the devive.
 */

/*******************************************************************************
 �������� :  rte_eal_pci_probe_one
 �������� :  pci bar�Ĵ����洢��pci�洢�ռ��ַ��ӳ�䵽�ں˵�ַ�ռ䣬�˴���ӳ�䵽�û�̬
 ������� :  
 ������� :  ��
 ����ֵ�� :  ��
 --------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸����� :  
 �޸�Ŀ�� :  
 �޸����� :  
*******************************************************************************/
int
rte_eal_pci_probe_one(const struct rte_pci_addr *addr)
{
	struct rte_pci_device *dev = NULL;
	int ret = 0;

	if (addr == NULL)
		return -1;

	/* update current pci device in global list, kernel bindings might have
	 * changed since last time we looked at it.
	 */
	if (pci_update_device(addr) < 0)
	{
		goto err_return;
	}
	
	/*����pci�豸����pci��ַ�ռ�ӳ�䵽�û�̬*/
	TAILQ_FOREACH(dev, &pci_device_list, next) 
	{
		if (rte_eal_compare_pci_addr(&dev->addr, addr))
			continue;

		/*pci bar�Ĵ����洢��pci�洢�ռ��ַ��ӳ�䵽�ں˵�ַ�ռ䣬�˴���ӳ�䵽�û�̬*/
		ret = pci_probe_all_drivers(dev);
		if (ret)
		{
			goto err_return;
		}
		return 0;
	}
	return -1;

err_return:
	RTE_LOG(WARNING, EAL,
		"Requested device " PCI_PRI_FMT " cannot be used\n",
		addr->domain, addr->bus, addr->devid, addr->function);
	return -1;
}

/*
 * Detach device specified by its pci address.
 */
int
rte_eal_pci_detach(const struct rte_pci_addr *addr)
{
	struct rte_pci_device *dev = NULL;
	int ret = 0;

	if (addr == NULL)
		return -1;

	TAILQ_FOREACH(dev, &pci_device_list, next) {
		if (rte_eal_compare_pci_addr(&dev->addr, addr))
			continue;

		ret = pci_detach_all_drivers(dev);
		if (ret < 0)
			goto err_return;

		TAILQ_REMOVE(&pci_device_list, dev, next);
		free(dev);
		return 0;
	}
	return -1;

err_return:
	RTE_LOG(WARNING, EAL, "Requested device " PCI_PRI_FMT
			" cannot be used\n", dev->addr.domain, dev->addr.bus,
			dev->addr.devid, dev->addr.function);
	return -1;
}

/*
 * Scan the content of the PCI bus, and call the probe() function for
 * all registered drivers that have a matching entry in its id_table
 * for discovered devices.
 */

/*******************************************************
  ������:		rte_eal_pci_probe
  ��������: 	pci�豸���
  ��������: 	
  ����ֵ:
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
int
rte_eal_pci_probe(void)
{
	struct rte_pci_device *dev = NULL;
	struct rte_devargs *devargs;
	int probe_all = 0;
	int ret = 0;

	/*������������ͳ�Ʊ����Ͳ�������*/
	if (rte_eal_devargs_type_count(RTE_DEVTYPE_WHITELISTED_PCI) == 0)
	{
		probe_all = 1;
	}
	
	/*����pci�豸��*/
	TAILQ_FOREACH(dev, &pci_device_list, next)
	{
		/* set devargs in PCI structure */

		/*�豸������ȡ*/
		devargs = pci_devargs_lookup(dev);
		if (devargs != NULL)
		{
			dev->device.devargs = devargs;
		}
		
		/* probe all or only whitelisted devices */
		/*������е��豸*/
		if (probe_all)
		{
			ret = pci_probe_all_drivers(dev);
		}
		else if (devargs != NULL 
			&& devargs->type == RTE_DEVTYPE_WHITELISTED_PCI)
		{
			ret = pci_probe_all_drivers(dev);
		}
		
		if (ret < 0)
		{
			rte_exit(EXIT_FAILURE, "Requested device " PCI_PRI_FMT " cannot be used\n", dev->addr.domain, dev->addr.bus, dev->addr.devid, dev->addr.function);
		}
	}

	return 0;
}

/* dump one device */
static int
pci_dump_one_device(FILE *f, struct rte_pci_device *dev)
{
	int i;

	fprintf(f, PCI_PRI_FMT, dev->addr.domain, dev->addr.bus,
	       dev->addr.devid, dev->addr.function);
	fprintf(f, " - vendor:%x device:%x\n", dev->id.vendor_id,
	       dev->id.device_id);

	for (i = 0; i != sizeof(dev->mem_resource) /
		sizeof(dev->mem_resource[0]); i++) {
		fprintf(f, "   %16.16"PRIx64" %16.16"PRIx64"\n",
			dev->mem_resource[i].phys_addr,
			dev->mem_resource[i].len);
	}
	return 0;
}

/* dump devices on the bus */
void
rte_eal_pci_dump(FILE *f)
{
	struct rte_pci_device *dev = NULL;

	TAILQ_FOREACH(dev, &pci_device_list, next) {
		pci_dump_one_device(f, dev);
	}
}

/* register a driver */
/*******************************************************************************
 �������� :  rte_eal_pci_register
 �������� :  pci����ע��ҵ�pci_driver_list pci��������probe������������
 ������� :  
 ������� :  ��
 ����ֵ�� :  ��
 --------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸����� :  
 �޸�Ŀ�� :  
 �޸����� :  
*******************************************************************************/
void
rte_eal_pci_register(struct rte_pci_driver *driver)
{
	TAILQ_INSERT_TAIL(&pci_driver_list, driver, next);
	rte_eal_driver_register(&driver->driver);
}

/* unregister a driver */
/*******************************************************************************
 �������� :  rte_eal_pci_unregister
 �������� :  ����ȡ��ע��
 ������� :  
 ������� :  ��
 ����ֵ�� :  ��
 --------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸����� :  
 �޸�Ŀ�� :  
 �޸����� :  
*******************************************************************************/
void
rte_eal_pci_unregister(struct rte_pci_driver *driver)
{
	rte_eal_driver_unregister(&driver->driver);
	TAILQ_REMOVE(&pci_driver_list, driver, next);
}
