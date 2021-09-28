/*-
 *   BSD LICENSE
 *
 *   Copyright 2014 6WIND S.A.
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
 *     * Neither the name of 6WIND S.A nor the names of its contributors
 *       may be used to endorse or promote products derived from this
 *       software without specific prior written permission.
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

/* This file manages the list of devices and their arguments, as given
 * by the user at startup
 *
 * Code here should not call rte_log since the EAL environment
 * may not be initialized.
 */

#include <stdio.h>
#include <string.h>

#include <rte_pci.h>
#include <rte_devargs.h>
#include "eal_private.h"

/** Global list of user devices */
/*全局设备参数链表，pci 虚拟地址*/
struct rte_devargs_list devargs_list = TAILQ_HEAD_INITIALIZER(devargs_list);

/*******************************************************
  函数名:		rte_eal_parse_devargs_str
  功能描述: 	参数解析
  参数描述:		devargs_str--参数字符串
  				drvname---解析出的设备名
  				drvargs---解析出的设备字符串
  返回值  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
int
rte_eal_parse_devargs_str(const char *devargs_str, char **drvname, char **drvargs)
{
	char *sep;

	if ((devargs_str) == NULL || (drvname) == NULL || (drvargs == NULL))
	{
		return -1;
	}

	/*地址赋值*/
	*drvname = strdup(devargs_str);
	if (*drvname == NULL)
	{
		return -1;
	}
	
	/* set the first ',' to '\0' to split name and arguments */
	/*获取参数中的name*/
	sep = strchr(*drvname, ',');
	if (sep != NULL)
	{
		sep[0] = '\0';
		*drvargs = strdup(sep + 1);
	}
	else
	{
		*drvargs = strdup("");
	}

	if (*drvargs == NULL) 
	{
		free(*drvname);
		return -1;
	}
	
	return 0;
}

/* store a whitelist parameter for later parsing */
/*******************************************************
  函数名:		rte_eal_devargs_add
  功能描述: 	参数解析
  参数描述: 	devtype---参数类型
  				devargs_str--参数字符串
  返回值  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
int
rte_eal_devargs_add(enum rte_devtype devtype, const char *devargs_str)
{
	struct rte_devargs *devargs = NULL;
	char *buf = NULL;
	int ret;

	/* use malloc instead of rte_malloc as it's called early at init */

	/*设备参数结构*/
	devargs = malloc(sizeof(*devargs));
	if (devargs == NULL)
	{
		goto fail;
	}
	memset(devargs, 0, sizeof(*devargs));
	
	devargs->type = devtype;


	/*解出pci参数字符串*/
	if (rte_eal_parse_devargs_str(devargs_str, &buf, &devargs->args))
	{
		goto fail;
	}
	
	switch (devargs->type)
	{
		case RTE_DEVTYPE_WHITELISTED_PCI:
		case RTE_DEVTYPE_BLACKLISTED_PCI:
		{
			/*解析pci地址,写入buf，寄存器*/
			/* try to parse pci identifier */
			if (eal_parse_pci_BDF(buf, &devargs->pci.addr) != 0
				&& eal_parse_pci_DomBDF(buf, &devargs->pci.addr) != 0)
			{
				goto fail;
			}

			break;
		}
		case RTE_DEVTYPE_VIRTUAL:
		{
			/*保存pci驱动的name*/
			/* save driver name */
			ret = snprintf(devargs->virt.drv_name, sizeof(devargs->virt.drv_name), "%s", buf);
			if (ret < 0 || ret >= (int)sizeof(devargs->virt.drv_name))
			{
				goto fail;
			}
			
			break;
		}
	}

	free(buf);

	/*参数链表挂链*/
	TAILQ_INSERT_TAIL(&devargs_list, devargs, next);

	return 0;

fail:

	free(buf);

	if (devargs)
	{
		free(devargs->args);
		free(devargs);
	}

	return -1;
}

/* count the number of devices of a specified type */

/*******************************************************
  函数名:		rte_eal_devargs_type_count
  功能描述: 	遍历参数链表，统计本类型参数个数
  参数描述: 	devtype---设备参数类型
  返回值:
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
unsigned int
rte_eal_devargs_type_count(enum rte_devtype devtype)
{
	struct rte_devargs *devargs;
	unsigned int count = 0;

	/*遍历参数链表，统计本类型参数个数*/
	TAILQ_FOREACH(devargs, &devargs_list, next) 
	{
		if (devargs->type != devtype)
		{
			continue;
		}
		
		count++;
	}
	
	return count;
}

/* dump the user devices on the console */
void
rte_eal_devargs_dump(FILE *f)
{
	struct rte_devargs *devargs;

	fprintf(f, "User device white list:\n");
	TAILQ_FOREACH(devargs, &devargs_list, next) {
		if (devargs->type == RTE_DEVTYPE_WHITELISTED_PCI)
			fprintf(f, "  PCI whitelist " PCI_PRI_FMT " %s\n",
			       devargs->pci.addr.domain,
			       devargs->pci.addr.bus,
			       devargs->pci.addr.devid,
			       devargs->pci.addr.function,
			       devargs->args);
		else if (devargs->type == RTE_DEVTYPE_BLACKLISTED_PCI)
			fprintf(f, "  PCI blacklist " PCI_PRI_FMT " %s\n",
			       devargs->pci.addr.domain,
			       devargs->pci.addr.bus,
			       devargs->pci.addr.devid,
			       devargs->pci.addr.function,
			       devargs->args);
		else if (devargs->type == RTE_DEVTYPE_VIRTUAL)
			fprintf(f, "  VIRTUAL %s %s\n",
			       devargs->virt.drv_name,
			       devargs->args);
		else
			fprintf(f, "  UNKNOWN %s\n", devargs->args);
	}
}
