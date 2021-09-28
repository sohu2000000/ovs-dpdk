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

#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <dirent.h>

#include <rte_log.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_common.h>
#include <rte_string_fns.h>
#include <rte_debug.h>

#include "eal_private.h"
#include "eal_filesystem.h"
#include "eal_thread.h"

#define SYS_CPU_DIR "/sys/devices/system/cpu/cpu%u"
#define CORE_ID_FILE "topology/core_id"
#define NUMA_NODE_PATH "/sys/devices/system/node"

/*******************************************************
  函数名:		eal_cpu_detected
  功能描述: 	CPU探测，作为设备文件来探测
  参数描述: 	
  返回值  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
/* Check if a cpu is present by the presence of the cpu information for it */
int
eal_cpu_detected(unsigned lcore_id)
{
	char path[PATH_MAX];
	/*/sys/devices/system/cpu/cpu0/topology/coreid文件能否被访问*/
	int len = snprintf(path, sizeof(path), SYS_CPU_DIR "/" CORE_ID_FILE, lcore_id);
	
	if (len <= 0 || (unsigned)len >= sizeof(path))
		return 0;

	/*文件是否可访问*/
	if (access(path, F_OK) != 0)
	{
		return 0;
	}
	
	return 1;
}

/*
 * Get CPU socket id (NUMA node) for a logical core.
 *
 * This searches each nodeX directories in /sys for the symlink for the given
 * lcore_id and returns the numa node where the lcore is found. If lcore is not
 * found on any numa node, returns zero.
 */

/*******************************************************
  函数名:		eal_cpu_socket_id
  功能描述: 	socket下的coreid是否可访问，可访问返回socketid，说明逻辑核属于本socket
  参数描述: 	lcore_id--逻辑核id
  返回值  :     socket 值
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
unsigned
eal_cpu_socket_id(unsigned lcore_id)
{
	unsigned socket;

	/*遍历8个socket节点,本节点下coreid是否可访问*/
	for (socket = 0; socket < RTE_MAX_NUMA_NODES; socket++) 
	{
		char path[PATH_MAX];

		/*/sys/devices/system/node/node0/cpu0*/
		snprintf(path, sizeof(path), "%s/node%u/cpu%u", NUMA_NODE_PATH, socket, lcore_id);
		if (access(path, F_OK) == 0)
		{
			return socket;
		}
	}
	return 0;
}

/* Get the cpu core id value from the /sys/.../cpuX core_id value */ 

/*******************************************************
  函数名:		eal_cpu_core_id
  功能描述: 	获取CPU核ID
  参数描述: 	lcore_id--逻辑核id
  返回值	  : 逻辑CPU id
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
unsigned
eal_cpu_core_id(unsigned lcore_id)
{
	char path[PATH_MAX];
	unsigned long id;
	
	/*/sys/devices/system/cpu/cpu0/topology/coreid文件能否被访问*/
	int len = snprintf(path, sizeof(path), SYS_CPU_DIR "/%s", lcore_id, CORE_ID_FILE);
	if (len <= 0 || (unsigned)len >= sizeof(path))
		goto err;

	/*打开core_id 文件获取逻辑CPU ID*/
	if (eal_parse_sysfs_value(path, &id) != 0)
	{
		goto err;
	}
	
	return (unsigned)id;

err:
	RTE_LOG(ERR, EAL, "Error reading core id value from %s "
			"for lcore %u - assuming core 0\n", SYS_CPU_DIR, lcore_id);
	return 0;
}
