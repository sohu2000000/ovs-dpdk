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
#include <rte_debug.h>

#include "eal_private.h"
#include "eal_thread.h"

/*
 * Parse /sys/devices/system/cpu to get the number of physical and logical
 * processors on the machine. The function will fill the cpu_info
 * structure.
 */
 /*******************************************************
  函数名:		rte_eal_cpu_init
  功能描述: 	CPU初始化，对文件的访问获取逻辑核ID和CPU 对应的socket id
  				逻辑核赋值socket
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
int rte_eal_cpu_init(void)
{
	/* pointer to global configuration */
	/*rte全局内存配置*/			/*&rte_config*/
	struct rte_config *config = rte_eal_get_configuration();
	unsigned lcore_id;
	unsigned count = 0;

	/*
	 * Parse the maximum set of logical cores, detect the subset of running
	 * ones and enable them by default.
	 */

	/*遍历128逻辑核，给可访问的逻辑核，分配socket*/
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) 
	{
		/*逻辑核索引，设置*/
		lcore_config[lcore_id].core_index = count;

		/* init cpuset for per lcore config */

		/*初始化逻辑核CPU集合*/
		CPU_ZERO(&lcore_config[lcore_id].cpuset);

		/* in 1:1 mapping, record related cpu detected state */

		/*逻辑核CPU是否能被访问,通过文件是否可访问，判断逻辑核是否被检测到*/
		lcore_config[lcore_id].detected = eal_cpu_detected(lcore_id);

		/*不可被访问*/
		if (lcore_config[lcore_id].detected == 0) 
		{
			config->lcore_role[lcore_id] = ROLE_OFF;
			lcore_config[lcore_id].core_index = -1;
			continue;
		}

		/* By default, lcore 1:1 map to cpu id */

		/*逻辑核lcore_id添加到CPU集*/
		/*设置本逻辑核的CPU亲和性*/
		CPU_SET(lcore_id, &lcore_config[lcore_id].cpuset);

		/* By default, each detected core is enabled */

		/*逻辑核*/
		config->lcore_role[lcore_id] = ROLE_RTE;

		/*从core_id 文件获取逻辑CPU id*/
		/*每个socket 一个内存节点, 每个CPU可对应多个socket*/
		lcore_config[lcore_id].core_id = eal_cpu_core_id(lcore_id);

		/*socket id*/
		/*socket下的coreid是否可访问，可访问返回socketid*/
		lcore_config[lcore_id].socket_id = eal_cpu_socket_id(lcore_id);

		/*socket id 非法*/
		if (lcore_config[lcore_id].socket_id >= RTE_MAX_NUMA_NODES)
		{
#ifdef RTE_EAL_ALLOW_INV_SOCKET_ID
			lcore_config[lcore_id].socket_id = 0;
#else
			rte_panic("Socket ID (%u) is greater than " "RTE_MAX_NUMA_NODES (%d)\n",
			lcore_config[lcore_id].socket_id, RTE_MAX_NUMA_NODES);
#endif
		}

		RTE_LOG(DEBUG, EAL, "Detected lcore %u as " "core %u on socket %u\n", lcore_id, lcore_config[lcore_id].core_id, lcore_config[lcore_id].socket_id);
		
		count++;
	}
	
	/* Set the count of enabled logical cores of the EAL configuration */

	/*逻辑核个数*/
	config->lcore_count = count;

	RTE_LOG(DEBUG, EAL,"Support maximum %u logical core(s) by configuration.\n", RTE_MAX_LCORE);
	RTE_LOG(INFO, EAL, "Detected %u lcore(s)\n", config->lcore_count);

	return 0;
}
