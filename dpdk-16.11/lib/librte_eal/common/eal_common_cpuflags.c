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

#include <stdio.h>

#include <rte_common.h>
#include <rte_cpuflags.h>

/**
 * Checks if the machine is adequate for running the binary. If it is not, the
 * program exits with status 1.
 */
/*******************************************************
  函数名:		rte_cpu_check_supported
  功能描述: 	检查CPU是否支持
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
void
rte_cpu_check_supported(void)
{
	/* This is generated at compile-time by the build system */

	/*初始化CPU枚举值初始值*/
	static const enum rte_cpu_flag_t compile_time_flags[] = 
	{
		RTE_COMPILE_TIME_CPUFLAGS
	};

	/*计算枚举个数*/
	unsigned count = RTE_DIM(compile_time_flags), i;
	int ret;

	/*遍历个数*/
	for (i = 0; i < count; i++) 
	{
		/*获取枚举对应标记是否开启，不同架构值不同，即查看是否支持本CPU类型*/
		ret = rte_cpu_get_flag_enabled(compile_time_flags[i]);

		if (ret < 0)
		{
			fprintf(stderr,"ERROR: CPU feature flag lookup failed with error %d\n",ret);
			exit(1);
		}

		if (!ret)
		{
			fprintf(stderr,"ERROR: This system does not support \"%s\".\n"
				"Please check that RTE_MACHINE is set correctly.\n", rte_cpu_get_flag_name(compile_time_flags[i]));
			exit(1);
		}
	}
}
