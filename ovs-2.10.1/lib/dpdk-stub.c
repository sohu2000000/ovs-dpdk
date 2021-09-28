/*
 * Copyright (c) 2014, 2015, 2016 Nicira, Inc.
 * Copyright (c) 2016 Red Hat, Inc.
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

#include <config.h>
#include "dpdk.h"

#include "smap.h"
#include "ovs-thread.h"
#include "openvswitch/vlog.h"
#include "vswitch-idl.h"

VLOG_DEFINE_THIS_MODULE(dpdk);

/*******************************************************************************
 函数名称  :    dpdk_init
 功能描述  :    dpdk init
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
void
dpdk_init(const struct smap *ovs_other_config)
{
    if (smap_get_bool(ovs_other_config, "dpdk-init", false)) {
        static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

        if (ovsthread_once_start(&once)) {
            VLOG_ERR("DPDK not supported in this copy of Open vSwitch.");
            ovsthread_once_done(&once);
        }
    }
}

void
dpdk_set_lcore_id(unsigned cpu OVS_UNUSED)
{
    /* Nothing */
}

const char *
dpdk_get_vhost_sock_dir(void)
{
    return NULL;
}

bool
dpdk_vhost_iommu_enabled(void)
{
    return false;
}

bool
dpdk_per_port_memory(void)
{
    return false;
}

void
print_dpdk_version(void)
{
}

void
dpdk_status(const struct ovsrec_open_vswitch *cfg)
{
    if (cfg) {
        ovsrec_open_vswitch_set_dpdk_initialized(cfg, false);
        ovsrec_open_vswitch_set_dpdk_version(cfg, "none");
    }
}
