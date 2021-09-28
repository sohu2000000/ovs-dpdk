/*
 * Copyright (c) 2014, 2015, 2016, 2017 Nicira, Inc.
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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>

#include <rte_errno.h>
#include <rte_log.h>
#include <rte_memzone.h>
#include <rte_version.h>
#ifdef DPDK_PDUMP
#include <rte_mempool.h>
#include <rte_pdump.h>
#endif

#include "dirs.h"
#include "fatal-signal.h"
#include "netdev-dpdk.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "ovs-numa.h"
#include "smap.h"
#include "vswitch-idl.h"

VLOG_DEFINE_THIS_MODULE(dpdk);

static FILE *log_stream = NULL;       /* Stream for DPDK log redirection */

static char *vhost_sock_dir = NULL;   /* Location of vhost-user sockets */
static bool vhost_iommu_enabled = false; /* Status of vHost IOMMU support */
static bool dpdk_initialized = false; /* Indicates successful initialization
                                       * of DPDK. */
static bool per_port_memory = false; /* Status of per port memory support */

static int
process_vhost_flags(char *flag, const char *default_val, int size,
                    const struct smap *ovs_other_config,
                    char **new_val)
{
    const char *val;
    int changed = 0;

    val = smap_get(ovs_other_config, flag);

    /* Process the vhost-sock-dir flag if it is provided, otherwise resort to
     * default value.
     */
    if (val && (strlen(val) <= size)) {
        changed = 1;
        *new_val = xstrdup(val);
        VLOG_INFO("User-provided %s in use: %s", flag, *new_val);
    } else {
        VLOG_INFO("No %s provided - defaulting to %s", flag, default_val);
        *new_val = xstrdup(default_val);
    }

    return changed;
}

static char **
grow_argv(char ***argv, size_t cur_siz, size_t grow_by)
{
    return xrealloc(*argv, sizeof(char *) * (cur_siz + grow_by));
}

static void
dpdk_option_extend(char ***argv, int argc, const char *option,
                   const char *value)
{
    char **newargv = grow_argv(argv, argc, 2);
    *argv = newargv;
    newargv[argc] = xstrdup(option);
    newargv[argc+1] = xstrdup(value);
}

static char **
move_argv(char ***argv, size_t cur_size, char **src_argv, size_t src_argc)
{
    char **newargv = grow_argv(argv, cur_size, src_argc);
    while (src_argc--) {
        newargv[cur_size+src_argc] = src_argv[src_argc];
        src_argv[src_argc] = NULL;
    }
    return newargv;
}

static int
extra_dpdk_args(const char *ovs_extra_config, char ***argv, int argc)
{
    int ret = argc;
    char *release_tok = xstrdup(ovs_extra_config);
    char *tok, *endptr = NULL;

    for (tok = strtok_r(release_tok, " ", &endptr); tok != NULL;
         tok = strtok_r(NULL, " ", &endptr)) {
        char **newarg = grow_argv(argv, ret, 1);
        *argv = newarg;
        newarg[ret++] = xstrdup(tok);
    }
    free(release_tok);
    return ret;
}

static bool
argv_contains(char **argv_haystack, const size_t argc_haystack,
              const char *needle)
{
    for (size_t i = 0; i < argc_haystack; ++i) {
        if (!strcmp(argv_haystack[i], needle))
            return true;
    }
    return false;
}

static int
construct_dpdk_options(const struct smap *ovs_other_config,
                       char ***argv, const int initial_size,
                       char **extra_args, const size_t extra_argc)
{
    struct dpdk_options_map {
        const char *ovs_configuration;
        const char *dpdk_option;
        bool default_enabled;
        const char *default_value;
    } opts[] = {
        {"dpdk-lcore-mask", "-c", false, NULL},
        {"dpdk-hugepage-dir", "--huge-dir", false, NULL},
    };

    int i, ret = initial_size;

    /*First, construct from the flat-options (non-mutex)*/
    for (i = 0; i < ARRAY_SIZE(opts); ++i) {
        const char *lookup = smap_get(ovs_other_config,
                                      opts[i].ovs_configuration);
        if (!lookup && opts[i].default_enabled) {
            lookup = opts[i].default_value;
        }

        if (lookup) {
            if (!argv_contains(extra_args, extra_argc, opts[i].dpdk_option)) {
                dpdk_option_extend(argv, ret, opts[i].dpdk_option, lookup);
                ret += 2;
            } else {
                VLOG_WARN("Ignoring database defined option '%s' due to "
                          "dpdk_extras config", opts[i].dpdk_option);
            }
        }
    }

    return ret;
}

/*******************************************************************************
 函数名称  :    construct_dpdk_socket_mem
 功能描述  :    配置默认的socket mem
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static char *
construct_dpdk_socket_mem(void)
{
    int numa;
    const char *def_value = "1024";

	/*2个node*/
    int numa_nodes = ovs_numa_get_n_numas();

    if (numa_nodes == 0 || numa_nodes == OVS_NUMA_UNSPEC) {
        numa_nodes = 1;
    }
    /* Allocate enough memory for digits, comma-sep and terminator. */
    char *dpdk_socket_mem = xzalloc(numa_nodes * (strlen(def_value) + 1));

	/*拼接*/
    strcat(dpdk_socket_mem, def_value);

	/*socket mem 配置成默认值1024*/
	for (numa = 1; numa < numa_nodes; ++numa) {
        strcat(dpdk_socket_mem, ",");
        strcat(dpdk_socket_mem, def_value);
    }

	/*配置字符串*/
    return dpdk_socket_mem;
}

#define MAX_DPDK_EXCL_OPTS 10

/*******************************************************************************
 函数名称  :    construct_dpdk_mutex_options
 功能描述  :    构造dpdk 互斥选项
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static int
construct_dpdk_mutex_options(const struct smap *ovs_other_config,
                             char ***argv, const int initial_size,
                             char **extra_args, const size_t extra_argc)
{
	/*默认2 个 socket mem 1024*/
    char *default_dpdk_socket_mem = construct_dpdk_socket_mem();
	
    struct dpdk_exclusive_options_map {
        const char *category;								/*类别*/
        const char *ovs_dpdk_options[MAX_DPDK_EXCL_OPTS];
        const char *eal_dpdk_options[MAX_DPDK_EXCL_OPTS];
        const char *default_value;							/*默认socket mem*/
        int default_option;									/*默认op 1*/
    } excl_opts[] = {
        {"memory type",
         {"dpdk-alloc-mem", "dpdk-socket-mem", NULL,},
         {"-m",             "--socket-mem",    NULL,},
         default_dpdk_socket_mem, 1
        },
    };

    int i, ret = initial_size;

	/*遍历参数*/
    for (i = 0; i < ARRAY_SIZE(excl_opts); ++i) 
	{
        int found_opts = 0, scan, found_pos = -1;
        const char *found_value;

		/*option map*/
        struct dpdk_exclusive_options_map *popt = &excl_opts[i];

		/*遍历option map  op参数存在*/
        for (scan = 0; scan < MAX_DPDK_EXCL_OPTS && popt->ovs_dpdk_options[scan]; ++scan) 
        {
        	/*查询配置在op选项中是否存在*/
            const char *lookup = smap_get(ovs_other_config,
                                          popt->ovs_dpdk_options[scan]);

			/*查到option*/
			if (lookup && strlen(lookup)) 
			{
                found_opts++;

				/*op位置*/
                found_pos = scan;

				/*查询结果*/
				found_value = lookup;
            }
        }

		/*op个数不为0*/
        if (!found_opts) 
		{
			/*使用默认op*/
            if (popt->default_option) 
			{
                found_pos = popt->default_option;
                found_value = popt->default_value;
            } 
			else 
			{
                continue;
            }
        }

		/*多重定义*/
        if (found_opts > 1) {
            VLOG_ERR("Multiple defined options for %s. Please check your"
                     " database settings and reconfigure if necessary.",
                     popt->category);
        }

		/*拓展参数包含 op*/
        if (!argv_contains(extra_args, extra_argc,
                           popt->eal_dpdk_options[found_pos])) {
            /*dpdk opt 拓展*/
            dpdk_option_extend(argv, ret, popt->eal_dpdk_options[found_pos],
                               found_value);
            ret += 2;
        } else {

			/*拓展参数不存在op中*/
            VLOG_WARN("Ignoring database defined option '%s' due to "
                      "dpdk_extras config", popt->eal_dpdk_options[found_pos]);
        }
    }

    free(default_dpdk_socket_mem);

    return ret;
}


/*******************************************************************************
 函数名称  :    get_dpdk_args
 功能描述  :    获取dpdk参数
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static int
get_dpdk_args(const struct smap *ovs_other_config, char ***argv,
              int argc)
{
    const char *extra_configuration;
    char **extra_args = NULL;
    int i;
    size_t extra_argc = 0;

	/*是否支持dpdk extra 参数*/
    extra_configuration = smap_get(ovs_other_config, "dpdk-extra");
    if (extra_configuration) {
        extra_argc = extra_dpdk_args(extra_configuration, &extra_args, 0);
    }

	/*构造dpdk op*/
    i = construct_dpdk_options(ovs_other_config, argv, argc, extra_args,
                               extra_argc);

	/*ovs参数解析*/
	i = construct_dpdk_mutex_options(ovs_other_config, argv, i, extra_args,
                                     extra_argc);

    if (extra_configuration) {
        *argv = move_argv(argv, i, extra_args, extra_argc);
    }

    return i + extra_argc;
}

static void
argv_release(char **dpdk_argv, char **dpdk_argv_release, size_t dpdk_argc)
{
    int result;
    for (result = 0; result < dpdk_argc; ++result) {
        free(dpdk_argv_release[result]);
    }

    free(dpdk_argv_release);
    free(dpdk_argv);
}

static ssize_t
dpdk_log_write(void *c OVS_UNUSED, const char *buf, size_t size)
{
    char *str = xmemdup0(buf, size);
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(600, 600);
    static struct vlog_rate_limit dbg_rl = VLOG_RATE_LIMIT_INIT(600, 600);

    switch (rte_log_cur_msg_loglevel()) {
        case RTE_LOG_DEBUG:
            VLOG_DBG_RL(&dbg_rl, "%s", str);
            break;
        case RTE_LOG_INFO:
        case RTE_LOG_NOTICE:
            VLOG_INFO_RL(&rl, "%s", str);
            break;
        case RTE_LOG_WARNING:
            VLOG_WARN_RL(&rl, "%s", str);
            break;
        case RTE_LOG_ERR:
            VLOG_ERR_RL(&rl, "%s", str);
            break;
        case RTE_LOG_CRIT:
        case RTE_LOG_ALERT:
        case RTE_LOG_EMERG:
            VLOG_EMER("%s", str);
            break;
        default:
            OVS_NOT_REACHED();
    }

    free(str);
    return size;
}

static cookie_io_functions_t dpdk_log_func = {
    .write = dpdk_log_write,
};

/*******************************************************************************
 函数名称  :    dpdk_init__
 功能描述  :    dpdk初始化
 			    1.eal 初始化
 			    2.设置cpu亲和性
 输入参数  :  	ovs_other_config---ovs的配置
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
dpdk_init__(const struct smap *ovs_other_config)
{
    char **argv = NULL, **argv_to_release = NULL;
    int result;
    int argc, argc_tmp;
	
	/*dpdk 逻辑核自动探测*/
    bool auto_determine = true;
    int err = 0;
    cpu_set_t cpuset;
    char *sock_dir_subcomponent;

	/*dpdk 日志流配置*/
    log_stream = fopencookie(NULL, "w+", dpdk_log_func);
    if (log_stream == NULL) {
        VLOG_ERR("Can't redirect DPDK log: %s.", ovs_strerror(errno));
    } else {
        setbuf(log_stream, NULL);
        rte_openlog_stream(log_stream);
    }

	/*解析vhost参数*/
    if (process_vhost_flags("vhost-sock-dir", ovs_rundir(),
                            NAME_MAX, ovs_other_config,
                            &sock_dir_subcomponent)) {
        struct stat s;
        if (!strstr(sock_dir_subcomponent, "..")) {
            vhost_sock_dir = xasprintf("%s/%s", ovs_rundir(),
                                       sock_dir_subcomponent);

            err = stat(vhost_sock_dir, &s);
            if (err) {
                VLOG_ERR("vhost-user sock directory '%s' does not exist.",
                         vhost_sock_dir);
            }
        } else {
            vhost_sock_dir = xstrdup(ovs_rundir());
            VLOG_ERR("vhost-user sock directory request '%s/%s' has invalid"
                     "characters '..' - using %s instead.",
                     ovs_rundir(), sock_dir_subcomponent, ovs_rundir());
        }
        free(sock_dir_subcomponent);
    } else {
        vhost_sock_dir = sock_dir_subcomponent;
    }

	/*是否支持iommu*/
    vhost_iommu_enabled = smap_get_bool(ovs_other_config,
                                        "vhost-iommu-support", false);
    VLOG_INFO("IOMMU support for vhost-user-client %s.",
               vhost_iommu_enabled ? "enabled" : "disabled");

	/*每port内存*/
    per_port_memory = smap_get_bool(ovs_other_config,
                                    "per-port-memory", false);

	VLOG_INFO("Per port memory for DPDK devices %s.",
              per_port_memory ? "enabled" : "disabled");

	/*参数*/
    argv = grow_argv(&argv, 0, 1);
    argc = 1;
    argv[0] = xstrdup(ovs_get_program_name());

	/*解析dpdk的参数*/
    argc_tmp = get_dpdk_args(ovs_other_config, &argv, argc);

	/**/
    while (argc_tmp != argc) 
	{
		/*配置了逻辑核*/
        if (!strcmp("-c", argv[argc]) || !strcmp("-l", argv[argc])) {
            auto_determine = false;
            break;
        }
        argc++;
    }
    argc = argc_tmp;

	/*探测dpdk 逻辑核*/
    /**
     * NOTE: This is an unsophisticated mechanism for determining the DPDK
     * lcore for the DPDK Master.
     */

	/*开启了dpdk逻辑核自动探测*/
    if (auto_determine) 
	{
        int i;

		/*获取主线程cpu 亲和性*/
        /* Get the main thread affinity */
        CPU_ZERO(&cpuset);
        err = pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t),
                                     &cpuset);
        if (!err) 
		{
			/*cpu亲和性*/
            for (i = 0; i < CPU_SETSIZE; i++) 
			{
                if (CPU_ISSET(i, &cpuset)) 
				{
                    argv = grow_argv(&argv, argc, 2);
                    argv[argc++] = xstrdup("-c");
                    argv[argc++] = xasprintf("0x%08llX", (1ULL<<i));
                    i = CPU_SETSIZE;
                }
            }
        } else {

			/*用户未设置亲和的逻辑核，使用默认值*/
            VLOG_ERR("Thread getaffinity error %d. Using core 0x1", err);
            /* User did not set dpdk-lcore-mask and unable to get current
             * thread affintity - default to core 0x1 */
            argv = grow_argv(&argv, argc, 2);
            argv[argc++] = xstrdup("-c");
            argv[argc++] = xasprintf("0x%X", 1);
        }
    }

    argv = grow_argv(&argv, argc, 1);
    argv[argc] = NULL;

    optind = 1;
		
	/*日志打开*/
    if (VLOG_IS_INFO_ENABLED()) 
	{
        struct ds eal_args;
        int opt;

		/*ds初始化*/
		ds_init(&eal_args);

		/*字符串拷贝*/
		ds_put_cstr(&eal_args, "EAL ARGS:");

		/*参数拷贝*/
		for (opt = 0; opt < argc; ++opt) {
            ds_put_cstr(&eal_args, " ");

			/*参数拷贝*/
            ds_put_cstr(&eal_args, argv[opt]);
        }
		
		/*打印日志*/
        VLOG_INFO("%s", ds_cstr_ro(&eal_args));
        ds_destroy(&eal_args);
    }

    argv_to_release = grow_argv(&argv_to_release, 0, argc);
    for (argc_tmp = 0; argc_tmp < argc; ++argc_tmp) {
        argv_to_release[argc_tmp] = argv[argc_tmp];
    }

    for(int zwl=0; zwl < argc; zwl++){
        VLOG_ERR("zwl %s argv[%d]=%s",__func__, zwl, argv[zwl]);
    }

	/*dpdk初始化*/
	/*dpdk init*/
    /* Make sure things are initialized ... */
    result = rte_eal_init(argc, argv);
    argv_release(argv, argv_to_release, argc);

	/*自动设置CPU的亲和性*/
    /* Set the main thread affinity back to pre rte_eal_init() value */
    if (auto_determine && !err) {
        err = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),
                                     &cpuset);
        if (err) {
            VLOG_ERR("Thread setaffinity error %d", err);
        }
    }

    if (result < 0) {
        VLOG_EMER("Unable to initialize DPDK: %s", ovs_strerror(rte_errno));
        return false;
    }

    rte_memzone_dump(stdout);

    /* We are called from the main thread here */
    RTE_PER_LCORE(_lcore_id) = NON_PMD_CORE_ID;

#ifdef DPDK_PDUMP
    VLOG_INFO("DPDK pdump packet capture enabled");
    err = rte_pdump_init(ovs_rundir());
    if (err) {
        VLOG_INFO("Error initialising DPDK pdump");
        rte_pdump_uninit();
    } else {
        char *server_socket_path;

        server_socket_path = xasprintf("%s/%s", ovs_rundir(),
                                       "pdump_server_socket");
        fatal_signal_add_file_to_unlink(server_socket_path);
        free(server_socket_path);
    }
#endif

	/*dpdk相关的类注册*/
    /* Finally, register the dpdk classes */
    netdev_dpdk_register();

    return true;
}

/*******************************************************************************
 函数名称  :    dpdk_init
 功能描述  :    dpdk初始化
 输入参数  :  	ovs_other_config---dpdk的配置
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
void
dpdk_init(const struct smap *ovs_other_config)
{
    static bool enabled = false;

    if (enabled || !ovs_other_config) 
	{
        return;
    }

	/*dpdk初始化参数*/
    const char *dpdk_init_val = smap_get_def(ovs_other_config, "dpdk-init", "false");

    bool try_only = !strcmp(dpdk_init_val, "try");

	/*try模式*/
	if (!strcmp(dpdk_init_val, "true") || try_only) 
	{
        static struct ovsthread_once once_enable = OVSTHREAD_ONCE_INITIALIZER;

        if (ovsthread_once_start(&once_enable)) 
		{
            VLOG_INFO("Using %s", rte_version());
            VLOG_INFO("DPDK Enabled - initializing...");

			/*dpdk初始化 根据ovs_other_config dpdk的配置*/
			enabled = dpdk_init__(ovs_other_config);
            if (enabled) 
			{
                VLOG_INFO("DPDK Enabled - initialized");
            } 
			else if (!try_only) 
			{
                ovs_abort(rte_errno, "Cannot init EAL");
            }
            ovsthread_once_done(&once_enable);
        } 
		else 
		{
            VLOG_ERR_ONCE("DPDK Initialization Failed.");
        }
    }
	else {
        VLOG_INFO_ONCE("DPDK Disabled - Use other_config:dpdk-init to enable");
    }

	/*dpdk初始化成功标记*/
    dpdk_initialized = enabled;
}

const char *
dpdk_get_vhost_sock_dir(void)
{
    return vhost_sock_dir;
}

bool
dpdk_vhost_iommu_enabled(void)
{
    return vhost_iommu_enabled;
}

bool
dpdk_per_port_memory(void)
{
    return per_port_memory;
}

/*******************************************************************************
 函数名称  :    dpdk_set_lcore_id
 功能描述  :    设置dpdk使用的逻辑核id，是之前为pmd分配的逻辑核id，根据pmd使用的逻辑核掩码
 输入参数  :    cpu---pmd线程配置的逻辑核ID
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
void dpdk_set_lcore_id(unsigned cpu)
{
    /* NON_PMD_CORE_ID is reserved for use by non pmd threads. */

	/*如果CPU用作非pmd线程报错*/
    ovs_assert(cpu != NON_PMD_CORE_ID);

	/*逻辑核CPU赋值给dpdk使用*/
    RTE_PER_LCORE(_lcore_id) = cpu;
}

void
print_dpdk_version(void)
{
    puts(rte_version());
}

void
dpdk_status(const struct ovsrec_open_vswitch *cfg)
{
    if (cfg) {
        ovsrec_open_vswitch_set_dpdk_initialized(cfg, dpdk_initialized);
        ovsrec_open_vswitch_set_dpdk_version(cfg, rte_version());
    }
}
