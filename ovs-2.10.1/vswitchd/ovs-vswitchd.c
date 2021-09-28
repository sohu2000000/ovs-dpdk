/* Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
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

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_MLOCKALL
#include <sys/mman.h>
#endif

#include "bridge.h"
#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "dirs.h"
#include "dpif.h"
#include "dummy.h"
#include "fatal-signal.h"
#include "memory.h"
#include "netdev.h"
#include "openflow/openflow.h"
#include "ovsdb-idl.h"
#include "ovs-rcu.h"
#include "ovs-router.h"
#include "ovs-thread.h"
#include "openvswitch/poll-loop.h"
#include "simap.h"
#include "stream-ssl.h"
#include "stream.h"
#include "svec.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "lib/vswitch-idl.h"
#include "lib/dns-resolve.h"

VLOG_DEFINE_THIS_MODULE(vswitchd);

/* --mlockall: If set, locks all process memory into physical RAM, preventing
 * the kernel from paging any of its memory to disk. */
static bool want_mlockall;

static unixctl_cb_func ovs_vswitchd_exit;

static char *parse_options(int argc, char *argv[], char **unixctl_path);
OVS_NO_RETURN static void usage(void);

/*虚拟交换机退出参数*/
struct ovs_vswitchd_exit_args 
{
    bool *exiting;
    bool *cleanup;
};

/*******************************************************************************
 函数名称  :    交换机初始化流程
 功能描述  :    ovs-vswitchd进程
 输入参数  :    ovs-vswitchd 
                unix:/var/run/openvswitch/db.sock 
                -vconsole:emer 
                -vsyslog:err 
                -vfile:info 
                --mlockall 
                --disable-system 
                --no-chdir 
                --log-file=/var/log/openvswitch/ovs-vswitchd.log 
                --pidfile=/var/run/openvswitch/ovs-vswitchd.pid 
                --detach --monitor
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
int main(int argc, char *argv[])
{
	/*unixctl路径*/
    char *unixctl_path = NULL;

	/*unixctl服务*/
    struct unixctl_server *unixctl;
	
    char *remote;
    bool exiting, cleanup;
    struct ovs_vswitchd_exit_args exit_args = {&exiting, &cleanup};
    int retval;

	/*设置程序名称、版本、编译日期等信息*/
    set_program_name(argv[0]);

	/*线程id初始化*/
    ovsthread_id_init();

	/*空函数*/
    dns_resolve_init(true);

	/*复制出输入的参数列表到新的存储中，让argv指向这块内存，
	主要是为了后面的proctitle_set()函数（在deamonize_start()->monitor_daemon()中调用，
	可能修改原argv存储）做准备*/
	ovs_cmdl_proctitle_init(argc, argv);

	/*注册回调和服务管理器出现故障错误时操作的配置*/
	service_start(&argc, &argv);

	/*解析参数
	 1.unixctl_path存储unixctrl域的sock名，作为接收外部控制命令的渠道；
	 2.而remote存储连接到ovsdb的信息，即连接到配置数据库的sock名
    */
    
	/*ovs有两大进程vswitchd和ovsdb-server，remote用于这两个进程的IPC，即进程间socket通信。
	  remote其实是一个socket文件地址，由 ovsdb-server服务端绑定监听时产生，作用类似于网络socket的Ip+Port地址，
  	  remote格式如unix:/usr/local/var/run/openvswitch/db.sock。后面创建网桥时会使用。
	*/
	remote = parse_options(argc, argv, &unixctl_path);

	/*忽略pipe读信号的结束*/
	fatal_ignore_sigpipe();

	/*让进程变为守护程序*/
    daemonize_start(true);

    if (want_mlockall) 
	{
#ifdef HAVE_MLOCKALL
        if (mlockall(MCL_CURRENT | MCL_FUTURE)) 
		{
            VLOG_ERR("mlockall failed: %s", ovs_strerror(errno));
        }
#else
        VLOG_ERR("mlockall not supported on this system");
#endif
    }

	/*创建一个unixctl server(存放unixctl)，并监听unixctl_path指定的unix路径,
	用于以后ovs vswitch的管理工具，如ofctl等连接的服务端*/
    retval = unixctl_server_create(unixctl_path, &unixctl);
    if (retval) 
	{
        exit(EXIT_FAILURE);
    }

	/*注册unixctl命令*/
    unixctl_command_register("exit", "[--cleanup]", 0, 1, ovs_vswitchd_exit, &exit_args);

	/*从remote数据库获取配置信息，并初始化bridge，
	初始化网桥bridge模型，通过remote地址，来从OVSDB服务端获取配置信息来实现网桥初始化配置：*/
    bridge_init(remote);
    free(remote);

    exiting = false;
    cleanup = false;

	/*1.进入正式工作状态（主要调用函数bridge_run()，进入网桥建立阶段）。
	  2.这里会反复循环，直到服务需要停止时，才退出ovs-vswitchd服务端，数据库有更新会立即处理*/
	while (!exiting) 
	{
		/*运行内存监视器，客户端调用memory_should_report()。此函数以及该模块的接口的剩余部分，仅被一个线程调用*/
        memory_run();

		/*报告内存使用信息*/
        if (memory_should_report())
		{
            struct simap usage;

            simap_init(&usage);
            bridge_get_memory_usage(&usage);
            memory_report(&usage);
            simap_destroy(&usage);
        }

		/*主要对网包进行完整处理过程。包括完成必要的配置更新
		  在配置更新中会从数据库中读取配置信息，生成必要的bridge和dp等数据结构*/


		/*1.初始化数据库中已经创建的虚拟网桥
		  2.创建bridge对应of层交换机，通过openflow与控制器通信
		  3.启动of层交换机
		*/
        bridge_run();

		/*启动/usr/local/var/run/openvswitch/ovs-vswitchd.pid.ctl 链接服务 处理链接*/
        unixctl_server_run(unixctl);

		/*执行在netdev_classes上定义的每个netdev_classs实体，调用他们的run()，会调用内核模块openvswitch.ko，在内核中添加虚拟网卡*/
		/*遍历netdev 执行run*/
		netdev_run();

        memory_wait();
        bridge_wait();

        /*在poll_block后等待消息，有消息则唤醒*/
        unixctl_server_wait(unixctl);
        netdev_wait();

        /*命令行设置了vswitchd退出*/
		if (exiting) 
		{
            poll_immediate_wake();
        }

		//阻塞，直到之前被poll_fd_wait()注册过的事件发生，或者等待时间超过
        poll_block();

        /*退出循环，只有windows在用*/
        if (should_service_stop()) 
		{
            exiting = true;
        }
    }
	
    bridge_exit(cleanup);

    /*释放链接 销毁server*/
    unixctl_server_destroy(unixctl);
    service_stop();
    vlog_disable_async();
    ovsrcu_exit();
    dns_resolve_destroy();

    return 0;
}

/*******************************************************************************
 函数名称  :    dpif_port_add
 功能描述  :    vswitchd的命令行
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
static char *
parse_options(int argc, char *argv[], char **unixctl_pathp)
{
    enum {
        OPT_PEER_CA_CERT = UCHAR_MAX + 1,
        OPT_MLOCKALL,
        OPT_UNIXCTL,
        VLOG_OPTION_ENUMS,
        OPT_BOOTSTRAP_CA_CERT,
        OPT_ENABLE_DUMMY,
        OPT_DISABLE_SYSTEM,
        DAEMON_OPTION_ENUMS,
        OPT_DPDK,
        SSL_OPTION_ENUMS,
        OPT_DUMMY_NUMA,
    };

	/*参数选项*/
    static const struct option long_options[] = {
        {"help",        no_argument, NULL, 'h'},
        {"version",     no_argument, NULL, 'V'},
        {"mlockall",    no_argument, NULL, OPT_MLOCKALL},
        {"unixctl",     required_argument, NULL, OPT_UNIXCTL},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {"peer-ca-cert", required_argument, NULL, OPT_PEER_CA_CERT},
        {"bootstrap-ca-cert", required_argument, NULL, OPT_BOOTSTRAP_CA_CERT},
        {"enable-dummy", optional_argument, NULL, OPT_ENABLE_DUMMY},
        {"disable-system", no_argument, NULL, OPT_DISABLE_SYSTEM},
        {"dpdk", optional_argument, NULL, OPT_DPDK},
        {"dummy-numa", required_argument, NULL, OPT_DUMMY_NUMA},
        {NULL, 0, NULL, 0},
    };

    /*长命令行改成短命令行*/
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    /*循环处理参数*/
    for (;;) {
        int c;

        /*获取op*/
        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case 'V':
            ovs_print_version(0, 0);
            print_dpdk_version();
            exit(EXIT_SUCCESS);

        case OPT_MLOCKALL:
            want_mlockall = true;
            break;

        /*unixctl 参数*/
        case OPT_UNIXCTL:
            *unixctl_pathp = optarg;
            break;

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS
        STREAM_SSL_OPTION_HANDLERS

        case OPT_PEER_CA_CERT:
            stream_ssl_set_peer_ca_cert_file(optarg);
            break;

        case OPT_BOOTSTRAP_CA_CERT:
            stream_ssl_set_ca_cert_file(optarg, true);
            break;

        case OPT_ENABLE_DUMMY:
            dummy_enable(optarg);
            break;

        case OPT_DISABLE_SYSTEM:
            dp_blacklist_provider("system");
            ovs_router_disable_system_routing_table();
            break;

        case '?':
            exit(EXIT_FAILURE);

        case OPT_DPDK:
            ovs_fatal(0, "Using --dpdk to configure DPDK is not supported.");
            break;

        case OPT_DUMMY_NUMA:
            ovs_numa_set_dummy(optarg);
            break;

        default:
            abort();
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;

    switch (argc) {
    case 0:
        return xasprintf("unix:%s/db.sock", ovs_rundir());

    case 1:
        return xstrdup(argv[0]);

    default:
        VLOG_FATAL("at most one non-option argument accepted; "
                   "use --help for usage");
    }
}

/*******************************************************************************
 函数名称  :    dpif_port_add
 功能描述  :    
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
static void
usage(void)
{
    printf("%s: Open vSwitch daemon\n"
           "usage: %s [OPTIONS] [DATABASE]\n"
           "where DATABASE is a socket on which ovsdb-server is listening\n"
           "      (default: \"unix:%s/db.sock\").\n",
           program_name, program_name, ovs_rundir());
    stream_usage("DATABASE", true, false, true);
    daemon_usage();
    vlog_usage();
    printf("\nDPDK options:\n"
           "Configuration of DPDK via command-line is removed from this\n"
           "version of Open vSwitch. DPDK is configured through ovsdb.\n"
          );
    printf("\nOther options:\n"
           "  --unixctl=SOCKET          override default control socket name\n"
           "  -h, --help                display this help message\n"
           "  -V, --version             display version information\n");
    exit(EXIT_SUCCESS);
}

/*******************************************************************************
 函数名称  :    ovs_vswitchd_exit
 功能描述  :    vswitchd主动退出命令行
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static void
ovs_vswitchd_exit(struct unixctl_conn *conn, int argc,
                  const char *argv[], void *exit_args_)
{
    struct ovs_vswitchd_exit_args *exit_args = exit_args_;

     /*设置退出 vswitchd退出*/
    *exit_args->exiting = true;
    *exit_args->cleanup = argc == 2 && !strcmp(argv[1], "--cleanup");

    unixctl_command_reply(conn, NULL);
}
