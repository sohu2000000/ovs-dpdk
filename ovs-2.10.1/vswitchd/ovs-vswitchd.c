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

/*���⽻�����˳�����*/
struct ovs_vswitchd_exit_args 
{
    bool *exiting;
    bool *cleanup;
};

/*******************************************************************************
 ��������  :    ��������ʼ������
 ��������  :    ovs-vswitchd����
 �������  :    ovs-vswitchd 
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
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
int main(int argc, char *argv[])
{
	/*unixctl·��*/
    char *unixctl_path = NULL;

	/*unixctl����*/
    struct unixctl_server *unixctl;
	
    char *remote;
    bool exiting, cleanup;
    struct ovs_vswitchd_exit_args exit_args = {&exiting, &cleanup};
    int retval;

	/*���ó������ơ��汾���������ڵ���Ϣ*/
    set_program_name(argv[0]);

	/*�߳�id��ʼ��*/
    ovsthread_id_init();

	/*�պ���*/
    dns_resolve_init(true);

	/*���Ƴ�����Ĳ����б��µĴ洢�У���argvָ������ڴ棬
	��Ҫ��Ϊ�˺����proctitle_set()��������deamonize_start()->monitor_daemon()�е��ã�
	�����޸�ԭargv�洢����׼��*/
	ovs_cmdl_proctitle_init(argc, argv);

	/*ע��ص��ͷ�����������ֹ��ϴ���ʱ����������*/
	service_start(&argc, &argv);

	/*��������
	 1.unixctl_path�洢unixctrl���sock������Ϊ�����ⲿ���������������
	 2.��remote�洢���ӵ�ovsdb����Ϣ�������ӵ��������ݿ��sock��
    */
    
	/*ovs���������vswitchd��ovsdb-server��remote�������������̵�IPC�������̼�socketͨ�š�
	  remote��ʵ��һ��socket�ļ���ַ���� ovsdb-server����˰󶨼���ʱ��������������������socket��Ip+Port��ַ��
  	  remote��ʽ��unix:/usr/local/var/run/openvswitch/db.sock�����洴������ʱ��ʹ�á�
	*/
	remote = parse_options(argc, argv, &unixctl_path);

	/*����pipe���źŵĽ���*/
	fatal_ignore_sigpipe();

	/*�ý��̱�Ϊ�ػ�����*/
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

	/*����һ��unixctl server(���unixctl)��������unixctl_pathָ����unix·��,
	�����Ժ�ovs vswitch�Ĺ����ߣ���ofctl�����ӵķ����*/
    retval = unixctl_server_create(unixctl_path, &unixctl);
    if (retval) 
	{
        exit(EXIT_FAILURE);
    }

	/*ע��unixctl����*/
    unixctl_command_register("exit", "[--cleanup]", 0, 1, ovs_vswitchd_exit, &exit_args);

	/*��remote���ݿ��ȡ������Ϣ������ʼ��bridge��
	��ʼ������bridgeģ�ͣ�ͨ��remote��ַ������OVSDB����˻�ȡ������Ϣ��ʵ�����ų�ʼ�����ã�*/
    bridge_init(remote);
    free(remote);

    exiting = false;
    cleanup = false;

	/*1.������ʽ����״̬����Ҫ���ú���bridge_run()���������Ž����׶Σ���
	  2.����ᷴ��ѭ����ֱ��������Ҫֹͣʱ�����˳�ovs-vswitchd����ˣ����ݿ��и��»���������*/
	while (!exiting) 
	{
		/*�����ڴ���������ͻ��˵���memory_should_report()���˺����Լ���ģ��Ľӿڵ�ʣ�ಿ�֣�����һ���̵߳���*/
        memory_run();

		/*�����ڴ�ʹ����Ϣ*/
        if (memory_should_report())
		{
            struct simap usage;

            simap_init(&usage);
            bridge_get_memory_usage(&usage);
            memory_report(&usage);
            simap_destroy(&usage);
        }

		/*��Ҫ��������������������̡�������ɱ�Ҫ�����ø���
		  �����ø����л�����ݿ��ж�ȡ������Ϣ�����ɱ�Ҫ��bridge��dp�����ݽṹ*/


		/*1.��ʼ�����ݿ����Ѿ���������������
		  2.����bridge��Ӧof�㽻������ͨ��openflow�������ͨ��
		  3.����of�㽻����
		*/
        bridge_run();

		/*����/usr/local/var/run/openvswitch/ovs-vswitchd.pid.ctl ���ӷ��� ��������*/
        unixctl_server_run(unixctl);

		/*ִ����netdev_classes�϶����ÿ��netdev_classsʵ�壬�������ǵ�run()��������ں�ģ��openvswitch.ko�����ں��������������*/
		/*����netdev ִ��run*/
		netdev_run();

        memory_wait();
        bridge_wait();

        /*��poll_block��ȴ���Ϣ������Ϣ����*/
        unixctl_server_wait(unixctl);
        netdev_wait();

        /*������������vswitchd�˳�*/
		if (exiting) 
		{
            poll_immediate_wake();
        }

		//������ֱ��֮ǰ��poll_fd_wait()ע������¼����������ߵȴ�ʱ�䳬��
        poll_block();

        /*�˳�ѭ����ֻ��windows����*/
        if (should_service_stop()) 
		{
            exiting = true;
        }
    }
	
    bridge_exit(cleanup);

    /*�ͷ����� ����server*/
    unixctl_server_destroy(unixctl);
    service_stop();
    vlog_disable_async();
    ovsrcu_exit();
    dns_resolve_destroy();

    return 0;
}

/*******************************************************************************
 ��������  :    dpif_port_add
 ��������  :    vswitchd��������
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
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

	/*����ѡ��*/
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

    /*�������иĳɶ�������*/
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    /*ѭ���������*/
    for (;;) {
        int c;

        /*��ȡop*/
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

        /*unixctl ����*/
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
 ��������  :    dpif_port_add
 ��������  :    
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
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
 ��������  :    ovs_vswitchd_exit
 ��������  :    vswitchd�����˳�������
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static void
ovs_vswitchd_exit(struct unixctl_conn *conn, int argc,
                  const char *argv[], void *exit_args_)
{
    struct ovs_vswitchd_exit_args *exit_args = exit_args_;

     /*�����˳� vswitchd�˳�*/
    *exit_args->exiting = true;
    *exit_args->cleanup = argc == 2 && !strcmp(argv[1], "--cleanup");

    unixctl_command_reply(conn, NULL);
}
