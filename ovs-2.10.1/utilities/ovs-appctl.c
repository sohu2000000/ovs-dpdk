/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2014 Nicira, Inc.
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "command-line.h"
#include "daemon.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "jsonrpc.h"
#include "process.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"

static void usage(void);
static const char *parse_command_line(int argc, char *argv[]);
static struct jsonrpc *connect_to_target(const char *target);

/*******************************************************************************
 函数名称  :    main
 功能描述  :    ovs-appctl 接收参数，下发流表
 输入参数  :  	ovs-appctl dpctl/add-flow "..."
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
int
main(int argc, char *argv[])
{
    char *cmd_result, *cmd_error;

	/*rpc客户端*/
    struct jsonrpc *client;

	/*命令行和参数*/
    char *cmd, **cmd_argv;

	/*链接地址*/
    const char *target;

	/*参数个数*/
    int cmd_argc;
    int error;

	
	/*设置程序的name ovs-appctl*/
    set_program_name(argv[0]);

	/*没有指定target则默认为ovs-vswitchd*/
	/*解析命令行*/
    /* Parse command line and connect to target. */
    target = parse_command_line(argc, argv);

	/*起客户端，打开unix_socket文件，链接*/
    client = connect_to_target(target);

	/*ovs-appctl 后面的命令，指向dpcl/add-flow*/
    /* Transact request and process reply. */
    cmd = argv[optind++];

	/*剩余参数个数 dpcl/add-flow "flow"*/
    cmd_argc = argc - optind;

	/*偏移到剩余参数位置*/
    cmd_argv = cmd_argc ? argv + optind : NULL;

	/*unixctl传数据*/
	error = unixctl_client_transact(client, cmd, cmd_argc, cmd_argv, &cmd_result, &cmd_error);
    if (error) {
        ovs_fatal(error, "%s: transaction error", target);
    }

	/*下发失败，关掉rpc clinet*/
    if (cmd_error) {
        jsonrpc_close(client);
        fputs(cmd_error, stderr);
        ovs_error(0, "%s: server returned an error", target);
        exit(2);
    } else if (cmd_result) {
    	/*输出结果*/
        fputs(cmd_result, stdout);
    } else {
        OVS_NOT_REACHED();
    }

	/*关掉客户端*/
    jsonrpc_close(client);

	/*释放*/
    free(cmd_result);
    free(cmd_error);

	return 0;
}

static void
usage(void)
{
    printf("\
%s, for querying and controlling Open vSwitch daemon\n\
usage: %s [TARGET] COMMAND [ARG...]\n\
Targets:\n\
  -t, --target=TARGET  pidfile or socket to contact\n\
Common commands:\n\
  list-commands      List commands supported by the target\n\
  version            Print version of the target\n\
  vlog/list          List current logging levels\n\
  vlog/list-pattern  List logging patterns for each destination.\n\
  vlog/set [SPEC]\n\
      Set log levels as detailed in SPEC, which may include:\n\
      A valid module name (all modules, by default)\n\
      'syslog', 'console', 'file' (all destinations, by default))\n\
      'off', 'emer', 'err', 'warn', 'info', or 'dbg' ('dbg', bydefault)\n\
  vlog/reopen        Make the program reopen its log file\n\
Other options:\n\
  --timeout=SECS     wait at most SECS seconds for a response\n\
  -h, --help         Print this helpful information\n\
  -V, --version      Display ovs-appctl version information\n",
           program_name, program_name);
    exit(EXIT_SUCCESS);
}

/*******************************************************************************
 函数名称  :    parse_command_line
 功能描述  :    解析ovs-appctl 命令行
 输入参数  :  	argc---ovs-appctl 参数个数
 				argv---参数
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static const char *
parse_command_line(int argc, char *argv[])
{
    enum {
        OPT_START = UCHAR_MAX + 1,
        VLOG_OPTION_ENUMS
    };

	/**/
    static const struct option long_options[] = {
        {"target", required_argument, NULL, 't'},
        {"execute", no_argument, NULL, 'e'},
        {"help", no_argument, NULL, 'h'},
        {"option", no_argument, NULL, 'o'},
        {"version", no_argument, NULL, 'V'},
        {"timeout", required_argument, NULL, 'T'},
        VLOG_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
	
    char *short_options_ = ovs_cmdl_long_options_to_short_options(long_options);
    char *short_options = xasprintf("+%s", short_options_);
    const char *target;
    int e_options;

    target = NULL;
    e_options = 0;

	/*解析cmd*/
    for (;;) {
        int option;

		/*解析ovs-appctl*/
        option = getopt_long(argc, argv, short_options, long_options, NULL);
        if (option == -1) {
            break;
        }

		/*op*/
        switch (option) {
        case 't':
            if (target) {
                ovs_fatal(0, "-t or --target may be specified only once");
            }
            target = optarg;
            break;

        case 'e':
            /* We ignore -e for compatibility.  Older versions specified the
             * command as the argument to -e.  Since the current version takes
             * the command as non-option arguments and we say that -e has no
             * arguments, this just works in the common case. */
            if (e_options++) {
                ovs_fatal(0, "-e or --execute may be speciifed only once");
            }
            break;

        case 'h':
            usage();
            break;

        case 'o':
            ovs_cmdl_print_options(long_options);
            exit(EXIT_SUCCESS);

        case 'T':
            time_alarm(atoi(optarg));
            break;

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            OVS_NOT_REACHED();
        }
    }
    free(short_options_);
    free(short_options);

    if (optind >= argc) {
        ovs_fatal(0, "at least one non-option argument is required "
                  "(use --help for help)");
    }

	/*没有指定target则默认为ovs-vswitchd*/
    return target ? target : "ovs-vswitchd";
}

/*******************************************************************************
 函数名称  :    connect_to_target
 功能描述  :    链接到ovs-vswitchd
 输入参数  :  	target---链接目标，没有指定就是，ovs-vswitchd
 输出参数  :	
 返 回 值  : 	client---返回创建的链接
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static struct jsonrpc *
connect_to_target(const char *target)
{
	/*rpc结构*/
    struct jsonrpc *client;
    char *socket_name;
    int error;

/*ovs-appctl linux环境*/
#ifndef _WIN32
    if (target[0] != '/') {
        char *pidfile_name;
        pid_t pid;

		/*/var/run/openvswitch/ovs-vswitchd.pid 获取pid*/
        pidfile_name = xasprintf("%s/%s.pid", ovs_rundir(), target);
        pid = read_pidfile(pidfile_name);
        if (pid < 0) {
            ovs_fatal(-pid, "cannot read pidfile \"%s\"", pidfile_name);
        }
        free(pidfile_name);

		/*socketname /var/run/openvswitch/ovs-vswitchd.pid.ctl*/
        socket_name = xasprintf("%s/%s.%ld.ctl",
                                ovs_rundir(), target, (long int) pid);
#else
    /* On windows, if the 'target' contains ':', we make an assumption that
     * it is an absolute path. */
    if (!strchr(target, ':')) {
        socket_name = xasprintf("%s/%s.ctl", ovs_rundir(), target);
#endif
    }
	else {
		/*socket name*/

		/*没有指定target则默认为ovs-vswitchd*/
        socket_name = xstrdup(target);
    }

	/*创建rpc client*/
    error = unixctl_client_create(socket_name, &client);
    if (error) {
        ovs_fatal(error, "cannot connect to \"%s\"", socket_name);
    }

	/*释放socket*/	
    free(socket_name);

	/*返回客户端*/
    return client;
}

