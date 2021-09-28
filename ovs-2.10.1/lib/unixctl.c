/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2016 Nicira, Inc.
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
#include "unixctl.h"
#include <errno.h>
#include <unistd.h>
#include "coverage.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "jsonrpc.h"
#include "openvswitch/list.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/shash.h"
#include "stream.h"
#include "stream-provider.h"
#include "svec.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(unixctl);

COVERAGE_DEFINE(unixctl_received);
COVERAGE_DEFINE(unixctl_replied);

/*unixctl的命令行*/
struct unixctl_command {
    const char *usage;						/*用法*/
    int min_args, max_args;					/*最新*/
    unixctl_cb_func *cb;					/*命令的回调*/
    void *aux;								/*unix命令行回调函数*/
};


/*unixctl的链接*/
struct unixctl_conn {
    struct ovs_list node;					/*链表头*/
    struct jsonrpc *rpc;					/*链接使用的jrpc结构*/

    /* Only one request can be in progress at a time.  While the request is
     * being processed, 'request_id' is populated, otherwise it is null. */
    struct json *request_id;   /* ID of the currently active request. */			/*当前活跃的rpc请求的id*/
};

/*unixctl 服务端*/
/* Server for control connection. */
struct unixctl_server {
    struct pstream *listener;				/*流数据监听listener*/
    struct ovs_list conns;					/*监听到的链接*/
    char *path;								/*unix socket路径*/
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);


/*走unixctl的命令行全都添加到这里， 全局命令hash，命令行添加到这个全局变量里*/
static struct shash commands = SHASH_INITIALIZER(&commands);


/*******************************************************************************
 函数名称  :    unixctl_list_commands
 功能描述  :    命令行list
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
unixctl_list_commands(struct unixctl_conn *conn, int argc OVS_UNUSED,
                      const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    const struct shash_node **nodes = shash_sort(&commands);
    size_t i;

    ds_put_cstr(&ds, "The available commands are:\n");

	/*命令*/
    for (i = 0; i < shash_count(&commands); i++) {
        const struct shash_node *node = nodes[i];
        const struct unixctl_command *command = node->data;

        ds_put_format(&ds, "  %-23s %s\n", node->name, command->usage);
    }
    free(nodes);

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

/*******************************************************************************
 函数名称  :    unixctl_version
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
unixctl_version(struct unixctl_conn *conn, int argc OVS_UNUSED,
                const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    unixctl_command_reply(conn, ovs_get_program_version());
}


/*******************************************************************************
 函数名称  :    unixctl_command_register
 功能描述  :    注册命令
 输入参数  :  	cb---命令解析回调函数
 				aux---命令行回调函数
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Registers a unixctl command with the given 'name'.  'usage' describes the
 * arguments to the command; it is used only for presentation to the user in
 * "list-commands" output.
 *
 * 'cb' is called when the command is received.  It is passed an array
 * containing the command name and arguments, plus a copy of 'aux'.  Normally
 * 'cb' should reply by calling unixctl_command_reply() or
 * unixctl_command_reply_error() before it returns, but if the command cannot
 * be handled immediately then it can defer the reply until later.  A given
 * connection can only process a single request at a time, so a reply must be
 * made eventually to avoid blocking that connection. */
void
unixctl_command_register(const char *name, const char *usage,
                         int min_args, int max_args,
                         unixctl_cb_func *cb, void *aux)
{
    struct unixctl_command *command;
    struct unixctl_command *lookup = shash_find_data(&commands, name);

    ovs_assert(!lookup || lookup->cb == cb);

    if (lookup) {
        return;
    }

    command = xmalloc(sizeof *command);
    command->usage = usage;
    command->min_args = min_args;
    command->max_args = max_args;
    command->cb = cb;
    command->aux = aux;


	/*注册的命令添加到全局command函数里*/
    shash_add(&commands, name, command);
}

/*******************************************************************************
 函数名称  :    unixctl_command_reply__
 功能描述  :    回应链接
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
unixctl_command_reply__(struct unixctl_conn *conn,
                        bool success, const char *body)
{
    struct json *body_json;
    struct jsonrpc_msg *reply;

    COVERAGE_INC(unixctl_replied);
    ovs_assert(conn->request_id);

    if (!body) {
        body = "";
    }

	/*没有换行符，给填换行符在结尾*/
    if (body[0] && body[strlen(body) - 1] != '\n') {
        body_json = json_string_create_nocopy(xasprintf("%s\n", body));
    } else {
    
    	/*有换行符直接jason string*/
        body_json = json_string_create(body);
    }

    if (success) {
        reply = jsonrpc_create_reply(body_json, conn->request_id);
    } else {
        reply = jsonrpc_create_error(body_json, conn->request_id);
    }

    if (VLOG_IS_DBG_ENABLED()) {
        char *id = json_to_string(conn->request_id, 0);
        VLOG_DBG("replying with %s, id=%s: \"%s\"",
                 success ? "success" : "error", id, body);
        free(id);
    }

    /* If jsonrpc_send() returns an error, the run loop will take care of the
     * problem eventually. */
    jsonrpc_send(conn->rpc, reply);
    json_destroy(conn->request_id);
    conn->request_id = NULL;
}

/*******************************************************************************
 函数名称  :    unixctl_command_reply
 功能描述  :    回应链接
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
/* Replies to the active unixctl connection 'conn'.  'result' is sent to the
 * client indicating the command was processed successfully.  Only one call to
 * unixctl_command_reply() or unixctl_command_reply_error() may be made per
 * request. */
void
unixctl_command_reply(struct unixctl_conn *conn, const char *result)
{
    unixctl_command_reply__(conn, true, result);
}

/*******************************************************************************
 函数名称  :    unixctl_command_reply_error
 功能描述  :    回应消息
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
/* Replies to the active unixctl connection 'conn'. 'error' is sent to the
 * client indicating an error occurred processing the command.  Only one call to
 * unixctl_command_reply() or unixctl_command_reply_error() may be made per
 * request. */
void
unixctl_command_reply_error(struct unixctl_conn *conn, const char *error)
{
    unixctl_command_reply__(conn, false, error);
}

/* Creates a unixctl server listening on 'path', which for POSIX may be:
 *
 *      - NULL, in which case <rundir>/<program>.<pid>.ctl is used.
 *
 *      - A name that does not start with '/', in which case it is put in
 *        <rundir>.
 *
 *      - An absolute path (starting with '/') that gives the exact name of
 *        the Unix domain socket to listen on.
 *
 * For Windows, a local named pipe is used. A file is created in 'path'
 * which may be:
 *
 *      - NULL, in which case <rundir>/<program>.ctl is used.
 *
 *      - An absolute path that gives the name of the file.
 *
 * For both POSIX and Windows, if the path is "none", the function will
 * return successfully but no socket will actually be created.
 *
 * A program that (optionally) daemonizes itself should call this function
 * *after* daemonization, so that the socket name contains the pid of the
 * daemon instead of the pid of the program that exited.  (Otherwise,
 * "ovs-appctl --target=<program>" will fail.)
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * sets '*serverp' to the new unixctl_server (or to NULL if 'path' was "none"),
 * otherwise to NULL. */


/*******************************************************************************
 函数名称  :    dpif_port_add
 功能描述  :    创建一个unixctl_server(存放在unixctl)，并监听在unixctl_path指定的punix路径，该路径作为ovs-appctl发送命令给ovsd的通道
 输入参数  :  	path---监听的路径，如果传null，使用默认路径
 				serverp---unixctl服务
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
unixctl_server_create(const char *path, struct unixctl_server **serverp)
{
    *serverp = NULL;
    if (path && !strcmp(path, "none")) {
        return 0;
    }

#ifdef _WIN32
    enum { WINDOWS = 1 };
#else
    enum { WINDOWS = 0 };
#endif

	/*获取进程id*/
    long int pid = getpid();

	/*/var/run/openvswitch/ovs-vswitchd.pid.ctl*/
    char *abs_path
        = (path ? abs_file_name(ovs_rundir(), path)
           : WINDOWS ? xasprintf("%s/%s.ctl", ovs_rundir(), program_name)
           : xasprintf("%s/%s.%ld.ctl", ovs_rundir(), program_name, pid));

    struct pstream *listener;

	/*punix:/usr/local/var/run/openvswitch/ovs-vswitchd.pid.ctl*/
	char *punix_path = xasprintf("punix:%s", abs_path);

	/*打开一个listener，这个unix路径打开一个监听链接的listener*/
    int error = pstream_open(punix_path, &listener, 0);

	free(punix_path);

    if (error) {
        ovs_error(error, "%s: could not initialize control socket", abs_path);
        free(abs_path);
        return error;
    }

    /*注册命令行*/
    unixctl_command_register("list-commands", "", 0, 0, unixctl_list_commands,
                             NULL);

    /*注册查看version*/
    unixctl_command_register("version", "", 0, 0, unixctl_version, NULL);

	/*创建unixctl 服务*/
    struct unixctl_server *server = xmalloc(sizeof *server);

	server->listener = listener;

	/*监听的路径/var/run/openvswitch/ovs-vswitchd.pid.ctl*/
    server->path = abs_path;

	/*支持的链接链表初始化*/
    ovs_list_init(&server->conns);

	*serverp = server;

	return 0;
}

/*******************************************************************************
 函数名称  :    process_command
 功能描述  :    解析命令
 输入参数  :  	conn---unixctl的链接
 				request---rpc请求消息
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
process_command(struct unixctl_conn *conn, struct jsonrpc_msg *request)
{
    char *error = NULL;

	/*命令行*/
    struct unixctl_command *command;

	/*jason参数*/
    struct json_array *params;

    COVERAGE_INC(unixctl_received);

	/*rpc 请求消息的id*/
	conn->request_id = json_clone(request->id);

	/*开启了debug*/
    if (VLOG_IS_DBG_ENABLED()) 
	{
        char *params_s = json_to_string(request->params, 0);
        char *id_s = json_to_string(request->id, 0);
        VLOG_DBG("received request %s%s, id=%s",
                 request->method, params_s, id_s);
        free(params_s);
        free(id_s);
    }

	/*解析出string jason*/
    params = json_array(request->params);

	/*rpc请求的命令*/
	command = shash_find_data(&commands, request->method);
    if (!command) {
        error = xasprintf("\"%s\" is not a valid command (use "
                          "\"list-commands\" to see a list of valid commands)",
                          request->method);
    } else if (params->n < command->min_args) {
        error = xasprintf("\"%s\" command requires at least %d arguments",
                          request->method, command->min_args);
    } else if (params->n > command->max_args) {
        error = xasprintf("\"%s\" command takes at most %d arguments",
                          request->method, command->max_args);
    } else {
        struct svec argv = SVEC_EMPTY_INITIALIZER;
        int  i;


		/*method 填入argv "dpctl/add-flow"*/
        svec_add(&argv, request->method);

		/*根据参数的个数填入 "match" "action" */
		for (i = 0; i < params->n; i++) {
            if (params->elems[i]->type != JSON_STRING) {
                error = xasprintf("\"%s\" command has non-string argument",
                                  request->method);
                break;
            }

			/*jason填入argv*/
            svec_add(&argv, json_string(params->elems[i]));
        }
        svec_terminate(&argv);

        if (!error) {

			/*执行命令行解析回调 dpctl的调用 dpctl_unixctl_handler*/
            command->cb(conn, argv.n, (const char **) argv.names,
                        command->aux);
        }

        svec_destroy(&argv);
    }

	/*报错回复错误信息*/
    if (error) {
        unixctl_command_reply_error(conn, error);
        free(error);
    }
}

/*******************************************************************************
 函数名称  :    run_connection
 功能描述  :    conn---建立的链接
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
static int
run_connection(struct unixctl_conn *conn)
{
    int error, i;

	/*rpc上有消息，先发出去，主要是回复客户端的*/
    jsonrpc_run(conn->rpc);

	/*获取rpc的状态*/
	error = jsonrpc_get_status(conn->rpc);

	/*rpc的状态，是否已经填满*/
    if (error || jsonrpc_get_backlog(conn->rpc)) {
        return error;
    }

	/*每个conn遍历10 次，最大同时接10条消息，串行*/
    for (i = 0; i < 10; i++) 
	{
        struct jsonrpc_msg *msg;

		/*链接请求的id*/
        if (error || conn->request_id) {
            break;
        }

		/*rpc收消息，从stream接收，还原成msg*/
        jsonrpc_recv(conn->rpc, &msg);
        if (msg) {

			/*rpc请求消息处理，调用回调函数*/
            if (msg->type == JSONRPC_REQUEST) {

if (msg->type == JSONRPC_REQUEST && !strcmp(msg->method, "echo")) {
	  /* Echo request.	Send reply. */
	  struct jsonrpc_msg *reply;

	  /*回reply*/
	  reply = jsonrpc_create_reply(json_clone(msg->params), msg->id);

	  /*直接发了出去*/
	  jsonrpc_session_send(s, reply);
  }

#ifdef zwl
				/*判断为探测消息*/
		        if (!strcmp(msg->method, "echo")) {
					
				    /*开启了debug*/
				    if (VLOG_IS_DBG_ENABLED()) 
					{
				        char *params_s = json_to_string(msg->params, 0);
				        char *id_s = json_to_string(msg->id, 0);
				        VLOG_DBG("received request %s%s, id=%s",
				                 msg->method, params_s, id_s);
				        free(params_s);
				        free(id_s);
				    }

					COVERAGE_INC(unixctl_received);
					
					/*rpc 请求消息的id*/
					conn->request_id = json_clone(msg->id);
					unixctl_command_reply(conn, json_clone(msg->params));					
				}else{
#endif	
					process_command(conn, msg);
				}
		
            } else {
                VLOG_WARN_RL(&rl, "%s: received unexpected %s message",
                             jsonrpc_get_name(conn->rpc),
                             jsonrpc_msg_type_to_string(msg->type));
                error = EINVAL;
            }

			/*destroy掉*/
            jsonrpc_msg_destroy(msg);
        }

		/*获取conn的状态*/
        error = error ? error : jsonrpc_get_status(conn->rpc);
    }

    return error;
}

/*******************************************************************************
 函数名称  :    kill_connection
 功能描述  :    杀死链接
 输入参数  :  	conn---
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
kill_connection(struct unixctl_conn *conn)
{
    ovs_list_remove(&conn->node);
    jsonrpc_close(conn->rpc);
    json_destroy(conn->request_id);
    free(conn);
}

/*******************************************************************************
 函数名称  :    unixctl_server_run
 功能描述  :    启动unixctl服务
 输入参数  :  	server---对unix路径创建的server
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
unixctl_server_run(struct unixctl_server *server)
{
	/*server存在*/
    if (!server) {
        return;
    }
	
	VLOG_WARN_RL("zwl unixctl_server_run");

	/*每次循环10次去accept链接请求，最大同时接收10个链接*/
    for (int i = 0; i < 10; i++) 
	{
		/*数据流*/
		struct stream *stream;
        int error;

		/*调用的消极接口，接收流的请求*/
        error = pstream_accept(server->listener, &stream);
        if (!error) {

			/*申请一个链接*/
            struct unixctl_conn *conn = xzalloc(sizeof *conn);

			/*挂链到server*/
			ovs_list_push_back(&server->conns, &conn->node);

			/*创建一个jasonrpc结构*/
			conn->rpc = jsonrpc_open(stream);
        } 
		/*没有监听到链接请求直接break*/
		else if (error == EAGAIN) 
		{
            break;
        }
		else 
        {
            VLOG_WARN_RL(&rl, "%s: accept failed: %s",
                         pstream_get_name(server->listener),
                         ovs_strerror(error));
        }
    }

    struct unixctl_conn *conn, *next;

	/*启动server上的链接，接收处理数据*/
    LIST_FOR_EACH_SAFE (conn, next, node, &server->conns) {

		/*启动链接，去收rpc请求消息*/
		int error = run_connection(conn);
        if (error && error != EAGAIN) {
            kill_connection(conn);
        }
    }
}


/*******************************************************************************
 函数名称  :    unixctl_server_wait
 功能描述  :    等待
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
void
unixctl_server_wait(struct unixctl_server *server)
{
	/*链接*/
    struct unixctl_conn *conn;

    if (!server) {
        return;
    }

	/*等待链接请求*/
    pstream_wait(server->listener);

	/*遍历链接*/
	LIST_FOR_EACH (conn, node, &server->conns) {

        /*等待消息*/
        jsonrpc_wait(conn->rpc);

        /**/
        if (!jsonrpc_get_backlog(conn->rpc)) {

			/*接收消息等待*/
			jsonrpc_recv_wait(conn->rpc);
        }
    }
}


/*******************************************************************************
 函数名称  :    unixctl_server_destroy
 功能描述  :    销毁
 输入参数  :  	server---unixctl server
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Destroys 'server' and stops listening for connections. */
void
unixctl_server_destroy(struct unixctl_server *server)
{
    if (server) {
        struct unixctl_conn *conn, *next;

		/*遍历server上的conn*/
        LIST_FOR_EACH_SAFE (conn, next, node, &server->conns) {
            /*杀死conn*/
            kill_connection(conn);
        }

        free (server->path);
        pstream_close(server->listener);
        free(server);
    }
}


/*******************************************************************************
 函数名称  :    unixctl_server_get_path
 功能描述  :    获取unixctl服务的路径
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
const char *
unixctl_server_get_path(const struct unixctl_server *server)
{
    return server ? server->path : NULL;
}

/*******************************************************************************
 函数名称  :    unixctl_client_create
 功能描述  :    创建rpc 客户端
 输入参数  :  	path---unixctl socket路径/var/run/openvswitch/ovs-vswitchd.pid.ctl
 				client---rpc客户端
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* On POSIX based systems, connects to a unixctl server socket.  'path' should
 * be the name of a unixctl server socket.  If it does not start with '/', it
 * will be prefixed with the rundir (e.g. /usr/local/var/run/openvswitch).
 *
 * On Windows, connects to a local named pipe. A file which resides in
 * 'path' is used to mimic the behavior of a Unix domain socket.
 * 'path' should be an absolute path of the file.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * sets '*client' to the new jsonrpc, otherwise to NULL. */
int
unixctl_client_create(const char *path, struct jsonrpc **client)
{
    struct stream *stream;
    int error;

	/*绝对路径 /usr/local/var/run/openvswitch/ovs-vswitchd*/
    char *abs_path = abs_file_name(ovs_rundir(), path);

	/*文件路径 unix:/usr/local/var/run/openvswitch/ovs-vswtichd*/
    char *unix_path = xasprintf("unix:%s", abs_path);

    *client = NULL;

	/*打开unix socket文件创建初始化一个对应的fd_stream结构, stream赋值给stream*/
	/*创建rpc client传输数据的流*/
    error = stream_open_block(stream_open(unix_path, &stream, DSCP_DEFAULT), &stream);

	/*释放内存*/
    free(unix_path);
    free(abs_path);

    if (error) {
        VLOG_WARN("failed to connect to %s", path);
        return error;
    }

	/*创建初始化jason rpc结构*/
    *client = jsonrpc_open(stream);
	
    return 0;
}

/*******************************************************************************
 函数名称  :    unixctl_client_transact
 功能描述  :    客户端传数据，走unix socket
 输入参数  :  	client---起的rpc客户端
 				command---dpcl/add-flow "flow"
 				argc---剩余参数个数---2---具体的flow
 				argv---剩余的具体的flow dpcl/add-flow "flow"
 				result---执行命令返回的结果
 				err---执行命令的结果
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Executes 'command' on the server with an argument vector 'argv' containing
 * 'argc' elements.  If successfully communicated with the server, returns 0
 * and sets '*result', or '*err' (not both) to the result or error the server
 * returned.  Otherwise, sets '*result' and '*err' to NULL and returns a
 * positive errno value.  The caller is responsible for freeing '*result' or
 * '*err' if not NULL. */
int
unixctl_client_transact(struct jsonrpc *client, const char *command, int argc,
                        char *argv[], char **result, char **err)
{
	/*rpc 请求、回应消息*/
    struct jsonrpc_msg *request, *reply;

	/*Jason的参数*/
	struct json **json_args, *params;
    int error, i;

    *result = NULL;
    *err = NULL;

	/*Jason参数指针数组*/
    json_args = xmalloc(argc * sizeof *json_args);

	/*每个参数创建Jason内存 dpcl/add-flow , "flow"*/
	for (i = 0; i < argc; i++) 
	{
		/*各字段jason 指针数组*/
        json_args[i] = json_string_create(argv[i]);
    }

	/*param类型为jason数组，记录多个jason string类型，每个jason指向argv[]*/
    params = json_array_create(json_args, argc);

	/*创建一个Jason请求msg*/
	request = jsonrpc_create_request(command, params, NULL);

	printf("zwl unixctl_client_transact request->id.integer=%Ld\n",request->id.integer);

	/*阻塞式传输，最终调用的是stream的函数*/
    error = jsonrpc_transact_block(client, request, &reply);
    if (error) {
        VLOG_WARN("error communicating with %s: %s", jsonrpc_get_name(client),
                  ovs_retval_to_string(error));
        return error;
    }

	/*流标下发失败的reply消息*/
    if (reply->error) {

		/*传输错误码，string类型*/
		if (reply->error->type == JSON_STRING) {
            *err = xstrdup(json_string(reply->error));
        } else {
            VLOG_WARN("%s: unexpected error type in JSON RPC reply: %s",
                      jsonrpc_get_name(client),
                      json_type_to_string(reply->error->type));
            error = EINVAL;
        }
    } 
	/*流表下发成功的reply*/
	else if (reply->result) {

		/*结果类型string*/
        if (reply->result->type == JSON_STRING) {
            *result = xstrdup(json_string(reply->result));
        } else {

			/*其他类型有问题*/
            VLOG_WARN("%s: unexpected result type in JSON rpc reply: %s",
                      jsonrpc_get_name(client),
                      json_type_to_string(reply->result->type));
            error = EINVAL;
        }
    }

 	/*删除reply信息*/
    jsonrpc_msg_destroy(reply);

	
    return error;
}
