/*
 * Copyright (c) 2009-2017 Nicira, Inc.
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

#include "jsonrpc.h"

#include <errno.h>

#include "byteq.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "openvswitch/json.h"
#include "openvswitch/list.h"
#include "openvswitch/ofpbuf.h"
#include "ovs-thread.h"
#include "openvswitch/poll-loop.h"
#include "reconnect.h"
#include "stream.h"
#include "svec.h"
#include "timeval.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(jsonrpc);


/*jasonrpc结构*/
struct jsonrpc {
    //struct stream *stream;			/*外部流结构*/
    struct stream *zwl_stream;			/*rpc client传输数据使用的流，打开unix_socket会对应创建一个*/
    char *name;							/*链接name*/
    int status;							/*rpc链接状态*/

    /* Input. */
    struct byteq input;					/*收消息字节队列*/
    uint8_t input_buffer[512];			/*收消息字节队列buffer*/
    struct json_parser *parser;			/*Jason解析*/

    /* Output. */
    struct ovs_list output;     /* Contains "struct ofpbuf"s. */			/*要发的消息链表*/
    size_t output_count;        /* Number of elements in "output". */		/*要发的消息个数*/
    size_t backlog;															/*当前rpc库存的字节数*/
};

/* Rate limit for error messages. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);

static struct jsonrpc_msg *jsonrpc_parse_received_message(struct jsonrpc *);
static void jsonrpc_cleanup(struct jsonrpc *);
static void jsonrpc_error(struct jsonrpc *, int error);

/* This is just the same as stream_open() except that it uses the default
 * JSONRPC port if none is specified. */
int
jsonrpc_stream_open(const char *name, struct stream **streamp, uint8_t dscp)
{
    return stream_open_with_default_port(name, OVSDB_PORT, streamp, dscp);
}

/* This is just the same as pstream_open() except that it uses the default
 * JSONRPC port if none is specified. */
int
jsonrpc_pstream_open(const char *name, struct pstream **pstreamp, uint8_t dscp)
{
    return pstream_open_with_default_port(name, OVSDB_PORT, pstreamp, dscp);
}

/*******************************************************************************
 函数名称  :    jsonrpc_open
 功能描述  :    创建jrpc结构
 输入参数  :  	stream---使用的流
 输出参数  :	
 返 回 值  : 	返回jason rpc结构
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Returns a new JSON-RPC stream that uses 'stream' for input and output.  The
 * new jsonrpc object takes ownership of 'stream'. */
struct jsonrpc *
jsonrpc_open(struct stream *stream)
{
	/*申请jason rpc*/
    struct jsonrpc *rpc;

    ovs_assert(stream != NULL);

	/*rpc结构申请*/
    rpc = xzalloc(sizeof *rpc);

	/*获取流的name*/
    rpc->name = xstrdup(stream_get_name(stream));

	/*rpc client数据传输使用的流，指向unix_socket对应的stream结构*/
	rpc->stream = stream;

	/*jsonrpc 512字节buffer初始化成q管理*/	
    byteq_init(&rpc->input, rpc->input_buffer, sizeof rpc->input_buffer);

	/*output链表头初始化*/
	ovs_list_init(&rpc->output);

    return rpc;
}

/*******************************************************************************
 函数名称  :    jsonrpc_close
 功能描述  :    关掉rpc
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
/* Destroys 'rpc', closing the stream on which it is based, and frees its
 * memory. */
void
jsonrpc_close(struct jsonrpc *rpc)
{
    if (rpc) {
        jsonrpc_cleanup(rpc);
        free(rpc->name);
        free(rpc);
    }
}

/*******************************************************************************
 函数名称  :    jsonrpc_run
 功能描述  :    flush掉rpc待发出的字节
 输入参数  :  	rpc---jason rpc client
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Performs periodic maintenance on 'rpc', such as flushing output buffers. */
void
jsonrpc_run(struct jsonrpc *rpc)
{
	/*zwl添加*/
	char data[1024] = {0};
	
    if (rpc->status) {
        return;
    }

	/*刷出字节流*/
    stream_run(rpc->stream);

	/*如果输出消息不为空，每个request消息对应output先发一遍，一遍一遍的发，理论上一个buf 一次性就发出去了*/
    while (!ovs_list_is_empty(&rpc->output)) {

		printf("zwl jsonrpc_run\n");

		/*从rpc尾部获取ofpbuf，每一个request对应一个buf*/
        struct ofpbuf *buf = ofpbuf_from_list(rpc->output.next);
        int retval;

		/*流数据发送，地址，size，调send 发出去*/
        retval = stream_send(rpc->stream, buf->data, buf->size);

		memcpy(data, buf->data, buf->size);
		
		printf("zwl jsonrpc_run buf->data=%s\n", buf->data);

		printf("zwl jsonrpc_run retval=%d\n",retval);

		/*send成功的字节数*/
		if (retval >= 0) {

			/*库存减掉发出去的字节数*/
            rpc->backlog -= retval;
			printf("zwl jsonrpc_run rpc->backlog=%d\n",rpc->backlog);

			/*从buf删除发出去的字节*/
			ofpbuf_pull(buf, retval);

			/*buf上没有数据，删除output节点*/
			if (!buf->size) 
			{
				/*buf节点删除*/
                ovs_list_remove(&buf->list_node);

				/*buf个数减少*/
				rpc->output_count--;

				printf("zwl jsonrpc_run after rpc->output_count--=%d\n",rpc->output_count);

				/*释放*/
                ofpbuf_delete(buf);
            }
        } 
		/*发送失败*/
		else {
            if (retval != -EAGAIN) {
                VLOG_WARN_RL(&rl, "%s: send error: %s",
                             rpc->name, ovs_strerror(-retval));
                jsonrpc_error(rpc, -retval);
            }

			printf("zwl jsonrpc_run send failed\n");
			
            break;
        }
    }
}

/*******************************************************************************
 函数名称  :    jsonrpc_wait
 功能描述  :    rpc等
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
/* Arranges for the poll loop to wake up when 'rpc' needs to perform
 * maintenance activities. */
void
jsonrpc_wait(struct jsonrpc *rpc)
{
    if (!rpc->status) {

		/*流等待*/
        stream_run_wait(rpc->stream);

		/*如果要发的数据不为空*/
        if (!ovs_list_is_empty(&rpc->output)) {
            stream_send_wait(rpc->stream);
        }
    }
}

/*
 * Returns the current status of 'rpc'.  The possible return values are:
 * - 0: no error yet
 * - >0: errno value
 * - EOF: end of file (remote end closed connection; not necessarily an error).
 *
 * When this function returns nonzero, 'rpc' is effectively out of
 * commission.  'rpc' will not receive any more messages and any further
 * messages that one attempts to send with 'rpc' will be discarded.  The
 * caller can keep 'rpc' around as long as it wants, but it's not going
 * to provide any more useful services.
 */
int
jsonrpc_get_status(const struct jsonrpc *rpc)
{
    return rpc->status;
}

/* Returns the number of bytes buffered by 'rpc' to be written to the
 * underlying stream.  Always returns 0 if 'rpc' has encountered an error or if
 * the remote end closed the connection. */
size_t
jsonrpc_get_backlog(const struct jsonrpc *rpc)
{
    return rpc->status ? 0 : rpc->backlog;
}

/* Returns the number of bytes that have been received on 'rpc''s underlying
 * stream.  (The value wraps around if it exceeds UINT_MAX.) */
unsigned int
jsonrpc_get_received_bytes(const struct jsonrpc *rpc)
{
    return rpc->input.head;
}

/* Returns 'rpc''s name, that is, the name returned by stream_get_name() for
 * the stream underlying 'rpc' when 'rpc' was created. */
const char *
jsonrpc_get_name(const struct jsonrpc *rpc)
{
    return rpc->name;
}

static void
jsonrpc_log_msg(const struct jsonrpc *rpc, const char *title,
                const struct jsonrpc_msg *msg)
{
    if (VLOG_IS_DBG_ENABLED()) {
        struct ds s = DS_EMPTY_INITIALIZER;
        if (msg->method) {
            ds_put_format(&s, ", method=\"%s\"", msg->method);
        }
        if (msg->params) {
            ds_put_cstr(&s, ", params=");
            json_to_ds(msg->params, 0, &s);
        }
        if (msg->result) {
            ds_put_cstr(&s, ", result=");
            json_to_ds(msg->result, 0, &s);
        }
        if (msg->error) {
            ds_put_cstr(&s, ", error=");
            json_to_ds(msg->error, 0, &s);
        }
        if (msg->id) {
            ds_put_cstr(&s, ", id=");
            json_to_ds(msg->id, 0, &s);
        }
        VLOG_DBG("%s: %s %s%s", rpc->name, title,
                 jsonrpc_msg_type_to_string(msg->type), ds_cstr(&s));
        ds_destroy(&s);
    }
}

/*******************************************************************************
 函数名称  :    jsonrpc_send
 功能描述  :    如果msg不能被立即发送，则先添加到一个buffer，流程应该都是先库存到buffer，后面再发
 输入参数  :  	rpc---rpc client
 				msg---rpc请求消息
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Schedules 'msg' to be sent on 'rpc' and returns 'rpc''s status (as with
 * jsonrpc_get_status()).
 *
 * If 'msg' cannot be sent immediately, it is appended to a buffer.  The caller
 * is responsible for ensuring that the amount of buffered data is somehow
 * limited.  (jsonrpc_get_backlog() returns the amount of data currently
 * buffered in 'rpc'.)
 *
 * Always takes ownership of 'msg', regardless of success. */
int
jsonrpc_send(struct jsonrpc *rpc, struct jsonrpc_msg *msg)
{
    struct ofpbuf *buf;
    struct json *json;
    struct ds ds = DS_EMPTY_INITIALIZER;
    size_t length;

	/*rpc的状态*/
    if (rpc->status) 
	{
        jsonrpc_msg_destroy(msg);
        return rpc->status;
    }

	/*打印jason各字段日志*/
    jsonrpc_log_msg(rpc, "send", msg);

	/*reques请求消息转为jason 链表*/
    json = jsonrpc_msg_to_json(msg);

	/*jason 序列化*/
    json_to_ds(json, 0, &ds);

	/*消息序列化后的长度*/
    length = ds.length;

	/*临时json数据结构不要了*/
    json_destroy(json);


	/*申请一个ofpbuf*/
    buf = xmalloc(sizeof *buf);

	/*ofpbuf使用ds这个结构描述buf*/
    ofpbuf_use_ds(buf, &ds);

	/*放入output链表*/
    ovs_list_push_back(&rpc->output, &buf->list_node);

	/*reques消息个数*/
	rpc->output_count++;

	printf("zwl jsonrpc_transact_block add rpc->output_count=%llu\n", rpc->output_count);

	/*rpc上库存的字节数*/
    rpc->backlog += length;

	printf("zwl jsonrpc_transact_block add length=%llu, rpc->backlog=%d\n", length, rpc->backlog);

	/*发库存*/
    if (rpc->output_count >= 50) {
        VLOG_INFO_RL(&rl, "excessive sending backlog, jsonrpc: %s, num of"
                     " msgs: %"PRIuSIZE", backlog: %"PRIuSIZE".", rpc->name,
                     rpc->output_count, rpc->backlog);
    }

	/*这是只有1条消息没有库存, 调用jsonrpc_run发出去，否则只是加入库存*/
    if (rpc->backlog == length) {

		printf("zwl jsonrpc_transact_block rpc->backlog == length = %llu jsonrpc_run\n",length);

		/*执行rcp*/
        jsonrpc_run(rpc);
    }

	printf("zwl jsonrpc_transact_block rpc->status=%d\n", rpc->status);

	
    return rpc->status;
}

/*******************************************************************************
 函数名称  :    jsonrpc_recv
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
/* Attempts to receive a message from 'rpc'.
 *
 * If successful, stores the received message in '*msgp' and returns 0.  The
 * caller takes ownership of '*msgp' and must eventually destroy it with
 * jsonrpc_msg_destroy().
 *
 * Otherwise, stores NULL in '*msgp' and returns one of the following:
 *
 *   - EAGAIN: No message has been received.
 *
 *   - EOF: The remote end closed the connection gracefully.
 *
 *   - Otherwise an errno value that represents a JSON-RPC protocol violation
 *     or another error fatal to the connection.  'rpc' will not send or
 *     receive any more messages.
 */
int
jsonrpc_recv(struct jsonrpc *rpc, struct jsonrpc_msg **msgp)
{
    int i;

	char recv_buf[1024] = {0};

    *msgp = NULL;
    if (rpc->status) {
        return rpc->status;
    }

	/*每个conn连续收50次，防止有数据没收上来*/
    for (i = 0; i < 50; i++) {
        size_t n, used;

		VLOG_WARN_RL("zwl jsonrpc_recv i=%d",i);

		/*rpc input里没有数据，就去收*/
        /* Fill our input buffer if it's empty. */
        if (byteq_is_empty(&rpc->input)) 
		{
            size_t chunk;
            int retval;

			/*512 buffer 可用长度*/
            chunk = byteq_headroom(&rpc->input);

			/*收数据，收到rpc的input buffer里，buffer 中head指向空闲启始字节*/
            retval = stream_recv(rpc->stream, byteq_head(&rpc->input), chunk);
            if (retval < 0) {
                if (retval == -EAGAIN) {
                    return EAGAIN;
                } else {
                    VLOG_WARN_RL(&rl, "%s: receive error: %s",
                                 rpc->name, ovs_strerror(-retval));
                    jsonrpc_error(rpc, -retval);
                    return rpc->status;
                }
            } else if (retval == 0) {
                jsonrpc_error(rpc, EOF);
                return EOF;
            }

			/*更新可用head 位置*/
            byteq_advance_head(&rpc->input, retval);
        }

		/*如果有数据，已经收上来来了，去解析*/
        /* We have some input.  Feed it into the JSON parser. */
        if (!rpc->parser) {
            rpc->parser = json_parser_create(0);
        }

		/*从tail开始用掉的长度head-tail，或者tail 到end的长度，两者取小*/
        n = byteq_tailroom(&rpc->input);

#if 1
		if (n < 1023) {
			memcpy(recv_buf,byteq_tail(&rpc->input), n);
			VLOG_WARN_RL("zwl jsonrpc_recv recv_buf=%s",recv_buf);
		}
#endif		

		/*解析出来收到的jason长度再填入到buff*/
        used = json_parser_feed(rpc->parser,
                                (char *) byteq_tail(&rpc->input), n);

		/*更新使用的长度*/
        byteq_advance_tail(&rpc->input, used);

		/*解析数据*/
        /* If we have complete JSON, attempt to parse it as JSON-RPC. */
        if (json_parser_is_done(rpc->parser)) {

			 /*接到消息解析*/
            *msgp = jsonrpc_parse_received_message(rpc);
            if (*msgp) {
                return 0;
            }

            if (rpc->status) {
                const struct byteq *q = &rpc->input;

				/*没有超512字节*/
				if (q->head <= q->size) {
                    stream_report_content(q->buffer, q->head, STREAM_JSONRPC, &this_module, rpc->name);
                }
				
                return rpc->status;
            }
        }
    }

    return EAGAIN;
}

/* Causes the poll loop to wake up when jsonrpc_recv() may return a value other
 * than EAGAIN. */
void
jsonrpc_recv_wait(struct jsonrpc *rpc)
{
    if (rpc->status || !byteq_is_empty(&rpc->input)) {
        poll_immediate_wake_at(rpc->name);
    } else {
        stream_recv_wait(rpc->stream);
    }
}

/*******************************************************************************
 函数名称  :    jsonrpc_send_block
 功能描述  :    阻塞式发送rpc 请求消息
 输入参数  :  	rpc---rpc client
 				msg---rpc请求消息
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Sends 'msg' on 'rpc' and waits for it to be successfully queued to the
 * underlying stream.  Returns 0 if 'msg' was sent successfully, otherwise a
 * status value (see jsonrpc_get_status()).
 *
 * Always takes ownership of 'msg', regardless of success. */
int
jsonrpc_send_block(struct jsonrpc *rpc, struct jsonrpc_msg *msg)
{
    int error;

    fatal_signal_run();

	/*消息发函数，如果库存没满加入库存，如果只有一条直接发出去*/
    error = jsonrpc_send(rpc, msg);
    if (error) {
        return error;
    }

	/*把rpc上的消息发完*/
    for (;;) {

		/*数据流的数据刷出*/
        jsonrpc_run(rpc);

		/*rpc 发消息，没有消息了，返回0*/
		if (ovs_list_is_empty(&rpc->output) || rpc->status) {
			printf("zwl jsonrpc_send_block send over rpc->output empty\n");
            return rpc->status;
        }

		/*rpc等待*/
		jsonrpc_wait(rpc);

		poll_block();
    }
}

/*******************************************************************************
 函数名称  :    jsonrpc_recv_block
 功能描述  :    阻塞接收回应消息
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
/* Waits for a message to be received on 'rpc'.  Same semantics as
 * jsonrpc_recv() except that EAGAIN will never be returned. */
int
jsonrpc_recv_block(struct jsonrpc *rpc, struct jsonrpc_msg **msgp)
{
    for (;;) {

		printf("zwl jsonrpc_recv_block reply recv msg\n");
		
		/*回应消息*/
        int error = jsonrpc_recv(rpc, msgp);
        if (error != EAGAIN) {
            fatal_signal_run();
            return error;
        }

        jsonrpc_run(rpc);
        jsonrpc_wait(rpc);
        jsonrpc_recv_wait(rpc);
        poll_block();
    }
}

/*******************************************************************************
 函数名称  :    jsonrpc_transact_block
 功能描述  :    阻塞式传递
 输入参数  :  	rpc--起的rpc client
 				request---rpc请求消息
 				replyp---rpc返回消息地址赋值给指针
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/

/* Sends 'request' to 'rpc' then waits for a reply.  The return value is 0 if
 * successful, in which case '*replyp' is set to the reply, which the caller
 * must eventually free with jsonrpc_msg_destroy().  Otherwise returns a status
 * value (see jsonrpc_get_status()).
 *
 * Discards any message received on 'rpc' that is not a reply to 'request'
 * (based on message id).
 *
 * Always takes ownership of 'request', regardless of success. */
int
jsonrpc_transact_block(struct jsonrpc *rpc, struct jsonrpc_msg *request,
                       struct jsonrpc_msg **replyp)
{
    struct jsonrpc_msg *reply = NULL;
    struct json *id;
    int error;

	/*复制json请求消息id*/
    id = json_clone(request->id);

	struct json *tmp = id;

	printf("zwl jsonrpc_transact_block id=%Ld\n", tmp->integer);

	/*调send 发request消息，send 默认最大一次87380字节*/
    error = jsonrpc_send_block(rpc, request);
    if (!error) {
        for (;;) {
			
			printf("zwl jsonrpc_transact_block wait reply\n");
			
			/*阻塞式发送*/
            error = jsonrpc_recv_block(rpc, &reply);
            if (error) {
                break;
            }

			/*判断返回值，id要一致*/
            if ((reply->type == JSONRPC_REPLY || reply->type == JSONRPC_ERROR)
                && json_equal(id, reply->id)) {

				printf("zwl jsonrpc_recv_block reply recv msg id=reply->id=%Ld\n", reply->id->integer);
				
                break;
            }

			/*返回值内存销毁*/
            jsonrpc_msg_destroy(reply);
        }
    }

	printf("zwl jsonrpc_recv_block reply recv msg sucess reply->id.integer=%Ld\n",reply->id->integer);
	
    *replyp = error ? NULL : reply;

	json_destroy(id);

	return error;
}


/*******************************************************************************
 函数名称  :    jsonrpc_parse_received_message
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
/* Attempts to parse the content of 'rpc->parser' (which is complete JSON) as a
 * JSON-RPC message.  If successful, returns the JSON-RPC message.  On failure,
 * signals an error on 'rpc' with jsonrpc_error() and returns NULL. */
static struct jsonrpc_msg *
jsonrpc_parse_received_message(struct jsonrpc *rpc)
{
    struct jsonrpc_msg *msg;
    struct json *json;
    char *error;

    json = json_parser_finish(rpc->parser);
    rpc->parser = NULL;

	/*string类型*/
    if (json->type == JSON_STRING) {
        VLOG_WARN_RL(&rl, "%s: error parsing stream: %s",
                     rpc->name, json_string(json));
        jsonrpc_error(rpc, EPROTO);
        json_destroy(json);
        return NULL;
    }

	/*从收到的jason解析出msg格式*/
    error = jsonrpc_msg_from_json(json, &msg);
    if (error) {
        VLOG_WARN_RL(&rl, "%s: received bad JSON-RPC message: %s",
                     rpc->name, error);
        free(error);
        jsonrpc_error(rpc, EPROTO);
        return NULL;
    }


	/*打印日志*/
	jsonrpc_log_msg(rpc, "received", msg);
	
    return msg;
}

static void
jsonrpc_error(struct jsonrpc *rpc, int error)
{
    ovs_assert(error);
    if (!rpc->status) {
        rpc->status = error;
        jsonrpc_cleanup(rpc);
    }
}

/*******************************************************************************
 函数名称  :    jsonrpc_cleanup
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
jsonrpc_cleanup(struct jsonrpc *rpc)
{
    stream_close(rpc->stream);
    rpc->stream = NULL;

    json_parser_abort(rpc->parser);
    rpc->parser = NULL;

	/*删除*/
    ofpbuf_list_delete(&rpc->output);

	rpc->backlog = 0;

	rpc->output_count = 0;
}

/*******************************************************************************
 函数名称  :    jsonrpc_create
 功能描述  :    构建jason消息
 输入参数  :  	type---JSONRPC_REQUEST
 				method---dpcl/add-flow "flow"
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static struct jsonrpc_msg *
jsonrpc_create(enum jsonrpc_msg_type type, const char *method,
                struct json *params, struct json *result, struct json *error,
                struct json *id)
{
	/*创建jason rpc消息*/
    struct jsonrpc_msg *msg = xmalloc(sizeof *msg);

	/*rpc的请求消息JSONRPC_REQUEST*/
    msg->type = type;

	/*dpctl/add-flow*/
    msg->method = nullable_xstrdup(method);

	/*jason数组类型，下面挂了多个jason string类型*/
	msg->params = params;

	/*返回的结果*/
    msg->result = result;
    msg->error = error;

	/*生成的jason id*/
    msg->id = id;

	/*返回msg*/
    return msg;
}

/*******************************************************************************
 函数名称  :    jsonrpc_create_id
 功能描述  :    创建Jason rpc的id,自动生成一个id
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
static struct json *
jsonrpc_create_id(void)
{
    static atomic_count next_id = ATOMIC_COUNT_INIT(0);
    unsigned int id;


    id = atomic_count_inc(&next_id);

    return json_integer_create(id);
}

/*******************************************************************************
 函数名称  :    jsonrpc_create_request
 功能描述  :    创建一个rcp请求消息
 输入参数  :  	method---dpcl/add-flow "flow"
 				params---dpcl/add-flow "flow"填到params*，jason数组
 				idp---NULL
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
struct jsonrpc_msg *
jsonrpc_create_request(const char *method, struct json *params,
                       struct json **idp)
{
	/*创建一个rpc的id，自动生成的*/
    struct json *id = jsonrpc_create_id();
    if (idp) {
        *idp = json_clone(id);
    }

	/*创建jason请求消息*/
    return jsonrpc_create(JSONRPC_REQUEST, method, params, NULL, NULL, id);
}

struct jsonrpc_msg *
jsonrpc_create_notify(const char *method, struct json *params)
{
    return jsonrpc_create(JSONRPC_NOTIFY, method, params, NULL, NULL, NULL);
}

struct jsonrpc_msg *
jsonrpc_create_reply(struct json *result, const struct json *id)
{
    return jsonrpc_create(JSONRPC_REPLY, NULL, NULL, result, NULL,
                           json_clone(id));
}

struct jsonrpc_msg *
jsonrpc_create_error(struct json *error, const struct json *id)
{
    return jsonrpc_create(JSONRPC_REPLY, NULL, NULL, NULL, error,
                           json_clone(id));
}

struct jsonrpc_msg *
jsonrpc_msg_clone(const struct jsonrpc_msg *old)
{
    return jsonrpc_create(old->type, old->method,
                          json_nullable_clone(old->params),
                          json_nullable_clone(old->result),
                          json_nullable_clone(old->error),
                          json_nullable_clone(old->id));
}

const char *
jsonrpc_msg_type_to_string(enum jsonrpc_msg_type type)
{
    switch (type) {
    case JSONRPC_REQUEST:
        return "request";

    case JSONRPC_NOTIFY:
        return "notification";

    case JSONRPC_REPLY:
        return "reply";

    case JSONRPC_ERROR:
        return "error";
    }
    return "(null)";
}

/*******************************************************************************
 函数名称  :    jsonrpc_msg_is_valid
 功能描述  :    jsonrpc msg是否合法
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
char *
jsonrpc_msg_is_valid(const struct jsonrpc_msg *m)
{
    const char *type_name;
    unsigned int pattern;

    if (m->params && m->params->type != JSON_ARRAY) {
        return xstrdup("\"params\" must be JSON array");
    }

    switch (m->type) {
    case JSONRPC_REQUEST:
        pattern = 0x11001;
        break;

    case JSONRPC_NOTIFY:
        pattern = 0x11000;
        break;

    case JSONRPC_REPLY:
        pattern = 0x00101;
        break;

    case JSONRPC_ERROR:
        pattern = 0x00011;
        break;

    default:
        return xasprintf("invalid JSON-RPC message type %d", m->type);
    }

    type_name = jsonrpc_msg_type_to_string(m->type);
    if ((m->method != NULL) != ((pattern & 0x10000) != 0)) {
        return xasprintf("%s must%s have \"method\"",
                         type_name, (pattern & 0x10000) ? "" : " not");

    }
    if ((m->params != NULL) != ((pattern & 0x1000) != 0)) {
        return xasprintf("%s must%s have \"params\"",
                         type_name, (pattern & 0x1000) ? "" : " not");

    }
    if ((m->result != NULL) != ((pattern & 0x100) != 0)) {
        return xasprintf("%s must%s have \"result\"",
                         type_name, (pattern & 0x100) ? "" : " not");

    }
    if ((m->error != NULL) != ((pattern & 0x10) != 0)) {
        return xasprintf("%s must%s have \"error\"",
                         type_name, (pattern & 0x10) ? "" : " not");

    }
    if ((m->id != NULL) != ((pattern & 0x1) != 0)) {
        return xasprintf("%s must%s have \"id\"",
                         type_name, (pattern & 0x1) ? "" : " not");

    }
    return NULL;
}

void
jsonrpc_msg_destroy(struct jsonrpc_msg *m)
{
    if (m) {
        free(m->method);
        json_destroy(m->params);
        json_destroy(m->result);
        json_destroy(m->error);
        json_destroy(m->id);
        free(m);
    }
}

static struct json *
null_from_json_null(struct json *json)
{
    if (json && json->type == JSON_NULL) {
        json_destroy(json);
        return NULL;
    }
    return json;
}

/*******************************************************************************
 函数名称  :    jsonrpc_msg_from_json
 功能描述  :    把收到的数据恢复成jason
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
char *
jsonrpc_msg_from_json(struct json *json, struct jsonrpc_msg **msgp)
{
    struct json *method = NULL;
    struct jsonrpc_msg *msg = NULL;
    struct shash *object;
    char *error;

	/*json的类型不是object类型*/
    if (json->type != JSON_OBJECT) {
        error = xstrdup("message is not a JSON object");
        goto exit;
    }

	/*恢复出object*/
    object = json_object(json);
    method = shash_find_and_delete(object, "method");

	/*string类型*/
    if (method && method->type != JSON_STRING) {
        error = xstrdup("method is not a JSON string");
        goto exit;
    }

	/*msg*/
    msg = xzalloc(sizeof *msg);
    msg->method = method ? xstrdup(method->string) : NULL;
    msg->params = null_from_json_null(shash_find_and_delete(object, "params"));
    msg->result = null_from_json_null(shash_find_and_delete(object, "result"));
    msg->error = null_from_json_null(shash_find_and_delete(object, "error"));
    msg->id = null_from_json_null(shash_find_and_delete(object, "id"));


	/*消息类型*/
    msg->type = (msg->result ? JSONRPC_REPLY
                 : msg->error ? JSONRPC_ERROR
                 : msg->id ? JSONRPC_REQUEST
                 : JSONRPC_NOTIFY);
    if (!shash_is_empty(object)) {
        error = xasprintf("message has unexpected member \"%s\"",
                          shash_first(object)->name);
        goto exit;
    }

	
    error = jsonrpc_msg_is_valid(msg);
    if (error) {
        goto exit;
    }

exit:
    json_destroy(method);
    json_destroy(json);
    if (error) {
        jsonrpc_msg_destroy(msg);
        msg = NULL;
    }
    *msgp = msg;
    return error;
}

/* Returns 'm' converted to JSON suitable for sending as a JSON-RPC message.
 *
 * Consumes and destroys 'm'. */
struct json *
jsonrpc_msg_to_json(struct jsonrpc_msg *m)
{
    struct json *json = json_object_create();

    if (m->method) {
        json_object_put(json, "method", json_string_create_nocopy(m->method));
    }

    if (m->params) {
        json_object_put(json, "params", m->params);
    }

    if (m->result) {
        json_object_put(json, "result", m->result);
    } else if (m->type == JSONRPC_ERROR) {
        json_object_put(json, "result", json_null_create());
    }

    if (m->error) {
        json_object_put(json, "error", m->error);
    } else if (m->type == JSONRPC_REPLY) {
        json_object_put(json, "error", json_null_create());
    }

    if (m->id) {
        json_object_put(json, "id", m->id);
    } else if (m->type == JSONRPC_NOTIFY) {
        json_object_put(json, "id", json_null_create());
    }

    free(m);

    return json;
}

char *
jsonrpc_msg_to_string(const struct jsonrpc_msg *m)
{
    struct jsonrpc_msg *copy = jsonrpc_msg_clone(m);
    struct json *json = jsonrpc_msg_to_json(copy);
    char *s = json_to_string(json, JSSF_SORT);
    json_destroy(json);
    return s;
}

/*jrp session结构*/
/* A JSON-RPC session with reconnection. */

struct jsonrpc_session {
    struct svec remotes;
    size_t next_remote;
    struct reconnect *reconnect;				/*重连使用*/
    struct reconnect *zwl_reconnect;		    /*重连使用*/
    struct jsonrpc *rpc;
    struct stream *stream;
    struct pstream *pstream;
    int last_error;
    unsigned int seqno;
    uint8_t dscp;
};

static void
jsonrpc_session_pick_remote(struct jsonrpc_session *s)
{
    reconnect_set_name(s->reconnect,
                       s->remotes.names[s->next_remote++ % s->remotes.n]);
}

/* Creates and returns a jsonrpc_session to 'name', which should be a string
 * acceptable to stream_open() or pstream_open().
 *
 * If 'name' is an active connection method, e.g. "tcp:127.1.2.3", the new
 * jsonrpc_session connects to 'name'.  If 'retry' is true, then the new
 * session connects and reconnects to 'name', with backoff.  If 'retry' is
 * false, the new session will only try to connect once and after a connection
 * failure or a disconnection jsonrpc_session_is_alive() will return false for
 * the new session.
 *
 * If 'name' is a passive connection method, e.g. "ptcp:", the new
 * jsonrpc_session listens for connections to 'name'.  It maintains at most one
 * connection at any given time.  Any new connection causes the previous one
 * (if any) to be dropped. */
struct jsonrpc_session *
jsonrpc_session_open(const char *name, bool retry)
{
    const struct svec remotes = { .names = (char **) &name, .n = 1 };
    return jsonrpc_session_open_multiple(&remotes, retry);
}

/*******************************************************************************
 函数名称  :    jsonrpc_session_open_multiple
 功能描述  :    js
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
struct jsonrpc_session *
jsonrpc_session_open_multiple(const struct svec *remotes, bool retry)
{
    struct jsonrpc_session *s;

    s = xmalloc(sizeof *s);

    /* Set 'n' remotes from 'names', shuffling them into random order. */
    ovs_assert(remotes->n > 0);
    svec_clone(&s->remotes, remotes);
    svec_shuffle(&s->remotes);
    s->next_remote = 0;

	/*创建一个reconnect结构*/
    s->reconnect = reconnect_create(time_msec());
    jsonrpc_session_pick_remote(s);
    reconnect_enable(s->reconnect, time_msec());
    reconnect_set_backoff_free_tries(s->reconnect, remotes->n);
    s->rpc = NULL;
    s->stream = NULL;
    s->pstream = NULL;
    s->seqno = 0;
    s->dscp = 0;
    s->last_error = 0;

	/*链接的name*/
    const char *name = reconnect_get_name(s->reconnect);
    if (!pstream_verify_name(name)) {
        reconnect_set_passive(s->reconnect, true, time_msec());
    } else if (!retry) {

		/*设置最大重连次数*/
        reconnect_set_max_tries(s->reconnect, remotes->n);
        reconnect_set_backoff(s->reconnect, INT_MAX, INT_MAX);
    }

	/*是否开启了probe*/
    if (!stream_or_pstream_needs_probes(name)) {

		/*设置探测间隔至少1000*/
        reconnect_set_probe_interval(s->reconnect, 0);
    }

    return s;
}

/*******************************************************************************
 函数名称  :    jsonrpc_session_open_unreliably
 功能描述  :    为链接建立一个session结构
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Creates and returns a jsonrpc_session that is initially connected to
 * 'jsonrpc'.  If the connection is dropped, it will not be reconnected.
 *
 * On the assumption that such connections are likely to be short-lived
 * (e.g. from ovs-vsctl), informational logging for them is suppressed. */
struct jsonrpc_session *
jsonrpc_session_open_unreliably(struct jsonrpc *jsonrpc, uint8_t dscp)
{
    struct jsonrpc_session *s;

    s = xmalloc(sizeof *s);
    svec_init(&s->remotes);
    svec_add(&s->remotes, jsonrpc_get_name(jsonrpc));
    s->next_remote = 0;
    s->reconnect = reconnect_create(time_msec());
    reconnect_set_quiet(s->reconnect, true);
    reconnect_set_name(s->reconnect, jsonrpc_get_name(jsonrpc));
    reconnect_set_max_tries(s->reconnect, 0);
    reconnect_connected(s->reconnect, time_msec());
    s->dscp = dscp;
    s->rpc = jsonrpc;
    s->stream = NULL;
    s->pstream = NULL;
    s->seqno = 1;

    return s;
}

void
jsonrpc_session_close(struct jsonrpc_session *s)
{
    if (s) {
        jsonrpc_close(s->rpc);
        reconnect_destroy(s->reconnect);
        stream_close(s->stream);
        pstream_close(s->pstream);
        svec_destroy(&s->remotes);
        free(s);
    }
}

struct jsonrpc *
jsonrpc_session_steal(struct jsonrpc_session *s)
{
    struct jsonrpc *rpc = s->rpc;
    s->rpc = NULL;
    jsonrpc_session_close(s);
    return rpc;
}

/*******************************************************************************
 函数名称  :    jsonrpc_session_disconnect
 功能描述  :    
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
jsonrpc_session_disconnect(struct jsonrpc_session *s)
{
    if (s->rpc) {
        jsonrpc_error(s->rpc, EOF);
        jsonrpc_close(s->rpc);
        s->rpc = NULL;
    } else if (s->stream) {
        stream_close(s->stream);
        s->stream = NULL;
    } else {
        return;
    }

    s->seqno++;
    jsonrpc_session_pick_remote(s);
}

static void
jsonrpc_session_connect(struct jsonrpc_session *s)
{
    const char *name = reconnect_get_name(s->reconnect);
    int error;

    jsonrpc_session_disconnect(s);
    if (!reconnect_is_passive(s->reconnect)) {
        error = jsonrpc_stream_open(name, &s->stream, s->dscp);
        if (!error) {
            reconnect_connecting(s->reconnect, time_msec());
        } else {
            s->last_error = error;
        }
    } else {
        error = s->pstream ? 0 : jsonrpc_pstream_open(name, &s->pstream,
                                                      s->dscp);
        if (!error) {
            reconnect_listening(s->reconnect, time_msec());
        }
    }

    if (error) {
        reconnect_connect_failed(s->reconnect, time_msec(), error);
        jsonrpc_session_pick_remote(s);
    }
}

/*******************************************************************************
 函数名称  :    jsonrpc_session_run
 功能描述  :    走session的存在echo msg
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
jsonrpc_session_run(struct jsonrpc_session *s)
{
	/*服务端逻辑*/
    if (s->pstream) {
        struct stream *stream;
        int error;

		/*接收一个链接*/
        error = pstream_accept(s->pstream, &stream);
        if (!error) {
            if (s->rpc || s->stream) {
                VLOG_INFO_RL(&rl,
                             "%s: new connection replacing active connection",
                             reconnect_get_name(s->reconnect));
                jsonrpc_session_disconnect(s);
            }

			/*重连*/
            reconnect_connected(s->reconnect, time_msec());

			/*打开对应的jsonrpc*/
            s->rpc = jsonrpc_open(stream);
            s->seqno++;
        } else if (error != EAGAIN) {
            reconnect_listen_error(s->reconnect, time_msec(), error);
            pstream_close(s->pstream);
            s->pstream = NULL;
        }
    }


	/*rpc存在发消息*/
    if (s->rpc) {
        size_t backlog;
        int error;

        backlog = jsonrpc_get_backlog(s->rpc);

		/*发消息*/
        jsonrpc_run(s->rpc);

		/*有消息*/
        if (jsonrpc_get_backlog(s->rpc) < backlog) {
            /* Data previously caught in a queue was successfully sent (or
             * there's an error, which we'll catch below.)
             *
             * We don't count data that is successfully sent immediately as
             * activity, because there's a lot of queuing downstream from us,
             * which means that we can push a lot of data into a connection
             * that has stalled and won't ever recover.
             */

			/*重设定时器*/
            reconnect_activity(s->reconnect, time_msec());
        }

		/*jsonrpc的链接状态*/
        error = jsonrpc_get_status(s->rpc);
        if (error) {
            reconnect_disconnected(s->reconnect, time_msec(), error);
            jsonrpc_session_disconnect(s);
            s->last_error = error;
        }
    } 
	/**/
	else if (s->stream) {
        int error;

		/*流启动*/
        stream_run(s->stream);

		/*流的链接状态检查*/
        error = stream_connect(s->stream);
		/**/
		if (!error) {

			/*重连*/
            reconnect_connected(s->reconnect, time_msec());

			/*打开js对应的jsonrpc*/
            s->rpc = jsonrpc_open(s->stream);
            s->stream = NULL;
            s->seqno++;
        } 
		/*其他错误信息*/
		else if (error != EAGAIN) {
            reconnect_connect_failed(s->reconnect, time_msec(), error);
            jsonrpc_session_pick_remote(s);
            stream_close(s->stream);
            s->stream = NULL;
            s->last_error = error;
        }
    }

	/*session重连的状态获取，如果定时器到时间，需要探活*/
    switch (reconnect_run(s->reconnect, time_msec())) {

	/*需要重连*/
    case RECONNECT_CONNECT:
        jsonrpc_session_connect(s);
        break;

	/*需要关闭链接*/
    case RECONNECT_DISCONNECT:
        reconnect_disconnected(s->reconnect, time_msec(), 0);
        jsonrpc_session_disconnect(s);
        break;

	/*需要发echo消息*/
    case RECONNECT_PROBE:
        if (s->rpc) {
            struct json *params;
            struct jsonrpc_msg *request;

			/*空的参数*/
            params = json_array_create_empty();

			/*method 为echo*/
            request = jsonrpc_create_request("echo", params, NULL);

			/*释放了id*/
            json_destroy(request->id);

			/*id挂string?*/
            request->id = json_string_create("echo");

			/*发探测请求*/
			jsonrpc_send(s->rpc, request);
        }
        break;
    }
}

void
jsonrpc_session_wait(struct jsonrpc_session *s)
{
    if (s->rpc) {
        jsonrpc_wait(s->rpc);
    } else if (s->stream) {
        stream_run_wait(s->stream);
        stream_connect_wait(s->stream);
    }
    if (s->pstream) {
        pstream_wait(s->pstream);
    }
    reconnect_wait(s->reconnect, time_msec());
}

size_t
jsonrpc_session_get_backlog(const struct jsonrpc_session *s)
{
    return s->rpc ? jsonrpc_get_backlog(s->rpc) : 0;
}

/* Always returns a pointer to a valid C string, assuming 's' was initialized
 * correctly. */
const char *
jsonrpc_session_get_name(const struct jsonrpc_session *s)
{
    return reconnect_get_name(s->reconnect);
}

const char *
jsonrpc_session_get_id(const struct jsonrpc_session *s)
{
    if (s->rpc && s->rpc->stream) {
        return stream_get_peer_id(s->rpc->stream);
    } else {
        return NULL;
    }
}

size_t
jsonrpc_session_get_n_remotes(const struct jsonrpc_session *s)
{
    return s->remotes.n;
}

/*******************************************************************************
 函数名称  :    jsonrpc_session_send
 功能描述  :    
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Always takes ownership of 'msg', regardless of success. */
int
jsonrpc_session_send(struct jsonrpc_session *s, struct jsonrpc_msg *msg)
{
	/*发消息*/
    if (s->rpc) {
        return jsonrpc_send(s->rpc, msg);
    } else {
        jsonrpc_msg_destroy(msg);
        return ENOTCONN;
    }
}

/*******************************************************************************
 函数名称  :    jsonrpc_session_recv
 功能描述  :    jsonrpc session 收消息
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
struct jsonrpc_msg *
jsonrpc_session_recv(struct jsonrpc_session *s)
{
    if (s->rpc) {
        unsigned int received_bytes;
        struct jsonrpc_msg *msg;

        received_bytes = jsonrpc_get_received_bytes(s->rpc);

		/*收msg*/
		jsonrpc_recv(s->rpc, &msg);
        if (received_bytes != jsonrpc_get_received_bytes(s->rpc)) {
            /* Data was successfully received.
             *
             * Previously we only counted receiving a full message as activity,
             * but with large messages or a slow connection that policy could
             * time out the session mid-message. */
            reconnect_activity(s->reconnect, time_msec());
        }

		/*处理收到的msg*/
        if (msg) {
			/*echo reques消息*/
            if (msg->type == JSONRPC_REQUEST && !strcmp(msg->method, "echo")) {
                /* Echo request.  Send reply. */
                struct jsonrpc_msg *reply;

				/*回reply*/
                reply = jsonrpc_create_reply(json_clone(msg->params), msg->id);

				/*直接发了出去*/
				jsonrpc_session_send(s, reply);
            }

			/*对echo的reply消息处理*/
			else if (msg->type == JSONRPC_REPLY
                       && msg->id && msg->id->type == JSON_STRING
                       && !strcmp(msg->id->string, "echo")) {
                /* It's a reply to our echo request.  Suppress it. */
            } else {
                return msg;
            }
			
            jsonrpc_msg_destroy(msg);
        }
    }
    return NULL;
}

void
jsonrpc_session_recv_wait(struct jsonrpc_session *s)
{
    if (s->rpc) {
        jsonrpc_recv_wait(s->rpc);
    }
}

/* Returns true if 's' is currently connected or trying to connect. */
bool
jsonrpc_session_is_alive(const struct jsonrpc_session *s)
{
    return s->rpc || s->stream || reconnect_get_max_tries(s->reconnect);
}

/* Returns true if 's' is currently connected. */
bool
jsonrpc_session_is_connected(const struct jsonrpc_session *s)
{
    return s->rpc != NULL;
}

/* Returns a sequence number for 's'.  The sequence number increments every
 * time 's' connects or disconnects.  Thus, a caller can use the change (or
 * lack of change) in the sequence number to figure out whether the underlying
 * connection is the same as before. */
unsigned int
jsonrpc_session_get_seqno(const struct jsonrpc_session *s)
{
    return s->seqno;
}

/* Returns the current status of 's'.  If 's' is NULL or is disconnected, this
 * is 0, otherwise it is the status of the connection, as reported by
 * jsonrpc_get_status(). */
int
jsonrpc_session_get_status(const struct jsonrpc_session *s)
{
    return s && s->rpc ? jsonrpc_get_status(s->rpc) : 0;
}

/* Returns the last error reported on a connection by 's'.  The return value is
 * 0 only if no connection made by 's' has ever encountered an error.  See
 * jsonrpc_get_status() for return value interpretation. */
int
jsonrpc_session_get_last_error(const struct jsonrpc_session *s)
{
    return s->last_error;
}

/* Populates 'stats' with statistics from 's'. */
void
jsonrpc_session_get_reconnect_stats(const struct jsonrpc_session *s,
                                    struct reconnect_stats *stats)
{
    reconnect_get_stats(s->reconnect, time_msec(), stats);
}

/* Enables 's' to reconnect to the peer if the connection drops. */
void
jsonrpc_session_enable_reconnect(struct jsonrpc_session *s)
{
    reconnect_set_max_tries(s->reconnect, UINT_MAX);
    reconnect_set_backoff(s->reconnect, RECONNECT_DEFAULT_MIN_BACKOFF,
                          RECONNECT_DEFAULT_MAX_BACKOFF);
}

/* Forces 's' to drop its connection (if any) and reconnect. */
void
jsonrpc_session_force_reconnect(struct jsonrpc_session *s)
{
    reconnect_force_reconnect(s->reconnect, time_msec());
}

/* Sets 'max_backoff' as the maximum time, in milliseconds, to wait after a
 * connection attempt fails before attempting to connect again. */
void
jsonrpc_session_set_max_backoff(struct jsonrpc_session *s, int max_backoff)
{
    reconnect_set_backoff(s->reconnect, 0, max_backoff);
}

/* Sets the "probe interval" for 's' to 'probe_interval', in milliseconds.  If
 * this is zero, it disables the connection keepalive feature.  Otherwise, if
 * 's' is idle for 'probe_interval' milliseconds then 's' will send an echo
 * request and, if no reply is received within an additional 'probe_interval'
 * milliseconds, close the connection (then reconnect, if that feature is
 * enabled). */
void
jsonrpc_session_set_probe_interval(struct jsonrpc_session *s,
                                   int probe_interval)
{
    reconnect_set_probe_interval(s->reconnect, probe_interval);
}

/* Sets the DSCP value used for 's''s connection to 'dscp'.  If this is
 * different from the DSCP value currently in use then the connection is closed
 * and reconnected. */
void
jsonrpc_session_set_dscp(struct jsonrpc_session *s, uint8_t dscp)
{
    if (s->dscp != dscp) {
        pstream_close(s->pstream);
        s->pstream = NULL;

        s->dscp = dscp;
        jsonrpc_session_force_reconnect(s);
    }
}
