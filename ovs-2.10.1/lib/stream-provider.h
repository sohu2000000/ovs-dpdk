/*
 * Copyright (c) 2009, 2010, 2012, 2013, 2015 Nicira, Inc.
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

#ifndef STREAM_PROVIDER_H
#define STREAM_PROVIDER_H 1

#include <sys/types.h>
#include "stream.h"


/*外部流结构*/
/* Active stream connection. */              /*主动流链接*/

/* Active stream connection.
 *
 * This structure should be treated as opaque by implementation. */
struct stream {
    const struct stream_class *class;									/*流操作op，实际 流对象，实际是stream_fd_class*/
    int state;															/*链接状态，连接状态 取值为SCS_CONNECTING等枚举*/
    int error;															/*错误码*/
    char *name;															/*形式hostIP:port 例如name = "127.0.0.1:6653"  */
    char *peer_id;														/*对端id*/
};

void stream_init(struct stream *, const struct stream_class *,
                 int connect_status, char *name);
static inline void stream_assert_class(const struct stream *stream,
                                       const struct stream_class *class)
{
    ovs_assert(stream->class == class);
}

/*流对象，对rpc流数据的操作*/
struct stream_class {
    /* Prefix for connection names, e.g. "tcp", "ssl", "unix". */
    const char *name;																/*流的操作类的类型*/

    /* True if this stream needs periodic probes to verify connectivity.  For
     * streams which need probes, it can take a long time to notice the
     * connection was dropped. */
    bool needs_probes;

    /* Attempts to connect to a peer.  'name' is the full connection name
     * provided by the user, e.g. "tcp:1.2.3.4".  This name is useful for error
     * messages but must not be modified.
     *
     * 'suffix' is a copy of 'name' following the colon and may be modified.
     * 'dscp' is the DSCP value that the new connection should use in the IP
     * packets it sends.
     *
     * Returns 0 if successful, otherwise a positive errno value.  If
     * successful, stores a pointer to the new connection in '*streamp'.
     *
     * The open function must not block waiting for a connection to complete.
     * If the connection cannot be completed immediately, it should return
     * EAGAIN (not EINPROGRESS, as returned by the connect system call) and
     * continue the connection in the background. */
    int (*open)(const char *name, char *suffix, struct stream **streamp,
                uint8_t dscp);

    /* Closes 'stream' and frees associated memory. */
    void (*close)(struct stream *stream);

    /* Tries to complete the connection on 'stream'.  If 'stream''s connection
     * is complete, returns 0 if the connection was successful or a positive
     * errno value if it failed.  If the connection is still in progress,
     * returns EAGAIN.
     *
     * The connect function must not block waiting for the connection to
     * complete; instead, it should return EAGAIN immediately. */
    int (*connect)(struct stream *stream);

    /* Tries to receive up to 'n' bytes from 'stream' into 'buffer', and
     * returns:
     *
     *     - If successful, the number of bytes received (between 1 and 'n').
     *
     *     - On error, a negative errno value.
     *
     *     - 0, if the connection has been closed in the normal fashion.
     *
     * The recv function will not be passed a zero 'n'.
     *
     * The recv function must not block waiting for data to arrive.  If no data
     * have been received, it should return -EAGAIN immediately. */
    ssize_t (*recv)(struct stream *stream, void *buffer, size_t n);

    /* Tries to send up to 'n' bytes of 'buffer' on 'stream', and returns:
     *
     *     - If successful, the number of bytes sent (between 1 and 'n').
     *
     *     - On error, a negative errno value.
     *
     *     - Never returns 0.
     *
     * The send function will not be passed a zero 'n'.
     *
     * The send function must not block.  If no bytes can be immediately
     * accepted for transmission, it should return -EAGAIN immediately. */
    ssize_t (*send)(struct stream *stream, const void *buffer, size_t n);

    /* Allows 'stream' to perform maintenance activities, such as flushing
     * output buffers.
     *
     * May be null if 'stream' doesn't have anything to do here. */
    void (*run)(struct stream *stream);

    /* Arranges for the poll loop to wake up when 'stream' needs to perform
     * maintenance activities.
     *
     * May be null if 'stream' doesn't have anything to do here. */
    void (*run_wait)(struct stream *stream);

    /* Arranges for the poll loop to wake up when 'stream' is ready to take an
     * action of the given 'type'. */
    void (*wait)(struct stream *stream, enum stream_wait_type type);
};

/*流数据监听*/
/* Passive listener for incoming stream connections.
 *
 * This structure should be treated as opaque by stream implementations. */
struct pstream {
    const struct pstream_class *class;								/*流操作类*/
    char *name;														/*流的name*/
    ovs_be16 bound_port;											/*绑定的端口是什么*/
};

void pstream_init(struct pstream *, const struct pstream_class *, char *name);
void pstream_set_bound_port(struct pstream *, ovs_be16 bound_port);
static inline void pstream_assert_class(const struct pstream *pstream,
                                        const struct pstream_class *class)
{
    ovs_assert(pstream->class == class);
}

/*流数据操作op，是被动流，只用来listen, accept新的连接*/
/*pstream_class是一个类似的接口类，其实现根据底层socket的不同（unix domain socket, tcp socket, ssl socket）而不同，p表示passive*/
struct pstream_class {
    /* Prefix for connection names, e.g. "ptcp", "pssl", "punix". */
    const char *name;

    /* True if this pstream needs periodic probes to verify connectivity.  For
     * pstreams which need probes, it can take a long time to notice the
     * connection was dropped. */
    bool needs_probes;																	/*为了确定链接状态，设置*/

    /* Attempts to start listening for stream connections.  'name' is the full
     * connection name provided by the user, e.g. "ptcp:1234".  This name is
     * useful for error messages but must not be modified.
     *
     * 'suffix' is a copy of 'name' following the colon and may be modified.
     * 'dscp' is the DSCP value that the new connection should use in the IP
     * packets it sends.
     *
     * Returns 0 if successful, otherwise a positive errno value.  If
     * successful, stores a pointer to the new connection in '*pstreamp'.
     *
     * The listen function must not block.  If the connection cannot be
     * completed immediately, it should return EAGAIN (not EINPROGRESS, as
     * returned by the connect system call) and continue the connection in the
     * background. */
    int (*listen)(const char *name, char *suffix, struct pstream **pstreamp,
                  uint8_t dscp);

    /* Closes 'pstream' and frees associated memory. */
    void (*close)(struct pstream *pstream);

    /* Tries to accept a new connection on 'pstream'.  If successful, stores
     * the new connection in '*new_streamp' and returns 0.  Otherwise, returns
     * a positive errno value.
     *
     * The accept function must not block waiting for a connection.  If no
     * connection is ready to be accepted, it should return EAGAIN. */
    int (*accept)(struct pstream *pstream, struct stream **new_streamp);

    /* Arranges for the poll loop to wake up when a connection is ready to be
     * accepted on 'pstream'. */
    void (*wait)(struct pstream *pstream);
};

/* Active and passive stream classes. */
extern const struct stream_class tcp_stream_class;
extern const struct pstream_class ptcp_pstream_class;
#ifndef _WIN32

/*活跃的stream 和 消极的stream*/
extern const struct stream_class unix_stream_class;
extern const struct pstream_class punix_pstream_class;
#else
extern const struct stream_class windows_stream_class;
extern const struct pstream_class pwindows_pstream_class;
#endif
#ifdef HAVE_OPENSSL
extern const struct stream_class ssl_stream_class;
extern const struct pstream_class pssl_pstream_class;
#endif

#endif /* stream-provider.h */
