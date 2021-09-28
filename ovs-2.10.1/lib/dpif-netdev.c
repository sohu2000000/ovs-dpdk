/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2016, 2017 Nicira, Inc.
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
#include "dpif-netdev.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bitmap.h"
#include "cmap.h"
#include "conntrack.h"
#include "coverage.h"
#include "ct-dpif.h"
#include "csum.h"
#include "dp-packet.h"
#include "dpif.h"
#include "dpif-netdev-perf.h"
#include "dpif-provider.h"
#include "dummy.h"
#include "fat-rwlock.h"
#include "flow.h"
#include "hmapx.h"
#include "id-pool.h"
#include "latch.h"
#include "netdev.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "netlink.h"
#include "odp-execute.h"
#include "odp-util.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/list.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"
#include "ovs-numa.h"
#include "ovs-rcu.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "pvector.h"
#include "random.h"
#include "seq.h"
#include "smap.h"
#include "sset.h"
#include "timeval.h"
#include "tnl-neigh-cache.h"
#include "tnl-ports.h"
#include "unixctl.h"
#include "util.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(dpif_netdev);

#define FLOW_DUMP_MAX_BATCH 50
/* Use per thread recirc_depth to prevent recirculation loop. */
#define MAX_RECIRC_DEPTH 6
DEFINE_STATIC_PER_THREAD_DATA(uint32_t, recirc_depth, 0)

/* Use instant packet send by default. */
#define DEFAULT_TX_FLUSH_INTERVAL 0

/* Configuration parameters. */
enum { MAX_FLOWS = 65536 };     /* Maximum number of flows in flow table. */
enum { MAX_METERS = 65536 };    /* Maximum number of meters. */
enum { MAX_BANDS = 8 };         /* Maximum number of bands / meter. */
enum { N_METER_LOCKS = 64 };    /* Maximum number of meters. */

/* Protects against changes to 'dp_netdevs'. */
static struct ovs_mutex dp_netdev_mutex = OVS_MUTEX_INITIALIZER;

/*所有dp_netdev链表*/
/* Contains all 'struct dp_netdev's. */
static struct shash dp_netdevs OVS_GUARDED_BY(dp_netdev_mutex)
    = SHASH_INITIALIZER(&dp_netdevs);

static struct vlog_rate_limit upcall_rl = VLOG_RATE_LIMIT_INIT(600, 600);

#define DP_NETDEV_CS_SUPPORTED_MASK (CS_NEW | CS_ESTABLISHED | CS_RELATED \
                                     | CS_INVALID | CS_REPLY_DIR | CS_TRACKED \
                                     | CS_SRC_NAT | CS_DST_NAT)
#define DP_NETDEV_CS_UNSUPPORTED_MASK (~(uint32_t)DP_NETDEV_CS_SUPPORTED_MASK)

/*支持的种类*/
static struct odp_support dp_netdev_support = {
    .max_vlan_headers = SIZE_MAX,
    .max_mpls_depth = SIZE_MAX,
    .recirc = true,
    .ct_state = true,
    .ct_zone = true,
    .ct_mark = true,
    .ct_label = true,
    .ct_state_nat = true,
    .ct_orig_tuple = true,
    .ct_orig_tuple6 = true,
};

/* Stores a miniflow with inline values */

/*从报文提取的miniflow key*/
struct netdev_flow_key 
{	
    uint32_t hash;       /* Hash function differs for different users. */     	/* 根据报文5元组(源IP、目的IP、协议号、源端口、目的端口) 计算出的Hash值，根据哈希遍历emc_entry*/
	uint32_t len;        /* Length of the following miniflow (incl. map). */  	/* len = sizeof(mf) + buf中实际存储的字节数 */

	struct miniflow mf;  														/* 报文对应的miniflow信息位图 */	
   																				/* 报文具体匹配字段的数据值存储在buf*/
	uint64_t buf[FLOW_MAX_PACKET_U64S];											/*报文压缩信息存储，在flow中有值的字段存储到这个buf*/
};

/* EMC cache and SMC cache compose the datapath flow cache (DFC)
 *
 * Exact match cache for frequently used flows
 *
 * The cache uses a 32-bit hash of the packet (which can be the RSS hash) to
 * search its entries for a miniflow that matches exactly the miniflow of the
 * packet. It stores the 'dpcls_rule' (rule) that matches the miniflow.
 *
 * A cache entry holds a reference to its 'dp_netdev_flow'.
 *
 * A miniflow with a given hash can be in one of EM_FLOW_HASH_SEGS different
 * entries. The 32-bit hash is split into EM_FLOW_HASH_SEGS values (each of
 * them is EM_FLOW_HASH_SHIFT bits wide and the remainder is thrown away). Each
 * value is the index of a cache entry where the miniflow could be.
 *
 *
 * Signature match cache (SMC)
 *
 * This cache stores a 16-bit signature for each flow without storing keys, and
 * stores the corresponding 16-bit flow_table index to the 'dp_netdev_flow'.
 * Each flow thus occupies 32bit which is much more memory efficient than EMC.
 * SMC uses a set-associative design that each bucket contains
 * SMC_ENTRY_PER_BUCKET number of entries.
 * Since 16-bit flow_table index is used, if there are more than 2^16
 * dp_netdev_flow, SMC will miss them that cannot be indexed by a 16-bit value.
 *
 *
 * Thread-safety
 * =============
 *
 * Each pmd_thread has its own private exact match cache.
 * If dp_netdev_input is not called from a pmd thread, a mutex is used.
 */

#define EM_FLOW_HASH_SHIFT 13
#define EM_FLOW_HASH_ENTRIES (1u << EM_FLOW_HASH_SHIFT)
#define EM_FLOW_HASH_MASK (EM_FLOW_HASH_ENTRIES - 1)
#define EM_FLOW_HASH_SEGS 2

/* SMC uses a set-associative design. A bucket contains a set of entries that
 * a flow item can occupy. For now, it uses one hash function rather than two
 * as for the EMC design. */
#define SMC_ENTRY_PER_BUCKET 4
#define SMC_ENTRIES (1u << 20)
#define SMC_BUCKET_CNT (SMC_ENTRIES / SMC_ENTRY_PER_BUCKET)
#define SMC_MASK (SMC_BUCKET_CNT - 1)

/* Default EMC insert probability is 1 / DEFAULT_EM_FLOW_INSERT_INV_PROB */
#define DEFAULT_EM_FLOW_INSERT_INV_PROB 100
#define DEFAULT_EM_FLOW_INSERT_MIN (UINT32_MAX /                     \
                                    DEFAULT_EM_FLOW_INSERT_INV_PROB)

/*emc入口*/
struct emc_entry {
    struct dp_netdev_flow *flow; 											  /* emc流表项，包含了匹配域及对应的Actions */
    struct netdev_flow_key key;   /* key.hash used for emc hash value. */   /*从报文提取的flow key，匹配EMC表项的关键字 */
};

/*emc表项，每个DPDK PMD线程都有一个EMC表，缓存8192条flow*/
struct emc_cache 
{
	/* EMC表项,总数为EM_FLOW_HASH_ENTRIES=1 << 13,即: 8192个表项 */ /*emc表项=flow+key*/
    struct emc_entry entries[EM_FLOW_HASH_ENTRIES];					 /*8192个entry*/
    int sweep_idx;                /* For emc_cache_slow_sweep(). */  /*用来删除*/
};

/*smc桶 桶深都为4*/
struct smc_bucket {
    uint16_t sig[SMC_ENTRY_PER_BUCKET];		  /*4*/
    uint16_t flow_idx[SMC_ENTRY_PER_BUCKET];  /*4*/
};

/* Signature match cache, differentiate from EMC cache */

/*smc缓存*/
struct smc_cache {
    struct smc_bucket buckets[SMC_BUCKET_CNT];
};


/*emc smc流表*/
struct dfc_cache {
    struct emc_cache emc_cache;
    struct smc_cache smc_cache;
};


/*EMC=cache struct emc_cache *cache*/
/*CURRENT_ENTRY=current_entry struct emc_entry *current_entry*/
/*HASH=hash  uint32_t  struct netdev_flow_key->hash */

/*循环条件 i<2  for循环查2次，32位hash 分为低13位与高29位两次查询

第一次 (CURRENT_ENTRY) = &(EMC)->entries[srch_hash__ & EM_FLOW_HASH_MASK]   ----- hash & (1<<13 -1)  低13位
第二次 (CURRENT_ENTRY) = &(EMC)->entries[srch_hash__ >>= EM_FLOW_HASH_SHIFT] &  ----- hash>>13 & (1>> 13) 高29位中的低13位 
EM_FLOW_HASH_MASK = 1>>13

*/

/* Iterate in the exact match cache through every entry that might contain a
 * miniflow with hash 'HASH'. */
#define EMC_FOR_EACH_POS_WITH_HASH(EMC, CURRENT_ENTRY, HASH)                 \
    for (uint32_t i__ = 0, srch_hash__ = (HASH);                             \
         (CURRENT_ENTRY) = &(EMC)->entries[srch_hash__ & EM_FLOW_HASH_MASK], \
         i__ < EM_FLOW_HASH_SEGS;                                            \
         i__++, srch_hash__ >>= EM_FLOW_HASH_SHIFT)

/* Simple non-wildcarding single-priority classifier. */

/* Time in microseconds between successive optimizations of the dpcls
 * subtable vector */
#define DPCLS_OPTIMIZATION_INTERVAL 1000000LL

/* Time in microseconds of the interval in which rxq processing cycles used
 * in rxq to pmd assignments is measured and stored. */
#define PMD_RXQ_INTERVAL_LEN 10000000LL

/* Number of intervals for which cycles are stored
 * and used during rxq to pmd assignment. */
#define PMD_RXQ_INTERVAL_MAX 6

/* dpcls匹配表.每个报文接收端口对应一个 */
struct dpcls 
{
	/* cmap链表节点 */
    struct cmap_node node;      /* Within dp_netdev_pmd_thread.classifiers */
	
    odp_port_t in_port;			/* 报文接收端口 */
	
    struct cmap subtables_map;  /*链表头，挂subtables 子表*/

    struct pvector subtables;   /*优先级，每个优先级包含对应的掩码, 所包含的子表信息, port下所有网段掩码，包含所有优先级的掩码*/
};

/* A rule to be inserted to the classifier. */
/*dpcls规则，作为cmap节点*/
struct dpcls_rule 
{
    struct cmap_node cmap_node;   /* Within struct dpcls_subtable 'rules'. */	/*链首*/
    struct netdev_flow_key *mask; /* Subtable's mask. */						/*subtable 提取的掩码miniflow key*/
    struct netdev_flow_key flow;  /* Matching key. */							/*从报文提取的flow key*/
    /* 'flow' must be the last field, additional space is allocated here. */
};

static void dpcls_init(struct dpcls *);
static void dpcls_destroy(struct dpcls *);
static void dpcls_sort_subtable_vector(struct dpcls *);
static void dpcls_insert(struct dpcls *, struct dpcls_rule *,
                         const struct netdev_flow_key *mask);
static void dpcls_remove(struct dpcls *, struct dpcls_rule *);
static bool dpcls_lookup(struct dpcls *cls,
                         const struct netdev_flow_key *keys[],
                         struct dpcls_rule **rules, size_t cnt,
                         int *num_lookups_p);
static bool dpcls_rule_matches_key(const struct dpcls_rule *rule,
                            const struct netdev_flow_key *target);
/* Set of supported meter flags */
#define DP_SUPPORTED_METER_FLAGS_MASK \
    (OFPMF13_STATS | OFPMF13_PKTPS | OFPMF13_KBPS | OFPMF13_BURST)

/* Set of supported meter band types */
#define DP_SUPPORTED_METER_BAND_TYPES           \
    ( 1 << OFPMBT13_DROP )

/*数据面meter带宽*/
struct dp_meter_band {
    struct ofputil_meter_band up; /* type, prec_level, pad, rate, burst_size */
    uint32_t bucket; /* In 1/1000 packets (for PKTPS), or in bits (for KBPS) */
    uint64_t packet_count;	/*命中报文数*/
    uint64_t byte_count;	/*命中字节数*/
};

/*数据面 meter*/
struct dp_meter {
    uint16_t flags;
    uint16_t n_bands;
    uint32_t max_delta_t;
    uint64_t used;
    uint64_t packet_count;
    uint64_t byte_count;
    struct dp_meter_band bands[];	/*meter 带宽流量统计*/
    
};

/* Datapath based on the network device interface from netdev.h.
 *
 *
 * Thread-safety
 * =============
 *
 * Some members, marked 'const', are immutable.  Accessing other members
 * requires synchronization, as noted in more detail below.
 *
 * Acquisition order is, from outermost to innermost:
 *
 *    dp_netdev_mutex (global)
 *    port_mutex
 *    non_pmd_mutex
 */

/*数据面网络设备结构*/
struct dp_netdev {
    const struct dpif_class *const class;	/*数据面 类结构 操作函数等*/
    const char *const name;					/*数据面name*/
    struct dpif *dpif; 					    /*ovs 数据面接口*/
    struct ovs_refcount ref_cnt;			/*引用次数*/
    atomic_flag destroyed;					/*设备摧毁次数*/

    /* Ports.
     *
     * Any lookup into 'ports' or any access to the dp_netdev_ports found
     * through 'ports' requires taking 'port_mutex'. */
    struct ovs_mutex port_mutex;
    struct hmap ports;															/*端口哈希链*/
    struct seq *port_seq;       /* Incremented whenever a port changes. */		/*端口序列号*/

    /* The time that a packet can wait in output batch for sending. */
    atomic_uint32_t tx_flush_interval;											/*报文在发送批处理最长时间*/

    /* Meters. */
    struct ovs_mutex meter_locks[N_METER_LOCKS]; 
    struct dp_meter *meters[MAX_METERS]; /* Meter bands. */					/*带宽[64]*/

    /* Probability of EMC insertions is a factor of 'emc_insert_min'.*/
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE) atomic_uint32_t emc_insert_min;			/*emc 流表最小值*/
    /* Enable collection of PMD performance metrics. */
    atomic_bool pmd_perf_metrics;												/*pmd流量统计开关*/
    /* Enable the SMC cache from ovsdb config */
    atomic_bool smc_enable_db;													/*从数据库配置使能smc*/

    /* Protects access to ofproto-dpif-upcall interface during revalidator
     * thread synchronization. */
    struct fat_rwlock upcall_rwlock;											/*upcall读写锁*/
    upcall_callback *upcall_cb;  /* Callback function for executing upcalls. */ /*upcall处理回调函数*/
    void *upcall_aux;

    /* Callback function for notifying the purging of dp flows (during
     * reseting pmd deletion). */
    dp_purge_callback *dp_purge_cb;
    void *dp_purge_aux;

    /* Stores all 'struct dp_netdev_pmd_thread's. */
    struct cmap poll_threads;													/*pmd线程s*/
    /* id pool for per thread static_tx_qid. */
    struct id_pool *tx_qid_pool;												/*pmd线程队列id池*/
    struct ovs_mutex tx_qid_pool_mutex;										/*发送队列锁*/

    /* Protects the access of the 'struct dp_netdev_pmd_thread'
     * instance for non-pmd thread. */
    struct ovs_mutex non_pmd_mutex;

    /* Each pmd thread will store its pointer to
     * 'struct dp_netdev_pmd_thread' in 'per_pmd_key'. */
    ovsthread_key_t per_pmd_key;												/*pmd线程结构地址*/

    struct seq *reconfigure_seq;												/*重新配置的序列号*/
    uint64_t last_reconfigure_seq;												/*记录最新的配置序号*/

    /* Cpu mask for pin of pmd threads. */
    char *pmd_cmask;															/*pmd占用CPU 掩码*/

    uint64_t last_tnl_conf_seq;

    //struct conntrack conntrack;													/*struct conntrack 链接跟踪*/

    struct conntrack zwl_conntrack;													/*struct conntrack 链接跟踪*/
};

static void meter_lock(const struct dp_netdev *dp, uint32_t meter_id)
    OVS_ACQUIRES(dp->meter_locks[meter_id % N_METER_LOCKS])
{
    ovs_mutex_lock(&dp->meter_locks[meter_id % N_METER_LOCKS]);
}

static void meter_unlock(const struct dp_netdev *dp, uint32_t meter_id)
    OVS_RELEASES(dp->meter_locks[meter_id % N_METER_LOCKS])
{
    ovs_mutex_unlock(&dp->meter_locks[meter_id % N_METER_LOCKS]);
}


static struct dp_netdev_port *dp_netdev_lookup_port(const struct dp_netdev *dp,
                                                    odp_port_t)
    OVS_REQUIRES(dp->port_mutex);

enum rxq_cycles_counter_type {
    RXQ_CYCLES_PROC_CURR,       /* Cycles spent successfully polling and
                                   processing packets during the current
                                   interval. */
    RXQ_CYCLES_PROC_HIST,       /* Total cycles of all intervals that are used
                                   during rxq to pmd assignment. */
    RXQ_N_CYCLES
};

enum {
    DP_NETDEV_FLOW_OFFLOAD_OP_ADD,
    DP_NETDEV_FLOW_OFFLOAD_OP_MOD,
    DP_NETDEV_FLOW_OFFLOAD_OP_DEL,
};

/*offload 项*/
struct dp_flow_offload_item 
{
    struct dp_netdev_pmd_thread *pmd;		/*pmd线程*/
    struct dp_netdev_flow *flow;			/*flow具体内容*/
    int op;									/*流表操作类型*/
    //struct match match;
	struct match m;							/*flow的match，下发flow时填充的*/
    struct nlattr *actions;					/*action链表，下发flow时填充的*/
    size_t actions_len;						/*action 个数*/

    struct ovs_list node;					/*offload项链表头*/
};

/*dp offload 的flow*/
struct dp_flow_offload {
    struct ovs_mutex mutex;
    struct ovs_list list;
    pthread_cond_t cond;
};

/*流表offload链表*/
static struct dp_flow_offload dp_flow_offload = {
    .mutex = OVS_MUTEX_INITIALIZER,
    .list  = OVS_LIST_INITIALIZER(&dp_flow_offload.list),
};

/*offload 线程*/
static struct ovsthread_once offload_thread_once
    = OVSTHREAD_ONCE_INITIALIZER;

#define XPS_TIMEOUT 500000LL    /* In microseconds. */

/* Contained by struct dp_netdev_port's 'rxqs' member.  */

/*端口接收队列*/
struct dp_netdev_rxq 
{
    struct dp_netdev_port *port;	   /*队列属于的端口*/
    struct netdev_rxq *rx;			   /*接收队列*/
    unsigned core_id;                  /* Core to which this queue should be        //队列绑定的逻辑核id
                                          pinned. OVS_CORE_UNSPEC if the
                                          queue doesn't need to be pinned to a
                                          particular core. */
    unsigned intrvl_idx;               /* Write index for 'cycles_intrvl'. */		/*循环间隔时间,poll 队列的时间间隔*/
    struct dp_netdev_pmd_thread *pmd;  /* pmd thread that polls this queue. */		/*pmd线程*/
    bool is_vhost;                     /* Is rxq of a vhost port. */				/*接收队列属于虚拟主机端口*/

    /* Counters of cycles spent successfully polling and processing pkts. */		/*成功poll队列处理报文的循环的计数*/
    atomic_ullong cycles[RXQ_N_CYCLES];											    /*队列poll的次数*/
    /* We store PMD_RXQ_INTERVAL_MAX intervals of data for an rxq and then
       sum them to yield the cycles used for an rxq. */
    atomic_ullong cycles_intrvl[PMD_RXQ_INTERVAL_MAX];								/*poll队列时间间隔梯度设置 数组为6*/
};

/* A port in a netdev-based datapath. */
/*netdev端口信息*/
struct dp_netdev_port {
    odp_port_t port_no;			/*端口ID*/
    bool dynamic_txqs;          /* If true XPS will be used. */                 /*主动配置的txq小于pmd+非pmd数，开启动态调整txq，根据txq的使用情况决定*/
    bool need_reconfigure;      /* True if we should reconfigure netdev. */
    struct netdev *netdev;														/*端口网络设备*/
    struct hmap_node node;      /* Node in dp_netdev's 'ports'. */
    struct netdev_saved_flags *sf;
    struct dp_netdev_rxq *rxqs;	/*接收队列*/
    unsigned n_rxq;             /* Number of elements in 'rxqs' */				/*端口rx队列个数*/
    unsigned *txq_used;         /* Number of threads that use each tx queue. */	/*记录队列引用次数*/
    struct ovs_mutex txq_used_mutex;
    char *type;                 /* Port type as requested by user. */			/*用户请求的端口类型*/
    char *rxq_affinity_list;    /* Requested affinity of rx queues. */          /*接收队列的cpu亲和性*/
};

/* Contained by struct dp_netdev_flow's 'stats' member.  */

/*流量统计*/
struct dp_netdev_flow_stats {
    atomic_llong used;             /* Last used time, in monotonic msecs. */
    atomic_ullong packet_count;    /* Number of packets matched. */
    atomic_ullong byte_count;      /* Number of bytes matched. */
    atomic_uint16_t tcp_flags;     /* Bitwise-OR of seen tcp_flags values. */
};

/* A flow in 'dp_netdev_pmd_thread's 'flow_table'.
 *
 *
 * Thread-safety
 * =============
 *
 * Except near the beginning or ending of its lifespan, rule 'rule' belongs to
 * its pmd thread's classifier.  The text below calls this classifier 'cls'.
 *
 * Motivation
 * ----------
 *
 * The thread safety rules described here for "struct dp_netdev_flow" are
 * motivated by two goals:
 *
 *    - Prevent threads that read members of "struct dp_netdev_flow" from
 *      reading bad data due to changes by some thread concurrently modifying
 *      those members.
 *
 *    - Prevent two threads making changes to members of a given "struct
 *      dp_netdev_flow" from interfering with each other.
 *
 *
 * Rules
 * -----
 *
 * A flow 'flow' may be accessed without a risk of being freed during an RCU
 * grace period.  Code that needs to hold onto a flow for a while
 * should try incrementing 'flow->ref_cnt' with dp_netdev_flow_ref().
 *
 * 'flow->ref_cnt' protects 'flow' from being freed.  It doesn't protect the
 * flow from being deleted from 'cls' and it doesn't protect members of 'flow'
 * from modification.
 *
 * Some members, marked 'const', are immutable.  Accessing other members
 * requires synchronization, as noted in more detail below.
 */

/* 表示一条流表项.立面包含了匹配域及对应的Actions */
struct dp_netdev_flow 
{
    const struct flow flow;      /* Unmasked flow that created this entry. */   /*struct flow 一条flow全部信息*/
    /* Hash table index by unmasked flow. */
    const struct cmap_node node; /* In owning dp_netdev_pmd_thread's */		
                                 /* 'flow_table'. */
    const struct cmap_node mark_node; /* In owning flow_mark's mark_to_flow */	/**/
    const ovs_u128 ufid;         /* Unique flow identifier. */					/*流表ID*/
    const ovs_u128 mega_ufid;    /* Unique mega flow identifier. */				/*mega flow ID*/
    const unsigned pmd_id;       /* The 'core_id' of pmd thread owning this */	/*逻辑核ID*/
                                 /* flow. */

    /* Number of references.
     * The classifier owns one reference.
     * Any thread trying to keep a rule from being freed should hold its own
     * reference. */
    struct ovs_refcount ref_cnt;												/*流引用计数*/

    bool dead;					 												/*false,表明该流表项仍然保活着*/
    uint32_t mark;               /* Unique flow mark assigned to a flow */

    /* Statistics. */
    struct dp_netdev_flow_stats stats;										/*流量统计*/

    /* Actions. */
    OVSRCU_TYPE(struct dp_netdev_actions *) actions;  						/*emc流表action*/

    /* While processing a group of input packets, the datapath uses the next
     * member to store a pointer to the output batch for the flow.  It is
     * reset after the batch has been sent out (See dp_netdev_queue_batches(),
     * packet_batch_per_flow_init() and packet_batch_per_flow_execute()). */
    struct packet_batch_per_flow *batch; 										/* 用于缓存匹配某个流表项的多个报文.最多缓存32个报文 */

    /* Packet classification. */
    struct dpcls_rule cr;        /* In owning dp_netdev's 'cls'. */			/*dpcls规则*/
    /* 'cr' must be the last member. */
};

static void dp_netdev_flow_unref(struct dp_netdev_flow *);
static bool dp_netdev_flow_ref(struct dp_netdev_flow *);
static int dpif_netdev_flow_from_nlattrs(const struct nlattr *, uint32_t,
                                         struct flow *, bool);

/* A set of datapath actions within a "struct dp_netdev_flow".
 *
 *
 * Thread-safety
 * =============
 *
 * A struct dp_netdev_actions 'actions' is protected with RCU. */

/*emc 流表 action*/
struct dp_netdev_actions {
    /* These members are immutable: they do not change during the struct's
     * lifetime.  */
    unsigned int size;          /* Size of 'actions', in bytes. */
    struct nlattr actions[];    /* Sequence of OVS_ACTION_ATTR_* attributes. */		/*action属性*/
};

struct dp_netdev_actions *dp_netdev_actions_create(const struct nlattr *,
                                                   size_t);
struct dp_netdev_actions *dp_netdev_flow_get_actions(
    const struct dp_netdev_flow *);
static void dp_netdev_actions_free(struct dp_netdev_actions *);

/*poll队列*/
struct polled_queue 
{
    struct dp_netdev_rxq *rxq;		/*接收队列*/
    odp_port_t port_no;				/*队列属于的端口号*/
};

/* Contained by struct dp_netdev_pmd_thread's 'poll_list' member. */
/*poll的接收队列*/
struct rxq_poll {
    struct dp_netdev_rxq *rxq;		/*poll节点对应接收队列*/
    struct hmap_node node;
};

/* Contained by struct dp_netdev_pmd_thread's 'send_port_cache',
 * 'tnl_port_cache' or 'tx_ports'. */

/*发送端口*/
struct tx_port {
    struct dp_netdev_port *port;			/*设备对应发包端口信息*/
    int qid;								/*端口对应发包队列id*/
    long long last_used;					/*上次使用时间*/
    struct hmap_node node;					/*哈希节点*/
    long long flush_time;					/*下次发包时间*/
    struct dp_packet_batch output_pkts;		/*发送方向批处理结构*/
    struct dp_netdev_rxq *output_pkts_rxqs[NETDEV_MAX_BURST];		/*发送队列，每次burst 32个报文*/
};

/* A set of properties for the current processing loop that is not directly
 * associated with the pmd thread itself, but with the packets being
 * processed or the short-term system configuration (for example, time).
 * Contained by struct dp_netdev_pmd_thread's 'ctx' member. */

/*pmd线程上下文*/
struct dp_netdev_pmd_thread_ctx 
{
    /* Latest measured time. See 'pmd_thread_ctx_time_update()'. */
    long long now;												/*pmd线程运行的当前时间*/
    /* RX queue from which last packet was received. */
    struct dp_netdev_rxq *last_rxq;								/*最后一个接收到报文的队列*/
};

/* PMD: Poll modes drivers.  PMD accesses devices via polling to eliminate
 * the performance overhead of interrupt processing.  Therefore netdev can
 * not implement rx-wait for these devices.  dpif-netdev needs to poll
 * these device to check for recv buffer.  pmd-thread does polling for
 * devices assigned to itself.
 *
 * DPDK used PMD for accessing NIC.
 *
 * Note, instance with cpu core id NON_PMD_CORE_ID will be reserved for
 * I/O of all non-pmd threads.  There will be no actual thread created
 * for the instance.
 *
 * Each struct has its own flow cache and classifier per managed ingress port.
 * For packets received on ingress port, a look up is done on corresponding PMD
 * thread's flow cache and in case of a miss, lookup is performed in the
 * corresponding classifier of port.  Packets are executed with the found
 * actions in either case.
 * */

/*pmd线程结构*/
struct dp_netdev_pmd_thread {
    struct dp_netdev *dp;														/*数据面netdev网络设备结构*/
    struct ovs_refcount ref_cnt;    /* Every reference must be refcount'ed. */  /*pmd线程结构引用计数*/
    struct cmap_node node;          /* In 'dp->poll_threads'. */				/*poll线程链表*/

    pthread_cond_t cond;            /* For synchronizing pmd thread reload. */
    struct ovs_mutex cond_mutex;    /* Mutex for condition variable. */

    /* Per thread exact-match cache.  Note, the instance for cpu core
     * NON_PMD_CORE_ID can be accessed by multiple threads, and thusly
     * need to be protected by 'non_pmd_mutex'.  Every other instance
     * will only be accessed by its own pmd thread. */
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE) struct dfc_cache flow_cache; 				/*flow_cache的成员指向了pmd对应的emc表项*/

    /* Flow-Table and classifiers
     *
     * Writers of 'flow_table' must take the 'flow_mutex'.  Corresponding
     * changes to 'classifiers' must be made while still holding the
     * 'flow_mutex'.
     */
    struct ovs_mutex flow_mutex;												/*流表锁*/
    struct cmap flow_table OVS_GUARDED; /* Flow table. */						/*flow节点挂链*/

    /* One classifier per in_port polled by the pmd */
    struct cmap classifiers;													/*cmap结构，报文分类器，每端口一个，每端口一个dpcls*/
    /* Periodically sort subtable vectors according to hit frequencies */   
    long long int next_optimization;											/**/
    /* End of the next time interval for which processing cycles
       are stored for each polled rxq. */
    long long int rxq_next_cycle_store;

    /* Last interval timestamp. */
    uint64_t intrvl_tsc_prev;													/*上次poll 时间戳*/
    /* Last interval cycles. */
    atomic_ullong intrvl_cycles;												/*上一次队列poll 时间间隔*/

    /* Current context of the PMD thread. */
    struct dp_netdev_pmd_thread_ctx ctx;									    /*pmd线程运行当前上下文*/

    struct latch exit_latch;        /* For terminating the pmd thread. */		/*用来结束线程*/
    struct seq *reload_seq;													    /*重载序号*/
    uint64_t last_reload_seq;												    /*最后重载序号*/
    atomic_bool reload;             /* Do we need to reload ports? */			/*重载端口*/
    pthread_t thread;															/*pmd处理线程*/
    unsigned core_id;               /* CPU core id of this pmd thread. */		/*pmd线程用的逻辑核id*/
    int numa_id;                    /* numa node id of this pmd thread. */		/*numa id*/
    bool isolated;																/*pmd关联了队列设置为隔离的*/

    /* Queue id used by this pmd thread to send packets on all netdevs if
     * XPS disabled for this netdev. All static_tx_qid's are unique and less
     * than 'cmap_count(dp->poll_threads)'. */
    uint32_t static_tx_qid;														/*静态发送队列id*/

    /* Number of filled output batches. */
    int n_output_batches;														/*发出的批处理报文计数*/

    struct ovs_mutex port_mutex;    /* Mutex for 'poll_list' and 'tx_ports'. */
    /* List of rx queues to poll. */
    struct hmap poll_list OVS_GUARDED;											/*用来poll的接收队列*/
    /* Map of 'tx_port's used for transmission.  Written by the main thread,
     * read by the pmd thread. */
    struct hmap tx_ports OVS_GUARDED;											/*发送端口哈希链*/

    /* These are thread-local copies of 'tx_ports'.  One contains only tunnel
     * ports (that support push_tunnel/pop_tunnel), the other contains ports
     * with at least one txq (that support send).  A port can be in both.
     *
     * There are two separate maps to make sure that we don't try to execute
     * OUTPUT on a device which has 0 txqs or PUSH/POP on a non-tunnel device.
     *
     * The instances for cpu core NON_PMD_CORE_ID can be accessed by multiple
     * threads, and thusly need to be protected by 'non_pmd_mutex'.  Every
     * other instance will only be accessed by its own pmd thread. */
    struct hmap tnl_port_cache;
    struct hmap send_port_cache;												/*发端口cache*/

    /* Keep track of detailed PMD performance statistics. */
    struct pmd_perf_stats perf_stats;											/*pmd线程流量统计*/

    /* Set to true if the pmd thread needs to be reloaded. */
    bool need_reload;															/*如果pmd需要 reload 设置true*/
};

/* Interface to netdev-based datapath. */
/*数据面结构 */
struct dpif_netdev {
    //struct dpif dpif;			/*ovs 数据面接口*/
	struct dpif dpif_zwl;		/*ovs 数据面接口*/
    struct dp_netdev *dp;		/*dp结构*/
    uint64_t last_port_seq;		/*最近更新过的端口序号*/
};

static int get_port_by_number(struct dp_netdev *dp, odp_port_t port_no,
                              struct dp_netdev_port **portp)
    OVS_REQUIRES(dp->port_mutex);
static int get_port_by_name(struct dp_netdev *dp, const char *devname,
                            struct dp_netdev_port **portp)
    OVS_REQUIRES(dp->port_mutex);
static void dp_netdev_free(struct dp_netdev *)
    OVS_REQUIRES(dp_netdev_mutex);
static int do_add_port(struct dp_netdev *dp, const char *devname,
                       const char *type, odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex);
static void do_del_port(struct dp_netdev *dp, struct dp_netdev_port *)
    OVS_REQUIRES(dp->port_mutex);
static int dpif_netdev_open(const struct dpif_class *, const char *name,
                            bool create, struct dpif **);
static void dp_netdev_execute_actions(struct dp_netdev_pmd_thread *pmd,
                                      struct dp_packet_batch *,
                                      bool should_steal,
                                      const struct flow *flow,
                                      const struct nlattr *actions,
                                      size_t actions_len);
static void dp_netdev_input(struct dp_netdev_pmd_thread *,
                            struct dp_packet_batch *, odp_port_t port_no);
static void dp_netdev_recirculate(struct dp_netdev_pmd_thread *,
                                  struct dp_packet_batch *);

static void dp_netdev_disable_upcall(struct dp_netdev *);
static void dp_netdev_pmd_reload_done(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_configure_pmd(struct dp_netdev_pmd_thread *pmd,
                                    struct dp_netdev *dp, unsigned core_id,
                                    int numa_id);
static void dp_netdev_destroy_pmd(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_set_nonpmd(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex);

static void *pmd_thread_main(void *);
static struct dp_netdev_pmd_thread *dp_netdev_get_pmd(struct dp_netdev *dp,
                                                      unsigned core_id);
static struct dp_netdev_pmd_thread *
dp_netdev_pmd_get_next(struct dp_netdev *dp, struct cmap_position *pos);
static void dp_netdev_del_pmd(struct dp_netdev *dp,
                              struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_destroy_all_pmds(struct dp_netdev *dp, bool non_pmd);
static void dp_netdev_pmd_clear_ports(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_add_port_tx_to_pmd(struct dp_netdev_pmd_thread *pmd,
                                         struct dp_netdev_port *port)
    OVS_REQUIRES(pmd->port_mutex);
static void dp_netdev_del_port_tx_from_pmd(struct dp_netdev_pmd_thread *pmd,
                                           struct tx_port *tx)
    OVS_REQUIRES(pmd->port_mutex);
static void dp_netdev_add_rxq_to_pmd(struct dp_netdev_pmd_thread *pmd,
                                     struct dp_netdev_rxq *rxq)
    OVS_REQUIRES(pmd->port_mutex);
static void dp_netdev_del_rxq_from_pmd(struct dp_netdev_pmd_thread *pmd,
                                       struct rxq_poll *poll)
    OVS_REQUIRES(pmd->port_mutex);
static int
dp_netdev_pmd_flush_output_packets(struct dp_netdev_pmd_thread *pmd,
                                   bool force);

static void reconfigure_datapath(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex);
static bool dp_netdev_pmd_try_ref(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_pmd_unref(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_pmd_flow_flush(struct dp_netdev_pmd_thread *pmd);
static void pmd_load_cached_ports(struct dp_netdev_pmd_thread *pmd)
    OVS_REQUIRES(pmd->port_mutex);
static inline void
dp_netdev_pmd_try_optimize(struct dp_netdev_pmd_thread *pmd,
                           struct polled_queue *poll_list, int poll_cnt);
static void
dp_netdev_rxq_set_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type,
                         unsigned long long cycles);
static uint64_t
dp_netdev_rxq_get_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type);
static void
dp_netdev_rxq_set_intrvl_cycles(struct dp_netdev_rxq *rx,
                           unsigned long long cycles);
static uint64_t
dp_netdev_rxq_get_intrvl_cycles(struct dp_netdev_rxq *rx, unsigned idx);
static void
dpif_netdev_xps_revalidate_pmd(const struct dp_netdev_pmd_thread *pmd,
                               bool purge);
static int dpif_netdev_xps_get_tx_qid(const struct dp_netdev_pmd_thread *pmd,
                                      struct tx_port *tx);

static inline bool emc_entry_alive(struct emc_entry *ce);
static void emc_clear_entry(struct emc_entry *ce);
static void smc_clear_entry(struct smc_bucket *b, int idx);

static void dp_netdev_request_reconfigure(struct dp_netdev *dp);
static inline bool
pmd_perf_metrics_enabled(const struct dp_netdev_pmd_thread *pmd);
static void queue_netdev_flow_del(struct dp_netdev_pmd_thread *pmd,
                                  struct dp_netdev_flow *flow);

static void
emc_cache_init(struct emc_cache *flow_cache)
{
    int i;

    flow_cache->sweep_idx = 0;
    for (i = 0; i < ARRAY_SIZE(flow_cache->entries); i++) {
        flow_cache->entries[i].flow = NULL;
        flow_cache->entries[i].key.hash = 0;
        flow_cache->entries[i].key.len = sizeof(struct miniflow);
        flowmap_init(&flow_cache->entries[i].key.mf.map);
    }
}

/*******************************************************************************
 函数名称  :    emc_cache_slow_sweep
 功能描述  :    smc bucket初始化
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
smc_cache_init(struct smc_cache *smc_cache)
{
    int i, j;

	/*smc 桶与桶深初始化，桶=1u << 20 /4 = 1048576*/
    for (i = 0; i < SMC_BUCKET_CNT; i++) 
	{
		/*桶深是4*/
        for (j = 0; j < SMC_ENTRY_PER_BUCKET; j++) 
		{
            smc_cache->buckets[i].flow_idx[j] = UINT16_MAX;
        }
    }
}

/*******************************************************************************
 函数名称  :    dfc_cache_init
 功能描述  :    emc缓存、smc缓存初始化
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
dfc_cache_init(struct dfc_cache *flow_cache)
{
	/*emc流表初始化*/
    emc_cache_init(&flow_cache->emc_cache);

	/*smc流表初始化*/
    smc_cache_init(&flow_cache->smc_cache);
}

static void
emc_cache_uninit(struct emc_cache *flow_cache)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(flow_cache->entries); i++) {
        emc_clear_entry(&flow_cache->entries[i]);
    }
}

/*******************************************************************************
 函数名称  :  smc_cache_uninit
 功能描述  :  smc表 clear
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
smc_cache_uninit(struct smc_cache *smc)
{
    int i, j;

	/*smc流表索引缓存桶1<<20/4*/
    for (i = 0; i < SMC_BUCKET_CNT; i++) {

		/*桶深是4*/
        for (j = 0; j < SMC_ENTRY_PER_BUCKET; j++) {
			
			/*缓存的流表index 清掉*/
            smc_clear_entry(&(smc->buckets[i]), j);
        }
    }
}

/*******************************************************************************
 函数名称  :  dfc_cache_uninit
 功能描述  :  pmd缓存smc emc 流表项索引清掉
 输入参数  :  flow_cache---流缓存
 			  
 输出参数  :  
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static void
dfc_cache_uninit(struct dfc_cache *flow_cache)
{
	/*smc表 clear*/
    smc_cache_uninit(&flow_cache->smc_cache);
	
	/*emc流表clear*/
    emc_cache_uninit(&flow_cache->emc_cache);
}

/* Check and clear dead flow references slowly (one entry at each
 * invocation).  */
 

/*******************************************************************************
 函数名称  :    emc_cache_slow_sweep
 功能描述  :    emc流表删除
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
emc_cache_slow_sweep(struct emc_cache *flow_cache)
{
	/*8192个entry中获取新的entry*/
    struct emc_entry *entry = &flow_cache->entries[flow_cache->sweep_idx];

	/*emc流表存在 且 活着*/
    if (!emc_entry_alive(entry)) 
	{
		/*emc流表删除*/
        emc_clear_entry(entry);
    }

	/*8192个entry hash出一个 作为老化entry index*/
    flow_cache->sweep_idx = (flow_cache->sweep_idx + 1) & EM_FLOW_HASH_MASK;
}

/* Updates the time in PMD threads context and should be called in three cases:
 *
 *     1. PMD structure initialization:
 *         - dp_netdev_configure_pmd()
 *
 *     2. Before processing of the new packet batch:
 *         - dpif_netdev_execute()
 *         - dp_netdev_process_rxq_port()
 *
 *     3. At least once per polling iteration in main polling threads if no
 *        packets received on current iteration:
 *         - dpif_netdev_run()
 *         - pmd_thread_main()
 *
 * 'pmd->ctx.now' should be used without update in all other cases if possible.
 */

/*******************************************************************************
 函数名称  :    pmd_thread_ctx_time_update
 功能描述  :    pmd线程上下文更新
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
static inline void
pmd_thread_ctx_time_update(struct dp_netdev_pmd_thread *pmd)
{
    pmd->ctx.now = time_usec();
}

/*******************************************************************************
 函数名称  :    dpif_is_netdev
 功能描述  :    dp接口 open函数是否是dpif_netdev_open
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Returns true if 'dpif' is a netdev or dummy dpif, false otherwise. */
bool
dpif_is_netdev(const struct dpif *dpif)
{
    return dpif->dpif_class->open == dpif_netdev_open;
}

/*******************************************************************************
 函数名称  :    dpif_netdev_cast
 功能描述  :    返回dp 接口结构首地址
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static struct dpif_netdev *
dpif_netdev_cast(const struct dpif *dpif)
{
    ovs_assert(dpif_is_netdev(dpif));

	/*返回dp 接口结构首地址*/
    return CONTAINER_OF(dpif, struct dpif_netdev, dpif);
}

/*******************************************************************************
 函数名称  :    get_dp_netdev
 功能描述  :    获取数据面的dp结构
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
static struct dp_netdev *
get_dp_netdev(const struct dpif *dpif)
{
	/*根据dpif 返回dp netdev结构*/
    return dpif_netdev_cast(dpif)->dp;
}

enum pmd_info_type {
    PMD_INFO_SHOW_STATS,  /* Show how cpu cycles are spent. */
    PMD_INFO_CLEAR_STATS, /* Set the cycles count to 0. */
    PMD_INFO_SHOW_RXQ,    /* Show poll lists of pmd threads. */
    PMD_INFO_PERF_SHOW,   /* Show pmd performance details. */
};

static void
format_pmd_thread(struct ds *reply, struct dp_netdev_pmd_thread *pmd)
{
    ds_put_cstr(reply, (pmd->core_id == NON_PMD_CORE_ID)
                        ? "main thread" : "pmd thread");
    if (pmd->numa_id != OVS_NUMA_UNSPEC) {
        ds_put_format(reply, " numa_id %d", pmd->numa_id);
    }
    if (pmd->core_id != OVS_CORE_UNSPEC && pmd->core_id != NON_PMD_CORE_ID) {
        ds_put_format(reply, " core_id %u", pmd->core_id);
    }
    ds_put_cstr(reply, ":\n");
}

static void
pmd_info_show_stats(struct ds *reply,
                    struct dp_netdev_pmd_thread *pmd)
{
    uint64_t stats[PMD_N_STATS];
    uint64_t total_cycles, total_packets;
    double passes_per_pkt = 0;
    double lookups_per_hit = 0;
    double packets_per_batch = 0;

    pmd_perf_read_counters(&pmd->perf_stats, stats);
    total_cycles = stats[PMD_CYCLES_ITER_IDLE]
                         + stats[PMD_CYCLES_ITER_BUSY];
    total_packets = stats[PMD_STAT_RECV];

    format_pmd_thread(reply, pmd);

    if (total_packets > 0) {
        passes_per_pkt = (total_packets + stats[PMD_STAT_RECIRC])
                            / (double) total_packets;
    }
    if (stats[PMD_STAT_MASKED_HIT] > 0) {
        lookups_per_hit = stats[PMD_STAT_MASKED_LOOKUP]
                            / (double) stats[PMD_STAT_MASKED_HIT];
    }
    if (stats[PMD_STAT_SENT_BATCHES] > 0) {
        packets_per_batch = stats[PMD_STAT_SENT_PKTS]
                            / (double) stats[PMD_STAT_SENT_BATCHES];
    }

    ds_put_format(reply,
                  "  packets received: %"PRIu64"\n"
                  "  packet recirculations: %"PRIu64"\n"
                  "  avg. datapath passes per packet: %.02f\n"
                  "  emc hits: %"PRIu64"\n"
                  "  smc hits: %"PRIu64"\n"
                  "  megaflow hits: %"PRIu64"\n"
                  "  avg. subtable lookups per megaflow hit: %.02f\n"
                  "  miss with success upcall: %"PRIu64"\n"
                  "  miss with failed upcall: %"PRIu64"\n"
                  "  avg. packets per output batch: %.02f\n",
                  total_packets, stats[PMD_STAT_RECIRC],
                  passes_per_pkt, stats[PMD_STAT_EXACT_HIT],
                  stats[PMD_STAT_SMC_HIT],
                  stats[PMD_STAT_MASKED_HIT], lookups_per_hit,
                  stats[PMD_STAT_MISS], stats[PMD_STAT_LOST],
                  packets_per_batch);

    if (total_cycles == 0) {
        return;
    }

    ds_put_format(reply,
                  "  idle cycles: %"PRIu64" (%.02f%%)\n"
                  "  processing cycles: %"PRIu64" (%.02f%%)\n",
                  stats[PMD_CYCLES_ITER_IDLE],
                  stats[PMD_CYCLES_ITER_IDLE] / (double) total_cycles * 100,
                  stats[PMD_CYCLES_ITER_BUSY],
                  stats[PMD_CYCLES_ITER_BUSY] / (double) total_cycles * 100);

    if (total_packets == 0) {
        return;
    }

    ds_put_format(reply,
                  "  avg cycles per packet: %.02f (%"PRIu64"/%"PRIu64")\n",
                  total_cycles / (double) total_packets,
                  total_cycles, total_packets);

    ds_put_format(reply,
                  "  avg processing cycles per packet: "
                  "%.02f (%"PRIu64"/%"PRIu64")\n",
                  stats[PMD_CYCLES_ITER_BUSY] / (double) total_packets,
                  stats[PMD_CYCLES_ITER_BUSY], total_packets);
}

/*******************************************************************************
 函数名称  :    emc_cache_slow_sweep
 功能描述  :    emc流表删除
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
pmd_info_show_perf(struct ds *reply,
                   struct dp_netdev_pmd_thread *pmd,
                   struct pmd_perf_params *par)
{
    if (pmd->core_id != NON_PMD_CORE_ID) {
        char *time_str =
                xastrftime_msec("%H:%M:%S.###", time_wall_msec(), true);
        long long now = time_msec();
        double duration = (now - pmd->perf_stats.start_ms) / 1000.0;

        ds_put_cstr(reply, "\n");
        ds_put_format(reply, "Time: %s\n", time_str);
        ds_put_format(reply, "Measurement duration: %.3f s\n", duration);
        ds_put_cstr(reply, "\n");
        format_pmd_thread(reply, pmd);
        ds_put_cstr(reply, "\n");

		
        pmd_perf_format_overall_stats(reply, &pmd->perf_stats, duration);
        if (pmd_perf_metrics_enabled(pmd)) {
            /* Prevent parallel clearing of perf metrics. */
            ovs_mutex_lock(&pmd->perf_stats.clear_mutex);
            if (par->histograms) {
                ds_put_cstr(reply, "\n");
                pmd_perf_format_histograms(reply, &pmd->perf_stats);
            }
            if (par->iter_hist_len > 0) {
                ds_put_cstr(reply, "\n");
                pmd_perf_format_iteration_history(reply, &pmd->perf_stats,
                        par->iter_hist_len);
            }
            if (par->ms_hist_len > 0) {
                ds_put_cstr(reply, "\n");
                pmd_perf_format_ms_history(reply, &pmd->perf_stats,
                        par->ms_hist_len);
            }
            ovs_mutex_unlock(&pmd->perf_stats.clear_mutex);
        }
        free(time_str);
    }
}

static int
compare_poll_list(const void *a_, const void *b_)
{
    const struct rxq_poll *a = a_;
    const struct rxq_poll *b = b_;

    const char *namea = netdev_rxq_get_name(a->rxq->rx);
    const char *nameb = netdev_rxq_get_name(b->rxq->rx);

    int cmp = strcmp(namea, nameb);
    if (!cmp) {
        return netdev_rxq_get_queue_id(a->rxq->rx)
               - netdev_rxq_get_queue_id(b->rxq->rx);
    } else {
        return cmp;
    }
}

static void
sorted_poll_list(struct dp_netdev_pmd_thread *pmd, struct rxq_poll **list,
                 size_t *n)
{
    struct rxq_poll *ret, *poll;
    size_t i;

    *n = hmap_count(&pmd->poll_list);
    if (!*n) {
        ret = NULL;
    } else {
        ret = xcalloc(*n, sizeof *ret);
        i = 0;
        HMAP_FOR_EACH (poll, node, &pmd->poll_list) {
            ret[i] = *poll;
            i++;
        }
        ovs_assert(i == *n);
        qsort(ret, *n, sizeof *ret, compare_poll_list);
    }

    *list = ret;
}

static void
pmd_info_show_rxq(struct ds *reply, struct dp_netdev_pmd_thread *pmd)
{
    if (pmd->core_id != NON_PMD_CORE_ID) {
        struct rxq_poll *list;
        size_t n_rxq;
        uint64_t total_cycles = 0;

        ds_put_format(reply,
                      "pmd thread numa_id %d core_id %u:\n  isolated : %s\n",
                      pmd->numa_id, pmd->core_id, (pmd->isolated)
                                                  ? "true" : "false");

        ovs_mutex_lock(&pmd->port_mutex);
        sorted_poll_list(pmd, &list, &n_rxq);

        /* Get the total pmd cycles for an interval. */
        atomic_read_relaxed(&pmd->intrvl_cycles, &total_cycles);
        /* Estimate the cycles to cover all intervals. */
        total_cycles *= PMD_RXQ_INTERVAL_MAX;

        for (int i = 0; i < n_rxq; i++) {
            struct dp_netdev_rxq *rxq = list[i].rxq;
            const char *name = netdev_rxq_get_name(rxq->rx);
            uint64_t proc_cycles = 0;

            for (int j = 0; j < PMD_RXQ_INTERVAL_MAX; j++) {
                proc_cycles += dp_netdev_rxq_get_intrvl_cycles(rxq, j);
            }
            ds_put_format(reply, "  port: %-16s  queue-id: %2d", name,
                          netdev_rxq_get_queue_id(list[i].rxq->rx));
            ds_put_format(reply, "  pmd usage: ");
            if (total_cycles) {
                ds_put_format(reply, "%2"PRIu64"",
                              proc_cycles * 100 / total_cycles);
                ds_put_cstr(reply, " %");
            } else {
                ds_put_format(reply, "%s", "NOT AVAIL");
            }
            ds_put_cstr(reply, "\n");
        }
        ovs_mutex_unlock(&pmd->port_mutex);
        free(list);
    }
}

static int
compare_poll_thread_list(const void *a_, const void *b_)
{
    const struct dp_netdev_pmd_thread *a, *b;

    a = *(struct dp_netdev_pmd_thread **)a_;
    b = *(struct dp_netdev_pmd_thread **)b_;

    if (a->core_id < b->core_id) {
        return -1;
    }
    if (a->core_id > b->core_id) {
        return 1;
    }
    return 0;
}

/* Create a sorted list of pmd's from the dp->poll_threads cmap. We can use
 * this list, as long as we do not go to quiescent state. */
static void
sorted_poll_thread_list(struct dp_netdev *dp,
                        struct dp_netdev_pmd_thread ***list,
                        size_t *n)
{
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev_pmd_thread **pmd_list;
    size_t k = 0, n_pmds;

    n_pmds = cmap_count(&dp->poll_threads);
    pmd_list = xcalloc(n_pmds, sizeof *pmd_list);

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (k >= n_pmds) {
            break;
        }
        pmd_list[k++] = pmd;
    }

    qsort(pmd_list, k, sizeof *pmd_list, compare_poll_thread_list);

    *list = pmd_list;
    *n = k;
}

static void
dpif_netdev_pmd_rebalance(struct unixctl_conn *conn, int argc,
                          const char *argv[], void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct dp_netdev *dp = NULL;

    ovs_mutex_lock(&dp_netdev_mutex);

    if (argc == 2) {
        dp = shash_find_data(&dp_netdevs, argv[1]);
    } else if (shash_count(&dp_netdevs) == 1) {
        /* There's only one datapath */
        dp = shash_first(&dp_netdevs)->data;
    }

    if (!dp) {
        ovs_mutex_unlock(&dp_netdev_mutex);
        unixctl_command_reply_error(conn,
                                    "please specify an existing datapath");
        return;
    }

    dp_netdev_request_reconfigure(dp);
    ovs_mutex_unlock(&dp_netdev_mutex);
    ds_put_cstr(&reply, "pmd rxq rebalance requested.\n");
    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

/*******************************************************************************
 函数名称  :    dpif_netdev_pmd_info
 功能描述  :    emc流表删除
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
dpif_netdev_pmd_info(struct unixctl_conn *conn, int argc, const char *argv[],
                     void *aux)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct dp_netdev_pmd_thread **pmd_list;
    struct dp_netdev *dp = NULL;
    enum pmd_info_type type = *(enum pmd_info_type *) aux;
    unsigned int core_id;
    bool filter_on_pmd = false;
    size_t n;

    ovs_mutex_lock(&dp_netdev_mutex);

    while (argc > 1) {

		/*指定了pmd*/
        if (!strcmp(argv[1], "-pmd") && argc > 2) {
            if (str_to_uint(argv[2], 10, &core_id)) {
                filter_on_pmd = true;
            }
            argc -= 2;
            argv += 2;
        } else {
            dp = shash_find_data(&dp_netdevs, argv[1]);
            argc -= 1;
            argv += 1;
        }
    }

    if (!dp) {
        if (shash_count(&dp_netdevs) == 1) {
            /* There's only one datapath */
            dp = shash_first(&dp_netdevs)->data;
        } else {
            ovs_mutex_unlock(&dp_netdev_mutex);
            unixctl_command_reply_error(conn,
                                        "please specify an existing datapath");
            return;
        }
    }

    sorted_poll_thread_list(dp, &pmd_list, &n);

	/*遍历所有pmd*/
    for (size_t i = 0; i < n; i++) {
        struct dp_netdev_pmd_thread *pmd = pmd_list[i];
        if (!pmd) {
            break;
        }
        if (filter_on_pmd && pmd->core_id != core_id) {
            continue;
        }
        if (type == PMD_INFO_SHOW_RXQ) {
            pmd_info_show_rxq(&reply, pmd);
        } else if (type == PMD_INFO_CLEAR_STATS) {
            pmd_perf_stats_clear(&pmd->perf_stats);
        } else if (type == PMD_INFO_SHOW_STATS) {
            pmd_info_show_stats(&reply, pmd);
        } else if (type == PMD_INFO_PERF_SHOW) {

			/*perf show*/
            pmd_info_show_perf(&reply, pmd, (struct pmd_perf_params *)aux);
        }
    }
    free(pmd_list);

    ovs_mutex_unlock(&dp_netdev_mutex);

    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

/*******************************************************************************
 函数名称  :    emc_cache_slow_sweep
 功能描述  :    emc流表删除
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
pmd_perf_show_cmd(struct unixctl_conn *conn, int argc,
                          const char *argv[],
                          void *aux OVS_UNUSED)
{
    struct pmd_perf_params par;
    long int it_hist = 0, ms_hist = 0;
    par.histograms = true;

    while (argc > 1) {
        if (!strcmp(argv[1], "-nh")) {
            par.histograms = false;
            argc -= 1;
            argv += 1;
        } else if (!strcmp(argv[1], "-it") && argc > 2) {
            it_hist = strtol(argv[2], NULL, 10);
            if (it_hist < 0) {
                it_hist = 0;
            } else if (it_hist > HISTORY_LEN) {
                it_hist = HISTORY_LEN;
            }
            argc -= 2;
            argv += 2;
        } else if (!strcmp(argv[1], "-ms") && argc > 2) {
            ms_hist = strtol(argv[2], NULL, 10);
            if (ms_hist < 0) {
                ms_hist = 0;
            } else if (ms_hist > HISTORY_LEN) {
                ms_hist = HISTORY_LEN;
            }
            argc -= 2;
            argv += 2;
        } else {
            break;
        }
    }
    par.iter_hist_len = it_hist;
    par.ms_hist_len = ms_hist;
    par.command_type = PMD_INFO_PERF_SHOW;
    dpif_netdev_pmd_info(conn, argc, argv, &par);
}

/*******************************************************************************
 函数名称  :    dpif_netdev_init
 功能描述  :    dpif命令行函数注册
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
dpif_netdev_init(void)
{
    static enum pmd_info_type show_aux = PMD_INFO_SHOW_STATS,
                              clear_aux = PMD_INFO_CLEAR_STATS,
                              poll_aux = PMD_INFO_SHOW_RXQ;

	/*流量统计*/
    unixctl_command_register("dpif-netdev/pmd-stats-show", "[-pmd core] [dp]",
                             0, 3, dpif_netdev_pmd_info,
                             (void *)&show_aux);

	/*流量清除*/
	unixctl_command_register("dpif-netdev/pmd-stats-clear", "[-pmd core] [dp]",
                             0, 3, dpif_netdev_pmd_info,
                             (void *)&clear_aux);

	/*pmd rx队列信息*/
    unixctl_command_register("dpif-netdev/pmd-rxq-show", "[-pmd core] [dp]",
                             0, 3, dpif_netdev_pmd_info,
                             (void *)&poll_aux);

	/*pmd 流量速率*/
	unixctl_command_register("dpif-netdev/pmd-perf-show",
                             "[-nh] [-it iter-history-len]"
                             " [-ms ms-history-len]"
                             " [-pmd core] [dp]",
                             0, 8, pmd_perf_show_cmd,
                             NULL);

	/*队列重新调整*/
	unixctl_command_register("dpif-netdev/pmd-rxq-rebalance", "[dp]",
                             0, 1, dpif_netdev_pmd_rebalance,
                             NULL);
	/*log*/
	unixctl_command_register("dpif-netdev/pmd-perf-log-set",
                             "on|off [-b before] [-a after] [-e|-ne] "
                             "[-us usec] [-q qlen]",
                             0, 10, pmd_perf_log_set_cmd,
                             NULL);
    return 0;
}

/*******************************************************************************
 函数名称  :    dpif_netdev_enumerate
 功能描述  :    emc流表删除
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
dpif_netdev_enumerate(struct sset *all_dps,
                      const struct dpif_class *dpif_class)
{
    struct shash_node *node;

    ovs_mutex_lock(&dp_netdev_mutex);
    SHASH_FOR_EACH(node, &dp_netdevs) {
        struct dp_netdev *dp = node->data;
        if (dpif_class != dp->class) {
            /* 'dp_netdevs' contains both "netdev" and "dummy" dpifs.
             * If the class doesn't match, skip this dpif. */
             continue;
        }
        sset_add(all_dps, node->name);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    return 0;
}

static bool
dpif_netdev_class_is_dummy(const struct dpif_class *class)
{
    return class != &dpif_netdev_class;
}

/*******************************************************************************
 函数名称  :    dpif_netdev_port_open_type
 功能描述  :    打开
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static const char *
dpif_netdev_port_open_type(const struct dpif_class *class, const char *type)
{
    return strcmp(type, "internal") ? type
                  : dpif_netdev_class_is_dummy(class) ? "dummy-internal"
                  : "tap";
}

/*******************************************************************************
 函数名称  :    create_dpif_netdev
 功能描述  :    创建dpif接口 并初始化
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static struct dpif *
create_dpif_netdev(struct dp_netdev *dp)
{
    uint16_t netflow_id = hash_string(dp->name, 0);
    struct dpif_netdev *dpif;

	/*dp引用*/
    ovs_refcount_ref(&dp->ref_cnt);

	/*dp接口申请*/
    dpif = xmalloc(sizeof *dpif);

	/*dp 接口描述结构初始化*/
    dpif_init(&dpif->dpif, dp->class, dp->name, netflow_id >> 8, netflow_id);

	/*dp 接口*/
	dpif->dp = dp;

	/*dp接口序列号*/
    dpif->last_port_seq = seq_read(dp->port_seq);

    return &dpif->dpif;
}

/*******************************************************************************
 函数名称  :    choose_port
 功能描述  :    选择一个未使用的port，非0端口
 输入参数  :  	dp---数据面
 				name---vport 对应的 dpif port name
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Choose an unused, non-zero port number and return it on success.
 * Return ODPP_NONE on failure. */
static odp_port_t
choose_port(struct dp_netdev *dp, const char *name)
    OVS_REQUIRES(dp->port_mutex)
{
    uint32_t port_no;

	/*数据面类不是 数据面接口操作类*/
    if (dp->class != &dpif_netdev_class) 
	{
        const char *p;
        int start_no = 0;

        /* If the port name begins with "br", start the number search at
         * 100 to make writing tests easier. */

		/*网桥启始端口设置100*/
        if (!strncmp(name, "br", 2)) 
		{
            start_no = 100;
        }

		
        /* If the port name contains a number, try to assign that port number.
         * This can make writing unit tests easier because port numbers are
         * predictable. */

		
        for (p = name; *p != '\0'; p++) 
		{
            if (isdigit((unsigned char) *p)) 
			{
				/*提取port name中带的port number*/
                port_no = start_no + strtol(p, NULL, 10);

				/*端口号不合法 或 dp找不到对应端口*/
				if (port_no > 0 && port_no != odp_to_u32(ODPP_NONE) && !dp_netdev_lookup_port(dp, u32_to_odp(port_no))) 
                {
                    return u32_to_odp(port_no);
                }
				
                break;
            }
        }
    }

	/*遍历端口号找对应port*/
    for (port_no = 1; port_no <= UINT16_MAX; port_no++) 
	{
		/*根据端口号找到对应port*/
        if (!dp_netdev_lookup_port(dp, u32_to_odp(port_no))) 
		{
            return u32_to_odp(port_no);
        }
    }

    return ODPP_NONE;
}

/*******************************************************************************
 函数名称  :    create_dp_netdev
 功能描述  :    创建dp netdev的node，挂入dp全局结构dp_netdevs
 输入参数  :  	name---dp name  backer name ovs-netdev，网桥name br0
 				class---dp对应的class
 				key---skb提取的key
 				dpp---打开或创建的netdev
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
create_dp_netdev(const char *name, const struct dpif_class *class,
                 struct dp_netdev **dpp)
    OVS_REQUIRES(dp_netdev_mutex)
{
	/*dp对应的netdev*/
    struct dp_netdev *dp;
    int error;

	/*申请dp 结构内存*/
    dp = xzalloc(sizeof *dp);

	/*挂到全局dp_netdev链表，name是ovs-netdev*/
    shash_add(&dp_netdevs, name, dp);

	/*dp赋值和初始化*/
    *CONST_CAST(const struct dpif_class **, &dp->class) = class;

	/*backer对应 dp_netdev的name 为ovs-netdev*/
	*CONST_CAST(const char **, &dp->name) = xstrdup(name);

	/*dp引用次数*/
	ovs_refcount_init(&dp->ref_cnt);
	
    atomic_flag_clear(&dp->destroyed);

    ovs_mutex_init(&dp->port_mutex);

	/*dp_netdev下port初始化*/
    hmap_init(&dp->ports);
	
    dp->port_seq = seq_create();
    fat_rwlock_init(&dp->upcall_rwlock);

	/*配置序列号*/
    dp->reconfigure_seq = seq_create();
    dp->last_reconfigure_seq = seq_read(dp->reconfigure_seq);

	/*meter锁初始化*/
    for (int i = 0; i < N_METER_LOCKS; ++i) {
        ovs_mutex_init_adaptive(&dp->meter_locks[i]);
    }

	/*关掉upcall*/
    /* Disable upcalls by default. */
    dp_netdev_disable_upcall(dp);
    dp->upcall_aux = NULL;
    dp->upcall_cb = NULL;

	/*dp_netdev对应链接跟踪初始化*/
    conntrack_init(&dp->conntrack);

    atomic_init(&dp->emc_insert_min, DEFAULT_EM_FLOW_INSERT_MIN);
    atomic_init(&dp->tx_flush_interval, DEFAULT_TX_FLUSH_INTERVAL);

    cmap_init(&dp->poll_threads);

    ovs_mutex_init(&dp->tx_qid_pool_mutex);
    /* We need 1 Tx queue for each possible core + 1 for non-PMD threads. */
    dp->tx_qid_pool = id_pool_create(0, ovs_numa_get_n_cores() + 1);

    ovs_mutex_init_recursive(&dp->non_pmd_mutex);
    ovsthread_key_create(&dp->per_pmd_key, NULL);

    ovs_mutex_lock(&dp->port_mutex);
    /* non-PMD will be created before all other threads and will
     * allocate static_tx_qid = 0. */

	dp_netdev_set_nonpmd(dp);

	/*打开port  添加vport 到dp 下port链表，网桥名相同的internal 端口*/
    error = do_add_port(dp, name, dpif_netdev_port_open_type(dp->class, "internal"), ODPP_LOCAL);
    ovs_mutex_unlock(&dp->port_mutex);
    if (error) {
        dp_netdev_free(dp);
        return error;
    }

    dp->last_tnl_conf_seq = seq_read(tnl_conf_seq);
    *dpp = dp;
    return 0;
}

/*******************************************************************************
 函数名称  :    dp_netdev_request_reconfigure
 功能描述  :    设置了亲和性，改变dp 重配序号，请求dp重新配置
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
dp_netdev_request_reconfigure(struct dp_netdev *dp)
{
    seq_change(dp->reconfigure_seq);
}

static bool
dp_netdev_is_reconf_required(struct dp_netdev *dp)
{
    return seq_read(dp->reconfigure_seq) != dp->last_reconfigure_seq;
}

/*******************************************************************************
 函数名称  :    dpif_netdev_open
 功能描述  :    打开netdev函数
 输入参数  :  	class
 				name---dp name，backer name ovs-netdev，网桥name br0
 				dpifp
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static int
dpif_netdev_open(const struct dpif_class *class, const char *name,
                 bool create, struct dpif **dpifp)
{
    struct dp_netdev *dp;
    int error;

    ovs_mutex_lock(&dp_netdev_mutex);

	/*根据name 找到dp_netdev node，name是backer name ovs-netdev，自定义name br0*/
    dp = shash_find_data(&dp_netdevs, name);
    if (!dp) 
	{
		/*没找到创建netdev类型的dp_netdev node，name是backer name ovs-netdev或br name*/
        error = create ? create_dp_netdev(name, class, &dp) : ENODEV;
    }
	else 
	{
		/*已存在*/
        error = (dp->class != class ? EINVAL
                 : create ? EEXIST
                 : 0);
    }

	/*创建dp netdev*/
	if (!error) 
	{
		/*dp_netdev创建对应的dpifp，接口结构创建并初始化*/
        *dpifp = create_dpif_netdev(dp);
        dp->dpif = *dpifp;
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    return error;
}

static void
dp_netdev_destroy_upcall_lock(struct dp_netdev *dp)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    /* Check that upcalls are disabled, i.e. that the rwlock is taken */
    ovs_assert(fat_rwlock_tryrdlock(&dp->upcall_rwlock));

    /* Before freeing a lock we should release it */
    fat_rwlock_unlock(&dp->upcall_rwlock);
    fat_rwlock_destroy(&dp->upcall_rwlock);
}

/*******************************************************************************
 函数名称  :    dp_delete_meter
 功能描述  :    meter 删除
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
dp_delete_meter(struct dp_netdev *dp, uint32_t meter_id)
    OVS_REQUIRES(dp->meter_locks[meter_id % N_METER_LOCKS])
{
	/*dp层软件meter资源存在*/
    if (dp->meters[meter_id]) 
	{
		/*软件meter资源释放*/
        free(dp->meters[meter_id]);
        dp->meters[meter_id] = NULL;
    }
}

/* Requires dp_netdev_mutex so that we can't get a new reference to 'dp'
 * through the 'dp_netdevs' shash while freeing 'dp'. */
static void
dp_netdev_free(struct dp_netdev *dp)
    OVS_REQUIRES(dp_netdev_mutex)
{
    struct dp_netdev_port *port, *next;

    shash_find_and_delete(&dp_netdevs, dp->name);

    ovs_mutex_lock(&dp->port_mutex);
    HMAP_FOR_EACH_SAFE (port, next, node, &dp->ports) {
        do_del_port(dp, port);
    }
    ovs_mutex_unlock(&dp->port_mutex);

    dp_netdev_destroy_all_pmds(dp, true);
    cmap_destroy(&dp->poll_threads);

    ovs_mutex_destroy(&dp->tx_qid_pool_mutex);
    id_pool_destroy(dp->tx_qid_pool);

    ovs_mutex_destroy(&dp->non_pmd_mutex);
    ovsthread_key_delete(dp->per_pmd_key);

    conntrack_destroy(&dp->conntrack);


    seq_destroy(dp->reconfigure_seq);

    seq_destroy(dp->port_seq);
    hmap_destroy(&dp->ports);
    ovs_mutex_destroy(&dp->port_mutex);

    /* Upcalls must be disabled at this point */
    dp_netdev_destroy_upcall_lock(dp);

    int i;

	/*循环删除meter*/
    for (i = 0; i < MAX_METERS; ++i) {
        meter_lock(dp, i);
        dp_delete_meter(dp, i);
        meter_unlock(dp, i);
    }
    for (i = 0; i < N_METER_LOCKS; ++i) {
        ovs_mutex_destroy(&dp->meter_locks[i]);
    }

    free(dp->pmd_cmask);
    free(CONST_CAST(char *, dp->name));
    free(dp);
}

static void
dp_netdev_unref(struct dp_netdev *dp)
{
    if (dp) {
        /* Take dp_netdev_mutex so that, if dp->ref_cnt falls to zero, we can't
         * get a new reference to 'dp' through the 'dp_netdevs' shash. */
        ovs_mutex_lock(&dp_netdev_mutex);
        if (ovs_refcount_unref_relaxed(&dp->ref_cnt) == 1) {
            dp_netdev_free(dp);
        }
        ovs_mutex_unlock(&dp_netdev_mutex);
    }
}

static void
dpif_netdev_close(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    dp_netdev_unref(dp);
    free(dpif);
}

static int
dpif_netdev_destroy(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    if (!atomic_flag_test_and_set(&dp->destroyed)) {
        if (ovs_refcount_unref_relaxed(&dp->ref_cnt) == 1) {
            /* Can't happen: 'dpif' still owns a reference to 'dp'. */
            OVS_NOT_REACHED();
        }
    }

    return 0;
}

/* Add 'n' to the atomic variable 'var' non-atomically and using relaxed
 * load/store semantics.  While the increment is not atomic, the load and
 * store operations are, making it impossible to read inconsistent values.
 *
 * This is used to update thread local stats counters. */
 
static void
non_atomic_ullong_add(atomic_ullong *var, unsigned long long n)
{
    unsigned long long tmp;

    atomic_read_relaxed(var, &tmp);
    tmp += n;
    atomic_store_relaxed(var, tmp);
}

static int
dpif_netdev_get_stats(const struct dpif *dpif, struct dpif_dp_stats *stats)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;
    uint64_t pmd_stats[PMD_N_STATS];

    stats->n_flows = stats->n_hit = stats->n_missed = stats->n_lost = 0;
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        stats->n_flows += cmap_count(&pmd->flow_table);
        pmd_perf_read_counters(&pmd->perf_stats, pmd_stats);
        stats->n_hit += pmd_stats[PMD_STAT_EXACT_HIT];
        stats->n_hit += pmd_stats[PMD_STAT_SMC_HIT];
        stats->n_hit += pmd_stats[PMD_STAT_MASKED_HIT];
        stats->n_missed += pmd_stats[PMD_STAT_MISS];
        stats->n_lost 
        
        += pmd_stats[PMD_STAT_LOST];
    }
    stats->n_masks = UINT32_MAX;
    stats->n_mask_hit = UINT64_MAX;

    return 0;
}

/*******************************************************************************
 函数名称  :    dp_netdev_reload_pmd__
 功能描述  :    reload pmd线程
 				1.发掉pmd缓存的发port节点缓存的报文
 		  		2.申请发端口缓存结构插入pmd发端口缓存链表
 输入参数  :  	pmd---pmd线程
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
dp_netdev_reload_pmd__(struct dp_netdev_pmd_thread *pmd)
{
	/*pmd使用的是非pmd 核，发掉pmd缓存的发port节点缓存的报文、申请发端口缓存结构插入pmd发端口缓存链表*/
    if (pmd->core_id == NON_PMD_CORE_ID) 
	{
        ovs_mutex_lock(&pmd->dp->non_pmd_mutex);
        ovs_mutex_lock(&pmd->port_mutex);

		/*pmd重新加载缓存的发送port*/
		/*1.发掉pmd缓存的发port节点缓存的报文
 		  2.申请发端口缓存结构插入pmd发端口缓存链表*/
        pmd_load_cached_ports(pmd);

		ovs_mutex_unlock(&pmd->port_mutex);
        ovs_mutex_unlock(&pmd->dp->non_pmd_mutex);
		
        return;
    }

    ovs_mutex_lock(&pmd->cond_mutex);

	/*pmd重载序列号更新，序列号+1*/
    seq_change(pmd->reload_seq);

	/*设置pmd reload标记为true，代表已reload*/
	atomic_store_relaxed(&pmd->reload, true);

	ovs_mutex_cond_wait(&pmd->cond, &pmd->cond_mutex);

	ovs_mutex_unlock(&pmd->cond_mutex);
}

static uint32_t
hash_port_no(odp_port_t port_no)
{
    return hash_int(odp_to_u32(port_no), 0);
}

/*******************************************************************************
 函数名称  :    port_create
 功能描述  :    端口创建
 输入参数  :  	devname---端口name，ovs-netdev，网桥name br0
 				type---netdev的类型，"system", "tap", "gre"
 				port_no---端口对应的dp 层端口号
 				portp---指针指向申请的端口
 				
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
port_create(const char *devname, const char *type, odp_port_t port_no, struct dp_netdev_port **portp)
{
	/*网络设备存储flag*/
    struct netdev_saved_flags *sf;
    struct dp_netdev_port *port;
    enum netdev_flags flags;
    struct netdev *netdev;
    int error;

    *portp = NULL;

    /* Open and validate network device. */
	/*创建netdev结构 默认1 txq  1 txq*/
    error = netdev_open(devname, type, &netdev);
    if (error) 
	{
        return error;
    }
    /* XXX reject non-Ethernet devices */

	/*获取flag*/
    netdev_get_flags(netdev, &flags);
    if (flags & NETDEV_LOOPBACK) 
	{
        VLOG_ERR("%s: cannot add a loopback device", devname);
        error = EINVAL;
        goto out;
    }

	/*开启端口混杂模式*/
    error = netdev_turn_flags_on(netdev, NETDEV_PROMISC, &sf);
    if (error) 
	{
        VLOG_ERR("%s: cannot set promisc flag", devname);
        goto out;
    }

	/*申请端口内存*/
    port = xzalloc(sizeof *port);

	/*填入信息*/
    port->port_no = port_no;
    port->netdev = netdev;
    port->type = xstrdup(type);
    port->sf = sf;

	/*需要重新配置网络设备*/
    port->need_reconfigure = true;

	ovs_mutex_init(&port->txq_used_mutex);

    *portp = port;

    return 0;

out:
    netdev_close(netdev);
    return error;
}

/*******************************************************************************
 函数名称  :    do_add_port
 功能描述  :    添加端口，插入网桥dp数据面port链表
 输入参数  :  	dp---数据面结构dp_netdev
 				devname--backer name ovs-netdev，网桥name br0
 				type---netdev的类型，"system", "tap", "gre"
 				port_no---给端口分的dp层端口号
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
do_add_port(struct dp_netdev *dp, const char *devname, const char *type, odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex)
{
	/*要添加的端口*/
    struct dp_netdev_port *port;
    int error;

    /* Reject devices already in 'dp'. */
	/*根据端口name 查找网桥数据面port链表中是否已存在端口*/
    if (!get_port_by_name(dp, devname, &port)) 
	{
        return EEXIST;
    }

	/*不存在port重新创建端口结构 默认1 rxq 1 txq*/
    error = port_create(devname, type, port_no, &port);
    if (error) 
	{
        return error;
    }

	/*端口结构节点插入hmap port 链表*/
    hmap_insert(&dp->ports, &port->node, hash_port_no(port_no));

	/*序列号改变 序列号+1*/
    seq_change(dp->port_seq);

	/*dp端口有变化重新配置网桥*/
    reconfigure_datapath(dp);

    return 0;
}

/*******************************************************************************
 函数名称  :    dpif_netdev_port_add
 功能描述  :    数据面添加端口
 输入参数  :  	dpif---数据面dp接口
 				netdev---描述dp 的网络设备结构
 				port_nop---端口号
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
dpif_netdev_port_add(struct dpif *dpif, struct netdev *netdev, odp_port_t *port_nop)
{
	/*获取数据面dp结构*/
    struct dp_netdev *dp = get_dp_netdev(dpif);

	/*缓存端口name*/
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];

	/*数据面结构端口*/
	const char *dpif_port;

	/*端口号*/
	odp_port_t port_no;

	int error;

    ovs_mutex_lock(&dp->port_mutex);

	/*虚拟端口获取对应 dpif_port*/
    dpif_port = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);

	/*端口号*/
    if (*port_nop != ODPP_NONE) 
	{
        port_no = *port_nop;

		/*根据端口号查找端口*/
        error = dp_netdev_lookup_port(dp, *port_nop) ? EBUSY : 0;
    } 
	else 
	{
		/*选择一个未使用的dp 层端口号*/
        port_no = choose_port(dp, dpif_port);

        error = port_no == ODPP_NONE ? EFBIG : 0;
    }

	/*端口不存在*/
    if (!error) 
	{
        *port_nop = port_no;

		/*添加端口*/
        error = do_add_port(dp, dpif_port, netdev_get_type(netdev), port_no);
    }

	ovs_mutex_unlock(&dp->port_mutex);

    return error;
}

static int
dpif_netdev_port_del(struct dpif *dpif, odp_port_t port_no)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int error;

    ovs_mutex_lock(&dp->port_mutex);
    if (port_no == ODPP_LOCAL) {
        error = EINVAL;
    } else {
        struct dp_netdev_port *port;

        error = get_port_by_number(dp, port_no, &port);
        if (!error) {
            do_del_port(dp, port);
        }
    }
    ovs_mutex_unlock(&dp->port_mutex);

    return error;
}

static bool
is_valid_port_number(odp_port_t port_no)
{
    return port_no != ODPP_NONE;
}

/*******************************************************************************
 函数名称  :    dp_netdev_lookup_port
 功能描述  :    根据端口号查找端口
 输入参数  :  	dp---数据面
 				port_no---端口号
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static struct dp_netdev_port *
dp_netdev_lookup_port(const struct dp_netdev *dp, odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;

	/*遍历dp 端口链查找端口*/
    HMAP_FOR_EACH_WITH_HASH (port, node, hash_port_no(port_no), &dp->ports) 
	{
		/*根据端口号查找端口*/
        if (port->port_no == port_no) 
		{
            return port;
        }
    }
	
    return NULL;
}

static int
get_port_by_number(struct dp_netdev *dp,
                   odp_port_t port_no, struct dp_netdev_port **portp)
    OVS_REQUIRES(dp->port_mutex)
{
    if (!is_valid_port_number(port_no)) {
        *portp = NULL;
        return EINVAL;
    } else {
        *portp = dp_netdev_lookup_port(dp, port_no);
        return *portp ? 0 : ENODEV;
    }
}

/*******************************************************************************
 函数名称  :    port_destroy
 功能描述  :    端口destroy
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
port_destroy(struct dp_netdev_port *port)
{
    if (!port) {
        return;
    }

    /*调用close port->netdev，把port netdev 都close掉*/
    netdev_close(port->netdev);
    netdev_restore_flags(port->sf);

    /*q close掉*/
    for (unsigned i = 0; i < port->n_rxq; i++) {
        netdev_rxq_close(port->rxqs[i].rx);
    }
    ovs_mutex_destroy(&port->txq_used_mutex);
    free(port->rxq_affinity_list);
    free(port->txq_used);
    free(port->rxqs);
    free(port->type);
    free(port);
}

/*******************************************************************************
 函数名称  :    get_port_by_name
 功能描述  :    根据name 获取端口
 输入参数  :  	dp---数据面网桥
 				devname---端口name
 				portp---获取的端口
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
get_port_by_name(struct dp_netdev *dp, const char *devname, struct dp_netdev_port **portp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;

	/*遍历dp端口链*/
    HMAP_FOR_EACH (port, node, &dp->ports) 
	{
		/*对比端口name*/
        if (!strcmp(netdev_get_name(port->netdev), devname)) 
		{
            *portp = port;
            return 0;
        }
    }

    /* Callers of dpif_netdev_port_query_by_name() expect ENODEV for a non
     * existing port. */
    return ENODEV;
}

/*******************************************************************************
 函数名称  :    has_pmd_port
 功能描述  :    检查dp上是否有端口使用pmd
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
/* Returns 'true' if there is a port with pmd netdev. */
static bool
has_pmd_port(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;

	/*遍历dp 上的端口*/
    HMAP_FOR_EACH (port, node, &dp->ports) 
	{
		/*判断端口是否有pmd标记*/
        if (netdev_is_pmd(port->netdev)) 
		{
            return true;
        }
    }

    return false;
}

static void
do_del_port(struct dp_netdev *dp, struct dp_netdev_port *port)
    OVS_REQUIRES(dp->port_mutex)
{
    hmap_remove(&dp->ports, &port->node);
    seq_change(dp->port_seq);

    reconfigure_datapath(dp);

    port_destroy(port);
}

static void
answer_port_query(const struct dp_netdev_port *port,
                  struct dpif_port *dpif_port)
{
    dpif_port->name = xstrdup(netdev_get_name(port->netdev));
    dpif_port->type = xstrdup(port->type);
    dpif_port->port_no = port->port_no;
}

static int
dpif_netdev_port_query_by_number(const struct dpif *dpif, odp_port_t port_no,
                                 struct dpif_port *dpif_port)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error;

    ovs_mutex_lock(&dp->port_mutex);
    error = get_port_by_number(dp, port_no, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_mutex_unlock(&dp->port_mutex);

    return error;
}

static int
dpif_netdev_port_query_by_name(const struct dpif *dpif, const char *devname,
                               struct dpif_port *dpif_port)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error;

    ovs_mutex_lock(&dp->port_mutex);
    error = get_port_by_name(dp, devname, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_mutex_unlock(&dp->port_mutex);

    return error;
}

/*******************************************************************************
 函数名称  :    dp_netdev_flow_free
 功能描述  :    释放流表资源
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
dp_netdev_flow_free(struct dp_netdev_flow *flow)
{
	/*释放流表的action资源*/
    dp_netdev_actions_free(dp_netdev_flow_get_actions(flow));

	/*释放flow资源*/
	free(flow);
}

/*******************************************************************************
 函数名称 :  dp_netdev_flow_unref
 功能描述 :  释放流表资源
 输入参数 :  
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static void dp_netdev_flow_unref(struct dp_netdev_flow *flow)
{
	/*flow 没有引用*/
    if (ovs_refcount_unref_relaxed(&flow->ref_cnt) == 1) 
	{
		/*释放流表资源*/
        ovsrcu_postpone(dp_netdev_flow_free, flow);
    }
}

static uint32_t
dp_netdev_flow_hash(const ovs_u128 *ufid)
{
    return ufid->u32[0];
}

/*******************************************************************************
 函数名称  :    dp_netdev_pmd_lookup_dpcls
 功能描述  :    根据in_port计算hash值，然后由此hash值在pmd->classifiers中查找dpcls，每个in_port拥有一个dpcls
 输入参数  :  	pmd---pmd线程结构
 				in_port---输入端口号
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline struct dpcls *
dp_netdev_pmd_lookup_dpcls(struct dp_netdev_pmd_thread *pmd, odp_port_t in_port)
{
    struct dpcls *cls;

	/*根据port算哈希*/
    uint32_t hash = hash_port_no(in_port);

	/*匹配端口哈希值查找dpcls*/
    CMAP_FOR_EACH_WITH_HASH (cls, node, hash, &pmd->classifiers) 
   	{
   		/*匹配端口返回dpcls*/
        if (cls->in_port == in_port) 
		{
            /* Port classifier exists already */
            return cls;
        }
    }
	
    return NULL;
}

/*******************************************************************************
 函数名称  :    dp_netdev_pmd_find_dpcls
 功能描述  :    查询dpcls是否存在不存在创建dpcls插入pmd->classifiers
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline struct dpcls *
dp_netdev_pmd_find_dpcls(struct dp_netdev_pmd_thread *pmd,
                         odp_port_t in_port)
    OVS_REQUIRES(pmd->flow_mutex)
{
	/*根据in_port计算hash值，然后由此hash值在pmd->classifiers中查找dpcls，每个in_port拥有一个dpcls*/
    struct dpcls *cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    uint32_t hash = hash_port_no(in_port);

	/*dpcls不存在*/
    if (!cls) 
	{
        /* Create new classifier for in_port */
        cls = xmalloc(sizeof(*cls));

		/*port dpcls初始化*/
        dpcls_init(cls);
        cls->in_port = in_port;

		/*dpcls插入pmd dpcls链表*/
        cmap_insert(&pmd->classifiers, &cls->node, hash);
        VLOG_DBG("Creating dpcls %p for in_port %d", cls, in_port);
    }
	
	/**/
    return cls;
}

#define MAX_FLOW_MARK       (UINT32_MAX - 1)
#define INVALID_FLOW_MARK   (UINT32_MAX)

struct megaflow_to_mark_data {
    const struct cmap_node node;
    ovs_u128 mega_ufid;
    uint32_t mark;
};

/*flow的mark*/
struct flow_mark {
    struct cmap megaflow_to_mark;		/*根据mega ufid 查mark map*/
    struct cmap mark_to_flow;			/*根据mark找flow*/
    struct id_pool *pool;
};

static struct flow_mark flow_mark = {
    .megaflow_to_mark = CMAP_INITIALIZER,
    .mark_to_flow = CMAP_INITIALIZER,
};

/*******************************************************************************
 函数名称  :    flow_mark_alloc
 功能描述  :    mark id池申请mark id
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
static uint32_t
flow_mark_alloc(void)
{
    uint32_t mark;

	/*mark id池不存在*/
    if (!flow_mark.pool) 
	{
        /* Haven't initiated yet, do it here */
        flow_mark.pool = id_pool_create(0, MAX_FLOW_MARK);
    }

	/*mark id池申请mark id*/
    if (id_pool_alloc_id(flow_mark.pool, &mark)) {
        return mark;
    }

    return INVALID_FLOW_MARK;
}

static void
flow_mark_free(uint32_t mark)
{
    id_pool_free_id(flow_mark.pool, mark);
}

/* associate megaflow with a mark, which is a 1:1 mapping */
static void
megaflow_to_mark_associate(const ovs_u128 *mega_ufid, uint32_t mark)
{
    size_t hash = dp_netdev_flow_hash(mega_ufid);
    struct megaflow_to_mark_data *data = xzalloc(sizeof(*data));

    data->mega_ufid = *mega_ufid;
    data->mark = mark;

    cmap_insert(&flow_mark.megaflow_to_mark,
                CONST_CAST(struct cmap_node *, &data->node), hash);
}

/* disassociate meagaflow with a mark */
static void
megaflow_to_mark_disassociate(const ovs_u128 *mega_ufid)
{
    size_t hash = dp_netdev_flow_hash(mega_ufid);
    struct megaflow_to_mark_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, &flow_mark.megaflow_to_mark) {
        if (ovs_u128_equals(*mega_ufid, data->mega_ufid)) {
            cmap_remove(&flow_mark.megaflow_to_mark,
                        CONST_CAST(struct cmap_node *, &data->node), hash);
            free(data);
            return;
        }
    }

    VLOG_WARN("Masked ufid "UUID_FMT" is not associated with a mark?\n",
              UUID_ARGS((struct uuid *)mega_ufid));
}

/*******************************************************************************
 函数名称  :    megaflow_to_mark_find
 功能描述  :    根据mega flow ufid查询mark
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline uint32_t
megaflow_to_mark_find(const ovs_u128 *mega_ufid)
{
	/*算hash*/
    size_t hash = dp_netdev_flow_hash(mega_ufid);
    struct megaflow_to_mark_data *data;

	/*全局mark链表查询*/
    CMAP_FOR_EACH_WITH_HASH (data, node, hash, &flow_mark.megaflow_to_mark) {

		/*匹配到mega ufid*/
		if (ovs_u128_equals(*mega_ufid, data->mega_ufid)) {
            return data->mark;
        }
    }

    VLOG_WARN("Mark id for ufid "UUID_FMT" was not found\n",
              UUID_ARGS((struct uuid *)mega_ufid));
    return INVALID_FLOW_MARK;
}

/*******************************************************************************
 函数名称  :    mark_to_flow_associate
 功能描述  :    mark关联到flow
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
/* associate mark with a flow, which is 1:N mapping */
static void
mark_to_flow_associate(const uint32_t mark, struct dp_netdev_flow *flow)
{
    dp_netdev_flow_ref(flow);

    cmap_insert(&flow_mark.mark_to_flow,
                CONST_CAST(struct cmap_node *, &flow->mark_node),
                hash_int(mark, 0));

	/*mark直接复制给flow*/
	flow->mark = mark;

    VLOG_DBG("Associated dp_netdev flow %p with mark %u\n", flow, mark);
}

static bool
flow_mark_has_no_ref(uint32_t mark)
{
    struct dp_netdev_flow *flow;

    CMAP_FOR_EACH_WITH_HASH (flow, mark_node, hash_int(mark, 0),
                             &flow_mark.mark_to_flow) {
        if (flow->mark == mark) {
            return false;
        }
    }

    return true;
}

/*******************************************************************************
 函数名称  :    mark_to_flow_disassociate
 功能描述  :    pmd线程流表删除
 输入参数  :  	pmd---pmd线程
 				flow---要删除的flow
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
mark_to_flow_disassociate(struct dp_netdev_pmd_thread *pmd,
                          struct dp_netdev_flow *flow)
{
    int ret = 0;
    uint32_t mark = flow->mark;

	/*flow 的mark 节点*/
    struct cmap_node *mark_node = CONST_CAST(struct cmap_node *,
                                             &flow->mark_node);

	/**/
    cmap_remove(&flow_mark.mark_to_flow, mark_node, hash_int(mark, 0));
    flow->mark = INVALID_FLOW_MARK;

    /*
     * no flow is referencing the mark any more? If so, let's
     * remove the flow from hardware and free the mark.
     */
    if (flow_mark_has_no_ref(mark)) 
	{
        struct dp_netdev_port *port;

		/**/
		odp_port_t in_port = flow->flow.in_port.odp_port;

        ovs_mutex_lock(&pmd->dp->port_mutex);

		/*pmd查port*/
        port = dp_netdev_lookup_port(pmd->dp, in_port);
        if (port) {

			/*删除flow*/
            ret = netdev_flow_del(port->netdev, &flow->mega_ufid, NULL);
        }
        ovs_mutex_unlock(&pmd->dp->port_mutex);

        flow_mark_free(mark);
        VLOG_DBG("Freed flow mark %u\n", mark);

        megaflow_to_mark_disassociate(&flow->mega_ufid);
    }
    dp_netdev_flow_unref(flow);

    return ret;
}

/*******************************************************************************
 函数名称  :    flow_mark_flush
 功能描述  :    flush掉 pmd上 mark的流表
 输入参数  :    pmd---pmd线程
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
flow_mark_flush(struct dp_netdev_pmd_thread *pmd)
{
    struct dp_netdev_flow *flow;

	/*遍历mark_to_flow上的流表*/
    CMAP_FOR_EACH (flow, mark_node, &flow_mark.mark_to_flow) 
	{
		/*确认流表属于本pmd*/
        if (flow->pmd_id == pmd->core_id) 
		{
			/*流表删除，包括offload流表*/
            queue_netdev_flow_del(pmd, flow);
        }
    }
}


/*******************************************************************************
 函数名称  :    mark_to_flow_find
 功能描述  :    根据报文带的所属流的mark直接找到对应的flow
 输入参数  :    pmd---pmd线程
 			  	mark---报文找到的flow的mark，一个id
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static struct dp_netdev_flow *
mark_to_flow_find(const struct dp_netdev_pmd_thread *pmd, const uint32_t mark)
{
    struct dp_netdev_flow *flow;

	/*根据mark命中flow*/
    CMAP_FOR_EACH_WITH_HASH (flow, mark_node, hash_int(mark, 0), &flow_mark.mark_to_flow) 
	{
		/*命中flow  mark相等、逻辑核是本pmd使用的逻辑核、流alive*/
        if (flow->mark == mark && flow->pmd_id == pmd->core_id && flow->dead == false) 
        {
            return flow;
        }
    }

    return NULL;
}

/*******************************************************************************
 函数名称  :    dp_netdev_alloc_flow_offload
 功能描述  :    申请一个offload项
 输入参数  :  	pmd---pmd线程
 				flow--下发删除的flow
 				op---流表增删标记
 输出参数  :	
 返 回 值  : 	offload---流表offload项
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static struct dp_flow_offload_item *
dp_netdev_alloc_flow_offload(struct dp_netdev_pmd_thread *pmd, struct dp_netdev_flow *flow, int op)
{
    struct dp_flow_offload_item *offload;

	/*流表offload项申请*/
    offload = xzalloc(sizeof(*offload));
    offload->pmd = pmd;
    offload->flow = flow;
    offload->op = op;

	/*flow引用计数*/
    dp_netdev_flow_ref(flow);

	/*pmd引用置位*/
    dp_netdev_pmd_try_ref(pmd);

    return offload;
}

/*******************************************************************************
 函数名称  :    dp_netdev_free_flow_offload
 功能描述  :    释放offload项
 输入参数  :  	offload---offload item
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
dp_netdev_free_flow_offload(struct dp_flow_offload_item *offload)
{
	/**/
    dp_netdev_pmd_unref(offload->pmd);
    dp_netdev_flow_unref(offload->flow);

    free(offload->actions);
    free(offload);
}

/*******************************************************************************
 函数名称  :    dp_netdev_append_flow_offload
 功能描述  :    offload节点添加
 输入参数  :  	offload---要offload的流表 item
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
dp_netdev_append_flow_offload(struct dp_flow_offload_item *offload)
{
    ovs_mutex_lock(&dp_flow_offload.mutex);

	/*offload添加list*/
    ovs_list_push_back(&dp_flow_offload.list, &offload->node);
    xpthread_cond_signal(&dp_flow_offload.cond);
    ovs_mutex_unlock(&dp_flow_offload.mutex);
}

/*******************************************************************************
 函数名称  :    dp_netdev_flow_offload_del
 功能描述  :    offload 流表删除
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
dp_netdev_flow_offload_del(struct dp_flow_offload_item *offload)
{
	/*flow 从pmd解除关联*/
    return mark_to_flow_disassociate(offload->pmd, offload->flow);
}

/*
 * There are two flow offload operations here: addition and modification.
 *
 * For flow addition, this function does:
 * - allocate a new flow mark id
 * - perform hardware flow offload
 * - associate the flow mark with flow and mega flow
 *
 * For flow modification, both flow mark and the associations are still
 * valid, thus only item 2 needed.
 */
 /*******************************************************************************
 函数名称  :    dp_netdev_flow_offload_put
 功能描述  :    流表offload添加、修改
 输入参数  :  	offload---流表offload项
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
dp_netdev_flow_offload_put(struct dp_flow_offload_item *offload)
{
    struct dp_netdev_port *port;

	/*pmd*/
    struct dp_netdev_pmd_thread *pmd = offload->pmd;

	/*offload item对应的flow*/
    struct dp_netdev_flow *flow = offload->flow;

	/*in port端口*/
    odp_port_t in_port = flow->flow.in_port.odp_port;

	/*offload的操作为mod*/
    bool modification = offload->op == DP_NETDEV_FLOW_OFFLOAD_OP_MOD;

	struct offload_info info;

	uint32_t mark;
    int ret;

	
    if (flow->dead) 
	{
        return -1;
    }

	/*mod动作*/
    if (modification) 
	{
		/*获取flow的 mark*/
        mark = flow->mark;
        ovs_assert(mark != INVALID_FLOW_MARK);
    } 
	else 
	{
        /*
         * If a mega flow has already been offloaded (from other PMD
         * instances), do not offload it again.
         */

		/*查询flow是否在其他pmd已经offload，mark是否存在*/
        mark = megaflow_to_mark_find(&flow->mega_ufid);
        if (mark != INVALID_FLOW_MARK) 
		{
            VLOG_DBG("Flow has already been offloaded with mark %u\n", mark);
            if (flow->mark != INVALID_FLOW_MARK) 
			{
                ovs_assert(flow->mark == mark);
            }
			else 
			{
				/*mark直接赋值给flow*/
                mark_to_flow_associate(mark, flow);
            }

			return 0;
        }

		/*新建流表mark 申请，mark id池申请mark id*/
        mark = flow_mark_alloc();
        if (mark == INVALID_FLOW_MARK) 
		{
            VLOG_ERR("Failed to allocate flow mark!\n");
        }
    }

	/*给流分配的mark id*/
    info.flow_mark = mark;

	/*dp port 操作互斥锁*/
    ovs_mutex_lock(&pmd->dp->port_mutex);

	/*在pmd dp查询inport*/
    port = dp_netdev_lookup_port(pmd->dp, in_port);
    if (!port) 
	{
        ovs_mutex_unlock(&pmd->dp->port_mutex);
        return -1;
    }

	/*offload流表下发*/
    ret = netdev_flow_put(port->netdev, &offload->match, CONST_CAST(struct nlattr *, offload->actions), offload->actions_len, &flow->mega_ufid, &info, NULL);
    ovs_mutex_unlock(&pmd->dp->port_mutex);

    if (ret) 
	{
        if (!modification) 
		{
            flow_mark_free(mark);
        } 
		else 
		{
			/*mark关联的flow 解除关联*/
            mark_to_flow_disassociate(pmd, flow);
        }
        return -1;
    }

    if (!modification) 
	{
        megaflow_to_mark_associate(&flow->mega_ufid, mark);
        mark_to_flow_associate(mark, flow);
    }

    return 0;
}

/*******************************************************************************
 函数名称  :    dp_netdev_flow_offload_main
 功能描述  :    流表offload线程，处理offload流表项增删
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
static void *
dp_netdev_flow_offload_main(void *data OVS_UNUSED)
{
    struct dp_flow_offload_item *offload;
    struct ovs_list *list;
    const char *op;
    int ret;

	/*一直起着线程*/
    for (;;) 
	{
		/*offload 操作互斥锁*/
        ovs_mutex_lock(&dp_flow_offload.mutex);

		/*ovs offload 流表链为空*/
		if (ovs_list_is_empty(&dp_flow_offload.list)) 
		{
            ovsrcu_quiesce_start();
            ovs_mutex_cond_wait(&dp_flow_offload.cond, &dp_flow_offload.mutex);
        }

		/*从offload链表 pop一个流表offload项*/
        list = ovs_list_pop_front(&dp_flow_offload.list);

		/*从item获取offload项 用来下发offload流表*/
        offload = CONTAINER_OF(list, struct dp_flow_offload_item, node);

		ovs_mutex_unlock(&dp_flow_offload.mutex);

		/*流表offload处理*/
        switch (offload->op) 
		{
			/*offload add*/
	        case DP_NETDEV_FLOW_OFFLOAD_OP_ADD:
	            op = "add";
				VLOG_DBG("zwl dp_netdev_flow_offload_main offload flow node pop and add");
	            ret = dp_netdev_flow_offload_put(offload);
	            break;
			/*offload mod*/
	        case DP_NETDEV_FLOW_OFFLOAD_OP_MOD:
	            op = "modify";
	            ret = dp_netdev_flow_offload_put(offload);
	            break;
			/*offload del*/
	        case DP_NETDEV_FLOW_OFFLOAD_OP_DEL:
	            op = "delete";
				/*offload flow删除*/
	            ret = dp_netdev_flow_offload_del(offload);
	            break;
	        default:
	            OVS_NOT_REACHED();
        }

        VLOG_DBG("%s to %s netdev flow\n", ret == 0 ? "succeed" : "failed", op);

		/*释放offload项*/
        dp_netdev_free_flow_offload(offload);
    }

    return NULL;
}

/*******************************************************************************
 函数名称  :    queue_netdev_flow_del
 功能描述  :    流表删除，包括offload流表
 输入参数  :  	pmd---pmd线程
 				flow---待删除流表
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
queue_netdev_flow_del(struct dp_netdev_pmd_thread *pmd, struct dp_netdev_flow *flow)
{
    struct dp_flow_offload_item *offload;

	/*offload获取操作锁*/
    if (ovsthread_once_start(&offload_thread_once)) 
	{
        xpthread_cond_init(&dp_flow_offload.cond, NULL);

		/*创建流表offload线程*/
        ovs_thread_create("dp_netdev_flow_offload",dp_netdev_flow_offload_main, NULL);

		/*offoad结束*/
        ovsthread_once_done(&offload_thread_once);
    }

	/*申请一个offload项*/
    offload = dp_netdev_alloc_flow_offload(pmd, flow, DP_NETDEV_FLOW_OFFLOAD_OP_DEL);

	/*流表添加offload*/
    dp_netdev_append_flow_offload(offload);
}

/*******************************************************************************
 函数名称  :    queue_netdev_flow_put
 功能描述  :    流表下发队列
 输入参数  :  	pmd---要下到的pmd
 				flow---解析出的flow信息
 				match---match条件
 				actions---actions
 				actions_len---action 申请内存长度
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static void
queue_netdev_flow_put(struct dp_netdev_pmd_thread *pmd,
                      struct dp_netdev_flow *flow, struct match *match,
                      const struct nlattr *actions, size_t actions_len)
{
	/*offlod项*/
    struct dp_flow_offload_item *offload;
    int op;

	/*api未使能*/
    if (!netdev_is_flow_api_enabled()) 
	{
        return;
    }

	/*offload下发流表流程，线程没启动则启动一次*/
    if (ovsthread_once_start(&offload_thread_once)) 
	{
		/*起线程下offload 流表处理线程*/
        xpthread_cond_init(&dp_flow_offload.cond, NULL);
        ovs_thread_create("dp_netdev_flow_offload", dp_netdev_flow_offload_main, NULL);
        ovsthread_once_done(&offload_thread_once);
    }

	/*flow mark存在*/
    if (flow->mark != INVALID_FLOW_MARK) 
	{
		/*offload flow mod*/
        op = DP_NETDEV_FLOW_OFFLOAD_OP_MOD;
    }
	/*mark不存在*/
	else 
	{
    	/*offload flow add*/
        op = DP_NETDEV_FLOW_OFFLOAD_OP_ADD;
    }
	
	/*申请offlod结构内存 关联flow*/
    offload = dp_netdev_alloc_flow_offload(pmd, flow, op);

	/*match条件赋值给offload*/
	offload->match = *match;

	/*offload action内存申请*/
	offload->actions = xmalloc(actions_len);

	/*flow actions拷贝到offload节点*/
	memcpy(offload->actions, actions, actions_len);

	/*action长度 字节*/
	offload->actions_len = actions_len;

	/*offload项 添加到offlod链表，线程统一处理*/
    dp_netdev_append_flow_offload(offload);

	VLOG_DBG("zwl queue_netdev_flow_put offload flow node insert list");
}

/*******************************************************************************
 函数名称  :    dp_netdev_pmd_remove_flow
 功能描述  :    获取互斥锁
 输入参数  :  	pmd---要删除的pmd
 				flow---pmd缓存的链表
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
dp_netdev_pmd_remove_flow(struct dp_netdev_pmd_thread *pmd, struct dp_netdev_flow *flow)
    OVS_REQUIRES(pmd->flow_mutex)
{
    struct cmap_node *node = CONST_CAST(struct cmap_node *, &flow->node);
    struct dpcls *cls;
    odp_port_t in_port = flow->flow.in_port.odp_port;

	/*获取port对应dpcls结构*/
    cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
	
    ovs_assert(cls != NULL);

	/*从cls删除flow*/
    dpcls_remove(cls, &flow->cr);

	/*从pmd flow缓存删除flow*/
    cmap_remove(&pmd->flow_table, node, dp_netdev_flow_hash(&flow->ufid));

	/*流表mark是有效的*/
	if (flow->mark != INVALID_FLOW_MARK) 
	{
		/*流表删除，包括offload流表*/
        queue_netdev_flow_del(pmd, flow);
    }

	/*删除完成flow，打上流表dead标记*/
    flow->dead = true;

	/*释放流表资源*/
    dp_netdev_flow_unref(flow);
}

/*******************************************************************************
 函数名称  :    dp_netdev_pmd_flow_flush
 功能描述  :    删除pmd缓存的链表
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
dp_netdev_pmd_flow_flush(struct dp_netdev_pmd_thread *pmd)
{
    struct dp_netdev_flow *netdev_flow;

    ovs_mutex_lock(&pmd->flow_mutex);

	/*遍历删除pmd缓存的链表*/
    CMAP_FOR_EACH (netdev_flow, node, &pmd->flow_table) 
	{
		/*删除pmd上流表*/
        dp_netdev_pmd_remove_flow(pmd, netdev_flow);
    }
	
    ovs_mutex_unlock(&pmd->flow_mutex);
}

/*******************************************************************************
 函数名称  :    dpif_netdev_flow_flush
 功能描述  :    flush掉流表
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
dpif_netdev_flow_flush(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        dp_netdev_pmd_flow_flush(pmd);
    }

    return 0;
}

struct dp_netdev_port_state {
    struct hmap_position position;
    char *name;
};

static int
dpif_netdev_port_dump_start(const struct dpif *dpif OVS_UNUSED, void **statep)
{
    *statep = xzalloc(sizeof(struct dp_netdev_port_state));
    return 0;
}

static int
dpif_netdev_port_dump_next(const struct dpif *dpif, void *state_,
                           struct dpif_port *dpif_port)
{
    struct dp_netdev_port_state *state = state_;
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct hmap_node *node;
    int retval;

    ovs_mutex_lock(&dp->port_mutex);
    node = hmap_at_position(&dp->ports, &state->position);
    if (node) {
        struct dp_netdev_port *port;

        port = CONTAINER_OF(node, struct dp_netdev_port, node);

        free(state->name);
        state->name = xstrdup(netdev_get_name(port->netdev));
        dpif_port->name = state->name;
        dpif_port->type = port->type;
        dpif_port->port_no = port->port_no;

        retval = 0;
    } else {
        retval = EOF;
    }
    ovs_mutex_unlock(&dp->port_mutex);

    return retval;
}

static int
dpif_netdev_port_dump_done(const struct dpif *dpif OVS_UNUSED, void *state_)
{
    struct dp_netdev_port_state *state = state_;
    free(state->name);
    free(state);
    return 0;
}

static int
dpif_netdev_port_poll(const struct dpif *dpif_, char **devnamep OVS_UNUSED)
{
    struct dpif_netdev *dpif = dpif_netdev_cast(dpif_);
    uint64_t new_port_seq;
    int error;

    new_port_seq = seq_read(dpif->dp->port_seq);
    if (dpif->last_port_seq != new_port_seq) {
        dpif->last_port_seq = new_port_seq;
        error = ENOBUFS;
    } else {
        error = EAGAIN;
    }

    return error;
}

static void
dpifseq_wait_netdev_port_poll_wait(const struct dpif *dpif_)
{
    struct dpif_netdev *dpif = dpif_netdev_cast(dpif_);

    (dpif->dp->port_seq, dpif->last_port_seq);
}

/*******************************************************************************
 函数名称 :  dp_netdev_flow_cast
 功能描述 :  从dpcls rule转出struct dp_netdev_flow
 输入参数 :  cr---dpcls规则
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static struct dp_netdev_flow *
dp_netdev_flow_cast(const struct dpcls_rule *cr)
{
    return cr ? CONTAINER_OF(cr, struct dp_netdev_flow, cr) : NULL;
}

/*******************************************************************************
 函数名称  :    dp_netdev_flow_ref
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
static bool dp_netdev_flow_ref(struct dp_netdev_flow *flow)
{
    return ovs_refcount_try_ref_rcu(&flow->ref_cnt);
}

/* netdev_flow_key utilities.
 *
 * netdev_flow_key is basically a miniflow.  We use these functions
 * (netdev_flow_key_clone, netdev_flow_key_equal, ...) instead of the miniflow
 * functions (miniflow_clone_inline, miniflow_equal, ...), because:
 *
 * - Since we are dealing exclusively with miniflows created by
 *   miniflow_extract(), if the map is different the miniflow is different.
 *   Therefore we can be faster by comparing the map and the miniflow in a
 *   single memcmp().
 * - These functions can be inlined by the compiler. */

/* Given the number of bits set in miniflow's maps, returns the size of the
 * 'netdev_flow_key.mf' */
static inline size_t
netdev_flow_key_size(size_t flow_u64s)
{
    return sizeof(struct miniflow) + MINIFLOW_VALUES_SIZE(flow_u64s);
}

/*******************************************************************************
 函数名称 :  netdev_flow_key_equal
 功能描述 :  flow key 是否相等
 输入参数 :  
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static inline bool
netdev_flow_key_equal(const struct netdev_flow_key *a, const struct netdev_flow_key *b)
{
    /* 'b->len' may be not set yet. */

	/*key的哈希值与miniflow都相等*/
    return a->hash == b->hash && !memcmp(&a->mf, &b->mf, a->len);
}

/* Used to compare 'netdev_flow_key' in the exact match cache to a miniflow.
 * The maps are compared bitwise, so both 'key->mf' and 'mf' must have been
 * generated by miniflow_extract. */
static inline bool
netdev_flow_key_equal_mf(const struct netdev_flow_key *key,
                         const struct miniflow *mf)
{
    return !memcmp(&key->mf, mf, key->len);
}


static inline void
netdev_flow_key_clone(struct netdev_flow_key *dst,const struct netdev_flow_key *src)
{
	/*key值拷贝*/
    memcpy(dst, src, offsetof(struct netdev_flow_key, mf) + src->len);
}

/*******************************************************************************
 函数名称  :    netdev_flow_mask_init
 功能描述  :    掩码初始化
 输入参数  :  	mask---netdev_flow_key flow key的掩码
 				match---flow的match部分
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Initialize a netdev_flow_key 'mask' from 'match'. */
static inline void
netdev_flow_mask_init(struct netdev_flow_key *mask, const struct match *match)
{
	/*miniflow的值，取值指针*/
    uint64_t *dst = miniflow_values(&mask->mf);

	/*miniflow 位图*/
	struct flowmap fmap;
    uint32_t hash = 0;
    size_t idx;

    /* Only check masks that make sense for the flow. */

	flow_wc_map(&match->flow, &fmap);

	/*set 0 */
	flowmap_init(&mask->mf.map);

	/**/
    FLOWMAP_FOR_EACH_INDEX(idx, fmap) 
	{
        uint64_t mask_u64 = flow_u64_value(&match->wc.masks, idx);

        if (mask_u64) 
		{
            flowmap_set(&mask->mf.map, idx, 1);
            *dst++ = mask_u64;
            hash = hash_add64(hash, mask_u64);
        }
    }

    map_t map;

    FLOWMAP_FOR_EACH_MAP (map, mask->mf.map) 
	{
        hash = hash_add64(hash, map);
    }

	/*miniflow的长度*/
    size_t n = dst - miniflow_get_values(&mask->mf);

	/*算hash和长度*/
    mask->hash = hash_finish(hash, n * 8);

	/*长度*/
	mask->len = netdev_flow_key_size(n);
}

/*******************************************************************************
 函数名称  :    netdev_flow_key_init_masked
 功能描述  :    flow key 初始化miniflow
 输入参数  :  	dst---存储提取的miniflow的结构，struct netdev_flow_key key
 				flow---match.flow 存储了match
 				mask---存储提取的miniflow mask的结构，struct netdev_flow_key mask
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Initializes 'dst' as a copy of 'flow' masked with 'mask'. */
static inline void
netdev_flow_key_init_masked(struct netdev_flow_key *dst,
                            const struct flow *flow,
                            const struct netdev_flow_key *mask)
{
	/*miniflow指针 指向unsigned long long map[(sizeof flow/8)+1 = ]*/
    uint64_t *dst_u64 = miniflow_values(&dst->mf);

	/*获取掩码miniflow值*/
	const uint64_t *mask_u64 = miniflow_get_values(&mask->mf);
    uint32_t hash = 0;
    uint64_t value;

    dst->len = mask->len;

	/*拷贝miniflow*/
    dst->mf = mask->mf;   /* Copy maps. */

	/**/
    FLOW_FOR_EACH_IN_MAPS(value, flow, mask->mf.map) 
	{
        *dst_u64 = value & *mask_u64++;

		/**/
        hash = hash_add64(hash, *dst_u64++);
    }

	/*五元组算hash ?*/
    dst->hash = hash_finish(hash,(dst_u64 - miniflow_get_values(&dst->mf)) * 8);
}

/* Iterate through netdev_flow_key TNL u64 values specified by 'FLOWMAP'. */
#define NETDEV_FLOW_KEY_FOR_EACH_IN_FLOWMAP(VALUE, KEY, FLOWMAP)   \
    MINIFLOW_FOR_EACH_IN_FLOWMAP(VALUE, &(KEY)->mf, FLOWMAP)

/*******************************************************************************
 函数名称  :    netdev_flow_key_hash_in_mask
 功能描述  :    计算掩码后哈希
 输入参数  :    key---miniflow key
 			    mask---miniflow掩码
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Returns a hash value for the bits of 'key' where there are 1-bits in
 * 'mask'. */
static inline uint32_t
netdev_flow_key_hash_in_mask(const struct netdev_flow_key *key, const struct netdev_flow_key *mask)
{
	/*获取miniflow 值*/
    const uint64_t *p = miniflow_get_values(&mask->mf);
	
    uint32_t hash = 0;

	uint64_t value;

	/**/
    NETDEV_FLOW_KEY_FOR_EACH_IN_FLOWMAP(value, key, mask->mf.map) 
	{
        hash = hash_add64(hash, value & *p++);
    }

    return hash_finish(hash, (p - miniflow_get_values(&mask->mf)) * 8);
}

/*******************************************************************************
 函数名称 :  emc_entry_alive
 功能描述 :  emc流表存在 且 活着
 输入参数 :  
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static inline bool
emc_entry_alive(struct emc_entry *ce)
{
	/*emc流表存在 且 活着*/
    return ce->flow && !ce->flow->dead;
}
/*******************************************************************************
 函数名称  :    emc_clear_entry
 功能描述  :    emc流表删除
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
emc_clear_entry(struct emc_entry *ce)
{
	/*emc流表存在*/
    if (ce->flow) 
	{
        dp_netdev_flow_unref(ce->flow);
        ce->flow = NULL;
    }
}
/*******************************************************************************
 函数名称  :    emc_change_entry
 功能描述  :    赋值netdev_flow_key和dp_netdev_flow
 输入参数  :    ce---emc 流表entry，相同的flow和key
 输出参数  :	flow--smc查到的流信息
 		        key---miniflow key
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline void emc_change_entry(struct emc_entry *ce, struct dp_netdev_flow *flow, const struct netdev_flow_key *key)
{
	/*entry对应的flow不是要添加的flow，释放旧flow，替入新flow*/
    if (ce->flow != flow) 
	{
		/*解除对flow的引用*/
        if (ce->flow) 
		{
            dp_netdev_flow_unref(ce->flow);
        }

		/*新flow 信息填入entry*/
        if (dp_netdev_flow_ref(flow)) 
		{
            ce->flow = flow;
        }
		else 
		{
            ce->flow = NULL;
        }
    }

	/*key信息值填入entry 的key*/
	if (key) 
	{
        netdev_flow_key_clone(&ce->key, key);
    }
}

/*******************************************************************************
 函数名称  :   emc_insert
 功能描述  :   emc 流表insert
			   1.根据key->hash找到hash桶，并且进行轮询
			   2.查看是否有匹配的key值，有的话调用emc_change_entry修改流表。
			   3.如果没有匹配的就会根据算法记录一个entry，用来替代
			   4.循环完毕之后，调用emc_change_entry替代之前不用的流表
 输入参数  :   cache---每个pmd一张ECM流表
 		       key---提取的报文的miniflow key
 		       flow---smc查到的flow
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline void
emc_insert(struct emc_cache *cache, const struct netdev_flow_key *key, struct dp_netdev_flow *flow)
{
    struct emc_entry *to_be_replaced = NULL;
    struct emc_entry *current_entry;

	/*根据key算出的哈希查找emc流表entry*/
    EMC_FOR_EACH_POS_WITH_HASH(cache, current_entry, key->hash) 
	{	
		/*对比miniflow key相等*/
        if (netdev_flow_key_equal(&current_entry->key, key)) 
		{
            /* We found the entry with the 'mf' miniflow */

			/*flow信息填入emc流表*/
            emc_change_entry(current_entry, flow, NULL);
			
            return;
        }

        /* Replacement policy: put the flow in an empty (not alive) entry, or
         * in the first entry where it can be */

		/*miniflow key不相等走这里*/  /*旧的flow活着*/				/*当前flow没活*/					/*哈希小于被替代的哈希、为啥*/
        if (!to_be_replaced || (emc_entry_alive(to_be_replaced) && !emc_entry_alive(current_entry)) || current_entry->key.hash < to_be_replaced->key.hash)
        {
        	/*被替换的entry*/
            to_be_replaced = current_entry;
        }
    }
    /* We didn't find the miniflow in the cache.
     * The 'to_be_replaced' entry is where the new flow will be stored */

	/*emc流表current entry填入 指向的flow*/
    emc_change_entry(to_be_replaced, flow, key);
}

/*******************************************************************************
 函数名称  :  emc_probabilistic_insert
 功能描述  :  emc流表插入
 输入参数  :  pmd---pmd线程
 			  key---报文miniflow key
 			  flow---smc查到的flow
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline void
emc_probabilistic_insert(struct dp_netdev_pmd_thread *pmd, const struct netdev_flow_key *key, struct dp_netdev_flow *flow)
{
    /* Insert an entry into the EMC based on probability value 'min'. By
     * default the value is UINT32_MAX / 100 which yields an insertion
     * probability of 1/100 ie. 1% */

    uint32_t min;

	/*原子读取当前emc流表项数*/
    atomic_read_relaxed(&pmd->dp->emc_insert_min, &min);

	/*emc流表未满*/
    if (min && random_uint32() <= min) 
	{
		/*flow插入 emc 流表*/
        emc_insert(&(pmd->flow_cache).emc_cache, key, flow);
    }
}

/*******************************************************************************
 函数名称  :  emc_lookup
 功能描述  :  emc 流表项查询
 输入参数  :  cache---pmd对应一张emc流表
 输出参数  :  key---报文提取的 miniflow key
 返 回 值  :  无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline struct dp_netdev_flow *emc_lookup(struct emc_cache *cache, const struct netdev_flow_key *key)
{
	/*单纯数组，非链表*/
    struct emc_entry *current_entry;

	/*2次哈希查询*/				  /*emc cache、emc查询entry、miniflow hash*/
    EMC_FOR_EACH_POS_WITH_HASH(cache, current_entry, key->hash) 
   	{
        if (current_entry->key.hash == key->hash	/*哈希值相等，哈希根据miniflow 五元组计算*/
            && emc_entry_alive(current_entry)		/*flow 活着*/
            && netdev_flow_key_equal_mf(&current_entry->key, &key->mf)) /*miniflow 位图相等*/
        {  

            /* We found the entry with the 'key->mf' miniflow */
			/*返回emc流表项*/
            return current_entry->flow;
        }
    }

    return NULL;
}

/*******************************************************************************
 函数名称  :  smc_entry_get
 功能描述  :  根据哈希查找smc 命中流表项
 输入参数  :  pmd---pmd线程
 			  hash---根据报文五元组算的哈希	
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline const struct cmap_node *
smc_entry_get(struct dp_netdev_pmd_thread *pmd, const uint32_t hash)
{
	/*smc表*/
    struct smc_cache *cache = &(pmd->flow_cache).smc_cache;

	/*根据报文五元组哈希命中哈希桶*/
    struct smc_bucket *bucket = &cache->buckets[hash & SMC_MASK];

	/*记录的哈希值*/
    uint16_t sig = hash >> 16;

	/*65536*/
    uint16_t index = UINT16_MAX;

	/*桶深为4*/
    for (int i = 0; i < SMC_ENTRY_PER_BUCKET; i++) 
	{
		/*存储的哈希值为 hash >> 16 */
        if (bucket->sig[i] == sig) 
		{
			/*获取bucket对应的流表的index*/
            index = bucket->flow_idx[i];
			
            break;
        }
    }

	/*根据index 返回smc流表项*/
    if (index != UINT16_MAX) 
	{
		/*返回真实的流表*/
        return cmap_find_by_index(&pmd->flow_table, index);
    }
	
    return NULL;
}

static void
smc_clear_entry(struct smc_bucket *b, int idx)
{
    b->flow_idx[idx] = UINT16_MAX;
}

/* Insert the flow_table index into SMC. Insertion may fail when 1) SMC is
 * turned off, 2) the flow_table index is larger than uint16_t can handle.
 * If there is already an SMC entry having same signature, the index will be
 * updated. If there is no existing entry, but an empty entry is available,
 * the empty entry will be taken. If no empty entry or existing same signature,
 * a random entry from the hashed bucket will be picked. */


/*******************************************************************************
 函数名称  :    smc_insert
 功能描述  :    精确流表插入emc流表
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
static inline void
smc_insert(struct dp_netdev_pmd_thread *pmd, const struct netdev_flow_key *key, uint32_t hash)
{
    struct smc_cache *smc_cache = &(pmd->flow_cache).smc_cache;
    struct smc_bucket *bucket = &smc_cache->buckets[key->hash & SMC_MASK];
    uint16_t index;
    uint32_t cmap_index;
    bool smc_enable_db;
    int i;

    atomic_read_relaxed(&pmd->dp->smc_enable_db, &smc_enable_db);
    if (!smc_enable_db) 
	{
        return;
    }

    cmap_index = cmap_find_index(&pmd->flow_table, hash);
    index = (cmap_index >= UINT16_MAX) ? UINT16_MAX : (uint16_t)cmap_index;

    /* If the index is larger than SMC can handle (uint16_t), we don't
     * insert */
    if (index == UINT16_MAX) 
	{
        return;
    }

    /* If an entry with same signature already exists, update the index */
    uint16_t sig = key->hash >> 16;
    for (i = 0; i < SMC_ENTRY_PER_BUCKET; i++) 
	{
        if (bucket->sig[i] == sig) 
		{
            bucket->flow_idx[i] = index;
            return;
        }
    }
	
    /* If there is an empty entry, occupy it. */
    for (i = 0; i < SMC_ENTRY_PER_BUCKET; i++) 
	{
        if (bucket->flow_idx[i] == UINT16_MAX) 
		{
            bucket->sig[i] = sig;
            bucket->flow_idx[i] = index;
            return;
        }
    }
	
    /* Otherwise, pick a random entry. */
    i = random_uint32() % SMC_ENTRY_PER_BUCKET;
	
    bucket->sig[i] = sig;

	bucket->flow_idx[i] = index;
}

/*******************************************************************************
 函数名称  :    dp_netdev_pmd_lookup_flow
 功能描述  :    查找流表
 输入参数  :  	pmd---pmd线程
 				key---存储miniflow的key struct netdev_flow_key
 				lookup_num_p---NULL
 输出参数  :	netdev_flow---命中的dpcls规则对应的netdev_flow
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static struct dp_netdev_flow *
dp_netdev_pmd_lookup_flow(struct dp_netdev_pmd_thread *pmd, const struct netdev_flow_key *key, int *lookup_num_p)
{
    struct dpcls *cls;
    struct dpcls_rule *rule;

	/*获取in_port*/
    odp_port_t in_port = u32_to_odp(MINIFLOW_GET_U32(&key->mf, in_port.odp_port));
    struct dp_netdev_flow *netdev_flow = NULL;

	/*根据端口查询dpcls*/
    cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    if (OVS_LIKELY(cls)) 
	{
		/*dpcls rule查询*/
        dpcls_lookup(cls, &key, &rule, 1, lookup_num_p);

		/*dpcls规则映射成netdev_flow*/
        netdev_flow = dp_netdev_flow_cast(rule);
    }
	
    return netdev_flow;
}

/*******************************************************************************
 函数名称  :    dp_netdev_pmd_find_flow
 功能描述  :    在pmd上查flow
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static struct dp_netdev_flow *
dp_netdev_pmd_find_flow(const struct dp_netdev_pmd_thread *pmd,
                        const ovs_u128 *ufidp, const struct nlattr *key,
                        size_t key_len)
{
    struct dp_netdev_flow *netdev_flow;
    struct flow flow;
    ovs_u128 ufid;

    /* If a UFID is not provided, determine one based on the key. */
    if (!ufidp && key && key_len
        && !dpif_netdev_flow_from_nlattrs(key, key_len, &flow, false)) {

		/*根据key生成ufid*/
		dpif_flow_hash(pmd->dp->dpif, &flow, sizeof flow, &ufid);
        ufidp = &ufid;
    }

    if (ufidp) {

		/*根据生成的ufid查flow*/
        CMAP_FOR_EACH_WITH_HASH (netdev_flow, node, dp_netdev_flow_hash(ufidp),
                                 &pmd->flow_table) {
            if (ovs_u128_equals(netdev_flow->ufid, *ufidp)) {
                return netdev_flow;
            }
        }
    }

    return NULL;
}

/*******************************************************************************
 函数名称  :    get_dpif_flow_stats
 功能描述  :    emc流表删除
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
get_dpif_flow_stats(const struct dp_netdev_flow *netdev_flow_,
                    struct dpif_flow_stats *stats)
{
    struct dp_netdev_flow *netdev_flow;
    unsigned long long n;
    long long used;
    uint16_t flags;

    netdev_flow = CONST_CAST(struct dp_netdev_flow *, netdev_flow_);

    atomic_read_relaxed(&netdev_flow->stats.packet_count, &n);
    stats->n_packets = n;
    atomic_read_relaxed(&netdev_flow->stats.byte_count, &n);
    stats->n_bytes = n;
    atomic_read_relaxed(&netdev_flow->stats.used, &used);


	/*时间戳直接赋值给了dpif flow*/
	stats->used = used;
    atomic_read_relaxed(&netdev_flow->stats.tcp_flags, &flags);
    stats->tcp_flags = flags;
}

/*******************************************************************************
 函数名称  :    dp_netdev_flow_to_dpif_flow
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
/* Converts to the dpif_flow format, using 'key_buf' and 'mask_buf' for
 * storing the netlink-formatted key/mask. 'key_buf' may be the same as
 * 'mask_buf'. Actions will be returned without copying, by relying on RCU to
 * protect them. */
static void
dp_netdev_flow_to_dpif_flow(const struct dp_netdev_flow *netdev_flow,
                            struct ofpbuf *key_buf, struct ofpbuf *mask_buf,
                            struct dpif_flow *flow, bool terse)
{
    if (terse) {
        memset(flow, 0, sizeof *flow);
    } else {
        struct flow_wildcards wc;
        struct dp_netdev_actions *actions;
        size_t offset;

		/*flow的参数*/
        struct odp_flow_key_parms odp_parms = {
            .flow = &netdev_flow->flow,
            .mask = &wc.masks,
            .support = dp_netdev_support,
        };

        miniflow_expand(&netdev_flow->cr.mask->mf, &wc.masks);
        /* in_port is exact matched, but we have left it out from the mask for
         * optimnization reasons. Add in_port back to the mask. */
        wc.masks.in_port.odp_port = ODPP_NONE;

        /* Key */
        offset = key_buf->size;
        flow->key = ofpbuf_tail(key_buf);
        odp_flow_key_from_flow(&odp_parms, key_buf);
        flow->key_len = key_buf->size - offset;

        /* Mask */
        offset = mask_buf->size;
        flow->mask = ofpbuf_tail(mask_buf);
        odp_parms.key_buf = key_buf;
        odp_flow_key_from_mask(&odp_parms, mask_buf);
        flow->mask_len = mask_buf->size - offset;

        /* Actions */
        actions = dp_netdev_flow_get_actions(netdev_flow);
        flow->actions = actions->actions;
        flow->actions_len = actions->size;
    }

	/*flow填充*/
    flow->ufid = netdev_flow->ufid;
    flow->ufid_present = true;
    flow->pmd_id = netdev_flow->pmd_id;

	/*获取flow的流量统计*/
    get_dpif_flow_stats(netdev_flow, &flow->stats);
}

/*******************************************************************************
 函数名称  :    dpif_netdev_mask_from_nlattrs
 功能描述  :    解析出flow 掩码
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
dpif_netdev_mask_from_nlattrs(const struct nlattr *key, uint32_t key_len,
                              const struct nlattr *mask_key,
                              uint32_t mask_key_len, const struct flow *flow,
                              struct flow_wildcards *wc, bool probe)
{
    enum odp_key_fitness fitness;

	/*解析流表掩码*/
    fitness = odp_flow_key_to_mask(mask_key, mask_key_len, wc, flow);
    if (fitness) 
	{
        if (!probe) 
		{
            /* This should not happen: it indicates that
             * odp_flow_key_from_mask() and odp_flow_key_to_mask()
             * disagree on the acceptable form of a mask.  Log the problem
             * as an error, with enough details to enable debugging. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            if (!VLOG_DROP_ERR(&rl)) 
			{
                struct ds s;

                ds_init(&s);
                odp_flow_format(key, key_len, mask_key, mask_key_len, NULL, &s,
                                true);
                VLOG_ERR("internal error parsing flow mask %s (%s)",
                ds_cstr(&s), odp_key_fitness_to_string(fitness));
                ds_destroy(&s);
            }
        }

        return EINVAL;
    }

    return 0;
}

/*******************************************************************************
 函数名称  :    dpif_netdev_flow_from_nlattrs
 功能描述  :    从key解析流表match 填入flow
 输入参数  :  	key---flow的match
 				key_len---flow的match长度
 				flow---要填入的flow结构
 				
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static int
dpif_netdev_flow_from_nlattrs(const struct nlattr *key, uint32_t key_len, struct flow *flow, bool probe)
{
	/*从key解析出match填入flow*/
    if (odp_flow_key_to_flow(key, key_len, flow)) 
	{
		/*prob函数为空*/
        if (!probe) 
		{
            /* This should not happen: it indicates that
             * odp_flow_key_from_flow() and odp_flow_key_to_flow() disagree on
             * the acceptable form of a flow.  Log the problem as an error,
             * with enough details to enable debugging. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            if (!VLOG_DROP_ERR(&rl)) 
			{
                struct ds s;

				/*初始化一个空buffer*/
                ds_init(&s);

				/**/
                odp_flow_format(key, key_len, NULL, 0, NULL, &s, true);
                VLOG_ERR("internal error parsing flow key %s", ds_cstr(&s));

				/*释放s 空buffer*/
				ds_destroy(&s);
            }
        }

        return EINVAL;
    }

    if (flow->ct_state & DP_NETDEV_CS_UNSUPPORTED_MASK) {
        return EINVAL;
    }

    return 0;
}

/*******************************************************************************
 函数名称  :    emc_cache_slow_sweep
 功能描述  :    emc流表删除
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
dpif_netdev_flow_get(const struct dpif *dpif, const struct dpif_flow_get *get)
{
	/*获取dp*/
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *netdev_flow;
    struct dp_netdev_pmd_thread *pmd;
    struct hmapx to_find = HMAPX_INITIALIZER(&to_find);
    struct hmapx_node *node;
    int error = EINVAL;

	/*未指定pmd*/
    if (get->pmd_id == PMD_ID_NULL) {

		/*遍历所有pmd*/
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {

			/*释放pmd*/
            if (dp_netdev_pmd_try_ref(pmd) && !hmapx_add(&to_find, pmd)) {
                dp_netdev_pmd_unref(pmd);
            }
        }
    } else {
    	/*根据指定的core_id 从pmd poll 链表获取核对应pmd*/
        pmd = dp_netdev_get_pmd(dp, get->pmd_id);
        if (!pmd) {
            goto out;
        }

		/*放入找到的pmd*/
        hmapx_add(&to_find, pmd);
    }

    if (!hmapx_count(&to_find)) {
        goto out;
    }

	/*遍历查到的pmd*/
    HMAPX_FOR_EACH (node, &to_find) 
	{
        pmd = (struct dp_netdev_pmd_thread *) node->data;

		/*在pmd上查flow*/
		netdev_flow = dp_netdev_pmd_find_flow(pmd, get->ufid, get->key,
                                              get->key_len);
		/*查到了flow*/
		if (netdev_flow) {
            dp_netdev_flow_to_dpif_flow(netdev_flow, get->buffer, get->buffer,
                                        get->flow, false);
            error = 0;
            break;
        } else {
            error = ENOENT;
        }
    }

    HMAPX_FOR_EACH (node, &to_find) {
        pmd = (struct dp_netdev_pmd_thread *) node->data;
        dp_netdev_pmd_unref(pmd);
    }
out:
    hmapx_destroy(&to_find);
    return error;
}

/*******************************************************************************
 函数名称  :    dp_netdev_get_mega_ufid
 功能描述  :    生产maga ufid
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
dp_netdev_get_mega_ufid(const struct match *match, ovs_u128 *mega_ufid)
{
    struct flow masked_flow;
    size_t i;

    for (i = 0; i < sizeof(struct flow); i++) {

		/*生成marked flow*/
        ((uint8_t *)&masked_flow)[i] = ((uint8_t *)&match->flow)[i] &
                                       ((uint8_t *)&match->wc)[i];
    }

	/*生成mega flow ufid*/
    dpif_flow_hash(NULL, &masked_flow, sizeof(struct flow), mega_ufid);
}
/*******************************************************************************
 函数名称  :    dp_netdev_flow_add
 功能描述  :    流表插入pmd 对应port的dpcls、和emc
 输入参数  :    pmd---pmd
 				match---提取出来的match条件
 				ufid---流表的ufid，指定的或生成的
 				actions---提取出的actions
 				actions_len---action的个数
 
 输出参数  :	
 返 回 值  : 	dp_netdev_flow
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static struct dp_netdev_flow *
dp_netdev_flow_add(struct dp_netdev_pmd_thread *pmd,
                   struct match *match, const ovs_u128 *ufid,
                   const struct nlattr *actions, size_t actions_len)
    OVS_REQUIRES(pmd->flow_mutex)
{
	/*流表*/
    struct dp_netdev_flow *flow;

	/*miniflow key 掩码结构*/
	struct netdev_flow_key mask;

	/*port的dpcls*/
    struct dpcls *cls;

	/*确保inport精确匹配*/
    /* Make sure in_port is exact matched before we read it. */
    ovs_assert(match->wc.masks.in_port.odp_port == ODPP_NONE);

	/*流表的in_port*/
    odp_port_t in_port = match->flow.in_port.odp_port;

    /* As we select the dpcls based on the port number, each netdev flow
     * belonging to the same dpcls will have the same odp_port value.
     * For performance reasons we wildcard odp_port here in the mask.  In the
     * typical case dp_hash is also wildcarded, and the resulting 8-byte
     * chunk {dp_hash, in_port} will be ignored by netdev_flow_mask_init() and
     * will not be part of the subtable mask.
     * This will speed up the hash computation during dpcls_lookup() because
     * there is one less call to hash_add64() in this case. */

	/*mask初始化*/
	match->wc.masks.in_port.odp_port = 0;

	/*flow 掩码初始化，提取miniflow key的掩码*/
    netdev_flow_mask_init(&mask, match);

	match->wc.masks.in_port.odp_port = ODPP_NONE;

    /* Make sure wc does not have metadata. */
    ovs_assert(!FLOWMAP_HAS_FIELD(&mask.mf.map, metadata)
               && !FLOWMAP_HAS_FIELD(&mask.mf.map, regs));

    /* Do not allocate extra space. */
	/*申请flow结构并填充*/
    flow = xmalloc(sizeof *flow - sizeof flow->cr.flow.mf + mask.len);

	memset(&flow->stats, 0, sizeof flow->stats);


	/*流表状态*/
	flow->dead = false;
    flow->batch = NULL;

	/*没有mark值*/
    flow->mark = INVALID_FLOW_MARK;

	/*flow的pmd ufid等*/
    *CONST_CAST(unsigned *, &flow->pmd_id) = pmd->core_id;

	/*填入match*/
    *CONST_CAST(struct flow *, &flow->flow) = match->flow;

	/*填入ufid*/
	*CONST_CAST(ovs_u128 *, &flow->ufid) = *ufid;

	/*初始化flow的引用情况*/
	ovs_refcount_init(&flow->ref_cnt);

	/*actions 填入dp_netdev_flow*/
	ovsrcu_set(&flow->actions, dp_netdev_actions_create(actions, actions_len));

	/*获取mega flow ufid*/
    dp_netdev_get_mega_ufid(match, CONST_CAST(ovs_u128 *, &flow->mega_ufid));

	/*初始化miniflow key mask*/
    netdev_flow_key_init_masked(&flow->cr.flow, &match->flow, &mask);

    /* Select dpcls for in_port. Relies on in_port to be exact match. */

	/*查询dpcls是否存在，不存在创建dpcls插入pmd->classifiers*/
    cls = dp_netdev_pmd_find_dpcls(pmd, in_port);

	VLOG_DBG("zwl dp_netdev_flow_add find dpcls ok in_port=%u",in_port);

	/*flow的dpcls rule 插入，根据掩码找到相应的子表，然后插入当前的流表*/
    dpcls_insert(cls, &flow->cr, &mask);

	VLOG_DBG("zwl dp_netdev_flow_add flow insert dpcls");

	/*flow插入pmd->flow_table 存储所有pmd flow，flow节点挂链*/
    cmap_insert(&pmd->flow_table, CONST_CAST(struct cmap_node *, &flow->node), dp_netdev_flow_hash(&flow->ufid));

	VLOG_DBG("zwl dp_netdev_flow_add flow insert flow_table");

	/*offload下发流表、flow添加到offload item 最终由offload线程下发*/
    queue_netdev_flow_put(pmd, flow, match, actions, actions_len);

	/**/
    if (OVS_UNLIKELY(!VLOG_DROP_DBG((&upcall_rl)))) 
	{
        struct ds ds = DS_EMPTY_INITIALIZER;
        struct ofpbuf key_buf, mask_buf;

		/*参数*/
        struct odp_flow_key_parms odp_parms = 
        {
            .flow = &match->flow,				/*match*/
            .mask = &match->wc.masks,			/*掩码*/
            .support = dp_netdev_support,
        };

		/*key与mask 内存初始化*/
        ofpbuf_init(&key_buf, 0);
        ofpbuf_init(&mask_buf, 0);

		/*解析出key mask*/
        odp_flow_key_from_flow(&odp_parms, &key_buf);
        odp_parms.key_buf = &key_buf;

		/*mask buf*/
        odp_flow_key_from_mask(&odp_parms, &mask_buf);

        ds_put_cstr(&ds, "flow_add: ");

		/*ufid*/
        odp_format_ufid(ufid, &ds);
        ds_put_cstr(&ds, " ");

		/*flow格式化*/
        odp_flow_format(key_buf.data, key_buf.size, mask_buf.data, mask_buf.size, NULL, &ds, false);
        ds_put_cstr(&ds, ", actions:");

		/*flow action 格式化*/
        format_odp_actions(&ds, actions, actions_len, NULL);

        VLOG_DBG("%s", ds_cstr(&ds));

		/*match和key内存*/
        ofpbuf_uninit(&key_buf);
        ofpbuf_uninit(&mask_buf);

        /* Add a printout of the actual match installed. */
        struct match m;
        ds_clear(&ds);
        ds_put_cstr(&ds, "flow match: ");

		/*mask的 miniflow 恢复*/
        miniflow_expand(&flow->cr.flow.mf, &m.flow);

		
        miniflow_expand(&flow->cr.mask->mf, &m.wc.masks);

		/*隧道metadata清空*/
        memset(&m.tun_md, 0, sizeof m.tun_md);

		match_format(&m, NULL, &ds, OFP_DEFAULT_PRIORITY);

        VLOG_DBG("%s", ds_cstr(&ds));

        ds_destroy(&ds);
    }

    return flow;
}

/*******************************************************************************
 函数名称  :    flow_put_on_pmd
 功能描述  :    流表下到pmd
 输入参数  :  	pmd---要下流表的pmd线程
 				key---提取的miniflow key，struct netdev_flow_key key
 				match---match，struct match match 提取的match
 				ufid---flow的ufid
 				put---构造的要下发的流表
 				stats---dptctl流量统计
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static int
flow_put_on_pmd(struct dp_netdev_pmd_thread *pmd,
                struct netdev_flow_key *key,
                struct match *match,
                ovs_u128 *ufid,
                const struct dpif_flow_put *put,
                struct dpif_flow_stats *stats)
{
	/*表示一条流表项，包含了匹配域及对应的Actions*/
    struct dp_netdev_flow *netdev_flow;
    int error = 0;

	/*清空流量统计*/
    if (stats) 
	{
        memset(stats, 0, sizeof *stats);
    }

    ovs_mutex_lock(&pmd->flow_mutex);

	VLOG_DBG("zwl flow_put_on_pmd pmd->core_id=%d, ufid=%lu",pmd->core_id,*ufid);

	/*在pmd查询流表是否存在，存在返回报文命中dpcls rule对应的netdev_flows  key 为存储miniflow的netdev_flow_key*/
    netdev_flow = dp_netdev_pmd_lookup_flow(pmd, key, NULL);
	
	/*流表不存在*/
    if (!netdev_flow) 
	{
		/*新流表*/
        if (put->flags & DPIF_FP_CREATE) 
		{
			/*pmd流表未满*/
            if (cmap_count(&pmd->flow_table) < MAX_FLOWS) 
			{
				/*下发流表到pmd*/
                dp_netdev_flow_add(pmd, match, ufid, put->actions, put->actions_len);
                error = 0;
            } 
			else 
			{
                error = EFBIG;
            }
        } 
		else 
		{
            error = ENOENT;
        }
    }
	/*流表存在*/
	else 
	{
    	/*存在是否是mod*/
        if (put->flags & DPIF_FP_MODIFY) 
		{
            struct dp_netdev_actions *new_actions;
            struct dp_netdev_actions *old_actions;

            new_actions = dp_netdev_actions_create(put->actions, put->actions_len);

            old_actions = dp_netdev_flow_get_actions(netdev_flow);
            ovsrcu_set(&netdev_flow->actions, new_actions);

			/*下发流表*/
            queue_netdev_flow_put(pmd, netdev_flow, match, put->actions, put->actions_len);

            if (stats) 
			{
                get_dpif_flow_stats(netdev_flow, stats);
            }
            if (put->flags & DPIF_FP_ZERO_STATS) {
                /* XXX: The userspace datapath uses thread local statistics
                 * (for flows), which should be updated only by the owning
                 * thread.  Since we cannot write on stats memory here,
                 * we choose not to support this flag.  Please note:
                 * - This feature is currently used only by dpctl commands with
                 *   option --clear.
                 * - Should the need arise, this operation can be implemented
                 *   by keeping a base value (to be update here) for each
                 *   counter, and subtracting it before outputting the stats */
                error = EOPNOTSUPP;
            }

            ovsrcu_postpone(dp_netdev_actions_free, old_actions);
        } else if (put->flags & DPIF_FP_CREATE) {
            error = EEXIST;
        } else {
            /* Overlapping flow. */
            error = EINVAL;
        }
    }
    ovs_mutex_unlock(&pmd->flow_mutex);
    return error;
}

/*******************************************************************************
 函数名称  :    dpif_netdev_flow_put
 功能描述  :    下发流表
 输入参数  :  	dpif---dp接口描述结构
 				put---下发的流表描述
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static int
dpif_netdev_flow_put(struct dpif *dpif, const struct dpif_flow_put *put)
{
	/*根据dp接口描述结构获取网桥dp结构*/
    struct dp_netdev *dp = get_dp_netdev(dpif);

	/*miniflow key mask提取的miniflow*/
    struct netdev_flow_key key, mask;

	/*pmd线程*/
    struct dp_netdev_pmd_thread *pmd;

	/*match条件*/
    struct match match;
    ovs_u128 ufid;
    int error;

	/*错误信息*/
    bool probe = put->flags & DPIF_FP_PROBE;

	VLOG_DBG("zwl flow dpif_netdev_flow_put 111");
	
	/*清空流表流量统计*/
    if (put->stats) 
	{
        memset(put->stats, 0, sizeof *put->stats);
    }

	/*解析put->key流表match填入match的 flow结构*/
    error = dpif_netdev_flow_from_nlattrs(put->key, put->key_len, &match.flow, probe);
    if (error) 
	{
        return error;
    }

	/*解析出flow put->mask掩码 填入match的mask结构*/
    error = dpif_netdev_mask_from_nlattrs(put->key, put->key_len, put->mask, put->mask_len, &match.flow, &match.wc, probe);
    if (error) 
	{
        return error;
    }

	/*获取流表ufid，流表指定了ufid*/
    if (put->ufid) 
	{
        ufid = *put->ufid;
    } 
	else 
	{
    	/*key与key长度算hash 生成uufid 填入match*/
        dpif_flow_hash(dpif, &match.flow, sizeof match.flow, &ufid);
    }

	VLOG_DBG("zwl flow ufid=%lu",ufid);

    /* The Netlink encoding of datapath flow keys cannot express
     * wildcarding the presence of a VLAN tag. Instead, a missing VLAN
     * tag is interpreted as exact match on the fact that there is no
     * VLAN.  Unless we refactor a lot of code that translates between
     * Netlink and struct flow representations, we have to do the same
     * here.  This must be in sync with 'match' in handle_packet_upcall(). */

	/*vlan字段*/
	if (!match.wc.masks.vlans[0].tci) 
	{
        match.wc.masks.vlans[0].tci = htons(0xffff);
    }

    /* Must produce a netdev_flow_key for lookup.
     * Use the same method as employed to create the key when adding
     * the flow to the dplcs to make sure they match. */

	/*mask和match 结构初始化*/
    netdev_flow_mask_init(&mask, &match);

	/*key 提取match 填入miniflow key和 flow 的 match，还有miniflow 的mask*/
    netdev_flow_key_init_masked(&key, &match.flow, &mask);

	VLOG_DBG("zwl dpif_netdev_flow_put put->pmd_id=%u", put->pmd_id);

	/*流表未指定pmd，下发流表到所有pmd*/
    if (put->pmd_id == PMD_ID_NULL) 
	{
		/*pmd线程数为0*/
        if (cmap_count(&dp->poll_threads) == 0) 
		{
            return EINVAL;
        }
		
		/*遍历dp上的pmd线程下发流表*/
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) 
        {
            struct dpif_flow_stats pmd_stats;
            int pmd_error;

			/*流表下到pmd*/
            pmd_error = flow_put_on_pmd(pmd, &key, &match, &ufid, put, &pmd_stats);
            if (pmd_error) 
			{
                error = pmd_error;
            } 
			else if (put->stats) 
            {

				/*流表流量统计*/
                put->stats->n_packets += pmd_stats.n_packets;
                put->stats->n_bytes += pmd_stats.n_bytes;
                put->stats->used = MAX(put->stats->used, pmd_stats.used);
                put->stats->tcp_flags |= pmd_stats.tcp_flags;
            }
        }
    }
	/*指定了pmd*/
	else 
	{
    	/*获取pmd线程*/
        pmd = dp_netdev_get_pmd(dp, put->pmd_id);
        if (!pmd) 
		{
            return EINVAL;
        }

		/*下发流表到指定pmd*/
        error = flow_put_on_pmd(pmd, &key, &match, &ufid, put, put->stats);

		dp_netdev_pmd_unref(pmd);
    }

    return error;
}

/*******************************************************************************
 函数名称  :    flow_del_on_pmd
 功能描述  :    从pmd上删除flow
 输入参数  :  	pmd---要删除flow的pmd
 				stats---要删除的flow的流量统计
 				del---要删除的flow
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static int
flow_del_on_pmd(struct dp_netdev_pmd_thread *pmd,
                struct dpif_flow_stats *stats,
                const struct dpif_flow_del *del)
{
	/*要删除的flow*/
    struct dp_netdev_flow *netdev_flow;
    int error = 0;

	/*获取互斥锁*/
    ovs_mutex_lock(&pmd->flow_mutex);

	/*pmd上找到flow*/
    netdev_flow = dp_netdev_pmd_find_flow(pmd, del->ufid, del->key,
                                          del->key_len);

	/*找到了要删除的flow*/
	if (netdev_flow) {
        if (stats) {
            get_dpif_flow_stats(netdev_flow, stats);
        }
		
		/*flow 删除*/
        dp_netdev_pmd_remove_flow(pmd, netdev_flow);
    } else {
        error = ENOENT;
    }

	/*释放互斥锁*/
    ovs_mutex_unlock(&pmd->flow_mutex);

    return error;
}

/*******************************************************************************
 函数名称  :    dpif_netdev_flow_del
 功能描述  :    删除flow
 输入参数  :  	del---要删除的flow
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static int
dpif_netdev_flow_del(struct dpif *dpif, const struct dpif_flow_del *del)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;
    int error = 0;

	/*要删除的flow的流量统计*/
    if (del->stats) {
        memset(del->stats, 0, sizeof *del->stats);
    }

	/*要删除的flow没有指定pmd*/
    if (del->pmd_id == PMD_ID_NULL) {

		/*poll节点个数*/
        if (cmap_count(&dp->poll_threads) == 0) {
            return EINVAL;
        }

		/*poll pmd 节点*/
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
            struct dpif_flow_stats pmd_stats;
            int pmd_error;

			/*删除flow*/
            pmd_error = flow_del_on_pmd(pmd, &pmd_stats, del);
            if (pmd_error) {
                error = pmd_error;
            } 
			/*要删除的flow的stats 赋值*/
			else if (del->stats) {

				/*要删除的flow的stats*/
                del->stats->n_packets += pmd_stats.n_packets;
                del->stats->n_bytes += pmd_stats.n_bytes;
                del->stats->used = MAX(del->stats->used, pmd_stats.used);
                del->stats->tcp_flags |= pmd_stats.tcp_flags;
            }
        }
    }
	else {

		/*获取要删除的flow的pmd*/
		pmd = dp_netdev_get_pmd(dp, del->pmd_id);
        if (!pmd) {
            return EINVAL;
        }

		/*从pmd上删除flow*/
        error = flow_del_on_pmd(pmd, del->stats, del);

		/*解除*/
		dp_netdev_pmd_unref(pmd);
    }


    return error;
}

/*pmd dump结构，描述dump，多revalidator线程互斥，只需第一个revalidator线程创建一次*/
struct dpif_netdev_flow_dump {
    struct dpif_flow_dump up;						/*dpif结构*/
    struct cmap_position poll_thread_pos;			/*标识是哪个pmd线程node*/
    struct cmap_position flow_pos;					/*遍历到cmap的位置*/
    struct dp_netdev_pmd_thread *cur_pmd;			/*当前pmd线程*/
    int status;										/*状态*/
    struct ovs_mutex mutex;							/*多revalidator线程互斥*/
};

static struct dpif_netdev_flow_dump *
dpif_netdev_flow_dump_cast(struct dpif_flow_dump *dump)
{
    return CONTAINER_OF(dump, struct dpif_netdev_flow_dump, up);
}

/*******************************************************************************
 函数名称  :    dpif_netdev_flow_dump_create
 功能描述  :    创建一个dump
 输入参数  :  	terse---true
 				type---NULL
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static struct dpif_flow_dump *
dpif_netdev_flow_dump_create(const struct dpif *dpif_, bool terse,
                             char *type OVS_UNUSED)
{
	/*创建一个dump结构*/
    struct dpif_netdev_flow_dump *dump;

	/*dump flow使用的结构*/
    dump = xzalloc(sizeof *dump);
	
    dpif_flow_dump_init(&dump->up, dpif_);

	/*设置了这个应该不返回具体信息*/
	dump->up.terse = terse;

	ovs_mutex_init(&dump->mutex);

    return &dump->up;
}

static int
dpif_netdev_flow_dump_destroy(struct dpif_flow_dump *dump_)
{
    struct dpif_netdev_flow_dump *dump = dpif_netdev_flow_dump_cast(dump_);

    ovs_mutex_destroy(&dump->mutex);
    free(dump);
    return 0;
}

/*dump 线程结构*/
struct dpif_netdev_flow_dump_thread {
    struct dpif_flow_dump_thread up;						/*dump线程内up结构*/
    struct dpif_netdev_flow_dump *dump;						/*dump线程对应的dump结构*/
    struct odputil_keybuf keybuf[FLOW_DUMP_MAX_BATCH];		/*记录match*/
    struct odputil_keybuf maskbuf[FLOW_DUMP_MAX_BATCH];		/*记录action*/
};

static struct dpif_netdev_flow_dump_thread *
dpif_netdev_flow_dump_thread_cast(struct dpif_flow_dump_thread *thread)
{
    return CONTAINER_OF(thread, struct dpif_netdev_flow_dump_thread, up);
}

/*******************************************************************************
 函数名称  :    dpif_netdev_flow_dump_thread_create
 功能描述  :    创建dump线程结构
 输入参数  :  	dump_---
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static struct dpif_flow_dump_thread *
dpif_netdev_flow_dump_thread_create(struct dpif_flow_dump *dump_)
{
	/*获取struct dpif_netdev_flow_dump结构，
	  pmd dump结构，描述dump，多revalidator线程互斥，只需第一个revalidator线程创建一次*/
    struct dpif_netdev_flow_dump *dump = dpif_netdev_flow_dump_cast(dump_);
    struct dpif_netdev_flow_dump_thread *thread;

	/*创建dump线程结构*/
    thread = xmalloc(sizeof *thread);
    dpif_flow_dump_thread_init(&thread->up, &dump->up);
    thread->dump = dump;

	return &thread->up;
}

static void
dpif_netdev_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread_)
{
    struct dpif_netdev_flow_dump_thread *thread
        = dpif_netdev_flow_dump_thread_cast(thread_);

    free(thread);
}

/*******************************************************************************
 函数名称  :    dpif_netdev_flow_dump_next
 功能描述  :    从dp dump 50条flow
 输入参数  :  	thread---struct dpif_flow_dump_thread  dump flow用到的线程
 				flows---记录dump到的dp flow，已转换为 struct dpif_flow
 				max_flows---每次最大dump 50条flow
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static int
dpif_netdev_flow_dump_next(struct dpif_flow_dump_thread *thread_,
                           struct dpif_flow *flows, int max_flows)
{
	/*获取线程dump结构*/
    struct dpif_netdev_flow_dump_thread *thread
        = dpif_netdev_flow_dump_thread_cast(thread_);

	/*获取dp层dump结构，多线程公用，只需第一个revalidator创建一次*/
    struct dpif_netdev_flow_dump *dump = thread->dump;

	/*dp层flow数组 50条*/
	struct dp_netdev_flow *netdev_flows[FLOW_DUMP_MAX_BATCH];

	int n_flows = 0;
    int i;

	/*互斥锁在全局dump结构*/
    ovs_mutex_lock(&dump->mutex);

	/*还可以获取pmd 去dump flow*/
    if (!dump->status) {

		/*获取dpif结构*/
		struct dpif_netdev *dpif = dpif_netdev_cast(thread->up.dpif);

		/*获取dp_netdev*/
        struct dp_netdev *dp = get_dp_netdev(&dpif->dpif);

		/*当前dump的线程*/
		struct dp_netdev_pmd_thread *pmd = dump->cur_pmd;

		/*每次dump 50条flow*/
		int flow_limit = MIN(max_flows, FLOW_DUMP_MAX_BATCH);

		/*没有指定pmd 获取pmd*/
        /* First call to dump_next(), extracts the first pmd thread.
         * If there is no pmd thread, returns immediately. */
        if (!pmd) {
			
			/*获取下一个pmd线程*/
            pmd = dp_netdev_pmd_get_next(dp, &dump->poll_thread_pos);
            if (!pmd) {
                ovs_mutex_unlock(&dump->mutex);
                return n_flows;

            }
        }

		/*执行成功就执行一次 dump 50条flow，本pmd上没有flow dump下一个pmd的50条flow*/
		/*最上面获取了互斥锁，同时只有一个revalidator线程访问pmd上flow*/
        do {
			/*遍历pmd上的flow 每轮限制50个*/
            for (n_flows = 0; n_flows < flow_limit; n_flows++) {
                struct cmap_node *node;

				/*遍历pmd上的flow table，每次1个，成功获取后更新位置*/
                node = cmap_next_position(&pmd->flow_table, &dump->flow_pos);
				/*存在空节点则break*/
				if (!node) {
                    break;
                }

				/*记录返回的struct dp_netdev_flow*/
                netdev_flows[n_flows] = CONTAINER_OF(node,
                                                     struct dp_netdev_flow,
                                                     node);
            }

			/*如果本pmd 没有dump够，换下一个pmd*/
            /* When finishing dumping the current pmd thread, moves to
             * the next. */
            if (n_flows < flow_limit) {

				/*没有dump 够 50条*/
                memset(&dump->flow_pos, 0, sizeof dump->flow_pos);
                dp_netdev_pmd_unref(pmd);

				/*获取下一个pmd线程*/
                pmd = dp_netdev_pmd_get_next(dp, &dump->poll_thread_pos);
                if (!pmd) {

					/*换pmd打上EOF标记*/
                    dump->status = EOF;
                    break;
                }
            }

			/*记录当前dump的pmd线程*/
            /* Keeps the reference to next caller. */
            dump->cur_pmd = pmd;

            /* If the current dump is empty, do not exit the loop, since the
             * remaining pmds could have flows to be dumped.  Just dumps again
             * on the new 'pmd'. */
        } while (!n_flows);
    }

	/*互斥锁解锁*/
    ovs_mutex_unlock(&dump->mutex);

	/*50条flow*/
    for (i = 0; i < n_flows; i++) {

		/*match*/
        struct odputil_keybuf *maskbuf = &thread->maskbuf[i];

		/*action*/
		struct odputil_keybuf *keybuf = &thread->keybuf[i];

		/*dp 层的flow*/
		struct dp_netdev_flow *netdev_flow = netdev_flows[i];

		/*转成dpif flow*/
		struct dpif_flow *f = &flows[i];
        struct ofpbuf key, mask;

		/*清0*/
        ofpbuf_use_stack(&key, keybuf, sizeof *keybuf);
        ofpbuf_use_stack(&mask, maskbuf, sizeof *maskbuf);

		/*flow转换成struct dpif_flow 填入f*/
		dp_netdev_flow_to_dpif_flow(netdev_flow, &key, &mask, f,
                                    dump->up.terse);
    }

    return n_flows;
}

/*******************************************************************************
 函数名称  :    dpif_netdev_execute
 功能描述  :    执行flow的action
 输入参数  :  	execute---dpif执行结构
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static int
dpif_netdev_execute(struct dpif *dpif, struct dpif_execute *execute)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
	/*获取dp*/
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;

	/*dp报文批处理*/
	struct dp_packet_batch pp;

	/*要处理的报文*/
    if (dp_packet_size(execute->packet) < ETH_HEADER_LEN ||
        dp_packet_size(execute->packet) > UINT16_MAX) {
        return EINVAL;
    }

    /* Tries finding the 'pmd'.  If NULL is returned, that means
     * the current thread is a non-pmd thread and should use
     * dp_netdev_get_pmd(dp, NON_PMD_CORE_ID). */

	/*查找dp所在pmd，查不到查非pmd线程*/
    pmd = ovsthread_getspecific(dp->per_pmd_key);
    if (!pmd) {
		/*查非pmd线程，查到非pmd*/
        pmd = dp_netdev_get_pmd(dp, NON_PMD_CORE_ID);
        if (!pmd) {
            return EBUSY;
        }
    }

	/*执行probe函数*/
    if (execute->probe) {
        /* If this is part of a probe, Drop the packet, since executing
         * the action may actually cause spurious packets be sent into
         * the network. */

		/*非pmd核*/
        if (pmd->core_id == NON_PMD_CORE_ID) {

			/*释放非pmd线程*/
            dp_netdev_pmd_unref(pmd);
        }
        
        return 0;
    }

    /* If the current thread is non-pmd thread, acquires
     * the 'non_pmd_mutex'. */

	/*非pmd线程*/
    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_lock(&dp->non_pmd_mutex);
    }

	/*更新非pmd线程上下文*/
    /* Update current time in PMD context. */
    pmd_thread_ctx_time_update(pmd);

    /* The action processing expects the RSS hash to be valid, because
     * it's always initialized at the beginning of datapath processing.
     * In this case, though, 'execute->packet' may not have gone through
     * the datapath at all, it may have been generated by the upper layer
     * (OpenFlow packet-out, BFD frame, ...). */

	/*RSS invalid的情况*/
	if (!dp_packet_rss_valid(execute->packet)) {

		/*设置报文的RSS*/
		dp_packet_set_rss_hash(execute->packet,
                               flow_hash_5tuple(execute->flow, 0));
    }

	/*dp报文批处理初始化*/
    dp_packet_batch_init_packet(&pp, execute->packet);

	/*对批处理报文执行flow的action*/
	dp_netdev_execute_actions(pmd, &pp, false, execute->flow,
                              execute->actions, execute->actions_len);

	/*pmd flush掉发端口要批量发出去的报文*/
	dp_netdev_pmd_flush_output_packets(pmd, true);

	/*非pmd线程解除关联*/
    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_unlock(&dp->non_pmd_mutex);

		/*释放pmd资源*/
        dp_netdev_pmd_unref(pmd);
    }

    return 0;
}

/*******************************************************************************
 函数名称  :    dpif_netdev_operate
 功能描述  :    dpif层对流表的操作
 输入参数  :  	dpif---dp 接口描述结构
 				ops---dp流表操作结构数组
 				n_ops---op要操作的流表个数
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static void
dpif_netdev_operate(struct dpif *dpif, struct dpif_op **ops, size_t n_ops)
{
    size_t i;

	VLOG_DBG("zwl flow dpif_netdev_operate 111");
	
	/*遍历对流表的操作*/
    for (i = 0; i < n_ops; i++) 
	{
		/*对dp的操作类型*/
        struct dpif_op *op = ops[i];

        switch (op->type) 
		{
	        case DPIF_OP_FLOW_PUT:
				/*dpif层流表下发*/
	            op->error = dpif_netdev_flow_put(dpif, &op->flow_put);
	            break;

	        case DPIF_OP_FLOW_DEL:
				/*dpif层流表删除*/
	            op->error = dpif_netdev_flow_del(dpif, &op->flow_del);
	            break;

	        case DPIF_OP_EXECUTE:
				/*执行flow的action*/
	            op->error = dpif_netdev_execute(dpif, &op->execute);
	            break;

	        case DPIF_OP_FLOW_GET:
				/*获取flow*/
	            op->error = dpif_netdev_flow_get(dpif, &op->flow_get);
	            break;
        }
    }
}


/* Applies datapath configuration from the database. Some of the changes are
 * actually applied in dpif_netdev_run(). */
static int
dpif_netdev_set_config(struct dpif *dpif, const struct smap *other_config)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    const char *cmask = smap_get(other_config, "pmd-cpu-mask");
    unsigned long long insert_prob =
        smap_get_ullong(other_config, "emc-insert-inv-prob",
                        DEFAULT_EM_FLOW_INSERT_INV_PROB);
    uint32_t insert_min, cur_min;
    uint32_t tx_flush_interval, cur_tx_flush_interval;

    tx_flush_interval = smap_get_int(other_config, "tx-flush-interval",
                                     DEFAULT_TX_FLUSH_INTERVAL);
    atomic_read_relaxed(&dp->tx_flush_interval, &cur_tx_flush_interval);
    if (tx_flush_interval != cur_tx_flush_interval) {
        atomic_store_relaxed(&dp->tx_flush_interval, tx_flush_interval);
        VLOG_INFO("Flushing interval for tx queues set to %"PRIu32" us",
                  tx_flush_interval);
    }

    if (!nullable_string_is_equal(dp->pmd_cmask, cmask)) {
        free(dp->pmd_cmask);
        dp->pmd_cmask = nullable_xstrdup(cmask);
        dp_netdev_request_reconfigure(dp);
    }

    atomic_read_relaxed(&dp->emc_insert_min, &cur_min);
    if (insert_prob <= UINT32_MAX) {
        insert_min = insert_prob == 0 ? 0 : UINT32_MAX / insert_prob;
    } else {
        insert_min = DEFAULT_EM_FLOW_INSERT_MIN;
        insert_prob = DEFAULT_EM_FLOW_INSERT_INV_PROB;
    }

    if (insert_min != cur_min) {
        atomic_store_relaxed(&dp->emc_insert_min, insert_min);
        if (insert_min == 0) {
            VLOG_INFO("EMC has been disabled");
        } else {
            VLOG_INFO("EMC insertion probability changed to 1/%llu (~%.2f%%)",
                      insert_prob, (100 / (float)insert_prob));
        }
    }

    bool perf_enabled = smap_get_bool(other_config, "pmd-perf-metrics", false);
    bool cur_perf_enabled;
    atomic_read_relaxed(&dp->pmd_perf_metrics, &cur_perf_enabled);
    if (perf_enabled != cur_perf_enabled) {
        atomic_store_relaxed(&dp->pmd_perf_metrics, perf_enabled);
        if (perf_enabled) {
            VLOG_INFO("PMD performance metrics collection enabled");
        } else {
            VLOG_INFO("PMD performance metrics collection disabled");
        }
    }

    bool smc_enable = smap_get_bool(other_config, "smc-enable", false);
    bool cur_smc;
    atomic_read_relaxed(&dp->smc_enable_db, &cur_smc);
    if (smc_enable != cur_smc) {
        atomic_store_relaxed(&dp->smc_enable_db, smc_enable);
        if (smc_enable) {
            VLOG_INFO("SMC cache is enabled");
        } else {
            VLOG_INFO("SMC cache is disabled");
        }
    }
    return 0;
}

/*******************************************************************************
 函数名称  :    parse_affinity_list
 功能描述  :    记录队列亲和的CPU id
 输入参数  :  	affinity_list---CPU的亲和性
 				core_ids---队列亲和的核id
 				n_rxq---接收队列个数
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Parses affinity list and returns result in 'core_ids'. */
static int
parse_affinity_list(const char *affinity_list, unsigned *core_ids, int n_rxq)
{
    unsigned i;
    char *list, *copy, *key, *value;
    int error = 0;

    for (i = 0; i < n_rxq; i++) {
        core_ids[i] = OVS_CORE_UNSPEC;
    }

    if (!affinity_list) {
        return 0;
    }

    list = copy = xstrdup(affinity_list);

	/**/
    while (ofputil_parse_key_value(&list, &key, &value)) 
	{
        int rxq_id, core_id;

		/*接收队列id 转换成int*/
        if (! str_to_int(key, 0, &rxq_id) || rxq_id < 0
            || !str_to_int(value, 0, &core_id) || core_id < 0) 
        {
            error = EINVAL;
            break;
        }

		/*接收队列id记录对应亲和的核id*/
        if (rxq_id < n_rxq) 
		{
            core_ids[rxq_id] = core_id;
        }
    }

    free(copy);
    return error;
}

/*******************************************************************************
 函数名称  :    dpif_netdev_port_set_rxq_affinity
 功能描述  :    设置端口上接收队列的亲和性，端口可以是多队列
 输入参数  :  	port---端口
 				affinity_list---亲和的CPU list
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Parses 'affinity_list' and applies configuration if it is valid. */
static int
dpif_netdev_port_set_rxq_affinity(struct dp_netdev_port *port, const char *affinity_list)
{
    unsigned *core_ids, i;
    int error = 0;

	/*申请端口所有队列 CPU核id*/
    core_ids = xmalloc(port->n_rxq * sizeof *core_ids);

	/*记录接收队列亲和的逻辑核id，队列与核一一对应*/
	if (parse_affinity_list(affinity_list, core_ids, port->n_rxq)) 
	{
        error = EINVAL;
        goto exit;
    }

	/*端口rxq队列对应的逻辑核id 设置*/
    for (i = 0; i < port->n_rxq; i++) 
	{
        port->rxqs[i].core_id = core_ids[i];
    }

exit:
    free(core_ids);
    return error;
}


/*******************************************************************************
 函数名称  :    dpif_netdev_port_set_config
 功能描述  :    设置端口rx队列的亲和性
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/

/* Changes the affinity of port's rx queues.  The changes are actually applied
 * in dpif_netdev_run(). */
static int
dpif_netdev_port_set_config(struct dpif *dpif, odp_port_t port_no,
                            const struct smap *cfg)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error = 0;

	/*端口亲和性配置*/
    const char *affinity_list = smap_get(cfg, "pmd-rxq-affinity");

    ovs_mutex_lock(&dp->port_mutex);
    error = get_port_by_number(dp, port_no, &port);
    if (error || !netdev_is_pmd(port->netdev)
        || nullable_string_is_equal(affinity_list, port->rxq_affinity_list)) {
        goto unlock;
    }

	/*设置端口rx队列的亲和性*/
    error = dpif_netdev_port_set_rxq_affinity(port, affinity_list);
    if (error) {
        goto unlock;
    }
    free(port->rxq_affinity_list);
	
    port->rxq_affinity_list = nullable_xstrdup(affinity_list);

	/*重新配置dp*/
    dp_netdev_request_reconfigure(dp);
unlock:
    ovs_mutex_unlock(&dp->port_mutex);
    return error;
}

static int
dpif_netdev_queue_to_priority(const struct dpif *dpif OVS_UNUSED,
                              uint32_t queue_id, uint32_t *priority)
{
    *priority = queue_id;
    return 0;
}

/*******************************************************************************
 函数名称  :    dp_netdev_actions_create
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
/* Creates and returns a new 'struct dp_netdev_actions', whose actions are
 * a copy of the 'size' bytes of 'actions' input parameters. */
struct dp_netdev_actions *
dp_netdev_actions_create(const struct nlattr *actions, size_t size)
{
    struct dp_netdev_actions *netdev_actions;

	/*action*/
    netdev_actions = xmalloc(sizeof *netdev_actions + size);
    memcpy(netdev_actions->actions, actions, size);
    netdev_actions->size = size;

    return netdev_actions;
}

/*******************************************************************************
 函数名称  :    dp_netdev_flow_get_actions
 功能描述  :    获取流表的action
 输入参数  :    
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
struct dp_netdev_actions *
dp_netdev_flow_get_actions(const struct dp_netdev_flow *flow)
{
    return ovsrcu_get(struct dp_netdev_actions *, &flow->actions);
}

static void
dp_netdev_actions_free(struct dp_netdev_actions *actions)
{
    free(actions);
}

/*******************************************************************************
 函数名称  :    dp_netdev_rxq_set_cycles
 功能描述  :    接收队列设置循环
 输入参数  :    rx---接收队列
 			    type---统计类型---RXQ_CYCLES_PROC_CURR
 			    cycles---队列poll的次数
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static void
dp_netdev_rxq_set_cycles(struct dp_netdev_rxq *rx, enum rxq_cycles_counter_type type, unsigned long long cycles)
{
   /*队列poll的次数赋值*/	
   atomic_store_relaxed(&rx->cycles[type], cycles);
}

/*******************************************************************************
 函数名称  :  dp_netdev_rxq_add_cycles
 功能描述  :  接收队列添加循环
 输入参数  :  rx---接收队列	
 			  type---流量统计类型 RXQ_CYCLES_PROC_CURR
 			  cycles---批处理循环次数
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static void
dp_netdev_rxq_add_cycles(struct dp_netdev_rxq *rx, enum rxq_cycles_counter_type type, unsigned long long cycles)
{
	/*流量统计*/
    non_atomic_ullong_add(&rx->cycles[type], cycles);
}

static uint64_t
dp_netdev_rxq_get_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type)
{
    unsigned long long processing_cycles;
    atomic_read_relaxed(&rx->cycles[type], &processing_cycles);
    return processing_cycles;
}

static void
dp_netdev_rxq_set_intrvl_cycles(struct dp_netdev_rxq *rx,
                                unsigned long long cycles)
{
    unsigned int idx = rx->intrvl_idx++ % PMD_RXQ_INTERVAL_MAX;
    atomic_store_relaxed(&rx->cycles_intrvl[idx], cycles);
}

/*******************************************************************************
 函数名称  :    dp_netdev_rxq_get_intrvl_cycles
 功能描述  :    读取poll队列时间间隔梯度设置
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
static uint64_t
dp_netdev_rxq_get_intrvl_cycles(struct dp_netdev_rxq *rx, unsigned idx)
{
    unsigned long long processing_cycles;

	/*读取poll队列时间间隔梯度设置 数组为6*/
    atomic_read_relaxed(&rx->cycles_intrvl[idx], &processing_cycles);
    return processing_cycles;
}

#if ATOMIC_ALWAYS_LOCK_FREE_8B

/*******************************************************************************
 函数名称  :    pmd_perf_metrics_enabled
 功能描述  :    获取流量统计是否开启开关
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
static inline bool
pmd_perf_metrics_enabled(const struct dp_netdev_pmd_thread *pmd)
{
    bool pmd_perf_enabled;

	/*读取流量统计是否开启*/
    atomic_read_relaxed(&pmd->dp->pmd_perf_metrics, &pmd_perf_enabled);

	return pmd_perf_enabled;
}
#else
/* If stores and reads of 64-bit integers are not atomic, the full PMD
 * performance metrics are not available as locked access to 64 bit
 * integers would be prohibitively expensive. */
static inline bool
pmd_perf_metrics_enabled(const struct dp_netdev_pmd_thread *pmd OVS_UNUSED)
{
    return false;
}
#endif

/*******************************************************************************
 函数名称  :  dp_netdev_pmd_flush_output_on_port
 功能描述  :  pmd发送端口待发送的批处理报文发出去
 输入参数  :  pmd---pmd线程
 			  p---pmd缓存的发端口
 输出参数  :  output_cnt---成功发的报文
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static int
dp_netdev_pmd_flush_output_on_port(struct dp_netdev_pmd_thread *pmd, struct tx_port *p)
{
    int i;
    int tx_qid;
    int output_cnt;
    bool dynamic_txqs;
    struct cycle_timer timer;
    uint64_t cycles;
    uint32_t tx_flush_interval;

	/*循环定时器启动*/
    cycle_timer_start(&pmd->perf_stats, &timer);

	/*端口使用动态发送队列开关使能*/
    dynamic_txqs = p->port->dynamic_txqs;
    if (dynamic_txqs) 
	{
		/*从发送队列ID池获取发送队列ID，动态调整*/
        tx_qid = dpif_netdev_xps_get_tx_qid(pmd, p);
    } 
	else 
	{
		/*pmd启动时指定的静态发队列id，从队列池中找的一个空闲的*/
        tx_qid = pmd->static_tx_qid;
    }

	/*端口等待要发出的批处理报文个数*/
    output_cnt = dp_packet_batch_size(&p->output_pkts);
    ovs_assert(output_cnt > 0);

	/*批处理报文发出去，从tx_qid 发队列*/
    netdev_send(p->port->netdev, tx_qid, &p->output_pkts, dynamic_txqs);

	/*报文批处理初始化*/
	dp_packet_batch_init(&p->output_pkts);

    /* Update time of the next flush. */
	/*读取发送时间*/
    atomic_read_relaxed(&pmd->dp->tx_flush_interval, &tx_flush_interval);

	/*更新下次发送报文flush时间*/
	p->flush_time = pmd->ctx.now + tx_flush_interval;

	/*发完报文有剩余报错*/
    ovs_assert(pmd->n_output_batches > 0);

	/*发出后批处理报文计数--*/
	pmd->n_output_batches--;

	/*发出去的包流量统计*/
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_SENT_PKTS, output_cnt);

	/*批处理发包流量统计*/
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_SENT_BATCHES, 1);

    /* Distribute send cycles evenly among transmitted packets and assign to
     * their respective rx queues. */
    /*循环时间定时器时间停止*/
    cycles = cycle_timer_stop(&pmd->perf_stats, &timer) / output_cnt;

	/*遍历端口发出去的批处理报文个数*/
	for (i = 0; i < output_cnt; i++) 
	{
		/*发包队列指针数组遍历*/
        if (p->output_pkts_rxqs[i]) 
		{
			/*流量统计*/
            dp_netdev_rxq_add_cycles(p->output_pkts_rxqs[i], RXQ_CYCLES_PROC_CURR, cycles);
        }
    }

	/*端口发出报文计数*/
    return output_cnt;
}

/*******************************************************************************
 函数名称  :    dp_netdev_pmd_flush_output_packets
 功能描述  :    pmd flush掉发端口要批量发出去的报文
 输入参数  :    pmd---pmd线程
 			    force---是否强制刷报文
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
dp_netdev_pmd_flush_output_packets(struct dp_netdev_pmd_thread *pmd, bool force)
{
    struct tx_port *p;
	
    int output_cnt = 0;

	/*出接口批处理报文数为0直接返回*/
    if (!pmd->n_output_batches) 
	{
        return 0;
    }

	/*遍历pmd缓存的发端口链表、把发端口上待发出的批处理缓存报文发掉*/
    HMAP_FOR_EACH (p, node, &pmd->send_port_cache) 
   	{
		/*批处理缓存报文数不为空 且 开启了强制发送开关 或 当前时间大于等于上次发送时间*/
        if (!dp_packet_batch_is_empty(&p->output_pkts) && (force || pmd->ctx.now >= p->flush_time)) 
       	{
           	/*报文刷出发端口*/ 
            output_cnt += dp_netdev_pmd_flush_output_on_port(pmd, p);
        }
    }

	/*返回发送的报文数*/
    return output_cnt;
}

/*******************************************************************************
 函数名称  :    dp_netdev_process_rxq_port
 功能描述  :    处理netdev的收包过程，负责接收报文
 			    1.调用接口dp_netdev_input–>dp_netdev_input__负责查表，
 			    2.调用packet_batch_execute–>dp_netdev_execute_actions执行actions操作。
 输入参数  :    pmd---port rx队列所在pmd线程结构
 		        rxq---poll的接收队列
 		        port_no---poll的收包端口
 输出参数  :	
 返 回 值  : 	读到port rx队列的报文数
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static int
dp_netdev_process_rxq_port(struct dp_netdev_pmd_thread *pmd, struct dp_netdev_rxq *rxq, odp_port_t port_no)
{
	/*流量统计*/
    struct pmd_perf_stats *s = &pmd->perf_stats;

	/*队列报文批处理缓存结构*/
    struct dp_packet_batch batch;

	/*循环定时器*/
	struct cycle_timer timer;

	int error;

	/*队列批处理缓存报文计数*/
    int batch_cnt = 0;

	/*队列中当前报文个数*/
    int rem_qlen = 0, *qlen_p = NULL;
    uint64_t cycles;

    /* Measure duration for polling and processing rx burst. */
	/*循环定时器开始*/
    cycle_timer_start(&pmd->perf_stats, &timer);

	/*记录最近读取的队列*/
    pmd->ctx.last_rxq = rxq;

	/*报文批处理结构初始化*/
    dp_packet_batch_init(&batch);

    /* Fetch the rx queue length only for vhostuser ports. */
	/*获取流量统计是否开启开关，获取接收队列长度、接收主机是虚拟主机*/
    if (pmd_perf_metrics_enabled(pmd) && rxq->is_vhost) 
	{
		/*当前队列报文个数、队列长度记录*/
        qlen_p = &rem_qlen;
    }

    /*从接收队列收包放入批处理结构，队列报文处理的都是批处理的结构*/
    error = netdev_rxq_recv(rxq->rx, &batch, qlen_p);
	
	VLOG_DBG("rxq recv ok")

	/*队列中poll到了报文*/
    if (!error) 
	{
        /* At least one packet received. */
		
        *recirc_depth_get() = 0;

		/*pmd线程上下文更新(当前时间)*/
        pmd_thread_ctx_time_update(pmd);

		/*队列批处理报文计数，从队列poll出的报文先放入批处理*/
		batch_cnt = batch.count;

		/*pmd 流量统计开关使能*/
        if (pmd_perf_metrics_enabled(pmd)) 
		{
            /* Update batch histogram. */

			/*当前队列流量统计，队列批处理缓存的报文*/
            s->current.batches++;

			/*批处理报文数矩形图添加*/
            histogram_add_sample(&s->pkts_per_batch, batch_cnt);

			/* Update the maximum vhost rx queue fill level. */

			/*队列为虚拟主机队列、当前队列报文个数、队列长度记录*/
            if (rxq->is_vhost && rem_qlen >= 0) 
			{
				/*队列填入报文数、批处理报文数*/
                uint32_t qfill = batch_cnt + rem_qlen;

				/*队列中报文数大于记录的最大虚拟主机中报文数*/
                if (qfill > s->current.max_vhost_qfill) 
				{
					/*虚拟主机队列报文数重填*/
                    s->current.max_vhost_qfill = qfill;
                }
            }
        }
		
        /* Process packet batch.*/
        /*将批处理batch中的包转入datapath 查emc、dpcls等操作，查找flow 、action，并且发送报文，前后都有计时*/
        dp_netdev_input(pmd, &batch, port_no);

        /* Assign processing cycles to rx queue. */
		/*接收队列处理循环停止*/
        cycles = cycle_timer_stop(&pmd->perf_stats, &timer);

		/*接收队列添加循环*/
        dp_netdev_rxq_add_cycles(rxq, RXQ_CYCLES_PROC_CURR, cycles);

		/*pmd flush掉 pmd output pkt 要发的报文*/
        dp_netdev_pmd_flush_output_packets(pmd, false);
    }
	else 
	{
        /* Discard cycles. */
		/*丢弃循环*/
        cycle_timer_stop(&pmd->perf_stats, &timer);
		
        if (error != EAGAIN && error != EOPNOTSUPP)
		{
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            VLOG_ERR_RL(&rl, "error receiving data from %s: %s", netdev_rxq_get_name(rxq->rx), ovs_strerror(error));
        }
    }

    pmd->ctx.last_rxq = NULL;

	/*批处理报文数*/
    return batch_cnt;
}

/*******************************************************************************
 函数名称  :  tx_port_lookup
 功能描述  :  pmd发送端口的报文
 输入参数  :  pmd---flow 所在pmd
 			  port_no---output端口
 			  
 输出参数  :  
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static struct tx_port *
tx_port_lookup(const struct hmap *hmap, odp_port_t port_no)
{
    struct tx_port *tx;

	/*命中发端口*/
    HMAP_FOR_EACH_IN_BUCKET (tx, node, hash_port_no(port_no), hmap) 
   	{
   		/*命中发端口*/
        if (tx->port->port_no == port_no) 
		{
            return tx;
        }
    }

    return NULL;
}

/*******************************************************************************
 函数名称  :    port_reconfigure
 功能描述  :    端口重新配置
 输入参数  :  	port---重新配置端口
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
port_reconfigure(struct dp_netdev_port *port)
{
	/*port 对应net结构*/
    struct netdev *netdev = port->netdev;
    int i, err;

    /* Closes the existing 'rxq's. */

	/*1.关闭释放端口所有收队列*/
    for (i = 0; i < port->n_rxq; i++) 
	{
        netdev_rxq_close(port->rxqs[i].rx);

		/*接收队列赋空*/
        port->rxqs[i].rx = NULL;
    }

	/*上次配置的port收队列数，port对应多队列*/
    unsigned last_nrxq = port->n_rxq;

	/*端口队列清0*/
    port->n_rxq = 0;

    /* Allows 'netdev' to apply the pending configuration changes. */

	/*端口netdev需重配，或port需要重新配置*/
    if (netdev_is_reconf_required(netdev) || port->need_reconfigure) 
	{
		/*端口netdev重新配置、更新重新配置序列号*/
        err = netdev_reconfigure(netdev);
        if (err && (err != EOPNOTSUPP)) 
		{
            VLOG_ERR("Failed to set interface %s new configuration", netdev_get_name(netdev));
            return err;
        }
    }

	/* If the netdev_reconfigure() above succeeds, reopens the 'rxq's. */
	/*重新申请端口接收队列*/		  /*端口收队列结构*/   /*端口收队列个数*/
	/*例如一个端口配置4个rx队列*/
    port->rxqs = xrealloc(port->rxqs, sizeof *port->rxqs * netdev_n_rxq(netdev));

	/* Realloc 'used' counters for tx queues. */
    free(port->txq_used);

	/*重新申请发队列引用次数记录结构数组unsigned，发队列个数，引用次数记录结构 unsigned*/
    port->txq_used = xcalloc(netdev_n_txq(netdev), sizeof *port->txq_used);

	/*遍历端口接收队列*/
    for (i = 0; i < netdev_n_rxq(netdev); i++) 
	{
	    /*上次配置的队列数已大于上次配置的收队列数*/
        bool new_queue = i >= last_nrxq;
		
        if (new_queue) 
		{
            memset(&port->rxqs[i], 0, sizeof port->rxqs[i]);
        }

		/*端口接收队列关联port*/
        port->rxqs[i].port = port;

		/*接收队列标记是否是dpdkvhost*/
        port->rxqs[i].is_vhost = !strncmp(port->type, "dpdkvhost", 9);

		/*打开端口接收队列 ，申请rxq*/
        err = netdev_rxq_open(netdev, &port->rxqs[i].rx, i);
        if (err) 
		{
            return err;
        }

		/*接收队列++*/
        port->n_rxq++;
    }

    /* Parse affinity list to apply configuration for new queues. */
	/*设置接收队列的cpu亲和性*/
    dpif_netdev_port_set_rxq_affinity(port, port->rxq_affinity_list);

    /* If reconfiguration was successful mark it as such, so we can use it */
    port->need_reconfigure = false;

    return 0;
}

/*numa节点list*/
struct rr_numa_list {
    struct hmap numas;  /* Contains 'struct rr_numa' */
};

/*numa节点*/
struct rr_numa {
    struct hmap_node node;

    int numa_id;										/*numa id*/

    /* Non isolated pmds on numa node 'numa_id' */
    struct dp_netdev_pmd_thread **pmds;				/*numa上非隔离的pmd*/
    int n_pmds;											/*numa上pmd个数*/

    int cur_index;
    bool idx_inc;
};

/*******************************************************************************
 函数名称  :    rr_numa_list_lookup
 功能描述  :    根据numa_id 在numa 链查找numa节点
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
static struct rr_numa *
rr_numa_list_lookup(struct rr_numa_list *rr, int numa_id)
{
    struct rr_numa *numa;

	/*根据numa_id 在numa 链查找numa节点*/
    HMAP_FOR_EACH_WITH_HASH (numa, node, hash_int(numa_id, 0), &rr->numas) 
    {
        if (numa->numa_id == numa_id) 
		{
            return numa;
        }
    }

    return NULL;
}

/*******************************************************************************
 函数名称  :    rr_numa_list_next
 功能描述  :    返回下一个轮询numa节点
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/

/* Returns the next node in numa list following 'numa' in round-robin fashion.
 * Returns first node if 'numa' is a null pointer or the last node in 'rr'.
 * Returns NULL if 'rr' numa list is empty. */
static struct rr_numa *
rr_numa_list_next(struct rr_numa_list *rr, const struct rr_numa *numa)
{
    struct hmap_node *node = NULL;

	/*轮询numa节点链表的下一个*/
    if (numa) {
        node = hmap_next(&rr->numas, &numa->node);
    }
    if (!node) {
        node = hmap_first(&rr->numas);
    }

    return (node) ? CONTAINER_OF(node, struct rr_numa, node) : NULL;
}

/*******************************************************************************
 函数名称  :    rr_numa_list_populate
 功能描述  :    numa轮询链表初始化
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
rr_numa_list_populate(struct dp_netdev *dp, struct rr_numa_list *rr)
{
    struct dp_netdev_pmd_thread *pmd;
    struct rr_numa *numa;

	/*numa轮询链表*/
    hmap_init(&rr->numas);

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {

		/*跳过已隔离的pmd和非pmd核*/
        if (pmd->core_id == NON_PMD_CORE_ID || pmd->isolated) {
            continue;
        }

		/*根据查询numa节点*/
        numa = rr_numa_list_lookup(rr, pmd->numa_id);
        if (!numa) {

			/*不存在则新建插入链表*/
            numa = xzalloc(sizeof *numa);
            numa->numa_id = pmd->numa_id;
            hmap_insert(&rr->numas, &numa->node, hash_int(pmd->numa_id, 0));
        }
        numa->n_pmds++;
        numa->pmds = xrealloc(numa->pmds, numa->n_pmds * sizeof *numa->pmds);
        numa->pmds[numa->n_pmds - 1] = pmd;
        /* At least one pmd so initialise curr_idx and idx_inc. */
        numa->cur_index = 0;
        numa->idx_inc = true;
    }
}

/*******************************************************************************
 函数名称  :    rr_numa_get_pmd
 功能描述  :    递增或递减顺序从中的numa节点返回下一个pmd
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

/* Returns the next pmd from the numa node in
 * incrementing or decrementing order. */
static struct dp_netdev_pmd_thread *
rr_numa_get_pmd(struct rr_numa *numa)
{
    int numa_idx = numa->cur_index;

    if (numa->idx_inc == true) {
        /* Incrementing through list of pmds. */
        if (numa->cur_index == numa->n_pmds-1) {
            /* Reached the last pmd. */
            numa->idx_inc = false;
        } else {
            numa->cur_index++;
        }
    } else {
        /* Decrementing through list of pmds. */
        if (numa->cur_index == 0) {
            /* Reached the first pmd. */
            numa->idx_inc = true;
        } else {
            numa->cur_index--;
        }
    }
    return numa->pmds[numa_idx];
}

/*******************************************************************************
 函数名称  :    rr_numa_list_destroy
 功能描述  :    numa 链destroy
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
rr_numa_list_destroy(struct rr_numa_list *rr)
{
    struct rr_numa *numa;

    HMAP_FOR_EACH_POP (numa, node, &rr->numas) {
        free(numa->pmds);
        free(numa);
    }
    hmap_destroy(&rr->numas);
}

/*******************************************************************************
 函数名称  :    compare_rxq_cycles
 功能描述  :    对比接收队列
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
/* Sort Rx Queues by the processing cycles they are consuming. */
static int
compare_rxq_cycles(const void *a, const void *b)
{
    struct dp_netdev_rxq *qa;
    struct dp_netdev_rxq *qb;
    uint64_t cycles_qa, cycles_qb;

    qa = *(struct dp_netdev_rxq **) a;
    qb = *(struct dp_netdev_rxq **) b;

    cycles_qa = dp_netdev_rxq_get_cycles(qa, RXQ_CYCLES_PROC_HIST);
    cycles_qb = dp_netdev_rxq_get_cycles(qb, RXQ_CYCLES_PROC_HIST);

    if (cycles_qa != cycles_qb) {
        return (cycles_qa < cycles_qb) ? 1 : -1;
    } else {
        /* Cycles are the same so tiebreak on port/queue id.
         * Tiebreaking (as opposed to return 0) ensures consistent
         * sort results across multiple OS's. */
        uint32_t port_qa = odp_to_u32(qa->port->port_no);
        uint32_t port_qb = odp_to_u32(qb->port->port_no);
        if (port_qa != port_qb) {
            return port_qa > port_qb ? 1 : -1;
        } else {
            return netdev_rxq_get_queue_id(qa->rx)
                    - netdev_rxq_get_queue_id(qb->rx);
        }
    }
}

/* Assign pmds to queues.  If 'pinned' is true, assign pmds to pinned
 * queues and marks the pmds as isolated.  Otherwise, assign non isolated
 * pmds to unpinned queues.
 *
 * If 'pinned' is false queues will be sorted by processing cycles they are
 * consuming and then assigned to pmds in round robin order.
 *
 * The function doesn't touch the pmd threads, it just stores the assignment
 * in the 'pmd' member of each rxq. */

/*******************************************************************************
 函数名称  :    rxq_scheduling
 功能描述  :    队列绑定了cpu，并将对应的pmd线程标记为隔离
 				1.port 的多队列，根据队列对应的core id 分给某个pmd，多队列对应多pmd
 输入参数  :  	pinned---固定标记，true
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
rxq_scheduling(struct dp_netdev *dp, bool pinned) OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;

	/*numa节点list*/
    struct rr_numa_list rr;

	/*非本地numa 轮询链*/
    struct rr_numa *non_local_numa = NULL;	
    struct dp_netdev_rxq ** rxqs = NULL;
    int n_rxqs = 0;
    struct rr_numa *numa = NULL;
    int numa_id;

	/*遍历dp上的port链表，遍历端口rxq*/
    HMAP_FOR_EACH (port, node, &dp->ports) 
	{
		/*port是非pmd的跳过*/
        if (!netdev_is_pmd(port->netdev)) 
		{
            continue;
        }

		/*遍历端口收队列，关联使用的pmd*/
        for (int qid = 0; qid < port->n_rxq; qid++) 
		{
			/*获取端口接收队列*/
            struct dp_netdev_rxq *q = &port->rxqs[qid];

			/*固定标记 端口rxq队列已绑定逻辑核，设置了亲和性就不是OVS_CORE_UNSPEC*/
            if (pinned && q->core_id != OVS_CORE_UNSPEC) 
			{
                struct dp_netdev_pmd_thread *pmd;

				/*根据port rx 队列设定的core_id，从pmd 链表获取对应pmd线程，一般一个pmd对应一个队列*/
                pmd = dp_netdev_get_pmd(dp, q->core_id);
                if (!pmd) 
				{
					/*核上没有绑pmd线程*/
                    VLOG_WARN("There is no PMD thread on core %d. Queue "
                              "%d on port \'%s\' will not be polled.",
                              q->core_id, qid, netdev_get_name(port->netdev));
                } 
				else 
				{
					/*port rx队列关联到pmd，由port 队列设定的core id决定用哪个pmd，多pmd对应多队列*/
                    q->pmd = pmd;

					/*pmd设置为隔离的*/
                    pmd->isolated = true;

					/*pmd存在且未引用*/
                    dp_netdev_pmd_unref(pmd);
                }
            } 

			/*port rx队列逻辑核存在未指定亲和性的rxq，按理说全部设置亲和性这里不应该有，有队列未设置亲和性,没有给队列绑定cpu走这个字的分配流程*/
			else if (!pinned && q->core_id == OVS_CORE_UNSPEC) 
			{
                uint64_t cycle_hist = 0;

				/*申请接收队列*/
                if (n_rxqs == 0) 
				{
                    rxqs = xmalloc(sizeof *rxqs);
                }
				else 
				{
                    rxqs = xrealloc(rxqs, sizeof *rxqs * (n_rxqs + 1));
                }

				/* Sum the queue intervals and store the cycle history. */
				/**/
                for (unsigned i = 0; i < PMD_RXQ_INTERVAL_MAX; i++) 
				{
					/*读取poll队列时间间隔梯度设置 叠加*/
                    cycle_hist += dp_netdev_rxq_get_intrvl_cycles(q, i);
                }

				/*接收队列设置cycle*/
                dp_netdev_rxq_set_cycles(q, RXQ_CYCLES_PROC_HIST, cycle_hist);

                /* Store the queue. */
				/*记录队列，需要调度分配pmd去poll的队列*/
                rxqs[n_rxqs++] = q;
            }
        }
    }

	/*未设置亲和性的rx队列不止1个*/
    if (n_rxqs > 1) 
	{
        /* Sort the queues in order of the processing cycles
         * they consumed during their last pmd interval. */
        /*接收排序排序*/
        qsort(rxqs, n_rxqs, sizeof *rxqs, compare_rxq_cycles);
    }

	/*numa轮询链表初始化*/
    rr_numa_list_populate(dp, &rr);
	
    /* Assign the sorted queues to pmds in round robin. */

	/*遍历port的接收队列，以循环方式将已排序的队列分配给pmds*/
	for (int i = 0; i < n_rxqs; i++) 
	{
		/*获取netdev所在numa*/
        numa_id = netdev_get_numa_id(rxqs[i]->port->netdev);

		/*根据numa_id 在numa 链查找numa节点，如果没找到说明numa上没有非隔离的pmd线程，numa上没有配逻辑核*/
		numa = rr_numa_list_lookup(&rr, numa_id);
        if (!numa) 
		{
			
            /* There are no pmds on the queue's local NUMA node.
               Round robin on the NUMA nodes that do have pmds. */

			/*队列的本地NUMA节点上没有PMD线程。在具有pmd的NUMA节点上进行轮询调度，如果没有找到其他有pmd线程未隔离的numa节点continue*/
            non_local_numa = rr_numa_list_next(&rr, non_local_numa);
            if (!non_local_numa) 
			{
                VLOG_ERR("There is no available (non-isolated) pmd "
                         "thread for port \'%s\' queue %d. This queue "
                         "will not be polled. Is pmd-cpu-mask set to "
                         "zero? Or are all PMDs isolated to other "
                         "queues?", netdev_rxq_get_name(rxqs[i]->rx),
                         netdev_rxq_get_queue_id(rxqs[i]->rx));
                continue;
            }

			/*递增或递减顺序从中的numa节点返回下一个pmd*/
            rxqs[i]->pmd = rr_numa_get_pmd(non_local_numa);
            VLOG_WARN("There's no available (non-isolated) pmd thread "
                      "on numa node %d. Queue %d on port \'%s\' will "
                      "be assigned to the pmd on core %d "
                      "(numa node %d). Expect reduced performance.",
                      numa_id, netdev_rxq_get_queue_id(rxqs[i]->rx),
                      netdev_rxq_get_name(rxqs[i]->rx),
                      rxqs[i]->pmd->core_id, rxqs[i]->pmd->numa_id);
        } 
		else 
		{
			/*递增或递减顺序从中的numa节点返回下一个pmd*/
			rxqs[i]->pmd = rr_numa_get_pmd(numa);
	        VLOG_INFO("Core %d on numa node %d assigned port \'%s\' "
	                  "rx queue %d (measured processing cycles %"PRIu64").",
	                  rxqs[i]->pmd->core_id, numa_id,
	                  netdev_rxq_get_name(rxqs[i]->rx),
	                  netdev_rxq_get_queue_id(rxqs[i]->rx),
	                  dp_netdev_rxq_get_cycles(rxqs[i], RXQ_CYCLES_PROC_HIST));
        }
    }


	/*numa 链destroy*/	
    rr_numa_list_destroy(&rr);
    free(rxqs);
}

/*******************************************************************************
 函数名称  :    reload_affected_pmds
 功能描述  :    重载受影响的pmd线程=未删除留下的pmd线程，遍历所有poll线程重载需要重载的pmd线程
 				dp重载需要重载的pmd线程，掩码后剩余的pmd重新加载、包括删除缓存的发端口上的报文
 输入参数  :  	dp---数据面结构
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
reload_affected_pmds(struct dp_netdev *dp)
{
    struct dp_netdev_pmd_thread *pmd;

	/*遍历dp上所有pmd线程重载需要重载的pmd线程，掩码后的pmd都要reload*/
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) 
    {
    	/*留下来的pmd需要reload，掩码后留下的pmd、新增的pmd需要reload*/
        if (pmd->need_reload) 
		{
			/*删除pmd上缓存的流表索引*/
            flow_mark_flush(pmd);

			/*重载pmd线程*/
            dp_netdev_reload_pmd__(pmd);

			/*重载完打false*/
			pmd->need_reload = false;
        }
    }
}
/*******************************************************************************
 函数名称  :    reconfigure_pmd_threads
 功能描述  :    重新配置pmd线程、删除掩码掩掉的pmd、新增新的pmd
 				1.dp重载需要重载的pmd线程
 				2.配置新增的pmd线程，初始化插入dp poll链表
 输入参数  :  	dp---数据面
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
reconfigure_pmd_threads(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex)
{
	/*pmd线程*/
    struct dp_netdev_pmd_thread *pmd;

	/*pmd线程numa信息 使用的CPU核信息*/
    struct ovs_numa_dump *pmd_cores;

	/*numa 逻辑核 id 对*/
    struct ovs_numa_info_core *core;

	/*待删除hmap结构*/
    struct hmapx to_delete = HMAPX_INITIALIZER(&to_delete);

	/*hmap节点 链表头*/
	struct hmapx_node *node;

	bool changed = false;

	/*是否需要调整静态发送队列ids*/
	bool need_to_adjust_static_tx_qids = false;

    /* The pmd threads should be started only if there's a pmd port in the
     * datapath.  If the user didn't provide any "pmd-cpu-mask", we start
     * NR_PMD_THREADS per numa node. */

	/*只有在pmd 上有端口时，pmd线程才启动。如果用户没有提供pmd使用的cpu掩码，我们在每numa 节点启动NR_PMD_THREADS=1 线程*/
	

	/*检查dp port链上是否有端口，如果没有端口，pmd_cores 为空*/
    if (!has_pmd_port(dp)) 
	{
		/*pmd上没有端口，每个numa上0个CPU核信息填入dump，numa要填入dump的核数为0*/
        pmd_cores = ovs_numa_dump_n_cores_per_numa(0);
    }
	/*dp上有port，然而配置了新的掩码，pmd占用CPU 掩码字符串指针pmd_cmask不为空，pmd_cmask[0]不为空，获取掩码后核与numa信息*/
	else if (dp->pmd_cmask && dp->pmd_cmask[0]) 
	{
		/*掩码中置位的核id填入所属numa节点，numa节点在dump*/
        pmd_cores = ovs_numa_dump_cores_with_cmask(dp->pmd_cmask);
    } 
	else 
	{
		/*没有配pmd掩码每个numa上1个CPU 核填入dump，参数为1*/
        pmd_cores = ovs_numa_dump_n_cores_per_numa(NR_PMD_THREADS);
    }

	/* 如果我们新配置减少了pmd线程，pmd掩码那么我们需要调整发队列的个数*/
    /* We need to adjust 'static_tx_qid's only if we're reducing number of
     * PMD threads. Otherwise, new threads will allocate all the freed ids. */

	/*dump上的core数小于线程数，置上需要调整静态发队列个数标记，一个收线程对应一个发队列*/
	if (ovs_numa_dump_count(pmd_cores) < cmap_count(&dp->poll_threads) - 1) 
	{
        /* Adjustment is required to keep 'static_tx_qid's sequential and
         * avoid possible issues, for example, imbalanced tx queue usage
         * and unnecessary locking caused by remapping on netdev level. */

		/*若有需要删掉的pmd，需要调整静态发队列个数标记，因为每个pmd一个发队列*/
        need_to_adjust_static_tx_qids = true;
    }

	/*遍历所有pmd线程，pmd线程使用的CPU若被掩码掉，pmd线程加入删队列，其他pmd线程设置reload标记*/
    /* Check for unwanted pmd threads */
	/*检查出不再需要的pmd线程*/
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) 
    {
    	/*跳过不是使用pmd cpu核的pmd*/
        if (pmd->core_id == NON_PMD_CORE_ID) 
		{
            continue;
        }

		/*pmd numa id core_id 对应的cpu核已不在掩码后的dump记录里，dump记录numa与核，numa填入to_delete*/
        if (!ovs_numa_dump_contains_core(pmd_cores, pmd->numa_id, pmd->core_id)) 
		{
			/*pmd使用的CPU已被掩码掩掉，pmd添加到待删除hmapx*/
            hmapx_add(&to_delete, pmd);
        }
		/*若有需要删掉的pmd，需要调整静态发队列个数标记，因为每个pmd一个发队列，把留下的pmd打上reload标记*/
		else if (need_to_adjust_static_tx_qids) 
		{
			/*未删除的pmd的reload标记设置true，pmd需调整静态发队列*/
            pmd->need_reload = true;
        }
    }

	/*遍历待删除pmd节点链to_delete，删除pmd，掩码掩掉的pmd填入了to_delete链表*/
    HMAPX_FOR_EACH (node, &to_delete) 
	{
		/*获取pmd线程*/
        pmd = (struct dp_netdev_pmd_thread *) node->data;
		
        VLOG_INFO("PMD thread on numa_id: %d, core id: %2d destroyed.", pmd->numa_id, pmd->core_id);

		/*从数据面删除不需要的pmd线程，之前pmd使用的CPU已被掩码掩掉，flush掉上面缓存的报文、流表*/
		/* 1.释放pmd缓存流表索引
		   2.发送pmd上缓存的发端口待发出的报文
 		   3.释放发队列
 		   4.删除pmd上发port、poll链表上poll节点
 		*/
		dp_netdev_del_pmd(dp, pmd);
    }

	/*to_delete链表为空*/
    changed = !hmapx_is_empty(&to_delete);

	/*删除to_delete结构*/
	hmapx_destroy(&to_delete);

	/*需要调整静态发队列*/
    if (need_to_adjust_static_tx_qids) 
	{
        /* 'static_tx_qid's are not sequential now.
         * Reload remaining threads to fix this. */
         
        /*静态发送队列的当前不是顺序的。重新加载剩余线程以修复此问题*/

		/*dp重载需要重载的pmd线程=掩码后留下的pmd，掩码后剩余的pmd重新加载、包括删除缓存的发端口上的报文*/
        reload_affected_pmds(dp);
    }

    /* Check for required new pmd threads */
	/*遍历掩码后构造的新的pmd_cores，查看核上是否已经有pmd，没有则启动新的pmd线程*/
    FOR_EACH_CORE_ON_DUMP(core, pmd_cores) 
    {
    	/* 根据core_id 从pmd线程链表获取核对应pmd，一个pmd占用多个核*/
		/*查看core 是否已经被pmd占用*/
        pmd = dp_netdev_get_pmd(dp, core->core_id);

		/*本core没有pmd占用*/
        if (!pmd) 
		{
			/*获取到去申请一个pmd*/
            pmd = xzalloc(sizeof *pmd);

			/*配置逻辑核给新增的pmd线程，初始化插入dp pmd poll线程链表*/
            dp_netdev_configure_pmd(pmd, dp, core->core_id, core->numa_id);

			/*创建新增pmd线程*/
            pmd->thread = ovs_thread_create("pmd", pmd_thread_main, pmd);
            VLOG_INFO("PMD thread on numa_id: %d, core id: %2d created.", pmd->numa_id, pmd->core_id);
            changed = true;
        } 
		else 
		{
			/*核已被pmd线程占用*/
            dp_netdev_pmd_unref(pmd);
        }
    }

	/*序号有更新或者要删的pmd已删除或有新增pmd*/
    if (changed) 
	{
        struct ovs_numa_info_numa *numa;

        /* Log the number of pmd threads per numa node. */

		/*记录每个numa节点的pmd线程数*/
        FOR_EACH_NUMA_ON_DUMP (numa, pmd_cores) 
        {
        	VLOG_INFO("There are %"PRIuSIZE" pmd threads on numa node %d", numa->n_cores, numa->numa_id);
        }
    }

	/*destroy掉掩码后的dump结构*/
    ovs_numa_dump_destroy(pmd_cores);
}

/*******************************************************************************
 函数名称  :    pmd_remove_stale_ports
 功能描述  :    从pmd线程中删除所有已删除的端口或需要重新配置的端口
 输入参数  :  	dp--数据面结构
 				pmd---遍历的pmd，取删除已被删除的端口
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
pmd_remove_stale_ports(struct dp_netdev *dp, struct dp_netdev_pmd_thread *pmd)
    OVS_EXCLUDED(pmd->port_mutex)
    OVS_REQUIRES(dp->port_mutex)
{
    struct rxq_poll *poll, *poll_next;
    struct tx_port *tx, *tx_next;

    ovs_mutex_lock(&pmd->port_mutex);

	/*遍历pmd poll_list获取一个poll结构，上面有接收队列*/
	HMAP_FOR_EACH_SAFE (poll, poll_next, node, &pmd->poll_list) 
	{
		/*poll结构节点上的接收队列对应的port*/
        struct dp_netdev_port *port = poll->rxq->port;

		/*端口需要重新配置，或dp的port链表中已删除此port，则poll节点需删除*/
        if (port->need_reconfigure || !hmap_contains(&dp->ports, &port->node)) 
        {
        	/*poll结构节点从pmd删除*/
            dp_netdev_del_rxq_from_pmd(pmd, poll);
        }
    }

	/*遍历pmd发端口*/
	HMAP_FOR_EACH_SAFE (tx, tx_next, node, &pmd->tx_ports) 
	{
		/*获取发队列端口*/
        struct dp_netdev_port *port = tx->port;

		/*端口需要重新配置，或dp的port链表中已删除此port，则poll节点需删除*/
        if (port->need_reconfigure || !hmap_contains(&dp->ports, &port->node)) 
		{
			/*pmd删除发端口节点*/
            dp_netdev_del_port_tx_from_pmd(pmd, tx);
        }
    }
    ovs_mutex_unlock(&pmd->port_mutex);
}

/* Must be called each time a port is added/removed or the cmask changes.
 * This creates and destroys pmd threads, reconfigures ports, opens their
 * rxqs and assigns all rxqs/txqs to pmd threads. */
 /*******************************************************************************
 函数名称  :    reconfigure_datapath
 功能描述  :    端口更新，重新配置数据面
 输入参数  :  	dp---netdev数据面结构
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
reconfigure_datapath(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev_port *port;
    int wanted_txqs;

	/*上次dp配置序号记录入last_reconfigure_seq*/
    dp->last_reconfigure_seq = seq_read(dp->reconfigure_seq);

    /* Step 1: Adjust the pmd threads based on the datapath ports, the cores
     * on the system and the user configuration. */

	/*调整数据面pmd线程数，根据pmd配置改变、端口增删 */
    reconfigure_pmd_threads(dp);

	/*需要的发送队列数=所有pmd线程数、每个poll线程一个*/
    wanted_txqs = cmap_count(&dp->poll_threads);

    /* The number of pmd threads might have changed, or a port can be new:
     * adjust the txqs. */

	/*遍历dp端口节点链表调整发送队列数，每个端口设置多发送队列、多队列数等于poll线程数，每个poll线程一个发队列*/
    HMAP_FOR_EACH (port, node, &dp->ports) 
    {
    	/*netdev设置多发送队列数=所有pmd线程数，端口对应每个pmd一个发队列*/
        netdev_set_tx_multiq(port->netdev, wanted_txqs);
    }

    /* Step 2: Remove from the pmd threads ports that have been removed or
     * need reconfiguration. */

    /* Check for all the ports that need reconfiguration.  We cache this in
     * 'port->need_reconfigure', because netdev_is_reconf_required() can
     * change at any time. */

	/*遍历dp端口链表节点，留存未删除的port 打上重载标记*/
	HMAP_FOR_EACH (port, node, &dp->ports) 
    {
    	/*序号与上次重配序号不一致的端口都需要重配，旧端口、新增端口*/
        if (netdev_is_reconf_required(port->netdev)) 
		{
			/*端口需要重新配置*/
            port->need_reconfigure = true;
        }
    }

    /* Remove from the pmd threads all the ports that have been deleted or
     * need reconfiguration. */

	/*从所有pmd线程中删除所有已删除的端口资源或需要重新配置的端口*/
	CMAP_FOR_EACH (pmd, node, &dp->poll_threads) 
    {
        pmd_remove_stale_ports(dp, pmd);
    }

    /* Reload affected pmd threads.  We must wait for the pmd threads before
     * reconfiguring the ports, because a port cannot be reconfigured while
     * it's being used. */

	/*重新加载受影响的pmd线程。我们必须先等待pmd线程重新配置端口，因为在它正在被使用、释放port对应的资源、流表*/
	/*重新加载pmd线程*/
    reload_affected_pmds(dp);

    /* Step 3: Reconfigure ports. */

    /* We only reconfigure the ports that we determined above, because they're
     * not being used by any pmd thread at the moment.  If a port fails to
     * reconfigure we remove it from the datapath. */

	/*重新配置端口*/
    struct dp_netdev_port *next_port;

	/*遍历dp端口链重配dp上的port*/
	HMAP_FOR_EACH_SAFE (port, next_port, node, &dp->ports) 
	{
        int err;

		/*端口不需要重配直接跳过*/
        if (!port->need_reconfigure) 
		{
            continue;
        }

		/*端口重配，释放port 旧rx队列、申请新rx队列，新port申请rx队列*/
        err = port_reconfigure(port);
        if (err) 
		{
			/*删除端口*/
            hmap_remove(&dp->ports, &port->node);

			/*序号改变*/
			seq_change(dp->port_seq);

			/*端口destroy*/
			port_destroy(port);
        } 
		else 
		{
			/*端口发送队列是否需要静态发队列，如果端口配置的发队列数小于pmd线程数，则使用静态发队列*/
            /*主动配置的txq小于pmd+非pmd数，开启动态调整txq*/
            port->dynamic_txqs = netdev_n_txq(port->netdev) < wanted_txqs;
        }
    }

    /* Step 4: Compute new rxq scheduling.  We don't touch the pmd threads
     * for now, we just update the 'pmd' pointer in each rxq to point to the
     * wanted thread according to the scheduling policy. */

    /* Reset all the pmd threads to non isolated. */

	/*重设所有pmd线程非孤立的*/
	CMAP_FOR_EACH (pmd, node, &dp->poll_threads) 
    {
        pmd->isolated = false;
    }

	/*设置端口所有队列为未关联pmd*/
    /* Reset all the queues to unassigned */
    HMAP_FOR_EACH (port, node, &dp->ports) 
    {
    	/*端口队列赋值NULL*/
        for (int i = 0; i < port->n_rxq; i++) 
		{
			/*清除port 之前队列关联的pmd，后面会根据rx 队列的lcore id 重新分配*/
            port->rxqs[i].pmd = NULL;
        }
    }

    /* Add pinned queues and mark pmd threads isolated. */
	/*添加固定队列并将pmd线程标记为隔离，固定队列既port的rx队列已指定了使用的lcore，
	  分pmd时也分到使用相同lcore的pmd，pmd线程poll对应队列
	*/
    rxq_scheduling(dp, true);

    /* Add non-pinned queues. */
	/*添加非固定的队列*/
    rxq_scheduling(dp, false);

    /* Step 5: Remove queues not compliant with new scheduling. */
	/*5.删除pmd线程上与新调度不一致的队列*/
	/*遍历dp上pmd节点，查看pmd上poll节点，poll节点上队列关联的pmd若不是本pmd，则删除poll节点*/
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) 
    {
        struct rxq_poll *poll, *poll_next;

        ovs_mutex_lock(&pmd->port_mutex);

		/*遍历pmd的poll链表*/
        HMAP_FOR_EACH_SAFE (poll, poll_next, node, &pmd->poll_list) 
		{
			/*poll节点对应port的rx队列关联的pmd已不是本队列，上面对port的rx q使用的pmd已重新调度*/
            if (poll->rxq->pmd != pmd) 
			{
				/*从pmd poll链表删除本pmd接收队列poll节点*/
                dp_netdev_del_rxq_from_pmd(pmd, poll);
            }
        }
		
        ovs_mutex_unlock(&pmd->port_mutex);
    }

    /* Reload affected pmd threads.  We must wait for the pmd threads to remove
     * the old queues before readding them, otherwise a queue can be polled by
     * two threads at the same time. */

	/*1.pmd删除旧的port rx q，port 的rx q已关联调度到其他pmd，根据给port rx q设定的core id，port rx q与pmd 同逻辑核*/

	/*重新加载受影响的pmd线程，我们必须在旧队列读取它们之前等待pmd线程移除，否则rx队列可以由同时两个线程读*/
    reload_affected_pmds(dp);

    /* Step 6: Add queues from scheduling, if they're not there already. */

	/*遍历port 创建poll节点记录port与rx 队列 填入pmd的poll链表*/
    HMAP_FOR_EACH (port, node, &dp->ports) 
    {
    	/*端口未使用pmd*/
        if (!netdev_is_pmd(port->netdev)) 
		{
            continue;
        }

		/*遍历port的接收队列*/
        for (int qid = 0; qid < port->n_rxq; qid++) 
		{
			/*获取接收队列*/
            struct dp_netdev_rxq *q = &port->rxqs[qid];
			
			/*队列已关联pmd*/
            if (q->pmd) 
			{
                ovs_mutex_lock(&q->pmd->port_mutex);

				/*port的接收队列添加到队列属于的pmd，一个pmd线程对应多个port，一个port对应多队列
				  poll节点记录port与port的一个rx队列，填入pmd的poll链表
				*/
				dp_netdev_add_rxq_to_pmd(q->pmd, q);

				ovs_mutex_unlock(&q->pmd->port_mutex);
            }
        }
    }

    /* Add every port to the tx cache of every pmd thread, if it's not
     * there already and if this pmd has at least one rxq to poll. */

	/*如果port还没填到pmd的发端口cache，或者pmd至少有一个接队列去poll，把pmd的每个port都填到pmd的发端口cache*/

	/*遍历所有pmd线程，把pmd上poll链表节点上的发port填入pmd的发缓存链表，port tx结构*/
	CMAP_FOR_EACH (pmd, node, &dp->poll_threads) 
    {
        ovs_mutex_lock(&pmd->port_mutex);

		/*pmd上poll链表节点不为空，有port的队列需要poll*/
		if (hmap_count(&pmd->poll_list) || pmd->core_id == NON_PMD_CORE_ID) 
		{
			/*遍历数据面上的端口，创建tx结构添加到pmd的发port缓存链表*/
            HMAP_FOR_EACH (port, node, &dp->ports) 
            {
            	/* 申请port的tx结构，将“port tx结构”添加到“pmd”的发送端口缓存链表，必须重载才能生效*/
                dp_netdev_add_port_tx_to_pmd(pmd, port);
            }
        }
        ovs_mutex_unlock(&pmd->port_mutex);
    }

    /* Reload affected pmd threads. */
	/*重载受影响的pmd线程*/
    reload_affected_pmds(dp);
}

/*******************************************************************************
 函数名称  :    ports_require_restart
 功能描述  :    端口需要重配
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
/* Returns true if one of the netdevs in 'dp' requires a reconfiguration */
static bool
ports_require_restart(const struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;

	/*遍历端口*/
    HMAP_FOR_EACH (port, node, &dp->ports) 
	{
		/*重新配置序列号*/
        if (netdev_is_reconf_required(port->netdev)) 
		{
            return true;
        }
    }

    return false;
}

/*******************************************************************************
 函数名称  :    dpif_netdev_run
 功能描述  :    起backer上的dpif上的pmd线程开始收包
 				dp需要reconfig 则reconfig
 输入参数  :  	dpif---某类型backer对应的dpif
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/

/* Return true if needs to revalidate datapath flows. */
static bool
dpif_netdev_run(struct dpif *dpif)
{
    struct dp_netdev_port *port;

	/*获取dp对应的netdev*/
    struct dp_netdev *dp = get_dp_netdev(dpif);

	/*pmd线程*/
    struct dp_netdev_pmd_thread *non_pmd;
    uint64_t new_tnl_seq;
    bool need_to_flush = true;

    ovs_mutex_lock(&dp->port_mutex);

	/*pmd*/
    non_pmd = dp_netdev_get_pmd(dp, NON_PMD_CORE_ID);

	/*pmd线程存在*/
	if (non_pmd) 
	{
        ovs_mutex_lock(&dp->non_pmd_mutex);

		/*遍历dp上的port*/
        HMAP_FOR_EACH (port, node, &dp->ports) {
        	/*port 没有在pmd上*/
            if (!netdev_is_pmd(port->netdev)) {
                int i;

				/*遍历port收队列收包处理报文*/
                for (i = 0; i < port->n_rxq; i++) {
                    if (dp_netdev_process_rxq_port(non_pmd,
                                                   &port->rxqs[i],
                                                   port->port_no)) {
                        need_to_flush = false;
                    }
                }
            }
        }

		/*pmd需要发掉报文*/
        if (need_to_flush) {
            /* We didn't receive anything in the process loop.
             * Check if we need to send something.
             * There was no time updates on current iteration. */
            pmd_thread_ctx_time_update(non_pmd);

			/* pmd flush掉发端口要批量发出去的报文*/
            dp_netdev_pmd_flush_output_packets(non_pmd, false);
        }

		/*非pmd线程释放发送队列的ID*/
        dpif_netdev_xps_revalidate_pmd(non_pmd, false);
        ovs_mutex_unlock(&dp->non_pmd_mutex);

		/*线程destroy*/
        dp_netdev_pmd_unref(non_pmd);
    }

	/*dp需要reconfigure*/
    if (dp_netdev_is_reconf_required(dp) || ports_require_restart(dp)) 
	{
		/*端口更新，重新配置数据面,真正起pmd线程开始收包的位置*/
        reconfigure_datapath(dp);
    }
    ovs_mutex_unlock(&dp->port_mutex);

    tnl_neigh_cache_run();
    tnl_port_map_run();
    new_tnl_seq = seq_read(tnl_conf_seq);

    if (dp->last_tnl_conf_seq != new_tnl_seq) {
        dp->last_tnl_conf_seq = new_tnl_seq;
        return true;
    }
    return false;
}

static void
dpif_netdev_wait(struct dpif *dpif)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp = get_dp_netdev(dpif);

    ovs_mutex_lock(&dp_netdev_mutex);
    ovs_mutex_lock(&dp->port_mutex);
    HMAP_FOR_EACH (port, node, &dp->ports) {
        netdev_wait_reconf_required(port->netdev);
        if (!netdev_is_pmd(port->netdev)) {
            int i;

            for (i = 0; i < port->n_rxq; i++) {
                netdev_rxq_wait(port->rxqs[i].rx);
            }
        }
    }
    ovs_mutex_unlock(&dp->port_mutex);
    ovs_mutex_unlock(&dp_netdev_mutex);
    seq_wait(tnl_conf_seq, dp->last_tnl_conf_seq);
}
/*******************************************************************************
 函数名称  :    pmd_free_cached_ports
 功能描述  :    发掉要删除的pmd上port的待发送的报文，释放掉发端口缓存结构、释放端口发队列id
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
static void pmd_free_cached_ports(struct dp_netdev_pmd_thread *pmd)
{
    struct tx_port *tx_port_cached;

    /* Flush all the queued packets. */
	/*1.遍历pmd缓存的发端口链表、把发端口上待发出的批处理缓存报文发掉*/
    dp_netdev_pmd_flush_output_packets(pmd, true);
	
    /* Free all used tx queue ids. */

	/*释放pmd上端口使用的发送队列的ID*/
    dpif_netdev_xps_revalidate_pmd(pmd, true);

	/*释放pmd上缓存的tnl port缓存结构*/
    HMAP_FOR_EACH_POP (tx_port_cached, node, &pmd->tnl_port_cache) 
   	{
        free(tx_port_cached);
    }

	/*发端口pmd上发送端口缓存结构*/
    HMAP_FOR_EACH_POP (tx_port_cached, node, &pmd->send_port_cache) 
	{
        free(tx_port_cached);
    }
}

/* Copies ports from 'pmd->tx_ports' (shared with the main thread) to
 * thread-local copies. Copy to 'pmd->tnl_port_cache' if it is a tunnel
 * device, otherwise to 'pmd->send_port_cache' if the port has at least
 * one txq. */
 
/*******************************************************************************
 函数名称  :    pmd_load_cached_ports
 功能描述  :    pmd 重载时加载缓存的发送端口
 				1.发掉pmd缓存的发port节点缓存的报文
 				2.申请发端口缓存结构插入pmd发端口缓存链表
 输入参数  :  	pmd--pmd线程
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
pmd_load_cached_ports(struct dp_netdev_pmd_thread *pmd)
    OVS_REQUIRES(pmd->port_mutex)
{
    struct tx_port *tx_port, *tx_port_cached;

	/*1.发掉要删除的pmd上缓存的发送port节点上待发送的报文
	  2.释放掉发端口缓存结构、释放端口发队列id*/
    pmd_free_cached_ports(pmd);
	
    hmap_shrink(&pmd->send_port_cache);
    hmap_shrink(&pmd->tnl_port_cache);

	/*遍历pmd的发送端口链表、申请对应tx结构tnl结构 填入pmd缓存链表*/
    HMAP_FOR_EACH (tx_port, node, &pmd->tx_ports) 
	{
		/*发port netdev存在等待隧道push pop的操作，申请port发缓存结构，放入隧道处理port链表*/
        if (netdev_has_tunnel_push_pop(tx_port->port->netdev)) 
		{
			/*缓存的发端口*/
            tx_port_cached = xmemdup(tx_port, sizeof *tx_port_cached);

			/*发端口插入隧道报文操作链表*/
            hmap_insert(&pmd->tnl_port_cache, &tx_port_cached->node, hash_port_no(tx_port_cached->port->port_no));
        }

		/*发端口发送队列个数*/
        if (netdev_n_txq(tx_port->port->netdev)) 
		{
			/*申请缓存的发端口结构*/
            tx_port_cached = xmemdup(tx_port, sizeof *tx_port_cached);

			/*发端口写入发端口缓存*/
			hmap_insert(&pmd->send_port_cache, &tx_port_cached->node, hash_port_no(tx_port_cached->port->port_no));
        }
    }
}
/*******************************************************************************
 函数名称  :    pmd_alloc_static_tx_qid
 功能描述  :    从发送队列ID池申请静态发送队列id
 输入参数  :    pmd---pmd线程结构
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
pmd_alloc_static_tx_qid(struct dp_netdev_pmd_thread *pmd)
{
	/*发送队列互斥锁*/
    ovs_mutex_lock(&pmd->dp->tx_qid_pool_mutex);

	/*id池申请发送队列ID，找一个空闲的id*/
    if (!id_pool_alloc_id(pmd->dp->tx_qid_pool, &pmd->static_tx_qid)) 
	{
        VLOG_ABORT("static_tx_qid allocation failed for PMD on core %2d" ", numa_id %d.", pmd->core_id, pmd->numa_id);
    }

	/*发队列解锁*/
    ovs_mutex_unlock(&pmd->dp->tx_qid_pool_mutex);

    VLOG_DBG("static_tx_qid = %d allocated for PMD thread on core %2d" ", numa_id %d.", pmd->static_tx_qid, pmd->core_id, pmd->numa_id);
}

/*******************************************************************************
 函数名称  :  pmd_free_static_tx_qid
 功能描述  :  释放发队列id
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
pmd_free_static_tx_qid(struct dp_netdev_pmd_thread *pmd)
{
    ovs_mutex_lock(&pmd->dp->tx_qid_pool_mutex);

	/*释放发队列id到发队列id池*/
    id_pool_free_id(pmd->dp->tx_qid_pool, pmd->static_tx_qid);

	ovs_mutex_unlock(&pmd->dp->tx_qid_pool_mutex);
}

/*******************************************************************************
 函数名称  :    pmd_load_queues_and_ports
 功能描述  :    获取pmd要poll的队列和端口、返回个数
 输入参数  :    pmd---pmd线程
 			    ppoll_list---poll队列指针数组，接收pmd->poll_list节点链表，每个节点记录poll的队列指针和对应端口号
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
pmd_load_queues_and_ports(struct dp_netdev_pmd_thread *pmd, struct polled_queue **ppoll_list)
{
	/*指针的地址*/
    struct polled_queue *poll_list = *ppoll_list;
    struct rxq_poll *poll;
    int i;

	/*端口上锁*/
    ovs_mutex_lock(&pmd->port_mutex);

	/*申请队列指针数组 poll_list[i]*/
    poll_list = xrealloc(poll_list, hmap_count(&pmd->poll_list) * sizeof *poll_list);

    i = 0;

	/*从pmd遍历poll节点链表 并记录队列和队列属于的端口*/
    HMAP_FOR_EACH (poll, node, &pmd->poll_list) 
    {
		/*poll队列指针数组，记录入pmd poll的队列*/
        poll_list[i].rxq = poll->rxq;

		/*队列对应的端口序号*/
		poll_list[i].port_no = poll->rxq->port->port_no;

        i++;
    }

	/*加载端口缓存、发端口*/
    pmd_load_cached_ports(pmd);

	/*解锁*/
    ovs_mutex_unlock(&pmd->port_mutex);

	/*队列指针数组赋值给pmd->poll_list*/
    *ppoll_list = poll_list;
	
    return i;
}

/*******************************************************************************
 函数名称  :    ovs_dp_process_packet
 功能描述  :    每pmd报文处理流程，匹配流表，执行相应的action
 				1.添加dpdk端口的时候，会触发创建pmd线程:
 				dpif_netdev_port_add-->do_add_port-->dp_netdev_set_pmds_on_numa-->pmd_thread_main
 				2.如果已经添加了dpdk端口，启动的时候也会触发创建pmd的线程
 				dpif_netdev_pmd_set-->dp_netdev_reset_pmd_threads-->dp_netdev_set_pmds_on_numa-->pmd_thread_main	

 				在其轮询列表中持续轮询输入端口，在每一个端口上最多可同时收32个包（NETDEV_MAX_BURST），
 				根据激活的流规则可将每一个收包进行分类。
 				分类的目的是为了找到一个流，从而对包进行恰当的处理。
 				包根据流进行分组，并且每一个分组将执行特定的动作。

				3.一个pmd上有很多poll节点，每个poll节点对应一个端口号和一个接队列，一个port可以有多个队列，
				pmd线程遍历所有poll节点去收包
 				
 输入参数  :  	f---pmd线程
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static void *pmd_thread_main(void *f_)
{
	/*pmd线程结构*/
    struct dp_netdev_pmd_thread *pmd = f_;

	/*pmd流量统计*/
    struct pmd_perf_stats *s = &pmd->perf_stats;
    unsigned int lc = 0;
    struct polled_queue *poll_list;
    bool exiting;
    int poll_cnt;
    int i;
    int process_packets = 0;

    poll_list = NULL;

	/*per_pmd_key 记录pmd线程结构地址*/
    /* Stores the pmd thread's 'pmd' to 'per_pmd_key'. */
    ovsthread_setspecific(pmd->dp->per_pmd_key, pmd);

	/*numa亲和性设置，pmd_thread_setaffinity_cpu设置线程绑定的lcore*/
    ovs_numa_thread_setaffinity_core(pmd->core_id);

	/*pmd配置的逻辑核赋值记录给dpdk*/
    dpdk_set_lcore_id(pmd->core_id);

	VLOG_DBG("pmd_thread_main pmd->core_id=%u",pmd->core_id);

    /*获取pmd上poll链表上节点，要poll的队列和端口，存入poll_list、返回pmd队列个数*/
	/*一个pmd要poll多个port，一个port可能对应多个收队列*/
    poll_cnt = pmd_load_queues_and_ports(pmd, &poll_list);

	VLOG_DBG("pmd_thread_mainpoll_cnt=%d",poll_cnt);

	/*pmd对应emc、smc缓存流表初始化*/
    dfc_cache_init(&pmd->flow_cache);
	
reload:

	/*从发送队列ID池申请静态发送队列id给本pmd*/
    pmd_alloc_static_tx_qid(pmd);

    /* List port/core affinity */

	/*遍历poll链表节点组成的数组，去队列poll报文*/
    for (i = 0; i < poll_cnt; i++)
	{
	   /*获取队列id*/
       VLOG_DBG("Core %d processing port \'%s\' with queue-id %d\n", pmd->core_id, netdev_rxq_get_name(poll_list[i].rxq->rx), netdev_rxq_get_queue_id(poll_list[i].rxq->rx));
	   
       /* Reset the rxq current cycles counter. */

	   /*设置接收队列poll间隔时间*/
       dp_netdev_rxq_set_cycles(poll_list[i].rxq, RXQ_CYCLES_PROC_CURR, 0);
    }

	/*如果需要poll的队列个数为0*/
    if (!poll_cnt) 
	{	
		/*reload序列号和上次序列号一致，说明没有端口变动、pmd个数变动等待，直到序号变动数据同步过来*/
        while (seq_read(pmd->reload_seq) == pmd->last_reload_seq) 
		{
            seq_wait(pmd->reload_seq, pmd->last_reload_seq);
            poll_block();
        }
		/*没有队列，循环次数置0*/
        lc = UINT_MAX;
    }

	/*上一次poll 间隔时间设置清0*/
    pmd->intrvl_tsc_prev = 0;

	/*上一次poll间隔时间清0*/
    atomic_store_relaxed(&pmd->intrvl_cycles, 0);

	/*上一次tsc时间戳，循环计数更新*/
    cycles_counter_update(s);
	
    /* Protect pmd stats from external clearing while polling.*/

	/*获取流量统计互斥锁*/
    ovs_mutex_lock(&pmd->perf_stats.stats_mutex);

	/*for循环各个端口(poll节点)，执行dp_netdev_process_rxq_port处理端口，循环中间，会根据变动重新加载pmd上端口和队列信息*/
    for (;;) 
	{
        uint64_t rx_packets = 0, tx_packets = 0;

		/*pmd流量统计启动迭代*/
        pmd_perf_start_iteration(s);

		/*遍历poll链表上的poll节点，去poll poll节点对应 port上收队列中的报文、可以多个收队列、一个poll结构一个队列*/
        for (i = 0; i < poll_cnt; i++) 
		{
			/*poll读取所有队列报文放入批处理，返回poll到的报文数，poll节点对应端口号和端口对应的队列，可以是多队列*/
            process_packets = dp_netdev_process_rxq_port(pmd, poll_list[i].rxq, poll_list[i].port_no);

			/*所有poll节点接收队列，接收的报文计数*/
            rx_packets += process_packets;

			VLOG_DBG("pmd_thread_main poll_cnt i=%d, process_packets=%d, rx_packets=%u", i, process_packets, rx_packets);
        }

		/*没有poll到报文*/
        if (!rx_packets) 
		{
            /* We didn't receive anything in the process loop.
             * Check if we need to send something.
             * There was no time updates on current iteration. */
             
			/*线程上下文时间更新为当前时间*/
            pmd_thread_ctx_time_update(pmd);

			/*pmd flush掉发送端口发队列的报文，返回发出的报文数*/
            tx_packets = dp_netdev_pmd_flush_output_packets(pmd, false);
			VLOG_DBG("pmd_thread_main pmd flush tx_packets=%u", tx_packets);
        }

		/*1024次没有从任何队列poll到报文*/
        if (lc++ > 1024) 
		{
            bool reload;

            lc = 0;

            coverage_try_clear();

			/*同步*/
            dp_netdev_pmd_try_optimize(pmd, poll_list, poll_cnt);

			/*emc精确流表老化*/
            if (!ovsrcu_try_quiesce()) 
			{
				/*emc流表删除*/
                emc_cache_slow_sweep(&((pmd->flow_cache).emc_cache));
				VLOG_DBG("pmd_thread_main pmd emc old sweep");
            }

			/*读取reload开关，如果需要reload pmd，则break，dp上端口增删、pmd掩码变化时需要reload*/
            atomic_read_relaxed(&pmd->reload, &reload);
            if (reload) 
			{
                break;
            }
        }

		/*pmd迭代流量统计*/
        pmd_perf_end_iteration(s, rx_packets, tx_packets, pmd_perf_metrics_enabled(pmd));
    }
    ovs_mutex_unlock(&pmd->perf_stats.stats_mutex);

	/*reload 开关需要reload pmd，重新读取pmd上poll链表所有节点上poll的队列与端口*/
    poll_cnt = pmd_load_queues_and_ports(pmd, &poll_list);

	//若设置pmd->exit_latch，那么终结pmd线程
    exiting = latch_is_set(&pmd->exit_latch);
	
    /* Signal here to make sure the pmd finishes
     * reloading the updated configuration. */

	/*重载工作完成后，reload标记置false、读取pmd上次reload的序列号计入last_reload_seq*/
    dp_netdev_pmd_reload_done(pmd);

	/*释放pmd线程发队列id*/
    pmd_free_static_tx_qid(pmd);

    if (!exiting) 
	{
        goto reload;
    }

	/*pmd缓存smc emc 流表项索引清掉*/
    dfc_cache_uninit(&pmd->flow_cache);

	/*释放队列指针数组*/
	free(poll_list);

	/*释放端口cache*/
	pmd_free_cached_ports(pmd);
    
	return NULL;
}

static void
dp_netdev_disable_upcall(struct dp_netdev *dp)
    OVS_ACQUIRES(dp->upcall_rwlock)
{
    fat_rwlock_wrlock(&dp->upcall_rwlock);
}


/* Meters */
static void
dpif_netdev_meter_get_features(const struct dpif * dpif OVS_UNUSED,
                               struct ofputil_meter_features *features)
{
    features->max_meters = MAX_METERS;
    features->band_types = DP_SUPPORTED_METER_BAND_TYPES;
    features->capabilities = DP_SUPPORTED_METER_FLAGS_MASK;
    features->max_bands = MAX_BANDS;
    features->max_color = 0;
}

/* Applies the meter identified by 'meter_id' to 'packets_'.  Packets
 * that exceed a band are dropped in-place. */

/*******************************************************************************
 函数名称  :    dp_netdev_run_meter
 功能描述  :    meter 限速，超速丢弃报文
 输入参数  :  	meter_id---流的属性数据这里是meter id
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static void
dp_netdev_run_meter(struct dp_netdev *dp, struct dp_packet_batch *packets_,
                    uint32_t meter_id, long long int now)
{
	/*meter 配置*/
    struct dp_meter *meter;
	/*数据面meter带宽*/
    struct dp_meter_band *band;

	/*批处理报文数*/
    struct dp_packet *packet;

	long long int long_delta_t; /* msec */
    uint32_t delta_t; /* msec */

	/*批处理报文个数*/
    const size_t cnt = dp_packet_batch_size(packets_);
	
    uint32_t bytes, volume;

	/*超过带宽报文记录*/
    int exceeded_band[NETDEV_MAX_BURST];

	/*超过速率报文记录*/
	uint32_t exceeded_rate[NETDEV_MAX_BURST];

	/*超过带宽的报文数*/
	int exceeded_pkt = cnt; /* First packet that exceeded a band rate. */

	/*meter最大65536*/
    if (meter_id >= MAX_METERS) {
        return;
    }

	/*meterid互斥锁*/
    meter_lock(dp, meter_id);

	/*根据流表的meter id 获取meter配置结构*/
    meter = dp->meters[meter_id];
    if (!meter) {
        goto out;
    }

	/*初始化超过带宽报文记录结构*/
    /* Initialize as negative values. */
    memset(exceeded_band, 0xff, cnt * sizeof *exceeded_band);

	/*初始化超过速率报文记录结构*/
	/* Initialize as zeroes. */
    memset(exceeded_rate, 0, cnt * sizeof *exceeded_rate);

    /* All packets will hit the meter at the same time. */

	/*当前时间-上次meter统计时间*/
    long_delta_t = (now - meter->used) / 1000; /* msec */

    /* Make sure delta_t will not be too large, so that bucket will not
     * wrap around below. */

	/*当前时间-上次meter统计时间 时间是否超时，超时使用最大时间，否则使用当前时间-上次meter统计时间*/
    delta_t = (long_delta_t > (long long int)meter->max_delta_t)
        ? meter->max_delta_t : (uint32_t)long_delta_t;

    /* Update meter stats. */
	/*更新meter时间为现在时间*/
    meter->used = now;

	/*更新meter报文数*/
    meter->packet_count += cnt;
    bytes = 0;

	/*遍历批处理报文算字节数*/
    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
        bytes += dp_packet_size(packet);
    }
	
	/*更新meter字节数计数*/
    meter->byte_count += bytes;

    /* Meters can operate in terms of packets per second or kilobits per
     * second. */

	/*按pps限速，计算pps*/
    if (meter->flags & OFPMF13_PKTPS) {
        /* Rate in packets/second, bucket 1/1000 packets. */
        /* msec * packets/sec = 1/1000 packets. */
        volume = cnt * 1000; /* Take 'cnt' packets from the bucket. */
    } 
	/*按bps限速，计算bps*/
	else {
        /* Rate in kbps, bucket in bits. */
        /* msec * kbps = bits */

        volume = bytes * 8;
    }

    /* Update all bands and find the one hit with the highest rate for each
     * packet (if any). */

	/*遍历meter下所有带宽配置*/
    for (int m = 0; m < meter->n_bands; ++m) {

		/*带宽配置*/
        band = &meter->bands[m];

        /* Update band's bucket. */

		/*带宽已使用量增加=时间差x速率*/
        band->bucket += delta_t * band->up.rate;

		/*带宽大于限制值，带宽使用burst_size*/
		if (band->bucket > band->up.burst_size) {
            band->bucket = band->up.burst_size;
        }

        /* Drain the bucket for all the packets, if possible. */

		/*未到带宽限制*/
        if (band->bucket >= volume) {

			/*计算剩余带宽*/
            band->bucket -= volume;
        } else {
            int band_exceeded_pkt;

            /* Band limit hit, must process packet-by-packet. */

			/*meter是按pps限速*/
            if (meter->flags & OFPMF13_PKTPS) 
			{

				/*kbps 超速报文个数k单位*/
                band_exceeded_pkt = band->bucket / 1000;

				/*剩余带宽对应报文个数*/
                band->bucket %= 1000; /* Remainder stays in bucket. */

                /* Update the exceeding band for each exceeding packet.
                 * (Only one band will be fired by a packet, and that
                 * can be different for each packet.) */

				/*超速报文数*/
				for (int i = band_exceeded_pkt; i < cnt; i++) 
				{
					/*未到速率限制*/
                    if (band->up.rate > exceeded_rate[i]) 
					{
						/*速率*/
                        exceeded_rate[i] = band->up.rate;

						/*超速对应的带宽限制*/
                        exceeded_band[i] = m;
                    }
                }
            } 
			else 
			{
                /* Packet sizes differ, must process one-by-one. */
                band_exceeded_pkt = cnt;

				/*遍历报文*/
				DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) 
				{
					/*bit*/
                    uint32_t bits = dp_packet_size(packet) * 8;

					/*未到bps限制*/
                    if (band->bucket >= bits) {
                        band->bucket -= bits;
                    } 
					else 
					{
                        if (i < band_exceeded_pkt) 
						{
                            band_exceeded_pkt = i;
                        }
                        /* Update the exceeding band for the exceeding packet.
                         * (Only one band will be fired by a packet, and that
                         * can be different for each packet.) */

						/**/
						if (band->up.rate > exceeded_rate[i]) 
						{
                            exceeded_rate[i] = band->up.rate;
                            exceeded_band[i] = m;
                        }
                    }
                }
            }

			/*超速*/
            /* Remember the first exceeding packet. */
            if (exceeded_pkt > band_exceeded_pkt) 
			{
                exceeded_pkt = band_exceeded_pkt;
            }
        }
    }

    /* Fire the highest rate band exceeded by each packet, and drop
     * packets if needed. */

	/*触发每个数据包超过的最高速率带，然后丢弃*必要时提供数据包*/
    size_t j;
    DP_PACKET_BATCH_REFILL_FOR_EACH (j, cnt, packet, packets_) 
	{
        if (exceeded_band[j] >= 0) 
		{
            /* Meter drop packet. */
            band = &meter->bands[exceeded_band[j]];
            band->packet_count += 1;
            band->byte_count += dp_packet_size(packet);

			/*删除packet*/
            dp_packet_delete(packet);
        } 
		else 
		{
            /* Meter accepts packet. */
			/*填回batch*/
            dp_packet_batch_refill(packets_, packet, j);
        }
    }
 out:
    meter_unlock(dp, meter_id);
}

/*******************************************************************************
 函数名称  :    dpif_netdev_meter_set
 功能描述  :    申请软件meter资源并配置
 输入参数  :  	meter_id---meter id
 				config---meter流表配置
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Meter set/get/del processing is still single-threaded. */
static int
dpif_netdev_meter_set(struct dpif *dpif, ofproto_meter_id meter_id,
                      struct ofputil_meter_config *config)
{
	/*获取dp*/
    struct dp_netdev *dp = get_dp_netdev(dpif);
	
    uint32_t mid = meter_id.uint32;
    struct dp_meter *meter;
    int i;

    if (mid >= MAX_METERS) 
	{
        return EFBIG; /* Meter_id out of range. */
    }

    if (config->flags & ~DP_SUPPORTED_METER_FLAGS_MASK) {
        return EBADF; /* Unsupported flags set */
    }

    if (config->n_bands > MAX_BANDS) {
        return EINVAL;
    }

    for (i = 0; i < config->n_bands; ++i) {
        switch (config->bands[i].type) {
        case OFPMBT13_DROP:
            break;
        default:
            return ENODEV; /* Unsupported band type */
        }
    }

	/*申请dp 层软件meter 内存资源*/
    /* Allocate meter */
    meter = xzalloc(sizeof *meter + config->n_bands * sizeof(struct dp_meter_band));
    if (meter) 
	{
		/*meter 配置赋值*/
        meter->flags = config->flags;
        meter->n_bands = config->n_bands;
        meter->max_delta_t = 0;
        meter->used = time_usec();

		/*设置带宽*/
        /* set up bands */
        for (i = 0; i < config->n_bands; ++i) 
		{
            uint32_t band_max_delta_t;

            /* Set burst size to a workable value if none specified. */
            if (config->bands[i].burst_size == 0) 
			{
                config->bands[i].burst_size = config->bands[i].rate;
            }

            meter->bands[i].up = config->bands[i];

			/* Convert burst size to the bucket units: */
            /* pkts => 1/1000 packets, kilobits => bits. */
            meter->bands[i].up.burst_size *= 1000;

			/* Initialize bucket to empty. */
            meter->bands[i].bucket = 0;

            /* Figure out max delta_t that is enough to fill any bucket. */
            band_max_delta_t = meter->bands[i].up.burst_size / meter->bands[i].up.rate;

			if (band_max_delta_t > meter->max_delta_t) {
                meter->max_delta_t = band_max_delta_t;
            }
        }

        meter_lock(dp, mid);

		/*存在先删除*/
        dp_delete_meter(dp, mid); /* Free existing meter, if any */


		/*meter dp层软件meter资源关联到dp meter*/
		dp->meters[mid] = meter;

#if 1
		/*下发dp 层成功*/
		VLOG_DBG("zwl:dpif_netdev_meter_set:%s: meter id: %"PRIu32" dp->meters[mid].id: %"PRIu32" ",
						dpif_name(dpif), mid, dp->meters[mid].id);

#endif
		
        meter_unlock(dp, mid);

        return 0;
    }
    return ENOMEM;
}

/*******************************************************************************
 函数名称  :    dpif_netdev_meter_get
 功能描述  :    软件meter资源查询
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
dpif_netdev_meter_get(const struct dpif *dpif,
                      ofproto_meter_id meter_id_,
                      struct ofputil_meter_stats *stats, uint16_t n_bands)
{
    const struct dp_netdev *dp = get_dp_netdev(dpif);
    uint32_t meter_id = meter_id_.uint32;
    int retval = 0;

    if (meter_id >= MAX_METERS) {
        return EFBIG;
    }

    meter_lock(dp, meter_id);

	/*根据id找到软件meter*/
    const struct dp_meter *meter = dp->meters[meter_id];
    if (!meter) {
        retval = ENOENT;
        goto done;
    }

	/*流量更新*/
    if (stats) {
        int i = 0;

        stats->packet_in_count = meter->packet_count;
        stats->byte_in_count = meter->byte_count;

        for (i = 0; i < n_bands && i < meter->n_bands; ++i) {
            stats->bands[i].packet_count = meter->bands[i].packet_count;
            stats->bands[i].byte_count = meter->bands[i].byte_count;
        }

        stats->n_bands = i;
    }

done:
    meter_unlock(dp, meter_id);
    return retval;
}

/*******************************************************************************
 函数名称  :    dpif_netdev_meter_del
 功能描述  :    dpif meter删除
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
dpif_netdev_meter_del(struct dpif *dpif,
                      ofproto_meter_id meter_id_,
                      struct ofputil_meter_stats *stats, uint16_t n_bands)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int error;

	/*先查询dpif层软件meter资源是否存在*/
    error = dpif_netdev_meter_get(dpif, meter_id_, stats, n_bands);
    if (!error) {
        uint32_t meter_id = meter_id_.uint32;

        meter_lock(dp, meter_id);

#if 1
		VLOG_DBG("zwl-dpif-delmeterflow dpif_netdev_meter_del meter_id=%u.", meter_id);
#endif

		/*根据meter id 删除meter*/
        dp_delete_meter(dp, meter_id);

		meter_unlock(dp, meter_id);
    }
    return error;
}


static void
dpif_netdev_disable_upcall(struct dpif *dpif)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp_netdev_disable_upcall(dp);
}

static void
dp_netdev_enable_upcall(struct dp_netdev *dp)
    OVS_RELEASES(dp->upcall_rwlock)
{
    fat_rwlock_unlock(&dp->upcall_rwlock);
}

static void
dpif_netdev_enable_upcall(struct dpif *dpif)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp_netdev_enable_upcall(dp);
}

/*******************************************************************************
 函数名称  :  dp_netdev_pmd_reload_done
 功能描述  :  重载工作完成后，reload标记置false、读取pmd上次reload的序列号计入last_reload_seq
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
dp_netdev_pmd_reload_done(struct dp_netdev_pmd_thread *pmd)
{
    ovs_mutex_lock(&pmd->cond_mutex);

	/*reload标记置false*/
    atomic_store_relaxed(&pmd->reload, false);

	/*读取pmd上次reload的序列号计入last_reload_seq*/
    pmd->last_reload_seq = seq_read(pmd->reload_seq);
	
    xpthread_cond_signal(&pmd->cond);
    ovs_mutex_unlock(&pmd->cond_mutex);
}

/* Finds and refs the dp_netdev_pmd_thread on core 'core_id'.  Returns
 * the pointer if succeeds, otherwise, NULL (it can return NULL even if
 * 'core_id' is NON_PMD_CORE_ID).
 *
 * Caller must unrefs the returned reference.  */
 /*******************************************************************************
 函数名称  :    dp_netdev_get_pmd
 功能描述  :    根据port 指定的core_id 从pmd poll 链表获取核对应pmd，一个pmd对应一个队列
 输入参数  :  	core_id---端口rxq绑定的lcore
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static struct dp_netdev_pmd_thread *dp_netdev_get_pmd(struct dp_netdev *dp, unsigned core_id)
{
    struct dp_netdev_pmd_thread *pmd;
    const struct cmap_node *pnode;

	/*从pmd poll链表线程根据core_id获取一个pmd节点，核上的pmd线程*/
    pnode = cmap_find(&dp->poll_threads, hash_int(core_id, 0));
    if (!pnode) 
	{
        return NULL;
    }

	/*线程节点对应pmd*/
    pmd = CONTAINER_OF(pnode, struct dp_netdev_pmd_thread, node);

	/*线程节点对应pmd*/
    return dp_netdev_pmd_try_ref(pmd) ? pmd : NULL;
}

/*******************************************************************************
 函数名称  :    emc_cache_slow_sweep
 功能描述  :    emc流表删除
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Sets the 'struct dp_netdev_pmd_thread' for non-pmd threads. */
static void
dp_netdev_set_nonpmd(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_pmd_thread *non_pmd;

    non_pmd = xzalloc(sizeof *non_pmd);
    dp_netdev_configure_pmd(non_pmd, dp, NON_PMD_CORE_ID, OVS_NUMA_UNSPEC);
}

/* Caller must have valid pointer to 'pmd'. */
static bool
dp_netdev_pmd_try_ref(struct dp_netdev_pmd_thread *pmd)
{
    return ovs_refcount_try_ref_rcu(&pmd->ref_cnt);
}

/*******************************************************************************
 函数名称  :    dp_netdev_pmd_unref
 功能描述  :    pmd存在且未引用
 输入参数  :  	pmd---pmd线程
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
dp_netdev_pmd_unref(struct dp_netdev_pmd_thread *pmd)
{
	/*pmd存在且未引用*/
    if (pmd && ovs_refcount_unref(&pmd->ref_cnt) == 1) 
	{
		/*释放pmd节点上剩余管理资源*/
        ovsrcu_postpone(dp_netdev_destroy_pmd, pmd);
    }
}

/*******************************************************************************
 函数名称  :    dp_netdev_pmd_get_next
 功能描述  :    从dp 上dump 50条flow
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Given cmap position 'pos', tries to ref the next node.  If try_ref()
 * fails, keeps checking for next node until reaching the end of cmap.
 *
 * Caller must unrefs the returned reference. */
static struct dp_netdev_pmd_thread *
dp_netdev_pmd_get_next(struct dp_netdev *dp, struct cmap_position *pos)
{
	/*pmd线程*/
    struct dp_netdev_pmd_thread *next;

    do {
        struct cmap_node *node;

		/*pmd线程节点*/
        node = cmap_next_position(&dp->poll_threads, pos);

		/*pmd线程*/
		next = node ? CONTAINER_OF(node, struct dp_netdev_pmd_thread, node)
            : NULL;
    } while (next && !dp_netdev_pmd_try_ref(next));

    return next;
}

/*******************************************************************************
 函数名称  :    dp_netdev_configure_pmd
 功能描述  :    配置新增的pmd线程，初始化插入dp poll链表
 输入参数  :  	pmd---新增的pmd线程
 				dp---数据面结构
 				core_id---逻辑核id
 				numa_id---所在的numa id
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Configures the 'pmd' based on the input argument. */
static void
dp_netdev_configure_pmd(struct dp_netdev_pmd_thread *pmd, struct dp_netdev *dp, unsigned core_id, int numa_id)
{
	/*新增pmd初始化*/
    pmd->dp = dp;
    pmd->core_id = core_id;
    pmd->numa_id = numa_id;
	
    pmd->need_reload = false;

	/*批处理个数为0*/
	pmd->n_output_batches = 0;

	/*未被引用*/
    ovs_refcount_init(&pmd->ref_cnt);
	
    latch_init(&pmd->exit_latch);

	/*创建重载序号*/
	pmd->reload_seq = seq_create();

	/*上次重载序号获取*/
	pmd->last_reload_seq = seq_read(pmd->reload_seq);

	/*reload标记赋值*/
	atomic_init(&pmd->reload, false);
	
    xpthread_cond_init(&pmd->cond, NULL);
    ovs_mutex_init(&pmd->cond_mutex);
    ovs_mutex_init(&pmd->flow_mutex);
    ovs_mutex_init(&pmd->port_mutex);

	/*pmd缓存流表索引初始化*/
    cmap_init(&pmd->flow_table);

	/*dpcls 分类器初始化*/
    cmap_init(&pmd->classifiers);

	/*pmd上下文 最新的接收队列赋值NULL*/
    pmd->ctx.last_rxq = NULL;

	/*pmd上下文时间更新为当前时间*/
    pmd_thread_ctx_time_update(pmd);
	
    pmd->next_optimization = pmd->ctx.now + DPCLS_OPTIMIZATION_INTERVAL;
    pmd->rxq_next_cycle_store = pmd->ctx.now + PMD_RXQ_INTERVAL_LEN;

	/*初始化poll 链*/
	hmap_init(&pmd->poll_list);

	/*初始化发端口*/
	hmap_init(&pmd->tx_ports);

	/*初始化隧道缓存端口hmap*/
	hmap_init(&pmd->tnl_port_cache);

	/*初始化缓存发端口hmap*/
	hmap_init(&pmd->send_port_cache);
    /* init the 'flow_cache' since there is no
     * actual thread created for NON_PMD_CORE_ID. */

	/*逻辑核id是非pmd的*/
	if (core_id == NON_PMD_CORE_ID) 
	{
		/* emc缓存、smc缓存初始化*/
        dfc_cache_init(&pmd->flow_cache);

		/*从发送队列ID池申请静态发送队列id*/
        pmd_alloc_static_tx_qid(pmd);
    }
	
	/*pmd流量统计初始化*/
    pmd_perf_stats_init(&pmd->perf_stats);

	/*pmd插入到dp poll线程链表cmap*/
	cmap_insert(&dp->poll_threads, CONST_CAST(struct cmap_node *, &pmd->node), hash_int(core_id, 0));
}

/*******************************************************************************
 函数名称  :    dp_netdev_destroy_pmd
 功能描述  :    释放pmd节点上剩余管理资源
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
dp_netdev_destroy_pmd(struct dp_netdev_pmd_thread *pmd)
{
    struct dpcls *cls;

	/*flush掉pmd上的报文*/
    dp_netdev_pmd_flow_flush(pmd);

	/*释放资源*/
    hmap_destroy(&pmd->send_port_cache);
    hmap_destroy(&pmd->tnl_port_cache);
    hmap_destroy(&pmd->tx_ports);
    hmap_destroy(&pmd->poll_list);

	/*遍历dpcls链表dpcls destroy掉*/
    /* All flows (including their dpcls_rules) have been deleted already */
    CMAP_FOR_EACH (cls, node, &pmd->classifiers) {
        dpcls_destroy(cls);
        ovsrcu_postpone(free, cls);
    }

	/*释放掉dpcls结构*/
	cmap_destroy(&pmd->classifiers);

	/*释放flow table*/
	cmap_destroy(&pmd->flow_table);

	ovs_mutex_destroy(&pmd->flow_mutex);
    latch_destroy(&pmd->exit_latch);
    seq_destroy(pmd->reload_seq);

	xpthread_cond_destroy(&pmd->cond);
    ovs_mutex_destroy(&pmd->cond_mutex);
    ovs_mutex_destroy(&pmd->port_mutex);
    free(pmd);
}

/*******************************************************************************
 函数名称  :    dp_netdev_del_pmd
 功能描述  :    从数据面删除pmd和pmd上的资源，清除引用标记
 				1.释放pmd缓存流表索引
 				2.发送pmd上缓存的发端口待发出的报文
 				3.释放发队列
 				4.删除pmd上发port、poll链表上poll节点
 				
 输入参数  :  	dp---数据面
 				pmd---待删除的pmd线程
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Stops the pmd thread, removes it from the 'dp->poll_threads',
 * and unrefs the struct. */
static void
dp_netdev_del_pmd(struct dp_netdev *dp, struct dp_netdev_pmd_thread *pmd)
{
    /* NON_PMD_CORE_ID doesn't have a thread, so we don't have to synchronize,
     * but extra cleanup is necessary */

	/*要删除的pmd线程使用的是非pmd CPU核，CPU核已被掩码掩掉*/
	if (pmd->core_id == NON_PMD_CORE_ID) 
	{
		/*非pmd资源处理锁*/
        ovs_mutex_lock(&dp->non_pmd_mutex);

		/*释放pmd缓存流表*/
        dfc_cache_uninit(&pmd->flow_cache);

		/*发出pmd缓存的port上待发出的批处理报文、释放pmd上缓存ports，*/
		pmd_free_cached_ports(pmd);

		/*释放pmd使用的静态发送队列id，在pmd发送队列id池找到节点并释放*/
		pmd_free_static_tx_qid(pmd);
		
        ovs_mutex_unlock(&dp->non_pmd_mutex);
    } 
	/*要删除的pmd线程用的核是pmd掩码的核*/
	else 
	{
		/*pmd 线程打上结束线程标记*/
        latch_set(&pmd->exit_latch);

		/*未被掩码掩掉的pmd 重载
		  1.发掉pmd缓存的发port节点缓存的报文
 		  2.申请发端口缓存结构插入pmd发端口缓存链表
 		*/
        dp_netdev_reload_pmd__(pmd);

		/*重新起pmd线程*/
		xpthread_join(pmd->thread, NULL);
    }

	/*删除pmd上发port、poll链表上poll节点*/
    dp_netdev_pmd_clear_ports(pmd);

    /* Purges the 'pmd''s flows after stopping the thread, but before
     * destroying the flows, so that the flow stats can be collected. */

	/*停止pmd线程前清除流表*/
    if (dp->dp_purge_cb) 
	{
        dp->dp_purge_cb(dp->dp_purge_aux, pmd->core_id);
    }

	/*从pmd线程链表 删除pmd 线程*/
	cmap_remove(&pmd->dp->poll_threads, &pmd->node, hash_int(pmd->core_id, 0));

	/*调用dp_netdev_destroy_pmd释放对pmd资源的引用*/
	dp_netdev_pmd_unref(pmd);
}

/* Destroys all pmd threads. If 'non_pmd' is true it also destroys the non pmd
 * thread. */
static void
dp_netdev_destroy_all_pmds(struct dp_netdev *dp, bool non_pmd)
{
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev_pmd_thread **pmd_list;
    size_t k = 0, n_pmds;

    n_pmds = cmap_count(&dp->poll_threads);
    pmd_list = xcalloc(n_pmds, sizeof *pmd_list);

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (!non_pmd && pmd->core_id == NON_PMD_CORE_ID) {
            continue;
        }
        /* We cannot call dp_netdev_del_pmd(), since it alters
         * 'dp->poll_threads' (while we're iterating it) and it
         * might quiesce. */
        ovs_assert(k < n_pmds);
        pmd_list[k++] = pmd;
    }

    for (size_t i = 0; i < k; i++) {
        dp_netdev_del_pmd(dp, pmd_list[i]);
    }
    free(pmd_list);
}
/*******************************************************************************
 函数名称  :    dp_netdev_pmd_clear_ports
 功能描述  :    删除pmd接管的port、poll链表上poll节点
 输入参数  :  	pmd---
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Deletes all rx queues from pmd->poll_list and all the ports from
 * pmd->tx_ports. */
static void
dp_netdev_pmd_clear_ports(struct dp_netdev_pmd_thread *pmd)
{
    struct rxq_poll *poll;
    struct tx_port *port;

    ovs_mutex_lock(&pmd->port_mutex);

	/*释放pmd上的所有poll节点*/
    HMAP_FOR_EACH_POP (poll, node, &pmd->poll_list) 
    {
        free(poll);
    }

	/*释放发port上的所有port*/
    HMAP_FOR_EACH_POP (port, node, &pmd->tx_ports) 
    {
        free(port);
    }
	
    ovs_mutex_unlock(&pmd->port_mutex);
}

/*******************************************************************************
 函数名称  :    dp_netdev_add_rxq_to_pmd
 功能描述  :    netdev添加接收队列到pmd
 输入参数  :  	pmd---队列对应pmd
 				rxq---port的接收队列
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Adds rx queue to poll_list of PMD thread, if it's not there already. */
static void
dp_netdev_add_rxq_to_pmd(struct dp_netdev_pmd_thread *pmd, struct dp_netdev_rxq *rxq)
    OVS_REQUIRES(pmd->port_mutex)
{
	/*获取接收队列的队列id*/
    int qid = netdev_rxq_get_queue_id(rxq->rx);

	/*接收队列id和它属于的端口一起算哈希*/
    uint32_t hash = hash_2words(odp_to_u32(rxq->port->port_no), qid);
    struct rxq_poll *poll;

	/*遍历pmd poll链表*/
    HMAP_FOR_EACH_WITH_HASH (poll, node, hash, &pmd->poll_list) 
	{
		/*port与接收队列对应的poll节点已在pmd的poll链表存在*/
        if (poll->rxq == rxq) 
		{
            /* 'rxq' is already polled by this thread. Do nothing. */
            return;
        }
    }

	/*申请poll节点，一个poll节点对应一个port的接收队列，poll节点记录port与rx队列*/
    poll = xmalloc(sizeof *poll);

	/*poll节点记录接收队列*/
    poll->rxq = rxq;

	/*poll节点插入pmd poll链表*/
    hmap_insert(&pmd->poll_list, &poll->node, hash);

	/*pmd打上需重载标记*/
    pmd->need_reload = true;
}

/*******************************************************************************
 函数名称  :    dp_netdev_del_rxq_from_pmd
 功能描述  :    从pmd删除poll接收队列
 输入参数  :  	pmd---端口使用的pmd
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Delete 'poll' from poll_list of PMD thread. */
static void
dp_netdev_del_rxq_from_pmd(struct dp_netdev_pmd_thread *pmd, struct rxq_poll *poll)
    OVS_REQUIRES(pmd->port_mutex)
{
	/*删除接收队列节点*/
    hmap_remove(&pmd->poll_list, &poll->node);
    free(poll);

    pmd->need_reload = true;
}
/*******************************************************************************
 函数名称  :    dp_netdev_add_port_tx_to_pmd
 功能描述  :    申请port的tx结构，将“port tx结构”添加到“pmd”的发送端口缓存链表，必须重载才能生效
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
/* Add 'port' to the tx port cache of 'pmd', which must be reloaded for the
 * changes to take effect. */
static void
dp_netdev_add_port_tx_to_pmd(struct dp_netdev_pmd_thread *pmd, struct dp_netdev_port *port)
    OVS_REQUIRES(pmd->port_mutex)
{
    struct tx_port *tx;

	/*查询port是否已存在于发端口缓存*/
    tx = tx_port_lookup(&pmd->tx_ports, port->port_no);
    if (tx) 
	{
        /* 'port' is already on this thread tx cache. Do nothing. */
        return;
    }

	/*发端口结构申请*/
    tx = xzalloc(sizeof *tx);

	/*port的发结构*/
    tx->port = port;
    tx->qid = -1;
    tx->flush_time = 0LL;

	/*发端口批处理初始化*/
    dp_packet_batch_init(&tx->output_pkts);

	/*port的发结构插入到hmap*/
    hmap_insert(&pmd->tx_ports, &tx->node, hash_port_no(tx->port->port_no));

	/*打上pmd需要重载标记*/
    pmd->need_reload = true;
}

/*******************************************************************************
 函数名称  :    dp_netdev_del_port_tx_from_pmd
 功能描述  :    从pmd 删除端口发队列
 输入参数  :  	pmd---pmd线程
 				tx---发送端口
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/

/* Del 'tx' from the tx port cache of 'pmd', which must be reloaded for the
 * changes to take effect. */
static void
dp_netdev_del_port_tx_from_pmd(struct dp_netdev_pmd_thread *pmd, struct tx_port *tx)
    OVS_REQUIRES(pmd->port_mutex)
{
	/*从pmd 端口删除发节点*/
    hmap_remove(&pmd->tx_ports, &tx->node);
    free(tx);

	/*发端口从发端口链表删除后，pmd需要reload，删除对应port的流表资源等、发送port上的报文*/
    pmd->need_reload = true;
}

static char *
dpif_netdev_get_datapath_version(void)
{
     return xstrdup("<built-in>");
}


/*******************************************************************************
 函数名称  :    dp_netdev_flow_used
 功能描述  :    emc流表删除
 输入参数  :  	netdev_flow---获取每流报文批处理对应的flow
 				cnt---每流报文批处理对应的报文数
 				tcp_flags---提取的miniflow对应的tcp flag
 				now---pmd线程运行的当前时间
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
dp_netdev_flow_used(struct dp_netdev_flow *netdev_flow, int cnt, int size, uint16_t tcp_flags, long long now)
{
    uint16_t flags;

	/*pmd运行当前时间*/
    atomic_store_relaxed(&netdev_flow->stats.used, now);

	/*每流报文批处理报文数*/
    non_atomic_ullong_add(&netdev_flow->stats.packet_count, cnt);

	/*每流报文批处理字节数*/
    non_atomic_ullong_add(&netdev_flow->stats.byte_count, size);

	/*每流报文批处理tcp flag 获取*/
    atomic_read_relaxed(&netdev_flow->stats.tcp_flags, &flags);
    flags |= tcp_flags;

	/*tcp flag存储*/
    atomic_store_relaxed(&netdev_flow->stats.tcp_flags, flags);
}
/*******************************************************************************
 函数名称  :    dp_netdev_upcall
 功能描述  :    进一步调用去ofproto classifier查表的接口，如果失败则删除报文
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
dp_netdev_upcall(struct dp_netdev_pmd_thread *pmd, struct dp_packet *packet_,
                 struct flow *flow, struct flow_wildcards *wc, ovs_u128 *ufid,
                 enum dpif_upcall_type type, const struct nlattr *userdata,
                 struct ofpbuf *actions, struct ofpbuf *put_actions)
{
    struct dp_netdev *dp = pmd->dp;

    if (OVS_UNLIKELY(!dp->upcall_cb)) {
        return ENODEV;
    }

    if (OVS_UNLIKELY(!VLOG_DROP_DBG(&upcall_rl))) 
	{
        struct ds ds = DS_EMPTY_INITIALIZER;
        char *packet_str;
        struct ofpbuf key;
		
        struct odp_flow_key_parms odp_parms = {
            .flow = flow,
            .mask = wc ? &wc->masks : NULL,
            .support = dp_netdev_support,
        };

        ofpbuf_init(&key, 0);
        odp_flow_key_from_flow(&odp_parms, &key);
        packet_str = ofp_dp_packet_to_string(packet_);

        odp_flow_key_format(key.data, key.size, &ds);

        VLOG_DBG("%s: %s upcall:\n%s\n%s", dp->name,
                 dpif_upcall_type_to_string(type), ds_cstr(&ds), packet_str);

        ofpbuf_uninit(&key);
        free(packet_str);

        ds_destroy(&ds);
    }

	/*upcall回调函数*/
    return dp->upcall_cb(packet_, flow, ufid, pmd->core_id, type, userdata, actions, wc, put_actions, dp->upcall_aux);
}

/*******************************************************************************
 函数名称  :    dpif_netdev_packet_get_rss_hash_orig_pkt
 功能描述  :    从dpdk rss 或根据miniflow五元组算哈希
 输入参数  :  	packet---每流报文批处理
 				mf---报文提取的miniflow
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline uint32_t
dpif_netdev_packet_get_rss_hash_orig_pkt(struct dp_packet *packet, const struct miniflow *mf)
{
    uint32_t hash;

    if (OVS_LIKELY(dp_packet_rss_valid(packet))) 
	{
		/*直接使用dpdk rss 哈希*/
        hash = dp_packet_get_rss_hash(packet);
    }
	else 
	{	
    	/*miniflow 五元组计算的哈希值*/
        hash = miniflow_hash_5tuple(mf, 0);

		/*使用miniflow算出的哈希设置rss 哈希值*/
        dp_packet_set_rss_hash(packet, hash);
    }

    return hash;
}

/*******************************************************************************
 函数名称  :    dpif_netdev_packet_get_rss_hash
 功能描述  :    根据报文获取rss hash
 输入参数  :  	packet---报文
 				mf---miniflow
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline uint32_t
dpif_netdev_packet_get_rss_hash(struct dp_packet *packet, const struct miniflow *mf)
{
    uint32_t hash, recirc_depth;

	/*直接从dpdk获取哈希*/
    if (OVS_LIKELY(dp_packet_rss_valid(packet))) 
	{
        hash = dp_packet_get_rss_hash(packet);
    } 
	else 
	{
    	/*根据miniflow 算五元组哈希*/
        hash = miniflow_hash_5tuple(mf, 0);

		/*设置rss hash*/
        dp_packet_set_rss_hash(packet, hash);
    }

    /* The RSS hash must account for the recirculation depth to avoid
     * collisions in the exact match cache */

	/*RSS散列必须考虑要避免的循环深度精确匹配缓存中的冲突*/
    recirc_depth = *recirc_depth_get_unsafe();

	if (OVS_UNLIKELY(recirc_depth)) 
	{
        hash = hash_finish(hash, recirc_depth);

		/*重设哈希*/
        dp_packet_set_rss_hash(packet, hash);
    }
	
    return hash;
}

/*每流表批处理结构，用于缓存匹配某个流表项的多个报文.最多缓存32个报文 */
struct packet_batch_per_flow {
    unsigned int byte_count;         /* 缓冲区中报文的总字节数 */
    uint16_t tcp_flags;			     /*从miniflow提取tcp_flag*/

    struct dp_netdev_flow *flow;   /* 指向所匹配的流表项信息 */

    struct dp_packet_batch array;  /*批处理报文缓存数组*/
								     /*从dpdk网卡接收报文时，一次可以批量接收32个报文，这些报文的信息都存储在dp_patch_batch数据结构中*/
};

/*******************************************************************************
 函数名称  :    packet_batch_per_flow_update
 功能描述  :    报文填到每流批处理数组
 输入参数  :    batch---每流批处理结构
 			    packet---添加的报文
 			    tcp_flags---tcp标记，从miniflow提取tcp_flag
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline void
packet_batch_per_flow_update(struct packet_batch_per_flow *batch, struct dp_packet *packet, uint16_t tcp_flags)
{
	/*批处理报文字节数*/
    batch->byte_count += dp_packet_size(packet);

	/*tcp标记*/
    batch->tcp_flags |= tcp_flags;

	/*报文填入每流报文批处理，一次批量可以接收32个报文 */
	batch->array.packets[batch->array.count++] = packet;
}

/*******************************************************************************
 函数名称  :    packet_batch_per_flow_init
 功能描述  :    每流批处理，缓存命中流的报文，进行批处理
 输入参数  :    batch---一个流报文批处理结构	
 			    flow---报文命中的流
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline void
packet_batch_per_flow_init(struct packet_batch_per_flow *batch, struct dp_netdev_flow *flow)
{
	/*流记录每流批处理结构*/
    flow->batch = batch;

	/*记录所属的流*/
    batch->flow = flow;

	/*每流报文批处理结构初始化*/
    dp_packet_batch_init(&batch->array);

	/*记录每流报文批处理字节数*/
    batch->byte_count = 0;

	/*提取的每流报文批处理tcp flag*/
    batch->tcp_flags = 0;
}

/*******************************************************************************
 函数名称  :    packet_batch_per_flow_execute
 功能描述  :    每流表报文批处理
 输入参数  :  	batch---每流报文批处理
 				key---skb提取的key
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline void
packet_batch_per_flow_execute(struct packet_batch_per_flow *batch, struct dp_netdev_pmd_thread *pmd)
{
    struct dp_netdev_actions *actions;

	/*获取每流报文批处理对应的flow*/
    struct dp_netdev_flow *flow = batch->flow;

	/*更新流的字节数、bit数*/
    dp_netdev_flow_used(flow, batch->array.count, batch->byte_count, batch->tcp_flags, pmd->ctx.now / 1000);

	/*获取flow对应的actions*/
    actions = dp_netdev_flow_get_actions(flow);

	/*执行命中的flow对应的actions*/
    dp_netdev_execute_actions(pmd, &batch->array, true, &flow->flow, actions->actions, actions->size);
}

/*******************************************************************************
 函数名称  :    dp_netdev_queue_batches
 功能描述  :    报文填到每流报文批处理
 输入参数  :    pkt---命中emc流表的报文
 			    flow---报文命中的smc 流信息
 			    tcp_flags---记录报文提取的tcp_flags，从miniflow提取tcp_flag
 			    batches---每流报文批处理结构数组，支持多个流
 			    n_batches---批处理index
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline void
dp_netdev_queue_batches(struct dp_packet *pkt, struct dp_netdev_flow *flow, uint16_t tcp_flags, struct packet_batch_per_flow *batches, size_t *n_batches)
{
	/*获取每流报文批处理结构*/
    struct packet_batch_per_flow *batch = flow->batch;

	/*流对应报文批处理不存在*/
    if (OVS_UNLIKELY(!batch)) 
	{
		/*获取一个流的批处理结构*/
        batch = &batches[(*n_batches)++];

		/*每流报文批处理初始化、记录对应的流*/
        packet_batch_per_flow_init(batch, flow);
    }

	/*每流报文批处理更新、报文填入每流批处理*/
    packet_batch_per_flow_update(batch, pkt, tcp_flags);
}

/* SMC lookup function for a batch of packets.
 * By doing batching SMC lookup, we can use prefetch
 * to hide memory access latency.
 */

/*******************************************************************************
 函数名称  :    smc_lookup_batch
 功能描述  :    emc miss的报文 smc流表 批处理查询，命中smc 流信息插入emc流表、统计命中smc报文流量
 输入参数  :    pmd---pmd线程
 			    keys---miniflow key结构，记录报文提取的miniflow key，emc已经miss的报文的miniflow key
 			    missed_keys---未命中emc流表的报文
 			    packets_---队列报文批处理结构
 			    batches---每流报文批处理结构、指针数组
 			    n_batches---批处理结构数
 			    cnt---miss的报文数
 				
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline void
smc_lookup_batch(struct dp_netdev_pmd_thread *pmd, struct netdev_flow_key *keys, struct netdev_flow_key **missed_keys,
            struct dp_packet_batch *packets_, struct packet_batch_per_flow batches[],size_t *n_batches, const int cnt)
{
    int i;
    struct dp_packet *packet;
    size_t n_smc_hit = 0, n_missed = 0;

	/*emc、smc*/
    struct dfc_cache *cache = &pmd->flow_cache;

	/*smc*/
	struct smc_cache *smc_cache = &cache->smc_cache;

	const struct cmap_node *flow_node;

    /* Prefetch buckets for all packets */

	/*预取*/
    for (i = 0; i < cnt; i++) 
	{
        OVS_PREFETCH(&smc_cache->buckets[keys[i].hash & SMC_MASK]);
    }

	/*遍历队列报文批处理报文，剩下的未名字emc的报文*/
    DP_PACKET_BATCH_REFILL_FOR_EACH (i, cnt, packet, packets_) 
	{
        struct dp_netdev_flow *flow = NULL;

		/*根据报文哈希获取smc流表节点*/
        flow_node = smc_entry_get(pmd, keys[i].hash);

		/*smc 命中初始值false*/
        bool hit = false;

		/*获取到了smc流表项节点*/
        if (OVS_LIKELY(flow_node != NULL)) 
		{
			/*smc 流表节点下的flow 遍历*/
            CMAP_NODE_FOR_EACH (flow, node, flow_node) 
			{
                /* Since we dont have per-port megaflow to check the port
                 * number, we need to  verify that the input ports match. */

				/*dpcls规则匹配*/											  /*报文匹配端口相等*/
                if (OVS_LIKELY(dpcls_rule_matches_key(&flow->cr, &keys[i]) && flow->flow.in_port.odp_port == packet->md.in_port.odp_port)) 
               	{
                    /* SMC hit and emc miss, we insert into EMC */
					/*获取miniflow key的size*/
                    keys[i].len = netdev_flow_key_size(miniflow_n_values(&keys[i].mf));

					/*命中smc，插入emc流表*/
                    emc_probabilistic_insert(pmd, &keys[i], flow);

					/*命中流表的报文填入每流报文批处理*/
                    dp_netdev_queue_batches(packet, flow, miniflow_get_tcp_flags(&keys[i].mf), batches, n_batches);

					/*smc命中++*/
					n_smc_hit++;

					/*smc命中标记*/
					hit = true;

					break;
                }
            }
			
			/*报文命中了smc 继续处理后续报文**/
            if (hit) 
			{
                continue;
            }
        }

        /* SMC missed. Group missed packets together at
         * the beginning of the 'packets' array. */

		/*未命中报文重新填入队列报文批处理*/
        dp_packet_batch_refill(packets_, packet, i);

		/* Put missed keys to the pointer arrays return to the caller */
		/*命中smc的报文的key 记录到miss key*/
        missed_keys[n_missed++] = &keys[i];
    }

	/*pmd更新smc命中流量统计*/
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_SMC_HIT, n_smc_hit);
}

/* Try to process all ('cnt') the 'packets' using only the datapath flow cache
 * 'pmd->flow_cache'. If a flow is not found for a packet 'packets[i]', the
 * miniflow is copied into 'keys' and the packet pointer is moved at the
 * beginning of the 'packets' array. The pointers of missed keys are put in the
 * missed_keys pointer array for future processing.
 *
 * The function returns the number of packets that needs to be processed in the
 * 'packets' array (they have been moved to the beginning of the vector).
 *
 * For performance reasons a caller may choose not to initialize the metadata
 * in 'packets_'.  If 'md_is_valid' is false, the metadata in 'packets'
 * is not valid and must be initialized by this function using 'port_no'.
 * If 'md_is_valid' is true, the metadata is already valid and 'port_no'
 * will be ignored.
 */

/*******************************************************************************
 函数名称  :    dfc_processing
 功能描述  :    emc流表查询、emc流表未命中查smc流表、命中smc流表插入emc流表、返回未命中的报文队列批处理结构 去查dpcls
 			    1.将dp_packet_batch中的所有包送入EMC(pmd->flow_cache)处理，精确流表匹配
			    2.返回要被送入fast_path_processing中处理的包数
			    3.同时若md_is_valid该函数还将根据port_no初始化metadata
			    收到的几个报文解析key值，并且从cache中查找流表，匹配的报文放入流表；返回不匹配的报文个数
 输入参数  :  	pmd--pmd线程
 输出参数  :	packets_---队列报文批处理结构
 				keys---命中emc的报文miniflow key，用来记录报文提取的miniflow key
 				missed_keys---记录未命中emc的报文miniflow key，指针数组
 				batches---每流报文批处理结构数组，支持多个流的批处理，每个流一个
 				n_batches---批处理报文个数
 				md_is_valid---false  metadata是否生效
 				port_no---in_port端口号
 				
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline size_t
dfc_processing(struct dp_netdev_pmd_thread *pmd, struct dp_packet_batch *packets_, struct netdev_flow_key *keys,
               struct netdev_flow_key **missed_keys, struct packet_batch_per_flow batches[], size_t *n_batches, bool md_is_valid, odp_port_t port_no)
{
	/*miniflow key 地址*/
    struct netdev_flow_key *key = &keys[0];

	/*命中与miss 计数*/
    size_t n_missed = 0, n_emc_hit = 0;

	/*pmd线程缓存索引、emc cached精确流表*/
    struct dfc_cache *cache = &pmd->flow_cache;

	
	struct dp_packet *packet;

	/*当前队列报文批处理缓存报文数*/
    const size_t cnt = dp_packet_batch_size(packets_);
	
    uint32_t cur_min;
    int i;
    uint16_t tcp_flags;

	/*数据库是否开启smc开关*/
    bool smc_enable_db;

	/*原子读取smc使能开关*/
    atomic_read_relaxed(&pmd->dp->smc_enable_db, &smc_enable_db);

	/*原子读当前emc流表最小数*/
    atomic_read_relaxed(&pmd->dp->emc_insert_min, &cur_min);

	/*pmd更新报文计数更新*/
    pmd_perf_update_counter(&pmd->perf_stats, md_is_valid ? PMD_STAT_RECIRC : PMD_STAT_RECV, cnt);
	
    /*遍历取出队列批处理报文处理(从队列取出报文，每次最多32个)*/
    DP_PACKET_BATCH_REFILL_FOR_EACH (i, cnt, packet, packets_) 
   	{
   		/*流表*/
        struct dp_netdev_flow *flow;

		/*报文mark*/
        uint32_t mark;

		/*若packet包长小于以太头的长度14 直接丢包*/
        if (OVS_UNLIKELY(dp_packet_size(packet) < ETH_HEADER_LEN)) 
		{
			/*释放报文*/
            dp_packet_delete(packet);
			
            continue;
        }

		/*对数据手工预取可减少读取延迟，从而提高性能*/
        if (i != cnt - 1) 
		{
			/*队列批处理报文指针数组*/
            struct dp_packet **packets = packets_->packets;
			
            /* Prefetch next packet data and metadata. */
			/*预取批处理报文*/
            OVS_PREFETCH(dp_packet_data(packets[i+1]));

			/*元数据预取*/
            pkt_metadata_prefetch_init(&packets[i+1]->md);
        }

	   /*metadata没有生效则初始化metadata，首先将pkt_metadata中flow_in_port前的字节全部设为0，然后将in_port.odp_port设为port_no,tunnel.ip_dst设为0从而tunnel中的其他字段*/
        if (!md_is_valid) 
		{
			/*报文元数据初始化，只填了inport*/
            pkt_metadata_init(&packet->md, port_no);
        }

		/*报文有流的Mark标记，且不是recircle报文，有mark代表之前命中过某条flow，打上了flow的mark*/
        if ((*recirc_depth_get() == 0) && dp_packet_has_flow_mark(packet, &mark)) 
        {
        	/*根据队列批处理报文的mark直接找到报文所属于的flow*/
            flow = mark_to_flow_find(pmd, mark);
            if (flow) 
			{
				/*从队列批处理报文提取tcp 标记*/
                tcp_flags = parse_tcp_flags(packet);

				/*报文直接命中流，报文添加到命中流表报文批处理缓存*/
                dp_netdev_queue_batches(packet, flow, tcp_flags, batches, n_batches);

				/*命中的报文填完批处理，继续后续报文处理*/
				continue;
            }
        }

		VLOG_DBG("dp_netdev_input__ miniflow_extract");

		/*从报文提取miniflow, 将报文解析到key值, 根据pkt_metadata中的值以及dp_packet->mbuf提取miniflow*/
        miniflow_extract(packet, &key->mf);

		/*miniflow 长度先置0*/
        key->len = 0; /* Not computed yet. */

		/*如果emc和smc都关掉，不去计算哈希*/
        /* If EMC and SMC disabled skip hash computation */

		/*计算与当前dp_packet相应的miniflow所在的netdev_flow_key中的hash，该hash将在emc_lookup中匹配entry，该hash可在NIC的RSS mode使能时可在收包时计算，或者由miniflow_hash_5tuple得到*/
        if (smc_enable_db == true || cur_min != 0) 
		{
			/*根据miniflow算哈希用来查emc，metadata 未生效，hash为算出来的*/
            if (!md_is_valid) 
			{
				/*从dpdk rss 或根据miniflow五元组算哈希*/
                key->hash = dpif_netdev_packet_get_rss_hash_orig_pkt(packet, &key->mf);
            }
			else 
			{
				/*根据报文获取rss hash*/
                key->hash = dpif_netdev_packet_get_rss_hash(packet, &key->mf);
            }
        }

		/*emc存在流表项*/
        if (cur_min) 
		{
			/*emc查询，从hash表中查找，并且进行key值比较，根据key->hash，emc_entry alive, miniflow 3个条件得到dp_netdev_flow*/
            flow = emc_lookup(&cache->emc_cache, key);
			VLOG_DBG("dp_netdev_input__ emc_lookup flow");
        } 
		else 
		{
			/*emc未查到流表项、赋值空*/
            flow = NULL;
        }

		/*命中了emc流表项*/
		if (OVS_LIKELY(flow)) 
		{
			/*从miniflow提取tcp_flags*/
            tcp_flags = miniflow_get_tcp_flags(&key->mf);

			/*如果匹配，调用dp_netdev_queue_batches将报文添加在flow->batches中，不匹配将不匹配的报文当前排*/
			/*根据dp_netdev_flow对dp_packet分类，将同以个dp_netdev_flow对应的所有dp_packet放入相同的packet_batch_per_flow*/

			/*命中emc流表的报文填到对应流报文批处理缓存，一次性执行action*/
            dp_netdev_queue_batches(packet, flow, tcp_flags, batches, n_batches);

			VLOG_DBG("dp_netdev_input__  flow hit insert queue batches n_emc_hit=%u",n_emc_hit);

			/*emc流表命中报文计数+1*/
            n_emc_hit++;
        } 
		/*未命中*/
		else 
		{
            /* Exact match cache missed. Group missed packets together at
             * the beginning of the 'packets' array. */

			/*未命中报文重新填入队列批处理*/
            dp_packet_batch_refill(packets_, packet, i);
			
            /* 'key[n_missed]' contains the key of the current packet and it
             * will be passed to SMC lookup. The next key should be extracted
             * to 'keys[n_missed + 1]'.
             * We also maintain a pointer array to keys missed both SMC and EMC
             * which will be returned to the caller for future processing. */

			/*记录未命中的报文key*/
            missed_keys[n_missed] = key;

			/*命中的报文指针，为什么用miss做下标*/
            key = &keys[++n_missed];
        }
    }

	/*emc流表命中报文流量统计*/
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_EXACT_HIT, n_emc_hit);

	/*数据库没有开启smc*/
    if (!smc_enable_db) 
	{
		/*返回队列批处理报文数*/
        return dp_packet_batch_size(packets_);
    }

	/*emc不匹配，去smc匹配*/
    /* Packets miss EMC will do a batch lookup in SMC if enabled */
    smc_lookup_batch(pmd, keys, missed_keys, packets_, batches, n_batches, n_missed);
	
	VLOG_DBG("dp_netdev_input__  smc_lookup_batch ");

	/*返回仍需要处理的 队列报文批处理报文数*/
    return dp_packet_batch_size(packets_);
}

/*******************************************************************************
 函数名称  :    handle_packet_upcall
 功能描述  :    upcall处理, ofproto classifier查找
 输入参数  :    key---skb提取的key
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline int
handle_packet_upcall(struct dp_netdev_pmd_thread *pmd, struct dp_packet *packet, const struct netdev_flow_key *key,
                     struct ofpbuf *actions, struct ofpbuf *put_actions)
{
    struct ofpbuf *add_actions;
    struct dp_packet_batch b;
    struct match match;
    ovs_u128 ufid;
    int error;

	/*流量统计时间更新*/
    uint64_t cycles = cycles_counter_update(&pmd->perf_stats);

    match.tun_md.valid = false;

	/*key->mf解析到match.flow*/
    miniflow_expand(&key->mf, &match.flow);

    ofpbuf_clear(actions);
    ofpbuf_clear(put_actions);

	/*根据key值计算出hash*/
    dpif_flow_hash(pmd->dp->dpif, &match.flow, sizeof match.flow, &ufid);

	/*进一步调用去ofproto classifier查表的接口，如果失败则删除报文*/
    error = dp_netdev_upcall(pmd, packet, &match.flow, &match.wc, &ufid, DPIF_UC_MISS, NULL, actions, put_actions);
    if (OVS_UNLIKELY(error && error != ENOSPC)) 
	{
        dp_packet_delete(packet);
        return error;
    }

    /* The Netlink encoding of datapath flow keys cannot express
     * wildcarding the presence of a VLAN tag. Instead, a missing VLAN
     * tag is interpreted as exact match on the fact that there is no
     * VLAN.  Unless we refactor a lot of code that translates between
     * Netlink and struct flow representations, we have to do the same
     * here.  This must be in sync with 'match' in dpif_netdev_flow_put(). */
    if (!match.wc.masks.vlans[0].tci) {
        match.wc.masks.vlans[0].tci = htons(0xffff);
    }

    /* We can't allow the packet batching in the next loop to execute
     * the actions.  Otherwise, if there are any slow path actions,
     * we'll send the packet up twice. */

	/*报文批处理初始化*/
    dp_packet_batch_init_packet(&b, packet);

	/*可能是直接执行action，后期需要看看为什么不能放入批处理*/
    dp_netdev_execute_actions(pmd, &b, true, &match.flow, actions->data, actions->size);

    add_actions = put_actions->size ? put_actions : actions;
    if (OVS_LIKELY(error != ENOSPC)) 
	{
        struct dp_netdev_flow *netdev_flow;

        /* XXX: There's a race window where a flow covering this packet
         * could have already been installed since we last did the flow
         * lookup before upcall.  This could be solved by moving the
         * mutex lock outside the loop, but that's an awful long time
         * to be locking everyone out of making flow installs.  If we
         * move to a per-core classifier, it would be reasonable. */
        ovs_mutex_lock(&pmd->flow_mutex);

		/*需要重新查找dpcls，没有查找到则调用dp_netdev_flow_add添加流表*/
        netdev_flow = dp_netdev_pmd_lookup_flow(pmd, key, NULL);
        if (OVS_LIKELY(!netdev_flow))
		{
			/*流表插入*/
            netdev_flow = dp_netdev_flow_add(pmd, &match, &ufid, add_actions->data, add_actions->size);
        }
        ovs_mutex_unlock(&pmd->flow_mutex);

		/*ufid哈希值*/
        uint32_t hash = dp_netdev_flow_hash(&netdev_flow->ufid);

		/*精确流表插入，dpcls的流表插入EMC中*/
        smc_insert(pmd, key, hash);

		/*emc流表插入*/
        emc_probabilistic_insert(pmd, key, netdev_flow);
    }
	
    if (pmd_perf_metrics_enabled(pmd)) 
	{
        /* Update upcall stats. */

		cycles = cycles_counter_update(&pmd->perf_stats) - cycles;

		/*每pmd流量统计*/
		struct pmd_perf_stats *s = &pmd->perf_stats;

		s->current.upcalls++;
        s->current.upcall_cycles += cycles;

		/*添加*/
        histogram_add_sample(&s->cycles_per_upcall, cycles);
    }
    return error;
}

/*******************************************************************************
 函数名称  :  fast_path_processing
 功能描述  :  快转路径处理，dpcls查询
 			  如果存在不匹配的报文，则调用fast_path_processing继续查找全部表项
			  找到则将流表放入cache，不匹配则上报到controller
 输入参数  :  pmd
              packets_---队列取出的报文，批处理报文
 			  keys---emc miss的报文key 指针数组地址
 			  batches---每流批处理数组，支持多个流
 			  n_batches---每流批处理，数组下标
 			  in_port---队列所属的端口 
 				
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline void
fast_path_processing(struct dp_netdev_pmd_thread *pmd, struct dp_packet_batch *packets_, struct netdev_flow_key **keys,
					struct packet_batch_per_flow batches[], size_t *n_batches, odp_port_t in_port)
{
	/*每队列批处理报文数*/
    const size_t cnt = dp_packet_batch_size(packets_);
	
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t PKT_ARRAY_SIZE = cnt;
#else
	/*批处理报文size 32*/
    /* Sparse or MSVC doesn't like variable length array. */
    enum { PKT_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    struct dp_packet *packet;
    struct dpcls *cls;

	/*记录查找到的dpcls rule 规则*/
    struct dpcls_rule *rules[PKT_ARRAY_SIZE];

	/*pmd所在dp 数据面结构*/
    struct dp_netdev *dp = pmd->dp;

	int upcall_ok_cnt = 0, upcall_fail_cnt = 0;
	
    int lookup_cnt = 0, add_lookup_cnt;

	bool any_miss;

	/*遍历每流报文批处理报文*/
    for (size_t i = 0; i < cnt; i++) 
	{
        /* Key length is needed in all the cases, hash computed on demand. */
		/*提取报文 miniflow 报文字段buf key长度，填入miniflow key len*/
        keys[i]->len = netdev_flow_key_size(miniflow_n_values(&keys[i]->mf));
    }
    /* Get the classifier for the in_port */
	/*1.根据in_port计算hash值，然后由此hash值在pmd->classifiers中查找dpcls
       2.每个in_port拥有一个dpcls
    */

	/*端口命中的dpcls*/
    cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    if (OVS_LIKELY(cls)) 
	{
		/*dpcls查询
		1.通过classifier查找子流表，如果所有的报文都找到了匹配的子流表，将流表插入emc缓存中，并且将报文加入flow->batches。
		2.如果不匹配，则上报到controller，没细看。
		3.统计匹配、不匹配和丢失。
		*/
		/*根据端口命中的dpcls，查找dpcls rule，存在miss的报文返回false*/
        any_miss = !dpcls_lookup(cls, (const struct netdev_flow_key **)keys, rules, cnt, &lookup_cnt);
    } 
	/*未找到dpcls规则*/
	else 
	{
        any_miss = true;
        memset(rules, 0, sizeof(rules));
    }

	/*对rules[i]为空的packets[i]转入upcall流程处理*/
    if (OVS_UNLIKELY(any_miss) && !fat_rwlock_tryrdlock(&dp->upcall_rwlock)) 
	{
        uint64_t actions_stub[512 / 8], slow_stub[512 / 8];
        struct ofpbuf actions, put_actions;

        ofpbuf_use_stub(&actions, actions_stub, sizeof actions_stub);
        ofpbuf_use_stub(&put_actions, slow_stub, sizeof slow_stub);

		/*遍历批处理报文*/
        DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) 
		{
            struct dp_netdev_flow *netdev_flow;

			/*dpcls规则存在*/
            if (OVS_LIKELY(rules[i])) 
			{
                continue;
            }

            /* It's possible that an earlier slow path execution installed
             * a rule covering this flow.  In this case, it's a lot cheaper
             * to catch it here than execute a miss. */

			/*根据keys中的miniflow得到in_port，利用该in_port查找dpcls，若找到就调用dpcls_lookup在进行一次rule的查找*/
            netdev_flow = dp_netdev_pmd_lookup_flow(pmd, keys[i], &add_lookup_cnt);
            if (netdev_flow) 
			{
				/*命中dpcls规则 计数 记录*/
                lookup_cnt += add_lookup_cnt;
                rules[i] = &netdev_flow->cr;
                continue;
            }

			/*报文upcall处理*/
            int error = handle_packet_upcall(pmd, packet, keys[i], &actions, &put_actions);
            if (OVS_UNLIKELY(error)) 
			{
                upcall_fail_cnt++;
            } 
			else 
			{
                upcall_ok_cnt++;
            }
        }

        ofpbuf_uninit(&actions);
		
        ofpbuf_uninit(&put_actions);
		
        fat_rwlock_unlock(&dp->upcall_rwlock);
    } 
	else if (OVS_UNLIKELY(any_miss)) 
	{
        DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) 
		{
            if (OVS_UNLIKELY(!rules[i])) 
			{
                dp_packet_delete(packet);
                upcall_fail_cnt++;
            }
        }
    }

	/*遍历批处理报文*/
    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) 
	{
        struct dp_netdev_flow *flow;

		/*未命中dpcls规则 continue*/
        if (OVS_UNLIKELY(!rules[i])) 
		{
            continue;
        }

		 /*根据每个包所对应的dpcls_rule得到相对应的miniflow 其后将该flow插入到emc中，同时根据该flow对packet进行入队*/
        flow = dp_netdev_flow_cast(rules[i]);

		
        uint32_t hash = dp_netdev_flow_hash(&flow->ufid);

		/*smc规则插入*/
        smc_insert(pmd, keys[i], hash);

		/*emc 插入*/
        emc_probabilistic_insert(pmd, keys[i], flow);

		/*报文批处理*/
        dp_netdev_queue_batches(packet, flow, miniflow_get_tcp_flags(&keys[i]->mf), batches, n_batches);
    }

	/*更新各种类型流量统计*/
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MASKED_HIT, cnt - upcall_ok_cnt - upcall_fail_cnt);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MASKED_LOOKUP, lookup_cnt);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MISS, upcall_ok_cnt);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_LOST,  upcall_fail_cnt);
}

/* Packets enter the datapath from a port (or from recirculation) here.
 *
 * When 'md_is_valid' is true the metadata in 'packets' are already valid.
 * When false the metadata in 'packets' need to be initialized. */

/*******************************************************************************
 函数名称  :    ovs_dp_process_packet
 功能描述  :    报文处理流程(流表的匹配，然后执行相应的action)
 输入参数  :    key---skb提取的key
 输出参数  :	pmd---pmd线程
			    packets---队列批处理缓存报文结构，临时结构，从队列取的报文
			    md_is_valid---metadata是否生效，recircle报文为true
 			    port_no---端口号
 			
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static void dp_netdev_input__(struct dp_netdev_pmd_thread *pmd, struct dp_packet_batch *packets, bool md_is_valid, odp_port_t port_no)
{

#if !defined(__CHECKER__) && !defined(_WIN32)

	/*当前需要批处理报文数*/
    const size_t PKT_ARRAY_SIZE = dp_packet_batch_size(packets);
#else
    /* Sparse or MSVC doesn't like variable length array. */
    enum { PKT_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE)

	/*从报文提取的miniflow key*/
	struct netdev_flow_key keys[PKT_ARRAY_SIZE];

	/*未命中emc、dpcls的报文miniflow key记录，指针数组，用于upcall上报*/
    struct netdev_flow_key *missed_keys[PKT_ARRAY_SIZE];

	/*每流报文批处理结构数组，记录名字flow的报文*/
    struct packet_batch_per_flow batches[PKT_ARRAY_SIZE];

	/*批处理结构数*/
    size_t n_batches;
    odp_port_t in_port;

    n_batches = 0;

	VLOG_DBG("dp_netdev_input__ pmd->core_id=%u",pmd->core_id);


	/* 1.将dp_packet_batch中的所有包送入EMC(pmd->flow_cache)处理，IP 5元组的精确匹配，返回未命中emc要被送入fast_path_processing中处理的包数
       2.同时若md_is_valid为false该函数还将根据port_no初始化metadata
    */

	/*1.将收到的报文解析key值，并且查emc流表，cache中，匹配的报文放入流表批处理，返回不匹配的报文个数
	  2.如果存在不匹配的报文，调用fast_path_processing则继续查找dpcls全部表项，找到则将流表放入emc cache，不匹配则上报到controller*/
    dfc_processing(pmd, packets, keys, missed_keys, batches, &n_batches, md_is_valid, port_no);

	/*队列批处理报文不为空(未命中EMC流表的报文)，去查dpcls*/
	if (!dp_packet_batch_is_empty(packets)) 
	{
        /* Get ingress port from first packet's metadata. */
		/*从报文metadata中获取队列批处理报文的inport*/
        in_port = packets->packets[0]->md.in_port.odp_port;

		/*快转路径处理，如果存在不匹配的报文，则调用fast_path_processing继续查找全部表项，找到则将流表放入cache，不匹配则上报到controller*/
		/*dpcls查询*/
        fast_path_processing(pmd, packets, missed_keys, batches, &n_batches, in_port);
    }

    /* All the flow batches need to be reset before any call to
     * packet_batch_per_flow_execute() as it could potentially trigger
     * recirculation. When a packet matching flow 鈥榡鈥� happens to be
     * recirculated, the nested call to dp_netdev_input__() could potentially
     * classify the packet as matching another flow - say 'k'. It could happen
     * that in the previous call to dp_netdev_input__() that same flow 'k' had
     * already its own batches[k] still waiting to be served.  So if its
     * 鈥榖atch鈥� member is not reset, the recirculated packet would be wrongly
     * appended to batches[k] of the 1st call to dp_netdev_input__(). */
    size_t i;

	/*批处理结构数，报文初始化*/
    for (i = 0; i < n_batches; i++) 
	{
		/*每流队列批处理结构下flow关联的批处理结构赋值NULL 为啥*/
        batches[i].flow->batch = NULL;
    }

	/*调用packet_batch_execute根据流表来操作报文，统一调用各自的action*/
    for (i = 0; i < n_batches; i++) 
	{	
		/*每流表报文批处理执行对应流的action*/
        packet_batch_per_flow_execute(&batches[i], pmd);
    }
}

/*******************************************************************************
 函数名称  :    dp_netdev_input
 功能描述  :    pmd报文批处理
 输入参数  :  	key---skb提取的key
 输出参数  :	pmd---pmd线程
 				packets---批处理缓存报文结构，临时结构
 				port_no---端口号
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static void
dp_netdev_input(struct dp_netdev_pmd_thread *pmd, struct dp_packet_batch *packets, odp_port_t port_no)
{
    dp_netdev_input__(pmd, packets, false, port_no);
}

/*******************************************************************************
 函数名称  :    dp_netdev_recirculate
 功能描述  :    查recircle流表
 输入参数  :  	pmd---收上报文的pmd
 				packets---recircle 批处理的报文
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
dp_netdev_recirculate(struct dp_netdev_pmd_thread *pmd, struct dp_packet_batch *packets)
{
	/*报文处理流程(流表的匹配，然后执行相应的action)，重新跑一遍*/
    dp_netdev_input__(pmd, packets, true, 0);
}

/*命中的flow和flow所在的pmd*/
struct dp_netdev_execute_aux {
    struct dp_netdev_pmd_thread *pmd;
    const struct flow *flow;
};

static void
dpif_netdev_register_dp_purge_cb(struct dpif *dpif, dp_purge_callback *cb,
                                 void *aux)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp->dp_purge_aux = aux;
    dp->dp_purge_cb = cb;
}

static void
dpif_netdev_register_upcall_cb(struct dpif *dpif, upcall_callback *cb,
                               void *aux)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp->upcall_aux = aux;
    dp->upcall_cb = cb;
}

/*******************************************************************************
 函数名称 :  dpif_netdev_xps_get_tx_qid
 功能描述 :  释放发送队列的ID
 输入参数 :  pmd---pmd线程
 		     purge---清除标记为false
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/

static void
dpif_netdev_xps_revalidate_pmd(const struct dp_netdev_pmd_thread *pmd, bool purge)
{
    struct tx_port *tx;
    struct dp_netdev_port *port;
    long long interval;

	/*遍历缓存的发端口、清掉使用的发队列id*/
    HMAP_FOR_EACH (tx, node, &pmd->send_port_cache) 
	{
		/*发端口使用动态队列标记未使能*/
        if (!tx->port->dynamic_txqs) 
		{
            continue;
        }

		/*跟上一次发送间隔时间*/
        interval = pmd->ctx.now - tx->last_used;

		/*发队列ID存在，且purge==false interval < 500000LL, 发队列ID清掉*/
		if (tx->qid >= 0 && (purge || interval >= XPS_TIMEOUT)) 
		{
			/*获取发队列端口*/
            port = tx->port;
            ovs_mutex_lock(&port->txq_used_mutex);

			/*端口下发队列引用次数--，为什么*/
            port->txq_used[tx->qid]--;
            ovs_mutex_unlock(&port->txq_used_mutex);

			/*发队列使用的ID清掉*/
            tx->qid = -1;
        }
    }
}

/*******************************************************************************
 函数名称 :  dpif_netdev_xps_get_tx_qid
 功能描述 :  从发队列ID池动态获取发送队列的ID
 输入参数 :  pmd---pmd线程
 			 p---pmd缓存的发端口
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
static int
dpif_netdev_xps_get_tx_qid(const struct dp_netdev_pmd_thread *pmd, struct tx_port *tx)
{
    struct dp_netdev_port *port;
    long long interval;
    int i, min_cnt, min_qid;

	/*发送队列使用时间间隔*/
    interval = pmd->ctx.now - tx->last_used;

	/*发送队列上次使用时间*/
    tx->last_used = pmd->ctx.now;

	/*发送队列ID存在，与上次发时间 间隔小于500000 微妙*/
    if (OVS_LIKELY(tx->qid >= 0 && interval < XPS_TIMEOUT)) 
	{
        return tx->qid;
    }

	/*发送端口*/
    port = tx->port;

	/*互斥锁获取*/
    ovs_mutex_lock(&port->txq_used_mutex);

	/*发送队列ID存在*/
    if (tx->qid >= 0) 
	{
		/*发送队列引用次数减少一次*/
        port->txq_used[tx->qid]--;

		/*清掉端口发队列ID*/
        tx->qid = -1;
    }

    min_cnt = -1;
    min_qid = 0;

	/*遍历端口上发队列，选出引用次数小于-1的队列*/
    for (i = 0; i < netdev_n_txq(port->netdev); i++) 
	{
		/*选出发队列i引用次数小于-1的队列，*/
        if (port->txq_used[i] < min_cnt || min_cnt == -1) 
		{
			/*记录队列i引用次数*/
            min_cnt = port->txq_used[i];

			/*记录队列id*/
            min_qid = i;
        }
    }

	/*发送队列i引用次数增加*/
    port->txq_used[min_qid]++;

	/*发队列id赋值*/
    tx->qid = min_qid;

	/*解锁发队列*/
    ovs_mutex_unlock(&port->txq_used_mutex);

	/*使重新生效*/
    dpif_netdev_xps_revalidate_pmd(pmd, false);

    VLOG_DBG("Core %d: New TX queue ID %d for port \'%s\'.", pmd->core_id, tx->qid, netdev_get_name(tx->port->netdev));
	
    return min_qid;
}

/*******************************************************************************
 函数名称  :  pmd_tnl_port_cache_lookup
 功能描述  :  根据端口号获取vxlan端口
 输入参数  :  
 			  
 输出参数  :  
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static struct tx_port *
pmd_tnl_port_cache_lookup(const struct dp_netdev_pmd_thread *pmd, odp_port_t port_no)
{
	/*根据端口号查询vxlan缓存端口*/
    return tx_port_lookup(&pmd->tnl_port_cache, port_no);
}

/*******************************************************************************
 函数名称  :  pmd_send_port_cache_lookup
 功能描述  :  根据端口号在pmd->send_port_cache 中查发端口
 输入参数  :  pmd---flow 所在pmd
 			  port_no---output端口
 			  
 输出参数  :  
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static struct tx_port *
pmd_send_port_cache_lookup(const struct dp_netdev_pmd_thread *pmd, odp_port_t port_no)
{
    return tx_port_lookup(&pmd->send_port_cache, port_no);
}

/*******************************************************************************
 函数名称  :  dp_netdev_pmd_flush_output_on_port
 功能描述  :  封装vxlan
 输入参数  :  key---skb提取的key
 			  a---流的属性
 			  should_steal---报文是否窃取
 			  batch---报文批处理
 			  
 输出参数  :  
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static int
push_tnl_action(const struct dp_netdev_pmd_thread *pmd, const struct nlattr *attr, struct dp_packet_batch *batch)
{
    struct tx_port *tun_port;
    const struct ovs_action_push_tnl *data;
    int err;

	/*从流属性获取vxlan属性数据*/
    data = nl_attr_get(attr);

	/*根据tnl_port端口号从pmd->tnl_port_cache中获取vxlan port*/
    tun_port = pmd_tnl_port_cache_lookup(pmd, data->tnl_port);
    if (!tun_port) 
	{
        err = -EINVAL;
        goto error;
    }

	/*封装vxlan头*/
    err = netdev_push_header(tun_port->port->netdev, batch, data);
    if (!err) 
	{
        return 0;
    }
error:

	/*批处理报文删除、释放报文内存*/
    dp_packet_delete_batch(batch, true);
    return err;
}

/*******************************************************************************
 函数名称  :    dp_execute_userspace_action
 功能描述  :    扔到用户态
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
dp_execute_userspace_action(struct dp_netdev_pmd_thread *pmd,
                            struct dp_packet *packet, bool should_steal,
                            struct flow *flow, ovs_u128 *ufid,
                            struct ofpbuf *actions,
                            const struct nlattr *userdata)
{
    struct dp_packet_batch b;
    int error;

    ofpbuf_clear(actions);

	/*扔到用户态*/
    error = dp_netdev_upcall(pmd, packet, flow, NULL, ufid,
                             DPIF_UC_ACTION, userdata, actions,
                             NULL);
    if (!error || error == ENOSPC) {
        dp_packet_batch_init_packet(&b, packet);
        dp_netdev_execute_actions(pmd, &b, should_steal, flow,
                                  actions->data, actions->size);
    } 
	/*报文窃取标记*/
	else if (should_steal) {
        dp_packet_delete(packet);
    }
}

/*******************************************************************************
 函数名称  :    dp_execute_cb
 功能描述  :    流表action回调函数
 输入参数  :  	aux_---pmd和flow信息
 				packets_---报文批处理结构
 				key---skb提取的key
 				a---流的属性，有output端口号
 				should_steal---报文是否窃取
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
dp_execute_cb(void *aux_, struct dp_packet_batch *packets_, const struct nlattr *a, bool should_steal)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
	/*pmd和flow信息*/
    struct dp_netdev_execute_aux *aux = aux_;

	/*已经recirc次数*/
    uint32_t *depth = recirc_depth_get();

	/*获取pmd*/
    struct dp_netdev_pmd_thread *pmd = aux->pmd;

	/*数据面网络设备结构*/
    struct dp_netdev *dp = pmd->dp;

	/*action 的类型*/
    int type = nl_attr_type(a);

	/*发送端口*/
    struct tx_port *p;

	/*flow的 action 的类型*/
    switch ((enum ovs_action_attr)type) 
	{
		/*调用dp_netdev_lookup_port查找端口，然后调用netdev_send进行报文发送*/
	    case OVS_ACTION_ATTR_OUTPUT:
			
			/*根据端口号在pmd->send_port_cache中查发端口，每个端口都在添加时生成了一个发结构*/
	        p = pmd_send_port_cache_lookup(pmd, nl_attr_get_odp_port(a));
	        if (OVS_LIKELY(p))
			{
	            struct dp_packet *packet;
	            struct dp_packet_batch out;

				/*窃取开关未开*/
	            if (!should_steal) 
				{
					/*批处理报文从packets_ clone一份到out结构，每个报文都有新buffer*/
	                dp_packet_batch_clone(&out, packets_);

					/*尾部要砍掉的长度设置0*/
	                dp_packet_batch_reset_cutlen(packets_);

					/*使用out批处理结构*/
	                packets_ = &out;
	            }

				/*重新设定报文长度为cut后的长度*/
	            dp_packet_batch_apply_cutlen(packets_);

/*dpdk的处理*/
#ifdef DPDK_NETDEV
				/*端口发报文发批处理报文为个数不为0，且存在的报文src与out里新的批处理报文src不相等，先发掉端口上已存在的批处理报文*/
	            if (OVS_UNLIKELY(!dp_packet_batch_is_empty(&p->output_pkts) && packets_->packets[0]->source != p->output_pkts.packets[0]->source)) 
	            {
	                /* XXX: netdev-dpdk assumes that all packets in a single
	                 *      output batch has the same source. Flush here to
	                 *      avoid memory access issues. */

					/*dpdk从发发端口报文批处理结构p->output_pkts发掉报文*/
	                dp_netdev_pmd_flush_output_on_port(pmd, p);
	            }
#endif
				/*新到的批处理报文加上已存在的发批处理报文个数大于32，则先发掉已存在的批处理报文*/
	            if (dp_packet_batch_size(&p->output_pkts) + dp_packet_batch_size(packets_) > NETDEV_MAX_BURST) 
				{
	                /* Flush here to avoid overflow. */

					/*发报文避免溢出*/
	                dp_netdev_pmd_flush_output_on_port(pmd, p);
	            }

				/*原来的批处理报文个数为空*/
	            if (dp_packet_batch_is_empty(&p->output_pkts)) 
				{
					/*发出的批处理报文计数*/
	                pmd->n_output_batches++;
	            }

				/*遍历报文填入端口发批处理结构*/
	            DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) 
				{
					/*记录pmd上次使用的发队列*/
	                p->output_pkts_rxqs[dp_packet_batch_size(&p->output_pkts)] = pmd->ctx.last_rxq;

					/*报文添加到端口发批处理结构*/
					dp_packet_batch_add(&p->output_pkts, packet);
	            }
				
	            return;
	        }

			break;

		/*调用push_tnl_action进行tunnel封装，然后调用dp_netdev_recirculate–>dp_netdev_input__重新查表操作*/
	    case OVS_ACTION_ATTR_TUNNEL_PUSH:
			/*报文被窃取*/
	        if (should_steal) 
			{
	            /* We're requested to push tunnel header, but also we need to take
	             * the ownership of these packets. Thus, we can avoid performing
	             * the action, because the caller will not use the result anyway.
	             * Just break to free the batch. */
	            break;
	        }

			/*应用新的报文长度为截取后的长度*/
	        dp_packet_batch_apply_cutlen(packets_);

			/*封vxlan*/
	        push_tnl_action(pmd, a, packets_);
			
	        return;

		/*调用netdev_pop_header解封装，然后调用dp_netdev_recirculate–>dp_netdev_input__重新查表操作*/
	    case OVS_ACTION_ATTR_TUNNEL_POP:

			/*recircle 深度为6 */
	        if (*depth < MAX_RECIRC_DEPTH) 
			{
	            struct dp_packet_batch *orig_packets_ = packets_;

				/*vxlan端口号*/
	            odp_port_t portno = nl_attr_get_odp_port(a);

				/*根据端口号获取in_port端口*/
	            p = pmd_tnl_port_cache_lookup(pmd, portno);
	            if (p)
				{
					/*封vxlan的批处理结构*/
	                struct dp_packet_batch tnl_pkt;

					/*报文未窃取*/
	                if (!should_steal) 
					{
						/*报文拷贝到tnl_pkt临时结构*/
	                    dp_packet_batch_clone(&tnl_pkt, packets_);
						
	                    packets_ = &tnl_pkt;

						/*重新设置尾巴需要cut的字节数成为0*/
						dp_packet_batch_reset_cutlen(orig_packets_);
	                }

					/*报文长度设置为cut后长度*/
	                dp_packet_batch_apply_cutlen(packets_);

					/*解vxlan头，解完报文重新填回batch*/
	                netdev_pop_header(p->port->netdev, packets_);

					/*报文批处理个数为空*/
					if (dp_packet_batch_is_empty(packets_)) 
					{
	                    return;
	                }

	                struct dp_packet *packet;

					/*遍历pop后的报文metadata填入 in_port*/
					DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) 
					{
						/*port号赋值给报文metadata*/
	                    packet->md.in_port.odp_port = portno;
	                }

					/*recircle深度+1*/
	                (*depth)++;
					
					/*解完vxlan做recircle重新匹配流表，报文处理流程(流表的匹配，然后执行相应的action)*/
	                dp_netdev_recirculate(pmd, packets_);
					
					/*recircle深度-1*/
	                (*depth)--;
					
	                return;
	            }
	        }
	        break;

		/*扔到用户态*/
	    case OVS_ACTION_ATTR_USERSPACE:
	        if (!fat_rwlock_tryrdlock(&dp->upcall_rwlock)) 
			{
	            struct dp_packet_batch *orig_packets_ = packets_;
	            const struct nlattr *userdata;
	            struct dp_packet_batch usr_pkt;
	            struct ofpbuf actions;
	            struct flow flow;
	            ovs_u128 ufid;
	            bool clone = false;

	            userdata = nl_attr_find_nested(a, OVS_USERSPACE_ATTR_USERDATA);
	            ofpbuf_init(&actions, 0);

	            if (packets_->trunc) 
				{
	                if (!should_steal) 
					{
	                    dp_packet_batch_clone(&usr_pkt, packets_);
	                    packets_ = &usr_pkt;
	                    clone = true;
	                    dp_packet_batch_reset_cutlen(orig_packets_);
	                }

	                dp_packet_batch_apply_cutlen(packets_);
	            }

	            struct dp_packet *packet;

				/*遍历报文upcall 扔到用户态*/
				DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) 
				{
	                flow_extract(packet, &flow);
	                dpif_flow_hash(dp->dpif, &flow, sizeof flow, &ufid);

					/*扔到用户态*/
	                dp_execute_userspace_action(pmd, packet, should_steal, &flow,
	                                            &ufid, &actions, userdata);
	            }

	            if (clone) 
				{
	                dp_packet_delete_batch(packets_, true);
	            }

	            ofpbuf_uninit(&actions);
	            fat_rwlock_unlock(&dp->upcall_rwlock);

	            return;
	        }
	        break;

		/*处理recircle流表*/
	    case OVS_ACTION_ATTR_RECIRC:

			/*recircle深度为6*/
	        if (*depth < MAX_RECIRC_DEPTH) 
			{
	            struct dp_packet_batch recirc_pkts;

				/*无窃取标记*/
	            if (!should_steal) 
				{
				   /*报文clone到新内存*/
	               dp_packet_batch_clone(&recirc_pkts, packets_);
	               packets_ = &recirc_pkts;
	            }

	            struct dp_packet *packet;

				/*批处理报文打上recircle id*/
	            DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) 
				{
	                packet->md.recirc_id = nl_attr_get_u32(a);
	            }

				/*重新去做recircle，去匹配一遍*/
	            (*depth)++;
				
				/*recircle流表，报文重新过一遍流表匹配*/
	            dp_netdev_recirculate(pmd, packets_);

				(*depth)--;

	            return;
	        }

	        VLOG_WARN("Packet dropped. Max recirculation depth exceeded.");
	        break;

		/*执行ct属性*/
	    case OVS_ACTION_ATTR_CT: 
		{
	        const struct nlattr *b;
			
	        bool force = false;
	        bool commit = false;
	        unsigned int left;

			uint16_t zone = 0;

			const char *helper = NULL;

			const uint32_t *setmark = NULL;

			const struct ovs_key_ct_labels *setlabel = NULL;
	        struct nat_action_info_t nat_action_info;
	        struct nat_action_info_t *nat_action_info_ref = NULL;
	        bool nat_config = false;

			/*从b中提取各字段*/
	        NL_ATTR_FOR_EACH_UNSAFE (b, left, nl_attr_get(a),
	                                 nl_attr_get_size(a)) 
	        {
	        	/**/
	            enum ovs_ct_attr sub_type = nl_attr_type(b);

				/*根据类型执行对应的操作*/
	            switch(sub_type) 
				{
		            case OVS_CT_ATTR_FORCE_COMMIT:
		                force = true;
		                /* fall through. */
		            case OVS_CT_ATTR_COMMIT:
		                commit = true;
		                break;
		            case OVS_CT_ATTR_ZONE:
		                zone = nl_attr_get_u16(b);
		                break;
		            case OVS_CT_ATTR_HELPER:
		                helper = nl_attr_get_string(b);
		                break;
		            case OVS_CT_ATTR_MARK:
		                setmark = nl_attr_get(b);
		                break;
		            case OVS_CT_ATTR_LABELS:
		                setlabel = nl_attr_get(b);
		                break;
		            case OVS_CT_ATTR_EVENTMASK:
		                /* Silently ignored, as userspace datapath does not generate
		                 * netlink events. */
		                break;

					/*nat操作*/
		            case OVS_CT_ATTR_NAT: 
					{
		                const struct nlattr *b_nest;
		                unsigned int left_nest;
		                bool ip_min_specified = false;
		                bool proto_num_min_specified = false;
		                bool ip_max_specified = false;
		                bool proto_num_max_specified = false;
		                memset(&nat_action_info, 0, sizeof nat_action_info);
		                nat_action_info_ref = &nat_action_info;

						/**/
		                NL_NESTED_FOR_EACH_UNSAFE (b_nest, left_nest, b) 
						{
		                    enum ovs_nat_attr sub_type_nest = nl_attr_type(b_nest);

		                    switch (sub_type_nest) 
							{
			                    case OVS_NAT_ATTR_SRC:
			                    case OVS_NAT_ATTR_DST:
			                        nat_config = true;
			                        nat_action_info.nat_action |=
			                            ((sub_type_nest == OVS_NAT_ATTR_SRC)
			                                ? NAT_ACTION_SRC : NAT_ACTION_DST);
			                        break;
			                    case OVS_NAT_ATTR_IP_MIN:
			                        memcpy(&nat_action_info.min_addr,
			                               nl_attr_get(b_nest),
			                               nl_attr_get_size(b_nest));
			                        ip_min_specified = true;
			                        break;
			                    case OVS_NAT_ATTR_IP_MAX:
			                        memcpy(&nat_action_info.max_addr,
			                               nl_attr_get(b_nest),
			                               nl_attr_get_size(b_nest));
			                        ip_max_specified = true;
			                        break;
			                    case OVS_NAT_ATTR_PROTO_MIN:
			                        nat_action_info.min_port =
			                            nl_attr_get_u16(b_nest);
			                        proto_num_min_specified = true;
			                        break;
			                    case OVS_NAT_ATTR_PROTO_MAX:
			                        nat_action_info.max_port =
			                            nl_attr_get_u16(b_nest);
			                        proto_num_max_specified = true;
			                        break;
			                    case OVS_NAT_ATTR_PERSISTENT:
			                    case OVS_NAT_ATTR_PROTO_HASH:
			                    case OVS_NAT_ATTR_PROTO_RANDOM:
			                        break;
			                    case OVS_NAT_ATTR_UNSPEC:
			                    case __OVS_NAT_ATTR_MAX:
			                        OVS_NOT_REACHED();
			                    }
		                }

		                if (ip_min_specified && !ip_max_specified) {
		                    nat_action_info.max_addr = nat_action_info.min_addr;
		                }
		                if (proto_num_min_specified && !proto_num_max_specified) 
						{
		                    nat_action_info.max_port = nat_action_info.min_port;
		                }
		                if (proto_num_min_specified || proto_num_max_specified) 
						{
		                    if (nat_action_info.nat_action & NAT_ACTION_SRC) {
		                        nat_action_info.nat_action |= NAT_ACTION_SRC_PORT;
		                    } else if (nat_action_info.nat_action & NAT_ACTION_DST) {
		                        nat_action_info.nat_action |= NAT_ACTION_DST_PORT;
		                    }
		                }
		                break;
		            }
		            case OVS_CT_ATTR_UNSPEC:
		            case __OVS_CT_ATTR_MAX:
		                OVS_NOT_REACHED();
		            }
	        }

	        /* We won't be able to function properly in this case, hence
	         * complain loudly. */
	        if (nat_config && !commit) 
			{
	            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
	            VLOG_WARN_RL(&rl, "NAT specified without commit.");
	        }

			/*执行链接跟踪action，创建一个conn*/
	        conntrack_execute(&dp->conntrack, packets_, aux->flow->dl_type, force,
	                          commit, zone, setmark, setlabel, aux->flow->tp_src,
	                          aux->flow->tp_dst, helper, nat_action_info_ref,
	                          pmd->ctx.now / 1000);
	        break;
	    }

		/*执行meter action*/
	    case OVS_ACTION_ATTR_METER:

			/*超速则drop*/
	        dp_netdev_run_meter(pmd->dp, packets_, nl_attr_get_u32(a), pmd->ctx.now);
	        break;

	    case OVS_ACTION_ATTR_PUSH_VLAN:
	    case OVS_ACTION_ATTR_POP_VLAN:
	    case OVS_ACTION_ATTR_PUSH_MPLS:
	    case OVS_ACTION_ATTR_POP_MPLS:
	    case OVS_ACTION_ATTR_SET:
	    case OVS_ACTION_ATTR_SET_MASKED:
	    case OVS_ACTION_ATTR_SAMPLE:
	    case OVS_ACTION_ATTR_HASH:
	    case OVS_ACTION_ATTR_UNSPEC:
	    case OVS_ACTION_ATTR_TRUNC:
	    case OVS_ACTION_ATTR_PUSH_ETH:
	    case OVS_ACTION_ATTR_POP_ETH:
	    case OVS_ACTION_ATTR_CLONE:
	    case OVS_ACTION_ATTR_PUSH_NSH:
	    case OVS_ACTION_ATTR_POP_NSH:
	    case OVS_ACTION_ATTR_CT_CLEAR:
			
	    case __OVS_ACTION_ATTR_MAX:
	        OVS_NOT_REACHED();
	}

	/*未匹配的报文删除*/
    dp_packet_delete_batch(packets_, should_steal);
}

/*******************************************************************************
 函数名称  :  dp_netdev_execute_actions
 功能描述  :  执行命中的flow对应的actions
 			  pmd---pmd线程
 			  packets--每流报文批处理数组
 			  should_steal---是否steal
 			  flow---流表
 			  actions---流表的action数组
 			  actions_len---流对应的action 字节长度
 			  
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
dp_netdev_execute_actions(struct dp_netdev_pmd_thread *pmd, struct dp_packet_batch *packets, bool should_steal, const struct flow *flow, const struct nlattr *actions, size_t actions_len)
{
    struct dp_netdev_execute_aux aux = { pmd, flow };

	/*如果是一些基本操作的话，调用接口dp_execute_cb*/
    odp_execute_actions(&aux, packets, should_steal, actions, actions_len, dp_execute_cb);
}

struct dp_netdev_ct_dump {
    struct ct_dpif_dump_state up;
    struct conntrack_dump dump;
    struct conntrack *ct;
    struct dp_netdev *dp;
};

static int
dpif_netdev_ct_dump_start(struct dpif *dpif, struct ct_dpif_dump_state **dump_,
                          const uint16_t *pzone, int *ptot_bkts)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_ct_dump *dump;

    dump = xzalloc(sizeof *dump);
    dump->dp = dp;
    dump->ct = &dp->conntrack;

    conntrack_dump_start(&dp->conntrack, &dump->dump, pzone, ptot_bkts);

    *dump_ = &dump->up;

    return 0;
}

static int
dpif_netdev_ct_dump_next(struct dpif *dpif OVS_UNUSED,
                         struct ct_dpif_dump_state *dump_,
                         struct ct_dpif_entry *entry)
{
    struct dp_netdev_ct_dump *dump;

    INIT_CONTAINER(dump, dump_, up);

    return conntrack_dump_next(&dump->dump, entry);
}

static int
dpif_netdev_ct_dump_done(struct dpif *dpif OVS_UNUSED,
                         struct ct_dpif_dump_state *dump_)
{
    struct dp_netdev_ct_dump *dump;
    int err;

    INIT_CONTAINER(dump, dump_, up);

    err = conntrack_dump_done(&dump->dump);

    free(dump);

    return err;
}

static int
dpif_netdev_ct_flush(struct dpif *dpif, const uint16_t *zone,
                     const struct ct_dpif_tuple *tuple)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    if (tuple) {
        return conntrack_flush_tuple(&dp->conntrack, tuple, zone ? *zone : 0);
    }
    return conntrack_flush(&dp->conntrack, zone);
}

static int
dpif_netdev_ct_set_maxconns(struct dpif *dpif, uint32_t maxconns)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_set_maxconns(&dp->conntrack, maxconns);
}

static int
dpif_netdev_ct_get_maxconns(struct dpif *dpif, uint32_t *maxconns)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_get_maxconns(&dp->conntrack, maxconns);
}

static int
dpif_netdev_ct_get_nconns(struct dpif *dpif, uint32_t *nconns)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_get_nconns(&dp->conntrack, nconns);
}

/*dpdk用的是netdev类型的dpif，数据面接口操作类*/
const struct dpif_class dpif_netdev_class = {
    "netdev",
    dpif_netdev_init,
    dpif_netdev_enumerate,
    dpif_netdev_port_open_type,
    dpif_netdev_open,
    dpif_netdev_close,
    dpif_netdev_destroy,
    dpif_netdev_run,								
    dpif_netdev_wait,
    dpif_netdev_get_stats,

	/*数据面添加端口*/
    dpif_netdev_port_add,
    dpif_netdev_port_del,

	/*设置端口rxq的亲和性*/
    dpif_netdev_port_set_config,
    dpif_netdev_port_query_by_number,
    dpif_netdev_port_query_by_name,
    NULL,                       /* port_get_pid */
    dpif_netdev_port_dump_start,
    dpif_netdev_port_dump_next,
    dpif_netdev_port_dump_done,
    dpif_netdev_port_poll,
    dpif_netdev_port_poll_wait,

	/*flow的操作*/
	dpif_netdev_flow_flush,
    dpif_netdev_flow_dump_create,
    dpif_netdev_flow_dump_destroy,
    dpif_netdev_flow_dump_thread_create,
    dpif_netdev_flow_dump_thread_destroy,
    dpif_netdev_flow_dump_next,
    dpif_netdev_operate,								/*流表的操作
    NULL,                       /* recv_set */
    NULL,                       /* handlers_set */

	/*config*/
	dpif_netdev_set_config,
    dpif_netdev_queue_to_priority,
    NULL,                       /* recv */
    NULL,                       /* recv_wait */
    NULL,                       /* recv_purge */

	
	dpif_netdev_register_dp_purge_cb,
    dpif_netdev_register_upcall_cb,
    dpif_netdev_enable_upcall,
    dpif_netdev_disable_upcall,
    dpif_netdev_get_datapath_version,

	/*ct操作*/
	dpif_netdev_ct_dump_start,
    dpif_netdev_ct_dump_next,
    dpif_netdev_ct_dump_done,
    dpif_netdev_ct_flush,
    dpif_netdev_ct_set_maxconns,
    dpif_netdev_ct_get_maxconns,
    dpif_netdev_ct_get_nconns,
    NULL,                       /* ct_set_limits */
    NULL,                       /* ct_get_limits */
    NULL,                       /* ct_del_limits */

	/*meter 操作*/
    dpif_netdev_meter_get_features,
    dpif_netdev_meter_set,
    dpif_netdev_meter_get,
    dpif_netdev_meter_del,
};

static void
dpif_dummy_change_port_number(struct unixctl_conn *conn, int argc OVS_UNUSED,
                              const char *argv[], void *aux OVS_UNUSED)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp;
    odp_port_t port_no;

    ovs_mutex_lock(&dp_netdev_mutex);
    dp = shash_find_data(&dp_netdevs, argv[1]);
    if (!dp || !dpif_netdev_class_is_dummy(dp->class)) {
        ovs_mutex_unlock(&dp_netdev_mutex);
        unixctl_command_reply_error(conn, "unknown datapath or not a dummy");
        return;
    }
    ovs_refcount_ref(&dp->ref_cnt);
    ovs_mutex_unlock(&dp_netdev_mutex);

    ovs_mutex_lock(&dp->port_mutex);
    if (get_port_by_name(dp, argv[2], &port)) {
        unixctl_command_reply_error(conn, "unknown port");
        goto exit;
    }

    port_no = u32_to_odp(atoi(argv[3]));
    if (!port_no || port_no == ODPP_NONE) {
        unixctl_command_reply_error(conn, "bad port number");
        goto exit;
    }
    if (dp_netdev_lookup_port(dp, port_no)) {
        unixctl_command_reply_error(conn, "port number already in use");
        goto exit;
    }

    /* Remove port. */
    hmap_remove(&dp->ports, &port->node);
    reconfigure_datapath(dp);

    /* Reinsert with new port number. */
    port->port_no = port_no;
    hmap_insert(&dp->ports, &port->node, hash_port_no(port_no));
    reconfigure_datapath(dp);

    seq_change(dp->port_seq);
    unixctl_command_reply(conn, NULL);

exit:
    ovs_mutex_unlock(&dp->port_mutex);
    dp_netdev_unref(dp);
}

static void
dpif_dummy_register__(const char *type)
{
    struct dpif_class *class;

    class = xmalloc(sizeof *class);
    *class = dpif_netdev_class;
    class->type = xstrdup(type);
    dp_register_provider(class);
}

static void
dpif_dummy_override(const char *type)
{
    int error;

    /*
     * Ignore EAFNOSUPPORT to allow --enable-dummy=system with
     * a userland-only build.  It's useful for testsuite.
     */
    error = dp_unregister_provider(type);
    if (error == 0 || error == EAFNOSUPPORT) {
        dpif_dummy_register__(type);
    }
}

void
dpif_dummy_register(enum dummy_level level)
{
    if (level == DUMMY_OVERRIDE_ALL) {
        struct sset types;
        const char *type;

        sset_init(&types);
        dp_enumerate_types(&types);
        SSET_FOR_EACH (type, &types) {
            dpif_dummy_override(type);
        }
        sset_destroy(&types);
    } else if (level == DUMMY_OVERRIDE_SYSTEM) {
        dpif_dummy_override("system");
    }

    dpif_dummy_register__("dummy");

    unixctl_command_register("dpif-dummy/change-port-number",
                             "dp port new-number",
                             3, 3, dpif_dummy_change_port_number, NULL);
}

/* Datapath Classifier. */

/* A set of rules that all have the same fields wildcarded. */
/* 掩码结构*/
struct dpcls_subtable 
{
    /* The fields are only used by writers. */
    struct cmap_node cmap_node OVS_GUARDED; /* Within dpcls 'subtables_map'. */

    /* These fields are accessed by readers. */
	/* 每个子表都可以包含多条流规则，dpcls规则. */
    struct cmap rules;           /* Contains "struct dpcls_rule"s. */         	    /*掩码下包含的所有dpcls 规则*/

	uint32_t hit_cnt;            /* Number of match hits in subtable in current  	/*命中该子表的统计计数*/
                                 /* optimization interval. */
	
    struct netdev_flow_key mask; /* Wildcards for fields (const). */				/*miniflow key 掩码*/
    /* 'mask' must be the last field, additional space is allocated here. */
};

/* Initializes 'cls' as a classifier that initially contains no classification
 * rules. */

/*******************************************************************************
 函数名称 :  dpcls_init
 功能描述 :  dpcls 初始化
 输入参数 :  cls---dpcls结构
 
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/

static void
dpcls_init(struct dpcls *cls)
{
	/*子表*/
    cmap_init(&cls->subtables_map);

	/*优先级子表*/
    pvector_init(&cls->subtables);
}

/*******************************************************************************
 函数名称  :  dpcls_destroy_subtable
 功能描述  :  pmd发送端口的报文
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
dpcls_destroy_subtable(struct dpcls *cls, struct dpcls_subtable *subtable)
{
    VLOG_DBG("Destroying subtable %p for in_port %d", subtable, cls->in_port);

	/*删除subtable*/
  	pvector_remove(&cls->subtables, subtable);

	cmap_remove(&cls->subtables_map, &subtable->cmap_node, subtable->mask.hash);
	
    cmap_destroy(&subtable->rules);

	ovsrcu_postpone(free, subtable);
}

/*******************************************************************************
 函数名称  :  dpcls_destroy
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
/* Destroys 'cls'.  Rules within 'cls', if any, are not freed; this is the
 * caller's responsibility.
 * May only be called after all the readers have been terminated. */
static void
dpcls_destroy(struct dpcls *cls)
{
    if (cls) 
	{
        struct dpcls_subtable *subtable;

        CMAP_FOR_EACH (subtable, cmap_node, &cls->subtables_map) 
		{
            ovs_assert(cmap_count(&subtable->rules) == 0);

			/*dpctl 表查询*/
            dpcls_destroy_subtable(cls, subtable);
        }
        cmap_destroy(&cls->subtables_map);
        pvector_destroy(&cls->subtables);
    }
}

/*******************************************************************************
 函数名称  :    emc_cache_slow_sweep
 功能描述  :    emc流表删除
 输入参数  :  	cls---dpcls规则
 				mask---掩码
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static struct dpcls_subtable *
dpcls_create_subtable(struct dpcls *cls, const struct netdev_flow_key *mask)
{
    struct dpcls_subtable *subtable;

    /* Need to add one. */
    subtable = xmalloc(sizeof *subtable - sizeof subtable->mask.mf + mask->len);

	/*掩码规则初始化*/
	cmap_init(&subtable->rules);

	/*掩码表命中次数初始化0*/
	subtable->hit_cnt = 0;

	/*掩码填入*/
	netdev_flow_key_clone(&subtable->mask, mask);

	/*掩码填入subtables_map*/
	cmap_insert(&cls->subtables_map, &subtable->cmap_node, mask->hash);

	/*插入*/
    /* Add the new subtable at the end of the pvector (with no hits yet) */
	pvector_insert(&cls->subtables, subtable, 0);

	VLOG_DBG("Creating %"PRIuSIZE". subtable %p for in_port %d",
             cmap_count(&cls->subtables_map), subtable, cls->in_port);

	pvector_publish(&cls->subtables);

    return subtable;
}

/*******************************************************************************
 函数名称  :    dpcls_find_subtable
 功能描述  :    查找掩码表
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
static inline struct dpcls_subtable *
dpcls_find_subtable(struct dpcls *cls, const struct netdev_flow_key *mask)
{
    struct dpcls_subtable *subtable;

    CMAP_FOR_EACH_WITH_HASH (subtable, cmap_node, mask->hash, &cls->subtables_map) 
	{
		/*命中掩码表*/
        if (netdev_flow_key_equal(&subtable->mask, mask)) {
            return subtable;
        }
    }

	/*创建掩码表*/
    return dpcls_create_subtable(cls, mask);
}


/*******************************************************************************
 函数名称  :  dpcls_sort_subtable_vector
 功能描述  :  dpcls subtable 向量排序
 输入参数  :  
 			  
 输出参数  :  
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Periodically sort the dpcls subtable vectors according to hit counts */
static void
dpcls_sort_subtable_vector(struct dpcls *cls)
{
    struct pvector *pvec = &cls->subtables;
    struct dpcls_subtable *subtable;

    PVECTOR_FOR_EACH (subtable, pvec) 
	{
		/*优先级*/
        pvector_change_priority(pvec, subtable, subtable->hit_cnt);
        subtable->hit_cnt = 0;
    }
	
    pvector_publish(pvec);
}

/*******************************************************************************
 函数名称  :  dp_netdev_pmd_try_optimize
 功能描述  :  pmd发送端口的报文
 输入参数  :  
 			  
 输出参数  :  
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline void
dp_netdev_pmd_try_optimize(struct dp_netdev_pmd_thread *pmd, struct polled_queue *poll_list, int poll_cnt)
{
    struct dpcls *cls;

    if (pmd->ctx.now > pmd->rxq_next_cycle_store) {
        uint64_t curr_tsc;
        /* Get the cycles that were used to process each queue and store. */
        for (unsigned i = 0; i < poll_cnt; i++) {
            uint64_t rxq_cyc_curr = dp_netdev_rxq_get_cycles(poll_list[i].rxq,
                                                        RXQ_CYCLES_PROC_CURR);
            dp_netdev_rxq_set_intrvl_cycles(poll_list[i].rxq, rxq_cyc_curr);
            dp_netdev_rxq_set_cycles(poll_list[i].rxq, RXQ_CYCLES_PROC_CURR,
                                     0);
        }
        curr_tsc = cycles_counter_update(&pmd->perf_stats);
        if (pmd->intrvl_tsc_prev) {
            /* There is a prev timestamp, store a new intrvl cycle count. */
            atomic_store_relaxed(&pmd->intrvl_cycles,
                                 curr_tsc - pmd->intrvl_tsc_prev);
        }
        pmd->intrvl_tsc_prev = curr_tsc;
        /* Start new measuring interval */
        pmd->rxq_next_cycle_store = pmd->ctx.now + PMD_RXQ_INTERVAL_LEN;
    }

    if (pmd->ctx.now > pmd->next_optimization) {
        /* Try to obtain the flow lock to block out revalidator threads.
         * If not possible, just try next time. */
        if (!ovs_mutex_trylock(&pmd->flow_mutex)) {
            /* Optimize each classifier */
            CMAP_FOR_EACH (cls, node, &pmd->classifiers) {
                dpcls_sort_subtable_vector(cls);
            }
            ovs_mutex_unlock(&pmd->flow_mutex);
            /* Start new measuring interval */
            pmd->next_optimization = pmd->ctx.now
                                     + DPCLS_OPTIMIZATION_INTERVAL;
        }
    }
}

/*******************************************************************************
 函数名称  :    dpcls_insert
 功能描述  :    根据掩码找到相应的子表，然后插入当前的流表
 输入参数  :  	cls---pmd port对应的dpcls结构
 				rule---flow生成的dpcls rule
 				mask---miniflow key mask
 输出参数  :	
 返 回 值  : 	无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
/* Insert 'rule' into 'cls'. */
static void
dpcls_insert(struct dpcls *cls, struct dpcls_rule *rule, const struct netdev_flow_key *mask)
{
	/*根据掩码获取掩码表  子表*/
    struct dpcls_subtable *subtable = dpcls_find_subtable(cls, mask);

    /* Refer to subtable's mask, also for later removal. */
    rule->mask = &subtable->mask;

	/*dpcls规则插入 miniflow的hash 定位cmap查询emc*/
    cmap_insert(&subtable->rules, &rule->cmap_node, rule->flow.hash);
}

/*******************************************************************************
 函数名称  :    dpcls_remove
 功能描述  :    dpcls流表删除
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
/* Removes 'rule' from 'cls', also destructing the 'rule'. */
static void
dpcls_remove(struct dpcls *cls, struct dpcls_rule *rule)
{
    struct dpcls_subtable *subtable;

    ovs_assert(rule->mask);

    /* Get subtable from reference in rule->mask. */
    INIT_CONTAINER(subtable, rule->mask, mask);
    if (cmap_remove(&subtable->rules, &rule->cmap_node, rule->flow.hash) == 0) {
        
        /* Delete empty subtable. */
		/*删除空的掩码表*/
		dpcls_destroy_subtable(cls, subtable);

		/**/
		pvector_publish(&cls->subtables);
    }
}

/* Returns true if 'target' satisfies 'key' in 'mask', that is, if each 1-bit
 * in 'mask' the values in 'key' and 'target' are the same. */
/*******************************************************************************
 函数名称  :    dpcls_rule_matches_key
 功能描述  :    dpcls 规则查询
 输入参数  :    rule---smc流表对应dpcls 规则
 				target---要匹配的报文的 miniflow key
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
dpcls_rule_matches_key(const struct dpcls_rule *rule, const struct netdev_flow_key *target)
{
	/*miniflow提取的值*/
    const uint64_t *keyp = miniflow_get_values(&rule->flow.mf);

	/*掩码值*/
	const uint64_t *maskp = miniflow_get_values(&rule->mask->mf);
    uint64_t value;

	/**/
    NETDEV_FLOW_KEY_FOR_EACH_IN_FLOWMAP(value, target, rule->flow.mf.map) 
	{
		/*掩码后miniflow 不等于?*/
        if (OVS_UNLIKELY((value & *maskp++) != *keyp++)) 
		{
            return false;
        }
    }
    return true;
}

/* For each miniflow in 'keys' performs a classifier lookup writing the result
 * into the corresponding slot in 'rules'.  If a particular entry in 'keys' is
 * NULL it is skipped.
 *
 * This function is optimized for use in the userspace datapath and therefore
 * does not implement a lot of features available in the standard
 * classifier_lookup() function.  Specifically, it does not implement
 * priorities, instead returning any rule which matches the flow.
 *
 * Returns true if all miniflows found a corresponding rule. */
 
/*******************************************************************************
 函数名称  :  dpcls_lookup
 功能描述  :  dpcls rule查询
 			  1.通过classifier查找掩码表，如果所有的报文都找到了匹配的子流表，将流表插入缓存中，并且将报文加入flow->batches
 			  如果不匹配，则上报到controller,统计匹配、不匹配和丢失

 			  dpcls-多个->subtables-多个->rules，
 			  cmap_find_batch在查找hash值的同时将对每个miniflow对应的rule进行赋值

 			  根据不同的掩码进行子表的区分，
 			  然后拿着报文分别去所有的子表用key和mask计算出hash，查看子表中有没有相应的node，
 			  如果有的话查看是否有hash冲突链，最终查看是否有匹配key值的表项

 输入参数  :  cls---port查找到的dpcls结构
 			  keys---报文miniflow key指针数组， emc miss的报文miniflow key
 			  rules---dpcls rule 指针数组，用于记录命中的dpcls rule 规则
 			  cnt---每队列批处理报文数
 			  num_lookups_p---dpcls规则查询次数
 输出参数  :	
 返 回 值  :  无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static bool
dpcls_lookup(struct dpcls *cls, const struct netdev_flow_key *keys[], struct dpcls_rule **rules, const size_t cnt, int *num_lookups_p)
{
    /* The received 'cnt' miniflows are the search-keys that will be processed
     * to find a matching entry into the available subtables.
     * The number of bits in map_type is equal to NETDEV_MAX_BURST. */
    typedef uint32_t map_type;
	
#define MAP_BITS (sizeof(map_type) * CHAR_BIT)
	
	/*bit大于32*/
    BUILD_ASSERT_DECL(MAP_BITS >= NETDEV_MAX_BURST);

	/*dpcls 掩码子表*/
    struct dpcls_subtable *subtable;

	/*keys_map所有位都置1*/
    map_type keys_map = TYPE_MAXIMUM(map_type); /* Set all bits. */
    map_type found_map;
	
    uint32_t hashes[MAP_BITS];

	/**/
	const struct cmap_node *nodes[MAP_BITS];

	/*keys_map中置1位数为包的总数，并且第i位对应第i个包，清除多余的位，只记录跟报文一样多的位*/
    if (cnt != MAP_BITS) 
	{
        keys_map >>= MAP_BITS - cnt; /* Clear extra bits. */
    }
	
	/*清空dpcls rule 指针数组，最多命中规则数与队列批处理报文数相等*/
    memset(rules, 0, cnt * sizeof *rules);

    int lookups_match = 0, subtable_pos = 1;

    /* The Datapath classifier - aka dpcls - is composed of subtables.
     * Subtables are dynamically created as needed when new rules are inserted.
     * Each subtable collects rules with matches on a specific subset of packet
     * fields as defined by the subtable's mask.  We proceed to process every
     * search-key against each subtable, but when a match is found for a
     * search-key, the search for that key can stop because the rules are
     * non-overlapping. */

	/*dpcls是由众多的subtables组成，当新的规则插入时，子表根据情况动态创建*/
    /*每个子表都是根据掩码来区分的，我们通过key和子表的掩码进行计算*/
    /*找到匹配的表项，因为不会重复，所以只要找到即可停止*/
    /*以下就是循环所有子表进行查找*/

	/*遍历匹配dpcls下的优先级 subtables 掩码子表*/
    PVECTOR_FOR_EACH (subtable, &cls->subtables) 
   	{
        int i;

        /* Compute hashes for the remaining keys.  Each search-key is
         * masked with the subtable's mask to avoid hashing the wildcarded
         * bits. */

		/*这个循环是找到keys_map是1的最低位是多少，一开始的时候肯定全是1，就是从0开始*/
        /*然后根据报文的key和mask计算出hash存储起来，继续下一个1的位，直到计算出所有报文hash值，下面会去匹配表项的
        /*hash值的计算可以通过cpu加速，需要cpu支持，并且编译时配置"-msse4.2"*/
        ULLONG_FOR_EACH_1(i, keys_map) 
       	{
            /*对报文的miniflow keys[i]计算hash值*/
            hashes[i] = netdev_flow_key_hash_in_mask(keys[i], &subtable->mask);
        }
		
        /* Lookup. */
		/*keys_map中bit为1的位将根据hashes在subtable->rules中查找
         *找到了就将found_map中该位置1，然后将与之相应的rule指针存于nodes中*/

		/*从子表中进行hash值的匹配，将匹配到node的报文的bit置1到found_map*/
        found_map = cmap_find_batch(&subtable->rules, keys_map, hashes, nodes);
        /* Check results.  When the i-th bit of found_map is set, it means
         * that a set of nodes with a matching hash value was found for the
         * i-th search-key.  Due to possible hash collisions we need to check
         * which of the found rules, if any, really matches our masked
         * search-key. */

		/*在找到匹配node的报文的冲突hash链中继续详细匹配报文*/
        ULLONG_FOR_EACH_1(i, found_map) 
        {
            struct dpcls_rule *rule;
			
			/*dpcls rule 冲突链中继续检测key值是否匹配*/
            CMAP_NODE_FOR_EACH (rule, cmap_node, nodes[i]) 
            {
				/*dpcls rule规则是否命中、miniflow 和 mask的对比*/
                if (OVS_LIKELY(dpcls_rule_matches_key(rule, keys[i]))) 
				{
					/*记录命中的dpcls规则*/
                    rules[i] = rule;
                    /* Even at 20 Mpps the 32-bit hit_cnt cannot wrap
                     * within one second optimization interval. */

					/*掩码表hit的次数*/
                    subtable->hit_cnt++;

					/*查询匹配次数*/
                    lookups_match += subtable_pos;

					goto next;
                }
            }
            /* None of the found rules was a match.  Reset the i-th bit to
             * keep searching this key in the next subtable. */

			/*不匹配则将该位设置为0*/
            ULLONG_SET0(found_map, i);  /* Did not match. */
        next:
            ;                     /* Keep Sparse happy. */
        }

		/*清除已经匹配流表的位*/
        keys_map &= ~found_map;             /* Clear the found rules. */
        if (!keys_map) 
		{
			/*dpcls规则查询次数*/
            if (num_lookups_p) 
			{
                *num_lookups_p = lookups_match;
            }
			
            return true;              /* All found. */
        }
		
        subtable_pos++;
    }

	if (num_lookups_p) 
	{
        *num_lookups_p = lookups_match;
    }

	return false;                     /* Some misses. */
}
