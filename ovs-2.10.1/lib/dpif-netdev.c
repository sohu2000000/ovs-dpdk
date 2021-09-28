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

/*����dp_netdev����*/
/* Contains all 'struct dp_netdev's. */
static struct shash dp_netdevs OVS_GUARDED_BY(dp_netdev_mutex)
    = SHASH_INITIALIZER(&dp_netdevs);

static struct vlog_rate_limit upcall_rl = VLOG_RATE_LIMIT_INIT(600, 600);

#define DP_NETDEV_CS_SUPPORTED_MASK (CS_NEW | CS_ESTABLISHED | CS_RELATED \
                                     | CS_INVALID | CS_REPLY_DIR | CS_TRACKED \
                                     | CS_SRC_NAT | CS_DST_NAT)
#define DP_NETDEV_CS_UNSUPPORTED_MASK (~(uint32_t)DP_NETDEV_CS_SUPPORTED_MASK)

/*֧�ֵ�����*/
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

/*�ӱ�����ȡ��miniflow key*/
struct netdev_flow_key 
{	
    uint32_t hash;       /* Hash function differs for different users. */     	/* ���ݱ���5Ԫ��(ԴIP��Ŀ��IP��Э��š�Դ�˿ڡ�Ŀ�Ķ˿�) �������Hashֵ�����ݹ�ϣ����emc_entry*/
	uint32_t len;        /* Length of the following miniflow (incl. map). */  	/* len = sizeof(mf) + buf��ʵ�ʴ洢���ֽ��� */

	struct miniflow mf;  														/* ���Ķ�Ӧ��miniflow��Ϣλͼ */	
   																				/* ���ľ���ƥ���ֶε�����ֵ�洢��buf*/
	uint64_t buf[FLOW_MAX_PACKET_U64S];											/*����ѹ����Ϣ�洢����flow����ֵ���ֶδ洢�����buf*/
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

/*emc���*/
struct emc_entry {
    struct dp_netdev_flow *flow; 											  /* emc�����������ƥ���򼰶�Ӧ��Actions */
    struct netdev_flow_key key;   /* key.hash used for emc hash value. */   /*�ӱ�����ȡ��flow key��ƥ��EMC����Ĺؼ��� */
};

/*emc���ÿ��DPDK PMD�̶߳���һ��EMC������8192��flow*/
struct emc_cache 
{
	/* EMC����,����ΪEM_FLOW_HASH_ENTRIES=1 << 13,��: 8192������ */ /*emc����=flow+key*/
    struct emc_entry entries[EM_FLOW_HASH_ENTRIES];					 /*8192��entry*/
    int sweep_idx;                /* For emc_cache_slow_sweep(). */  /*����ɾ��*/
};

/*smcͰ Ͱ�Ϊ4*/
struct smc_bucket {
    uint16_t sig[SMC_ENTRY_PER_BUCKET];		  /*4*/
    uint16_t flow_idx[SMC_ENTRY_PER_BUCKET];  /*4*/
};

/* Signature match cache, differentiate from EMC cache */

/*smc����*/
struct smc_cache {
    struct smc_bucket buckets[SMC_BUCKET_CNT];
};


/*emc smc����*/
struct dfc_cache {
    struct emc_cache emc_cache;
    struct smc_cache smc_cache;
};


/*EMC=cache struct emc_cache *cache*/
/*CURRENT_ENTRY=current_entry struct emc_entry *current_entry*/
/*HASH=hash  uint32_t  struct netdev_flow_key->hash */

/*ѭ������ i<2  forѭ����2�Σ�32λhash ��Ϊ��13λ���29λ���β�ѯ

��һ�� (CURRENT_ENTRY) = &(EMC)->entries[srch_hash__ & EM_FLOW_HASH_MASK]   ----- hash & (1<<13 -1)  ��13λ
�ڶ��� (CURRENT_ENTRY) = &(EMC)->entries[srch_hash__ >>= EM_FLOW_HASH_SHIFT] &  ----- hash>>13 & (1>> 13) ��29λ�еĵ�13λ 
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

/* dpclsƥ���.ÿ�����Ľ��ն˿ڶ�Ӧһ�� */
struct dpcls 
{
	/* cmap����ڵ� */
    struct cmap_node node;      /* Within dp_netdev_pmd_thread.classifiers */
	
    odp_port_t in_port;			/* ���Ľ��ն˿� */
	
    struct cmap subtables_map;  /*����ͷ����subtables �ӱ�*/

    struct pvector subtables;   /*���ȼ���ÿ�����ȼ�������Ӧ������, ���������ӱ���Ϣ, port�������������룬�����������ȼ�������*/
};

/* A rule to be inserted to the classifier. */
/*dpcls������Ϊcmap�ڵ�*/
struct dpcls_rule 
{
    struct cmap_node cmap_node;   /* Within struct dpcls_subtable 'rules'. */	/*����*/
    struct netdev_flow_key *mask; /* Subtable's mask. */						/*subtable ��ȡ������miniflow key*/
    struct netdev_flow_key flow;  /* Matching key. */							/*�ӱ�����ȡ��flow key*/
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

/*������meter����*/
struct dp_meter_band {
    struct ofputil_meter_band up; /* type, prec_level, pad, rate, burst_size */
    uint32_t bucket; /* In 1/1000 packets (for PKTPS), or in bits (for KBPS) */
    uint64_t packet_count;	/*���б�����*/
    uint64_t byte_count;	/*�����ֽ���*/
};

/*������ meter*/
struct dp_meter {
    uint16_t flags;
    uint16_t n_bands;
    uint32_t max_delta_t;
    uint64_t used;
    uint64_t packet_count;
    uint64_t byte_count;
    struct dp_meter_band bands[];	/*meter ��������ͳ��*/
    
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

/*�����������豸�ṹ*/
struct dp_netdev {
    const struct dpif_class *const class;	/*������ ��ṹ ����������*/
    const char *const name;					/*������name*/
    struct dpif *dpif; 					    /*ovs ������ӿ�*/
    struct ovs_refcount ref_cnt;			/*���ô���*/
    atomic_flag destroyed;					/*�豸�ݻٴ���*/

    /* Ports.
     *
     * Any lookup into 'ports' or any access to the dp_netdev_ports found
     * through 'ports' requires taking 'port_mutex'. */
    struct ovs_mutex port_mutex;
    struct hmap ports;															/*�˿ڹ�ϣ��*/
    struct seq *port_seq;       /* Incremented whenever a port changes. */		/*�˿����к�*/

    /* The time that a packet can wait in output batch for sending. */
    atomic_uint32_t tx_flush_interval;											/*�����ڷ����������ʱ��*/

    /* Meters. */
    struct ovs_mutex meter_locks[N_METER_LOCKS]; 
    struct dp_meter *meters[MAX_METERS]; /* Meter bands. */					/*����[64]*/

    /* Probability of EMC insertions is a factor of 'emc_insert_min'.*/
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE) atomic_uint32_t emc_insert_min;			/*emc ������Сֵ*/
    /* Enable collection of PMD performance metrics. */
    atomic_bool pmd_perf_metrics;												/*pmd����ͳ�ƿ���*/
    /* Enable the SMC cache from ovsdb config */
    atomic_bool smc_enable_db;													/*�����ݿ�����ʹ��smc*/

    /* Protects access to ofproto-dpif-upcall interface during revalidator
     * thread synchronization. */
    struct fat_rwlock upcall_rwlock;											/*upcall��д��*/
    upcall_callback *upcall_cb;  /* Callback function for executing upcalls. */ /*upcall����ص�����*/
    void *upcall_aux;

    /* Callback function for notifying the purging of dp flows (during
     * reseting pmd deletion). */
    dp_purge_callback *dp_purge_cb;
    void *dp_purge_aux;

    /* Stores all 'struct dp_netdev_pmd_thread's. */
    struct cmap poll_threads;													/*pmd�߳�s*/
    /* id pool for per thread static_tx_qid. */
    struct id_pool *tx_qid_pool;												/*pmd�̶߳���id��*/
    struct ovs_mutex tx_qid_pool_mutex;										/*���Ͷ�����*/

    /* Protects the access of the 'struct dp_netdev_pmd_thread'
     * instance for non-pmd thread. */
    struct ovs_mutex non_pmd_mutex;

    /* Each pmd thread will store its pointer to
     * 'struct dp_netdev_pmd_thread' in 'per_pmd_key'. */
    ovsthread_key_t per_pmd_key;												/*pmd�߳̽ṹ��ַ*/

    struct seq *reconfigure_seq;												/*�������õ����к�*/
    uint64_t last_reconfigure_seq;												/*��¼���µ��������*/

    /* Cpu mask for pin of pmd threads. */
    char *pmd_cmask;															/*pmdռ��CPU ����*/

    uint64_t last_tnl_conf_seq;

    //struct conntrack conntrack;													/*struct conntrack ���Ӹ���*/

    struct conntrack zwl_conntrack;													/*struct conntrack ���Ӹ���*/
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

/*offload ��*/
struct dp_flow_offload_item 
{
    struct dp_netdev_pmd_thread *pmd;		/*pmd�߳�*/
    struct dp_netdev_flow *flow;			/*flow��������*/
    int op;									/*�����������*/
    //struct match match;
	struct match m;							/*flow��match���·�flowʱ����*/
    struct nlattr *actions;					/*action�����·�flowʱ����*/
    size_t actions_len;						/*action ����*/

    struct ovs_list node;					/*offload������ͷ*/
};

/*dp offload ��flow*/
struct dp_flow_offload {
    struct ovs_mutex mutex;
    struct ovs_list list;
    pthread_cond_t cond;
};

/*����offload����*/
static struct dp_flow_offload dp_flow_offload = {
    .mutex = OVS_MUTEX_INITIALIZER,
    .list  = OVS_LIST_INITIALIZER(&dp_flow_offload.list),
};

/*offload �߳�*/
static struct ovsthread_once offload_thread_once
    = OVSTHREAD_ONCE_INITIALIZER;

#define XPS_TIMEOUT 500000LL    /* In microseconds. */

/* Contained by struct dp_netdev_port's 'rxqs' member.  */

/*�˿ڽ��ն���*/
struct dp_netdev_rxq 
{
    struct dp_netdev_port *port;	   /*�������ڵĶ˿�*/
    struct netdev_rxq *rx;			   /*���ն���*/
    unsigned core_id;                  /* Core to which this queue should be        //���а󶨵��߼���id
                                          pinned. OVS_CORE_UNSPEC if the
                                          queue doesn't need to be pinned to a
                                          particular core. */
    unsigned intrvl_idx;               /* Write index for 'cycles_intrvl'. */		/*ѭ�����ʱ��,poll ���е�ʱ����*/
    struct dp_netdev_pmd_thread *pmd;  /* pmd thread that polls this queue. */		/*pmd�߳�*/
    bool is_vhost;                     /* Is rxq of a vhost port. */				/*���ն����������������˿�*/

    /* Counters of cycles spent successfully polling and processing pkts. */		/*�ɹ�poll���д����ĵ�ѭ���ļ���*/
    atomic_ullong cycles[RXQ_N_CYCLES];											    /*����poll�Ĵ���*/
    /* We store PMD_RXQ_INTERVAL_MAX intervals of data for an rxq and then
       sum them to yield the cycles used for an rxq. */
    atomic_ullong cycles_intrvl[PMD_RXQ_INTERVAL_MAX];								/*poll����ʱ�����ݶ����� ����Ϊ6*/
};

/* A port in a netdev-based datapath. */
/*netdev�˿���Ϣ*/
struct dp_netdev_port {
    odp_port_t port_no;			/*�˿�ID*/
    bool dynamic_txqs;          /* If true XPS will be used. */                 /*�������õ�txqС��pmd+��pmd����������̬����txq������txq��ʹ���������*/
    bool need_reconfigure;      /* True if we should reconfigure netdev. */
    struct netdev *netdev;														/*�˿������豸*/
    struct hmap_node node;      /* Node in dp_netdev's 'ports'. */
    struct netdev_saved_flags *sf;
    struct dp_netdev_rxq *rxqs;	/*���ն���*/
    unsigned n_rxq;             /* Number of elements in 'rxqs' */				/*�˿�rx���и���*/
    unsigned *txq_used;         /* Number of threads that use each tx queue. */	/*��¼�������ô���*/
    struct ovs_mutex txq_used_mutex;
    char *type;                 /* Port type as requested by user. */			/*�û�����Ķ˿�����*/
    char *rxq_affinity_list;    /* Requested affinity of rx queues. */          /*���ն��е�cpu�׺���*/
};

/* Contained by struct dp_netdev_flow's 'stats' member.  */

/*����ͳ��*/
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

/* ��ʾһ��������.���������ƥ���򼰶�Ӧ��Actions */
struct dp_netdev_flow 
{
    const struct flow flow;      /* Unmasked flow that created this entry. */   /*struct flow һ��flowȫ����Ϣ*/
    /* Hash table index by unmasked flow. */
    const struct cmap_node node; /* In owning dp_netdev_pmd_thread's */		
                                 /* 'flow_table'. */
    const struct cmap_node mark_node; /* In owning flow_mark's mark_to_flow */	/**/
    const ovs_u128 ufid;         /* Unique flow identifier. */					/*����ID*/
    const ovs_u128 mega_ufid;    /* Unique mega flow identifier. */				/*mega flow ID*/
    const unsigned pmd_id;       /* The 'core_id' of pmd thread owning this */	/*�߼���ID*/
                                 /* flow. */

    /* Number of references.
     * The classifier owns one reference.
     * Any thread trying to keep a rule from being freed should hold its own
     * reference. */
    struct ovs_refcount ref_cnt;												/*�����ü���*/

    bool dead;					 												/*false,��������������Ȼ������*/
    uint32_t mark;               /* Unique flow mark assigned to a flow */

    /* Statistics. */
    struct dp_netdev_flow_stats stats;										/*����ͳ��*/

    /* Actions. */
    OVSRCU_TYPE(struct dp_netdev_actions *) actions;  						/*emc����action*/

    /* While processing a group of input packets, the datapath uses the next
     * member to store a pointer to the output batch for the flow.  It is
     * reset after the batch has been sent out (See dp_netdev_queue_batches(),
     * packet_batch_per_flow_init() and packet_batch_per_flow_execute()). */
    struct packet_batch_per_flow *batch; 										/* ���ڻ���ƥ��ĳ��������Ķ������.��໺��32������ */

    /* Packet classification. */
    struct dpcls_rule cr;        /* In owning dp_netdev's 'cls'. */			/*dpcls����*/
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

/*emc ���� action*/
struct dp_netdev_actions {
    /* These members are immutable: they do not change during the struct's
     * lifetime.  */
    unsigned int size;          /* Size of 'actions', in bytes. */
    struct nlattr actions[];    /* Sequence of OVS_ACTION_ATTR_* attributes. */		/*action����*/
};

struct dp_netdev_actions *dp_netdev_actions_create(const struct nlattr *,
                                                   size_t);
struct dp_netdev_actions *dp_netdev_flow_get_actions(
    const struct dp_netdev_flow *);
static void dp_netdev_actions_free(struct dp_netdev_actions *);

/*poll����*/
struct polled_queue 
{
    struct dp_netdev_rxq *rxq;		/*���ն���*/
    odp_port_t port_no;				/*�������ڵĶ˿ں�*/
};

/* Contained by struct dp_netdev_pmd_thread's 'poll_list' member. */
/*poll�Ľ��ն���*/
struct rxq_poll {
    struct dp_netdev_rxq *rxq;		/*poll�ڵ��Ӧ���ն���*/
    struct hmap_node node;
};

/* Contained by struct dp_netdev_pmd_thread's 'send_port_cache',
 * 'tnl_port_cache' or 'tx_ports'. */

/*���Ͷ˿�*/
struct tx_port {
    struct dp_netdev_port *port;			/*�豸��Ӧ�����˿���Ϣ*/
    int qid;								/*�˿ڶ�Ӧ��������id*/
    long long last_used;					/*�ϴ�ʹ��ʱ��*/
    struct hmap_node node;					/*��ϣ�ڵ�*/
    long long flush_time;					/*�´η���ʱ��*/
    struct dp_packet_batch output_pkts;		/*���ͷ���������ṹ*/
    struct dp_netdev_rxq *output_pkts_rxqs[NETDEV_MAX_BURST];		/*���Ͷ��У�ÿ��burst 32������*/
};

/* A set of properties for the current processing loop that is not directly
 * associated with the pmd thread itself, but with the packets being
 * processed or the short-term system configuration (for example, time).
 * Contained by struct dp_netdev_pmd_thread's 'ctx' member. */

/*pmd�߳�������*/
struct dp_netdev_pmd_thread_ctx 
{
    /* Latest measured time. See 'pmd_thread_ctx_time_update()'. */
    long long now;												/*pmd�߳����еĵ�ǰʱ��*/
    /* RX queue from which last packet was received. */
    struct dp_netdev_rxq *last_rxq;								/*���һ�����յ����ĵĶ���*/
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

/*pmd�߳̽ṹ*/
struct dp_netdev_pmd_thread {
    struct dp_netdev *dp;														/*������netdev�����豸�ṹ*/
    struct ovs_refcount ref_cnt;    /* Every reference must be refcount'ed. */  /*pmd�߳̽ṹ���ü���*/
    struct cmap_node node;          /* In 'dp->poll_threads'. */				/*poll�߳�����*/

    pthread_cond_t cond;            /* For synchronizing pmd thread reload. */
    struct ovs_mutex cond_mutex;    /* Mutex for condition variable. */

    /* Per thread exact-match cache.  Note, the instance for cpu core
     * NON_PMD_CORE_ID can be accessed by multiple threads, and thusly
     * need to be protected by 'non_pmd_mutex'.  Every other instance
     * will only be accessed by its own pmd thread. */
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE) struct dfc_cache flow_cache; 				/*flow_cache�ĳ�Աָ����pmd��Ӧ��emc����*/

    /* Flow-Table and classifiers
     *
     * Writers of 'flow_table' must take the 'flow_mutex'.  Corresponding
     * changes to 'classifiers' must be made while still holding the
     * 'flow_mutex'.
     */
    struct ovs_mutex flow_mutex;												/*������*/
    struct cmap flow_table OVS_GUARDED; /* Flow table. */						/*flow�ڵ����*/

    /* One classifier per in_port polled by the pmd */
    struct cmap classifiers;													/*cmap�ṹ�����ķ�������ÿ�˿�һ����ÿ�˿�һ��dpcls*/
    /* Periodically sort subtable vectors according to hit frequencies */   
    long long int next_optimization;											/**/
    /* End of the next time interval for which processing cycles
       are stored for each polled rxq. */
    long long int rxq_next_cycle_store;

    /* Last interval timestamp. */
    uint64_t intrvl_tsc_prev;													/*�ϴ�poll ʱ���*/
    /* Last interval cycles. */
    atomic_ullong intrvl_cycles;												/*��һ�ζ���poll ʱ����*/

    /* Current context of the PMD thread. */
    struct dp_netdev_pmd_thread_ctx ctx;									    /*pmd�߳����е�ǰ������*/

    struct latch exit_latch;        /* For terminating the pmd thread. */		/*���������߳�*/
    struct seq *reload_seq;													    /*�������*/
    uint64_t last_reload_seq;												    /*����������*/
    atomic_bool reload;             /* Do we need to reload ports? */			/*���ض˿�*/
    pthread_t thread;															/*pmd�����߳�*/
    unsigned core_id;               /* CPU core id of this pmd thread. */		/*pmd�߳��õ��߼���id*/
    int numa_id;                    /* numa node id of this pmd thread. */		/*numa id*/
    bool isolated;																/*pmd�����˶�������Ϊ�����*/

    /* Queue id used by this pmd thread to send packets on all netdevs if
     * XPS disabled for this netdev. All static_tx_qid's are unique and less
     * than 'cmap_count(dp->poll_threads)'. */
    uint32_t static_tx_qid;														/*��̬���Ͷ���id*/

    /* Number of filled output batches. */
    int n_output_batches;														/*�������������ļ���*/

    struct ovs_mutex port_mutex;    /* Mutex for 'poll_list' and 'tx_ports'. */
    /* List of rx queues to poll. */
    struct hmap poll_list OVS_GUARDED;											/*����poll�Ľ��ն���*/
    /* Map of 'tx_port's used for transmission.  Written by the main thread,
     * read by the pmd thread. */
    struct hmap tx_ports OVS_GUARDED;											/*���Ͷ˿ڹ�ϣ��*/

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
    struct hmap send_port_cache;												/*���˿�cache*/

    /* Keep track of detailed PMD performance statistics. */
    struct pmd_perf_stats perf_stats;											/*pmd�߳�����ͳ��*/

    /* Set to true if the pmd thread needs to be reloaded. */
    bool need_reload;															/*���pmd��Ҫ reload ����true*/
};

/* Interface to netdev-based datapath. */
/*������ṹ */
struct dpif_netdev {
    //struct dpif dpif;			/*ovs ������ӿ�*/
	struct dpif dpif_zwl;		/*ovs ������ӿ�*/
    struct dp_netdev *dp;		/*dp�ṹ*/
    uint64_t last_port_seq;		/*������¹��Ķ˿����*/
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
 ��������  :    emc_cache_slow_sweep
 ��������  :    smc bucket��ʼ��
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
smc_cache_init(struct smc_cache *smc_cache)
{
    int i, j;

	/*smc Ͱ��Ͱ���ʼ����Ͱ=1u << 20 /4 = 1048576*/
    for (i = 0; i < SMC_BUCKET_CNT; i++) 
	{
		/*Ͱ����4*/
        for (j = 0; j < SMC_ENTRY_PER_BUCKET; j++) 
		{
            smc_cache->buckets[i].flow_idx[j] = UINT16_MAX;
        }
    }
}

/*******************************************************************************
 ��������  :    dfc_cache_init
 ��������  :    emc���桢smc�����ʼ��
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
dfc_cache_init(struct dfc_cache *flow_cache)
{
	/*emc�����ʼ��*/
    emc_cache_init(&flow_cache->emc_cache);

	/*smc�����ʼ��*/
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
 ��������  :  smc_cache_uninit
 ��������  :  smc�� clear
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
smc_cache_uninit(struct smc_cache *smc)
{
    int i, j;

	/*smc������������Ͱ1<<20/4*/
    for (i = 0; i < SMC_BUCKET_CNT; i++) {

		/*Ͱ����4*/
        for (j = 0; j < SMC_ENTRY_PER_BUCKET; j++) {
			
			/*���������index ���*/
            smc_clear_entry(&(smc->buckets[i]), j);
        }
    }
}

/*******************************************************************************
 ��������  :  dfc_cache_uninit
 ��������  :  pmd����smc emc �������������
 �������  :  flow_cache---������
 			  
 �������  :  
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static void
dfc_cache_uninit(struct dfc_cache *flow_cache)
{
	/*smc�� clear*/
    smc_cache_uninit(&flow_cache->smc_cache);
	
	/*emc����clear*/
    emc_cache_uninit(&flow_cache->emc_cache);
}

/* Check and clear dead flow references slowly (one entry at each
 * invocation).  */
 

/*******************************************************************************
 ��������  :    emc_cache_slow_sweep
 ��������  :    emc����ɾ��
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
emc_cache_slow_sweep(struct emc_cache *flow_cache)
{
	/*8192��entry�л�ȡ�µ�entry*/
    struct emc_entry *entry = &flow_cache->entries[flow_cache->sweep_idx];

	/*emc������� �� ����*/
    if (!emc_entry_alive(entry)) 
	{
		/*emc����ɾ��*/
        emc_clear_entry(entry);
    }

	/*8192��entry hash��һ�� ��Ϊ�ϻ�entry index*/
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
 ��������  :    pmd_thread_ctx_time_update
 ��������  :    pmd�߳������ĸ���
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
static inline void
pmd_thread_ctx_time_update(struct dp_netdev_pmd_thread *pmd)
{
    pmd->ctx.now = time_usec();
}

/*******************************************************************************
 ��������  :    dpif_is_netdev
 ��������  :    dp�ӿ� open�����Ƿ���dpif_netdev_open
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
/* Returns true if 'dpif' is a netdev or dummy dpif, false otherwise. */
bool
dpif_is_netdev(const struct dpif *dpif)
{
    return dpif->dpif_class->open == dpif_netdev_open;
}

/*******************************************************************************
 ��������  :    dpif_netdev_cast
 ��������  :    ����dp �ӿڽṹ�׵�ַ
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static struct dpif_netdev *
dpif_netdev_cast(const struct dpif *dpif)
{
    ovs_assert(dpif_is_netdev(dpif));

	/*����dp �ӿڽṹ�׵�ַ*/
    return CONTAINER_OF(dpif, struct dpif_netdev, dpif);
}

/*******************************************************************************
 ��������  :    get_dp_netdev
 ��������  :    ��ȡ�������dp�ṹ
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
static struct dp_netdev *
get_dp_netdev(const struct dpif *dpif)
{
	/*����dpif ����dp netdev�ṹ*/
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
 ��������  :    emc_cache_slow_sweep
 ��������  :    emc����ɾ��
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
 ��������  :    dpif_netdev_pmd_info
 ��������  :    emc����ɾ��
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

		/*ָ����pmd*/
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

	/*��������pmd*/
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
 ��������  :    emc_cache_slow_sweep
 ��������  :    emc����ɾ��
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
 ��������  :    dpif_netdev_init
 ��������  :    dpif�����к���ע��
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
dpif_netdev_init(void)
{
    static enum pmd_info_type show_aux = PMD_INFO_SHOW_STATS,
                              clear_aux = PMD_INFO_CLEAR_STATS,
                              poll_aux = PMD_INFO_SHOW_RXQ;

	/*����ͳ��*/
    unixctl_command_register("dpif-netdev/pmd-stats-show", "[-pmd core] [dp]",
                             0, 3, dpif_netdev_pmd_info,
                             (void *)&show_aux);

	/*�������*/
	unixctl_command_register("dpif-netdev/pmd-stats-clear", "[-pmd core] [dp]",
                             0, 3, dpif_netdev_pmd_info,
                             (void *)&clear_aux);

	/*pmd rx������Ϣ*/
    unixctl_command_register("dpif-netdev/pmd-rxq-show", "[-pmd core] [dp]",
                             0, 3, dpif_netdev_pmd_info,
                             (void *)&poll_aux);

	/*pmd ��������*/
	unixctl_command_register("dpif-netdev/pmd-perf-show",
                             "[-nh] [-it iter-history-len]"
                             " [-ms ms-history-len]"
                             " [-pmd core] [dp]",
                             0, 8, pmd_perf_show_cmd,
                             NULL);

	/*�������µ���*/
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
 ��������  :    dpif_netdev_enumerate
 ��������  :    emc����ɾ��
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
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
 ��������  :    dpif_netdev_port_open_type
 ��������  :    ��
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static const char *
dpif_netdev_port_open_type(const struct dpif_class *class, const char *type)
{
    return strcmp(type, "internal") ? type
                  : dpif_netdev_class_is_dummy(class) ? "dummy-internal"
                  : "tap";
}

/*******************************************************************************
 ��������  :    create_dpif_netdev
 ��������  :    ����dpif�ӿ� ����ʼ��
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static struct dpif *
create_dpif_netdev(struct dp_netdev *dp)
{
    uint16_t netflow_id = hash_string(dp->name, 0);
    struct dpif_netdev *dpif;

	/*dp����*/
    ovs_refcount_ref(&dp->ref_cnt);

	/*dp�ӿ�����*/
    dpif = xmalloc(sizeof *dpif);

	/*dp �ӿ������ṹ��ʼ��*/
    dpif_init(&dpif->dpif, dp->class, dp->name, netflow_id >> 8, netflow_id);

	/*dp �ӿ�*/
	dpif->dp = dp;

	/*dp�ӿ����к�*/
    dpif->last_port_seq = seq_read(dp->port_seq);

    return &dpif->dpif;
}

/*******************************************************************************
 ��������  :    choose_port
 ��������  :    ѡ��һ��δʹ�õ�port����0�˿�
 �������  :  	dp---������
 				name---vport ��Ӧ�� dpif port name
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
/* Choose an unused, non-zero port number and return it on success.
 * Return ODPP_NONE on failure. */
static odp_port_t
choose_port(struct dp_netdev *dp, const char *name)
    OVS_REQUIRES(dp->port_mutex)
{
    uint32_t port_no;

	/*�������಻�� ������ӿڲ�����*/
    if (dp->class != &dpif_netdev_class) 
	{
        const char *p;
        int start_no = 0;

        /* If the port name begins with "br", start the number search at
         * 100 to make writing tests easier. */

		/*������ʼ�˿�����100*/
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
				/*��ȡport name�д���port number*/
                port_no = start_no + strtol(p, NULL, 10);

				/*�˿ںŲ��Ϸ� �� dp�Ҳ�����Ӧ�˿�*/
				if (port_no > 0 && port_no != odp_to_u32(ODPP_NONE) && !dp_netdev_lookup_port(dp, u32_to_odp(port_no))) 
                {
                    return u32_to_odp(port_no);
                }
				
                break;
            }
        }
    }

	/*�����˿ں��Ҷ�Ӧport*/
    for (port_no = 1; port_no <= UINT16_MAX; port_no++) 
	{
		/*���ݶ˿ں��ҵ���Ӧport*/
        if (!dp_netdev_lookup_port(dp, u32_to_odp(port_no))) 
		{
            return u32_to_odp(port_no);
        }
    }

    return ODPP_NONE;
}

/*******************************************************************************
 ��������  :    create_dp_netdev
 ��������  :    ����dp netdev��node������dpȫ�ֽṹdp_netdevs
 �������  :  	name---dp name  backer name ovs-netdev������name br0
 				class---dp��Ӧ��class
 				key---skb��ȡ��key
 				dpp---�򿪻򴴽���netdev
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
create_dp_netdev(const char *name, const struct dpif_class *class,
                 struct dp_netdev **dpp)
    OVS_REQUIRES(dp_netdev_mutex)
{
	/*dp��Ӧ��netdev*/
    struct dp_netdev *dp;
    int error;

	/*����dp �ṹ�ڴ�*/
    dp = xzalloc(sizeof *dp);

	/*�ҵ�ȫ��dp_netdev����name��ovs-netdev*/
    shash_add(&dp_netdevs, name, dp);

	/*dp��ֵ�ͳ�ʼ��*/
    *CONST_CAST(const struct dpif_class **, &dp->class) = class;

	/*backer��Ӧ dp_netdev��name Ϊovs-netdev*/
	*CONST_CAST(const char **, &dp->name) = xstrdup(name);

	/*dp���ô���*/
	ovs_refcount_init(&dp->ref_cnt);
	
    atomic_flag_clear(&dp->destroyed);

    ovs_mutex_init(&dp->port_mutex);

	/*dp_netdev��port��ʼ��*/
    hmap_init(&dp->ports);
	
    dp->port_seq = seq_create();
    fat_rwlock_init(&dp->upcall_rwlock);

	/*�������к�*/
    dp->reconfigure_seq = seq_create();
    dp->last_reconfigure_seq = seq_read(dp->reconfigure_seq);

	/*meter����ʼ��*/
    for (int i = 0; i < N_METER_LOCKS; ++i) {
        ovs_mutex_init_adaptive(&dp->meter_locks[i]);
    }

	/*�ص�upcall*/
    /* Disable upcalls by default. */
    dp_netdev_disable_upcall(dp);
    dp->upcall_aux = NULL;
    dp->upcall_cb = NULL;

	/*dp_netdev��Ӧ���Ӹ��ٳ�ʼ��*/
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

	/*��port  ���vport ��dp ��port������������ͬ��internal �˿�*/
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
 ��������  :    dp_netdev_request_reconfigure
 ��������  :    �������׺��ԣ��ı�dp ������ţ�����dp��������
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
 ��������  :    dpif_netdev_open
 ��������  :    ��netdev����
 �������  :  	class
 				name---dp name��backer name ovs-netdev������name br0
 				dpifp
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
dpif_netdev_open(const struct dpif_class *class, const char *name,
                 bool create, struct dpif **dpifp)
{
    struct dp_netdev *dp;
    int error;

    ovs_mutex_lock(&dp_netdev_mutex);

	/*����name �ҵ�dp_netdev node��name��backer name ovs-netdev���Զ���name br0*/
    dp = shash_find_data(&dp_netdevs, name);
    if (!dp) 
	{
		/*û�ҵ�����netdev���͵�dp_netdev node��name��backer name ovs-netdev��br name*/
        error = create ? create_dp_netdev(name, class, &dp) : ENODEV;
    }
	else 
	{
		/*�Ѵ���*/
        error = (dp->class != class ? EINVAL
                 : create ? EEXIST
                 : 0);
    }

	/*����dp netdev*/
	if (!error) 
	{
		/*dp_netdev������Ӧ��dpifp���ӿڽṹ��������ʼ��*/
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
 ��������  :    dp_delete_meter
 ��������  :    meter ɾ��
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
dp_delete_meter(struct dp_netdev *dp, uint32_t meter_id)
    OVS_REQUIRES(dp->meter_locks[meter_id % N_METER_LOCKS])
{
	/*dp�����meter��Դ����*/
    if (dp->meters[meter_id]) 
	{
		/*���meter��Դ�ͷ�*/
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

	/*ѭ��ɾ��meter*/
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
 ��������  :    dp_netdev_reload_pmd__
 ��������  :    reload pmd�߳�
 				1.����pmd����ķ�port�ڵ㻺��ı���
 		  		2.���뷢�˿ڻ���ṹ����pmd���˿ڻ�������
 �������  :  	pmd---pmd�߳�
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
dp_netdev_reload_pmd__(struct dp_netdev_pmd_thread *pmd)
{
	/*pmdʹ�õ��Ƿ�pmd �ˣ�����pmd����ķ�port�ڵ㻺��ı��ġ����뷢�˿ڻ���ṹ����pmd���˿ڻ�������*/
    if (pmd->core_id == NON_PMD_CORE_ID) 
	{
        ovs_mutex_lock(&pmd->dp->non_pmd_mutex);
        ovs_mutex_lock(&pmd->port_mutex);

		/*pmd���¼��ػ���ķ���port*/
		/*1.����pmd����ķ�port�ڵ㻺��ı���
 		  2.���뷢�˿ڻ���ṹ����pmd���˿ڻ�������*/
        pmd_load_cached_ports(pmd);

		ovs_mutex_unlock(&pmd->port_mutex);
        ovs_mutex_unlock(&pmd->dp->non_pmd_mutex);
		
        return;
    }

    ovs_mutex_lock(&pmd->cond_mutex);

	/*pmd�������кŸ��£����к�+1*/
    seq_change(pmd->reload_seq);

	/*����pmd reload���Ϊtrue��������reload*/
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
 ��������  :    port_create
 ��������  :    �˿ڴ���
 �������  :  	devname---�˿�name��ovs-netdev������name br0
 				type---netdev�����ͣ�"system", "tap", "gre"
 				port_no---�˿ڶ�Ӧ��dp ��˿ں�
 				portp---ָ��ָ������Ķ˿�
 				
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
port_create(const char *devname, const char *type, odp_port_t port_no, struct dp_netdev_port **portp)
{
	/*�����豸�洢flag*/
    struct netdev_saved_flags *sf;
    struct dp_netdev_port *port;
    enum netdev_flags flags;
    struct netdev *netdev;
    int error;

    *portp = NULL;

    /* Open and validate network device. */
	/*����netdev�ṹ Ĭ��1 txq  1 txq*/
    error = netdev_open(devname, type, &netdev);
    if (error) 
	{
        return error;
    }
    /* XXX reject non-Ethernet devices */

	/*��ȡflag*/
    netdev_get_flags(netdev, &flags);
    if (flags & NETDEV_LOOPBACK) 
	{
        VLOG_ERR("%s: cannot add a loopback device", devname);
        error = EINVAL;
        goto out;
    }

	/*�����˿ڻ���ģʽ*/
    error = netdev_turn_flags_on(netdev, NETDEV_PROMISC, &sf);
    if (error) 
	{
        VLOG_ERR("%s: cannot set promisc flag", devname);
        goto out;
    }

	/*����˿��ڴ�*/
    port = xzalloc(sizeof *port);

	/*������Ϣ*/
    port->port_no = port_no;
    port->netdev = netdev;
    port->type = xstrdup(type);
    port->sf = sf;

	/*��Ҫ�������������豸*/
    port->need_reconfigure = true;

	ovs_mutex_init(&port->txq_used_mutex);

    *portp = port;

    return 0;

out:
    netdev_close(netdev);
    return error;
}

/*******************************************************************************
 ��������  :    do_add_port
 ��������  :    ��Ӷ˿ڣ���������dp������port����
 �������  :  	dp---������ṹdp_netdev
 				devname--backer name ovs-netdev������name br0
 				type---netdev�����ͣ�"system", "tap", "gre"
 				port_no---���˿ڷֵ�dp��˿ں�
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
do_add_port(struct dp_netdev *dp, const char *devname, const char *type, odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex)
{
	/*Ҫ��ӵĶ˿�*/
    struct dp_netdev_port *port;
    int error;

    /* Reject devices already in 'dp'. */
	/*���ݶ˿�name ��������������port�������Ƿ��Ѵ��ڶ˿�*/
    if (!get_port_by_name(dp, devname, &port)) 
	{
        return EEXIST;
    }

	/*������port���´����˿ڽṹ Ĭ��1 rxq 1 txq*/
    error = port_create(devname, type, port_no, &port);
    if (error) 
	{
        return error;
    }

	/*�˿ڽṹ�ڵ����hmap port ����*/
    hmap_insert(&dp->ports, &port->node, hash_port_no(port_no));

	/*���кŸı� ���к�+1*/
    seq_change(dp->port_seq);

	/*dp�˿��б仯������������*/
    reconfigure_datapath(dp);

    return 0;
}

/*******************************************************************************
 ��������  :    dpif_netdev_port_add
 ��������  :    ��������Ӷ˿�
 �������  :  	dpif---������dp�ӿ�
 				netdev---����dp �������豸�ṹ
 				port_nop---�˿ں�
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
dpif_netdev_port_add(struct dpif *dpif, struct netdev *netdev, odp_port_t *port_nop)
{
	/*��ȡ������dp�ṹ*/
    struct dp_netdev *dp = get_dp_netdev(dpif);

	/*����˿�name*/
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];

	/*������ṹ�˿�*/
	const char *dpif_port;

	/*�˿ں�*/
	odp_port_t port_no;

	int error;

    ovs_mutex_lock(&dp->port_mutex);

	/*����˿ڻ�ȡ��Ӧ dpif_port*/
    dpif_port = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);

	/*�˿ں�*/
    if (*port_nop != ODPP_NONE) 
	{
        port_no = *port_nop;

		/*���ݶ˿ںŲ��Ҷ˿�*/
        error = dp_netdev_lookup_port(dp, *port_nop) ? EBUSY : 0;
    } 
	else 
	{
		/*ѡ��һ��δʹ�õ�dp ��˿ں�*/
        port_no = choose_port(dp, dpif_port);

        error = port_no == ODPP_NONE ? EFBIG : 0;
    }

	/*�˿ڲ�����*/
    if (!error) 
	{
        *port_nop = port_no;

		/*��Ӷ˿�*/
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
 ��������  :    dp_netdev_lookup_port
 ��������  :    ���ݶ˿ںŲ��Ҷ˿�
 �������  :  	dp---������
 				port_no---�˿ں�
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static struct dp_netdev_port *
dp_netdev_lookup_port(const struct dp_netdev *dp, odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;

	/*����dp �˿������Ҷ˿�*/
    HMAP_FOR_EACH_WITH_HASH (port, node, hash_port_no(port_no), &dp->ports) 
	{
		/*���ݶ˿ںŲ��Ҷ˿�*/
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
 ��������  :    port_destroy
 ��������  :    �˿�destroy
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
port_destroy(struct dp_netdev_port *port)
{
    if (!port) {
        return;
    }

    /*����close port->netdev����port netdev ��close��*/
    netdev_close(port->netdev);
    netdev_restore_flags(port->sf);

    /*q close��*/
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
 ��������  :    get_port_by_name
 ��������  :    ����name ��ȡ�˿�
 �������  :  	dp---����������
 				devname---�˿�name
 				portp---��ȡ�Ķ˿�
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
get_port_by_name(struct dp_netdev *dp, const char *devname, struct dp_netdev_port **portp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;

	/*����dp�˿���*/
    HMAP_FOR_EACH (port, node, &dp->ports) 
	{
		/*�Աȶ˿�name*/
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
 ��������  :    has_pmd_port
 ��������  :    ���dp���Ƿ��ж˿�ʹ��pmd
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
/* Returns 'true' if there is a port with pmd netdev. */
static bool
has_pmd_port(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;

	/*����dp �ϵĶ˿�*/
    HMAP_FOR_EACH (port, node, &dp->ports) 
	{
		/*�ж϶˿��Ƿ���pmd���*/
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
 ��������  :    dp_netdev_flow_free
 ��������  :    �ͷ�������Դ
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
dp_netdev_flow_free(struct dp_netdev_flow *flow)
{
	/*�ͷ������action��Դ*/
    dp_netdev_actions_free(dp_netdev_flow_get_actions(flow));

	/*�ͷ�flow��Դ*/
	free(flow);
}

/*******************************************************************************
 �������� :  dp_netdev_flow_unref
 �������� :  �ͷ�������Դ
 ������� :  
 ������� :  ��
 ����ֵ�� :  ��
 --------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸����� :  
 �޸�Ŀ�� :  
 �޸����� :  
*******************************************************************************/
static void dp_netdev_flow_unref(struct dp_netdev_flow *flow)
{
	/*flow û������*/
    if (ovs_refcount_unref_relaxed(&flow->ref_cnt) == 1) 
	{
		/*�ͷ�������Դ*/
        ovsrcu_postpone(dp_netdev_flow_free, flow);
    }
}

static uint32_t
dp_netdev_flow_hash(const ovs_u128 *ufid)
{
    return ufid->u32[0];
}

/*******************************************************************************
 ��������  :    dp_netdev_pmd_lookup_dpcls
 ��������  :    ����in_port����hashֵ��Ȼ���ɴ�hashֵ��pmd->classifiers�в���dpcls��ÿ��in_portӵ��һ��dpcls
 �������  :  	pmd---pmd�߳̽ṹ
 				in_port---����˿ں�
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static inline struct dpcls *
dp_netdev_pmd_lookup_dpcls(struct dp_netdev_pmd_thread *pmd, odp_port_t in_port)
{
    struct dpcls *cls;

	/*����port���ϣ*/
    uint32_t hash = hash_port_no(in_port);

	/*ƥ��˿ڹ�ϣֵ����dpcls*/
    CMAP_FOR_EACH_WITH_HASH (cls, node, hash, &pmd->classifiers) 
   	{
   		/*ƥ��˿ڷ���dpcls*/
        if (cls->in_port == in_port) 
		{
            /* Port classifier exists already */
            return cls;
        }
    }
	
    return NULL;
}

/*******************************************************************************
 ��������  :    dp_netdev_pmd_find_dpcls
 ��������  :    ��ѯdpcls�Ƿ���ڲ����ڴ���dpcls����pmd->classifiers
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static inline struct dpcls *
dp_netdev_pmd_find_dpcls(struct dp_netdev_pmd_thread *pmd,
                         odp_port_t in_port)
    OVS_REQUIRES(pmd->flow_mutex)
{
	/*����in_port����hashֵ��Ȼ���ɴ�hashֵ��pmd->classifiers�в���dpcls��ÿ��in_portӵ��һ��dpcls*/
    struct dpcls *cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    uint32_t hash = hash_port_no(in_port);

	/*dpcls������*/
    if (!cls) 
	{
        /* Create new classifier for in_port */
        cls = xmalloc(sizeof(*cls));

		/*port dpcls��ʼ��*/
        dpcls_init(cls);
        cls->in_port = in_port;

		/*dpcls����pmd dpcls����*/
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

/*flow��mark*/
struct flow_mark {
    struct cmap megaflow_to_mark;		/*����mega ufid ��mark map*/
    struct cmap mark_to_flow;			/*����mark��flow*/
    struct id_pool *pool;
};

static struct flow_mark flow_mark = {
    .megaflow_to_mark = CMAP_INITIALIZER,
    .mark_to_flow = CMAP_INITIALIZER,
};

/*******************************************************************************
 ��������  :    flow_mark_alloc
 ��������  :    mark id������mark id
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
static uint32_t
flow_mark_alloc(void)
{
    uint32_t mark;

	/*mark id�ز�����*/
    if (!flow_mark.pool) 
	{
        /* Haven't initiated yet, do it here */
        flow_mark.pool = id_pool_create(0, MAX_FLOW_MARK);
    }

	/*mark id������mark id*/
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
 ��������  :    megaflow_to_mark_find
 ��������  :    ����mega flow ufid��ѯmark
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static inline uint32_t
megaflow_to_mark_find(const ovs_u128 *mega_ufid)
{
	/*��hash*/
    size_t hash = dp_netdev_flow_hash(mega_ufid);
    struct megaflow_to_mark_data *data;

	/*ȫ��mark�����ѯ*/
    CMAP_FOR_EACH_WITH_HASH (data, node, hash, &flow_mark.megaflow_to_mark) {

		/*ƥ�䵽mega ufid*/
		if (ovs_u128_equals(*mega_ufid, data->mega_ufid)) {
            return data->mark;
        }
    }

    VLOG_WARN("Mark id for ufid "UUID_FMT" was not found\n",
              UUID_ARGS((struct uuid *)mega_ufid));
    return INVALID_FLOW_MARK;
}

/*******************************************************************************
 ��������  :    mark_to_flow_associate
 ��������  :    mark������flow
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
/* associate mark with a flow, which is 1:N mapping */
static void
mark_to_flow_associate(const uint32_t mark, struct dp_netdev_flow *flow)
{
    dp_netdev_flow_ref(flow);

    cmap_insert(&flow_mark.mark_to_flow,
                CONST_CAST(struct cmap_node *, &flow->mark_node),
                hash_int(mark, 0));

	/*markֱ�Ӹ��Ƹ�flow*/
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
 ��������  :    mark_to_flow_disassociate
 ��������  :    pmd�߳�����ɾ��
 �������  :  	pmd---pmd�߳�
 				flow---Ҫɾ����flow
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
mark_to_flow_disassociate(struct dp_netdev_pmd_thread *pmd,
                          struct dp_netdev_flow *flow)
{
    int ret = 0;
    uint32_t mark = flow->mark;

	/*flow ��mark �ڵ�*/
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

		/*pmd��port*/
        port = dp_netdev_lookup_port(pmd->dp, in_port);
        if (port) {

			/*ɾ��flow*/
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
 ��������  :    flow_mark_flush
 ��������  :    flush�� pmd�� mark������
 �������  :    pmd---pmd�߳�
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
flow_mark_flush(struct dp_netdev_pmd_thread *pmd)
{
    struct dp_netdev_flow *flow;

	/*����mark_to_flow�ϵ�����*/
    CMAP_FOR_EACH (flow, mark_node, &flow_mark.mark_to_flow) 
	{
		/*ȷ���������ڱ�pmd*/
        if (flow->pmd_id == pmd->core_id) 
		{
			/*����ɾ��������offload����*/
            queue_netdev_flow_del(pmd, flow);
        }
    }
}


/*******************************************************************************
 ��������  :    mark_to_flow_find
 ��������  :    ���ݱ��Ĵ�����������markֱ���ҵ���Ӧ��flow
 �������  :    pmd---pmd�߳�
 			  	mark---�����ҵ���flow��mark��һ��id
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static struct dp_netdev_flow *
mark_to_flow_find(const struct dp_netdev_pmd_thread *pmd, const uint32_t mark)
{
    struct dp_netdev_flow *flow;

	/*����mark����flow*/
    CMAP_FOR_EACH_WITH_HASH (flow, mark_node, hash_int(mark, 0), &flow_mark.mark_to_flow) 
	{
		/*����flow  mark��ȡ��߼����Ǳ�pmdʹ�õ��߼��ˡ���alive*/
        if (flow->mark == mark && flow->pmd_id == pmd->core_id && flow->dead == false) 
        {
            return flow;
        }
    }

    return NULL;
}

/*******************************************************************************
 ��������  :    dp_netdev_alloc_flow_offload
 ��������  :    ����һ��offload��
 �������  :  	pmd---pmd�߳�
 				flow--�·�ɾ����flow
 				op---������ɾ���
 �������  :	
 �� �� ֵ  : 	offload---����offload��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static struct dp_flow_offload_item *
dp_netdev_alloc_flow_offload(struct dp_netdev_pmd_thread *pmd, struct dp_netdev_flow *flow, int op)
{
    struct dp_flow_offload_item *offload;

	/*����offload������*/
    offload = xzalloc(sizeof(*offload));
    offload->pmd = pmd;
    offload->flow = flow;
    offload->op = op;

	/*flow���ü���*/
    dp_netdev_flow_ref(flow);

	/*pmd������λ*/
    dp_netdev_pmd_try_ref(pmd);

    return offload;
}

/*******************************************************************************
 ��������  :    dp_netdev_free_flow_offload
 ��������  :    �ͷ�offload��
 �������  :  	offload---offload item
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
dp_netdev_free_flow_offload(struct dp_flow_offload_item *offload)
{
	/**/
    dp_netdev_pmd_unref(offload->pmd);
    dp_netdev_flow_unref(offload->flow);

    free(offload->actions);
    free(offload);
}

/*******************************************************************************
 ��������  :    dp_netdev_append_flow_offload
 ��������  :    offload�ڵ����
 �������  :  	offload---Ҫoffload������ item
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
dp_netdev_append_flow_offload(struct dp_flow_offload_item *offload)
{
    ovs_mutex_lock(&dp_flow_offload.mutex);

	/*offload���list*/
    ovs_list_push_back(&dp_flow_offload.list, &offload->node);
    xpthread_cond_signal(&dp_flow_offload.cond);
    ovs_mutex_unlock(&dp_flow_offload.mutex);
}

/*******************************************************************************
 ��������  :    dp_netdev_flow_offload_del
 ��������  :    offload ����ɾ��
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
dp_netdev_flow_offload_del(struct dp_flow_offload_item *offload)
{
	/*flow ��pmd�������*/
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
 ��������  :    dp_netdev_flow_offload_put
 ��������  :    ����offload��ӡ��޸�
 �������  :  	offload---����offload��
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
dp_netdev_flow_offload_put(struct dp_flow_offload_item *offload)
{
    struct dp_netdev_port *port;

	/*pmd*/
    struct dp_netdev_pmd_thread *pmd = offload->pmd;

	/*offload item��Ӧ��flow*/
    struct dp_netdev_flow *flow = offload->flow;

	/*in port�˿�*/
    odp_port_t in_port = flow->flow.in_port.odp_port;

	/*offload�Ĳ���Ϊmod*/
    bool modification = offload->op == DP_NETDEV_FLOW_OFFLOAD_OP_MOD;

	struct offload_info info;

	uint32_t mark;
    int ret;

	
    if (flow->dead) 
	{
        return -1;
    }

	/*mod����*/
    if (modification) 
	{
		/*��ȡflow�� mark*/
        mark = flow->mark;
        ovs_assert(mark != INVALID_FLOW_MARK);
    } 
	else 
	{
        /*
         * If a mega flow has already been offloaded (from other PMD
         * instances), do not offload it again.
         */

		/*��ѯflow�Ƿ�������pmd�Ѿ�offload��mark�Ƿ����*/
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
				/*markֱ�Ӹ�ֵ��flow*/
                mark_to_flow_associate(mark, flow);
            }

			return 0;
        }

		/*�½�����mark ���룬mark id������mark id*/
        mark = flow_mark_alloc();
        if (mark == INVALID_FLOW_MARK) 
		{
            VLOG_ERR("Failed to allocate flow mark!\n");
        }
    }

	/*���������mark id*/
    info.flow_mark = mark;

	/*dp port ����������*/
    ovs_mutex_lock(&pmd->dp->port_mutex);

	/*��pmd dp��ѯinport*/
    port = dp_netdev_lookup_port(pmd->dp, in_port);
    if (!port) 
	{
        ovs_mutex_unlock(&pmd->dp->port_mutex);
        return -1;
    }

	/*offload�����·�*/
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
			/*mark������flow �������*/
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
 ��������  :    dp_netdev_flow_offload_main
 ��������  :    ����offload�̣߳�����offload��������ɾ
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
static void *
dp_netdev_flow_offload_main(void *data OVS_UNUSED)
{
    struct dp_flow_offload_item *offload;
    struct ovs_list *list;
    const char *op;
    int ret;

	/*һֱ�����߳�*/
    for (;;) 
	{
		/*offload ����������*/
        ovs_mutex_lock(&dp_flow_offload.mutex);

		/*ovs offload ������Ϊ��*/
		if (ovs_list_is_empty(&dp_flow_offload.list)) 
		{
            ovsrcu_quiesce_start();
            ovs_mutex_cond_wait(&dp_flow_offload.cond, &dp_flow_offload.mutex);
        }

		/*��offload���� popһ������offload��*/
        list = ovs_list_pop_front(&dp_flow_offload.list);

		/*��item��ȡoffload�� �����·�offload����*/
        offload = CONTAINER_OF(list, struct dp_flow_offload_item, node);

		ovs_mutex_unlock(&dp_flow_offload.mutex);

		/*����offload����*/
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
				/*offload flowɾ��*/
	            ret = dp_netdev_flow_offload_del(offload);
	            break;
	        default:
	            OVS_NOT_REACHED();
        }

        VLOG_DBG("%s to %s netdev flow\n", ret == 0 ? "succeed" : "failed", op);

		/*�ͷ�offload��*/
        dp_netdev_free_flow_offload(offload);
    }

    return NULL;
}

/*******************************************************************************
 ��������  :    queue_netdev_flow_del
 ��������  :    ����ɾ��������offload����
 �������  :  	pmd---pmd�߳�
 				flow---��ɾ������
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
queue_netdev_flow_del(struct dp_netdev_pmd_thread *pmd, struct dp_netdev_flow *flow)
{
    struct dp_flow_offload_item *offload;

	/*offload��ȡ������*/
    if (ovsthread_once_start(&offload_thread_once)) 
	{
        xpthread_cond_init(&dp_flow_offload.cond, NULL);

		/*��������offload�߳�*/
        ovs_thread_create("dp_netdev_flow_offload",dp_netdev_flow_offload_main, NULL);

		/*offoad����*/
        ovsthread_once_done(&offload_thread_once);
    }

	/*����һ��offload��*/
    offload = dp_netdev_alloc_flow_offload(pmd, flow, DP_NETDEV_FLOW_OFFLOAD_OP_DEL);

	/*�������offload*/
    dp_netdev_append_flow_offload(offload);
}

/*******************************************************************************
 ��������  :    queue_netdev_flow_put
 ��������  :    �����·�����
 �������  :  	pmd---Ҫ�µ���pmd
 				flow---��������flow��Ϣ
 				match---match����
 				actions---actions
 				actions_len---action �����ڴ泤��
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static void
queue_netdev_flow_put(struct dp_netdev_pmd_thread *pmd,
                      struct dp_netdev_flow *flow, struct match *match,
                      const struct nlattr *actions, size_t actions_len)
{
	/*offlod��*/
    struct dp_flow_offload_item *offload;
    int op;

	/*apiδʹ��*/
    if (!netdev_is_flow_api_enabled()) 
	{
        return;
    }

	/*offload�·��������̣��߳�û����������һ��*/
    if (ovsthread_once_start(&offload_thread_once)) 
	{
		/*���߳���offload �������߳�*/
        xpthread_cond_init(&dp_flow_offload.cond, NULL);
        ovs_thread_create("dp_netdev_flow_offload", dp_netdev_flow_offload_main, NULL);
        ovsthread_once_done(&offload_thread_once);
    }

	/*flow mark����*/
    if (flow->mark != INVALID_FLOW_MARK) 
	{
		/*offload flow mod*/
        op = DP_NETDEV_FLOW_OFFLOAD_OP_MOD;
    }
	/*mark������*/
	else 
	{
    	/*offload flow add*/
        op = DP_NETDEV_FLOW_OFFLOAD_OP_ADD;
    }
	
	/*����offlod�ṹ�ڴ� ����flow*/
    offload = dp_netdev_alloc_flow_offload(pmd, flow, op);

	/*match������ֵ��offload*/
	offload->match = *match;

	/*offload action�ڴ�����*/
	offload->actions = xmalloc(actions_len);

	/*flow actions������offload�ڵ�*/
	memcpy(offload->actions, actions, actions_len);

	/*action���� �ֽ�*/
	offload->actions_len = actions_len;

	/*offload�� ��ӵ�offlod�����߳�ͳһ����*/
    dp_netdev_append_flow_offload(offload);

	VLOG_DBG("zwl queue_netdev_flow_put offload flow node insert list");
}

/*******************************************************************************
 ��������  :    dp_netdev_pmd_remove_flow
 ��������  :    ��ȡ������
 �������  :  	pmd---Ҫɾ����pmd
 				flow---pmd���������
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
dp_netdev_pmd_remove_flow(struct dp_netdev_pmd_thread *pmd, struct dp_netdev_flow *flow)
    OVS_REQUIRES(pmd->flow_mutex)
{
    struct cmap_node *node = CONST_CAST(struct cmap_node *, &flow->node);
    struct dpcls *cls;
    odp_port_t in_port = flow->flow.in_port.odp_port;

	/*��ȡport��Ӧdpcls�ṹ*/
    cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
	
    ovs_assert(cls != NULL);

	/*��clsɾ��flow*/
    dpcls_remove(cls, &flow->cr);

	/*��pmd flow����ɾ��flow*/
    cmap_remove(&pmd->flow_table, node, dp_netdev_flow_hash(&flow->ufid));

	/*����mark����Ч��*/
	if (flow->mark != INVALID_FLOW_MARK) 
	{
		/*����ɾ��������offload����*/
        queue_netdev_flow_del(pmd, flow);
    }

	/*ɾ�����flow����������dead���*/
    flow->dead = true;

	/*�ͷ�������Դ*/
    dp_netdev_flow_unref(flow);
}

/*******************************************************************************
 ��������  :    dp_netdev_pmd_flow_flush
 ��������  :    ɾ��pmd���������
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
dp_netdev_pmd_flow_flush(struct dp_netdev_pmd_thread *pmd)
{
    struct dp_netdev_flow *netdev_flow;

    ovs_mutex_lock(&pmd->flow_mutex);

	/*����ɾ��pmd���������*/
    CMAP_FOR_EACH (netdev_flow, node, &pmd->flow_table) 
	{
		/*ɾ��pmd������*/
        dp_netdev_pmd_remove_flow(pmd, netdev_flow);
    }
	
    ovs_mutex_unlock(&pmd->flow_mutex);
}

/*******************************************************************************
 ��������  :    dpif_netdev_flow_flush
 ��������  :    flush������
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
 �������� :  dp_netdev_flow_cast
 �������� :  ��dpcls ruleת��struct dp_netdev_flow
 ������� :  cr---dpcls����
 ������� :  ��
 ����ֵ�� :  ��
 --------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸����� :  
 �޸�Ŀ�� :  
 �޸����� :  
*******************************************************************************/
static struct dp_netdev_flow *
dp_netdev_flow_cast(const struct dpcls_rule *cr)
{
    return cr ? CONTAINER_OF(cr, struct dp_netdev_flow, cr) : NULL;
}

/*******************************************************************************
 ��������  :    dp_netdev_flow_ref
 ��������  :    
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
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
 �������� :  netdev_flow_key_equal
 �������� :  flow key �Ƿ����
 ������� :  
 ������� :  ��
 ����ֵ�� :  ��
 --------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸����� :  
 �޸�Ŀ�� :  
 �޸����� :  
*******************************************************************************/
static inline bool
netdev_flow_key_equal(const struct netdev_flow_key *a, const struct netdev_flow_key *b)
{
    /* 'b->len' may be not set yet. */

	/*key�Ĺ�ϣֵ��miniflow�����*/
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
	/*keyֵ����*/
    memcpy(dst, src, offsetof(struct netdev_flow_key, mf) + src->len);
}

/*******************************************************************************
 ��������  :    netdev_flow_mask_init
 ��������  :    �����ʼ��
 �������  :  	mask---netdev_flow_key flow key������
 				match---flow��match����
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
/* Initialize a netdev_flow_key 'mask' from 'match'. */
static inline void
netdev_flow_mask_init(struct netdev_flow_key *mask, const struct match *match)
{
	/*miniflow��ֵ��ȡֵָ��*/
    uint64_t *dst = miniflow_values(&mask->mf);

	/*miniflow λͼ*/
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

	/*miniflow�ĳ���*/
    size_t n = dst - miniflow_get_values(&mask->mf);

	/*��hash�ͳ���*/
    mask->hash = hash_finish(hash, n * 8);

	/*����*/
	mask->len = netdev_flow_key_size(n);
}

/*******************************************************************************
 ��������  :    netdev_flow_key_init_masked
 ��������  :    flow key ��ʼ��miniflow
 �������  :  	dst---�洢��ȡ��miniflow�Ľṹ��struct netdev_flow_key key
 				flow---match.flow �洢��match
 				mask---�洢��ȡ��miniflow mask�Ľṹ��struct netdev_flow_key mask
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
/* Initializes 'dst' as a copy of 'flow' masked with 'mask'. */
static inline void
netdev_flow_key_init_masked(struct netdev_flow_key *dst,
                            const struct flow *flow,
                            const struct netdev_flow_key *mask)
{
	/*miniflowָ�� ָ��unsigned long long map[(sizeof flow/8)+1 = ]*/
    uint64_t *dst_u64 = miniflow_values(&dst->mf);

	/*��ȡ����miniflowֵ*/
	const uint64_t *mask_u64 = miniflow_get_values(&mask->mf);
    uint32_t hash = 0;
    uint64_t value;

    dst->len = mask->len;

	/*����miniflow*/
    dst->mf = mask->mf;   /* Copy maps. */

	/**/
    FLOW_FOR_EACH_IN_MAPS(value, flow, mask->mf.map) 
	{
        *dst_u64 = value & *mask_u64++;

		/**/
        hash = hash_add64(hash, *dst_u64++);
    }

	/*��Ԫ����hash ?*/
    dst->hash = hash_finish(hash,(dst_u64 - miniflow_get_values(&dst->mf)) * 8);
}

/* Iterate through netdev_flow_key TNL u64 values specified by 'FLOWMAP'. */
#define NETDEV_FLOW_KEY_FOR_EACH_IN_FLOWMAP(VALUE, KEY, FLOWMAP)   \
    MINIFLOW_FOR_EACH_IN_FLOWMAP(VALUE, &(KEY)->mf, FLOWMAP)

/*******************************************************************************
 ��������  :    netdev_flow_key_hash_in_mask
 ��������  :    ����������ϣ
 �������  :    key---miniflow key
 			    mask---miniflow����
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
/* Returns a hash value for the bits of 'key' where there are 1-bits in
 * 'mask'. */
static inline uint32_t
netdev_flow_key_hash_in_mask(const struct netdev_flow_key *key, const struct netdev_flow_key *mask)
{
	/*��ȡminiflow ֵ*/
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
 �������� :  emc_entry_alive
 �������� :  emc������� �� ����
 ������� :  
 ������� :  ��
 ����ֵ�� :  ��
 --------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸����� :  
 �޸�Ŀ�� :  
 �޸����� :  
*******************************************************************************/
static inline bool
emc_entry_alive(struct emc_entry *ce)
{
	/*emc������� �� ����*/
    return ce->flow && !ce->flow->dead;
}
/*******************************************************************************
 ��������  :    emc_clear_entry
 ��������  :    emc����ɾ��
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
emc_clear_entry(struct emc_entry *ce)
{
	/*emc�������*/
    if (ce->flow) 
	{
        dp_netdev_flow_unref(ce->flow);
        ce->flow = NULL;
    }
}
/*******************************************************************************
 ��������  :    emc_change_entry
 ��������  :    ��ֵnetdev_flow_key��dp_netdev_flow
 �������  :    ce---emc ����entry����ͬ��flow��key
 �������  :	flow--smc�鵽������Ϣ
 		        key---miniflow key
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static inline void emc_change_entry(struct emc_entry *ce, struct dp_netdev_flow *flow, const struct netdev_flow_key *key)
{
	/*entry��Ӧ��flow����Ҫ��ӵ�flow���ͷž�flow��������flow*/
    if (ce->flow != flow) 
	{
		/*�����flow������*/
        if (ce->flow) 
		{
            dp_netdev_flow_unref(ce->flow);
        }

		/*��flow ��Ϣ����entry*/
        if (dp_netdev_flow_ref(flow)) 
		{
            ce->flow = flow;
        }
		else 
		{
            ce->flow = NULL;
        }
    }

	/*key��Ϣֵ����entry ��key*/
	if (key) 
	{
        netdev_flow_key_clone(&ce->key, key);
    }
}

/*******************************************************************************
 ��������  :   emc_insert
 ��������  :   emc ����insert
			   1.����key->hash�ҵ�hashͰ�����ҽ�����ѯ
			   2.�鿴�Ƿ���ƥ���keyֵ���еĻ�����emc_change_entry�޸�����
			   3.���û��ƥ��ľͻ�����㷨��¼һ��entry���������
			   4.ѭ�����֮�󣬵���emc_change_entry���֮ǰ���õ�����
 �������  :   cache---ÿ��pmdһ��ECM����
 		       key---��ȡ�ı��ĵ�miniflow key
 		       flow---smc�鵽��flow
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static inline void
emc_insert(struct emc_cache *cache, const struct netdev_flow_key *key, struct dp_netdev_flow *flow)
{
    struct emc_entry *to_be_replaced = NULL;
    struct emc_entry *current_entry;

	/*����key����Ĺ�ϣ����emc����entry*/
    EMC_FOR_EACH_POS_WITH_HASH(cache, current_entry, key->hash) 
	{	
		/*�Ա�miniflow key���*/
        if (netdev_flow_key_equal(&current_entry->key, key)) 
		{
            /* We found the entry with the 'mf' miniflow */

			/*flow��Ϣ����emc����*/
            emc_change_entry(current_entry, flow, NULL);
			
            return;
        }

        /* Replacement policy: put the flow in an empty (not alive) entry, or
         * in the first entry where it can be */

		/*miniflow key�����������*/  /*�ɵ�flow����*/				/*��ǰflowû��*/					/*��ϣС�ڱ�����Ĺ�ϣ��Ϊɶ*/
        if (!to_be_replaced || (emc_entry_alive(to_be_replaced) && !emc_entry_alive(current_entry)) || current_entry->key.hash < to_be_replaced->key.hash)
        {
        	/*���滻��entry*/
            to_be_replaced = current_entry;
        }
    }
    /* We didn't find the miniflow in the cache.
     * The 'to_be_replaced' entry is where the new flow will be stored */

	/*emc����current entry���� ָ���flow*/
    emc_change_entry(to_be_replaced, flow, key);
}

/*******************************************************************************
 ��������  :  emc_probabilistic_insert
 ��������  :  emc�������
 �������  :  pmd---pmd�߳�
 			  key---����miniflow key
 			  flow---smc�鵽��flow
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static inline void
emc_probabilistic_insert(struct dp_netdev_pmd_thread *pmd, const struct netdev_flow_key *key, struct dp_netdev_flow *flow)
{
    /* Insert an entry into the EMC based on probability value 'min'. By
     * default the value is UINT32_MAX / 100 which yields an insertion
     * probability of 1/100 ie. 1% */

    uint32_t min;

	/*ԭ�Ӷ�ȡ��ǰemc��������*/
    atomic_read_relaxed(&pmd->dp->emc_insert_min, &min);

	/*emc����δ��*/
    if (min && random_uint32() <= min) 
	{
		/*flow���� emc ����*/
        emc_insert(&(pmd->flow_cache).emc_cache, key, flow);
    }
}

/*******************************************************************************
 ��������  :  emc_lookup
 ��������  :  emc �������ѯ
 �������  :  cache---pmd��Ӧһ��emc����
 �������  :  key---������ȡ�� miniflow key
 �� �� ֵ  :  ��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static inline struct dp_netdev_flow *emc_lookup(struct emc_cache *cache, const struct netdev_flow_key *key)
{
	/*�������飬������*/
    struct emc_entry *current_entry;

	/*2�ι�ϣ��ѯ*/				  /*emc cache��emc��ѯentry��miniflow hash*/
    EMC_FOR_EACH_POS_WITH_HASH(cache, current_entry, key->hash) 
   	{
        if (current_entry->key.hash == key->hash	/*��ϣֵ��ȣ���ϣ����miniflow ��Ԫ�����*/
            && emc_entry_alive(current_entry)		/*flow ����*/
            && netdev_flow_key_equal_mf(&current_entry->key, &key->mf)) /*miniflow λͼ���*/
        {  

            /* We found the entry with the 'key->mf' miniflow */
			/*����emc������*/
            return current_entry->flow;
        }
    }

    return NULL;
}

/*******************************************************************************
 ��������  :  smc_entry_get
 ��������  :  ���ݹ�ϣ����smc ����������
 �������  :  pmd---pmd�߳�
 			  hash---���ݱ�����Ԫ����Ĺ�ϣ	
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static inline const struct cmap_node *
smc_entry_get(struct dp_netdev_pmd_thread *pmd, const uint32_t hash)
{
	/*smc��*/
    struct smc_cache *cache = &(pmd->flow_cache).smc_cache;

	/*���ݱ�����Ԫ���ϣ���й�ϣͰ*/
    struct smc_bucket *bucket = &cache->buckets[hash & SMC_MASK];

	/*��¼�Ĺ�ϣֵ*/
    uint16_t sig = hash >> 16;

	/*65536*/
    uint16_t index = UINT16_MAX;

	/*Ͱ��Ϊ4*/
    for (int i = 0; i < SMC_ENTRY_PER_BUCKET; i++) 
	{
		/*�洢�Ĺ�ϣֵΪ hash >> 16 */
        if (bucket->sig[i] == sig) 
		{
			/*��ȡbucket��Ӧ�������index*/
            index = bucket->flow_idx[i];
			
            break;
        }
    }

	/*����index ����smc������*/
    if (index != UINT16_MAX) 
	{
		/*������ʵ������*/
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
 ��������  :    smc_insert
 ��������  :    ��ȷ�������emc����
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
 ��������  :    dp_netdev_pmd_lookup_flow
 ��������  :    ��������
 �������  :  	pmd---pmd�߳�
 				key---�洢miniflow��key struct netdev_flow_key
 				lookup_num_p---NULL
 �������  :	netdev_flow---���е�dpcls�����Ӧ��netdev_flow
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static struct dp_netdev_flow *
dp_netdev_pmd_lookup_flow(struct dp_netdev_pmd_thread *pmd, const struct netdev_flow_key *key, int *lookup_num_p)
{
    struct dpcls *cls;
    struct dpcls_rule *rule;

	/*��ȡin_port*/
    odp_port_t in_port = u32_to_odp(MINIFLOW_GET_U32(&key->mf, in_port.odp_port));
    struct dp_netdev_flow *netdev_flow = NULL;

	/*���ݶ˿ڲ�ѯdpcls*/
    cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    if (OVS_LIKELY(cls)) 
	{
		/*dpcls rule��ѯ*/
        dpcls_lookup(cls, &key, &rule, 1, lookup_num_p);

		/*dpcls����ӳ���netdev_flow*/
        netdev_flow = dp_netdev_flow_cast(rule);
    }
	
    return netdev_flow;
}

/*******************************************************************************
 ��������  :    dp_netdev_pmd_find_flow
 ��������  :    ��pmd�ϲ�flow
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
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

		/*����key����ufid*/
		dpif_flow_hash(pmd->dp->dpif, &flow, sizeof flow, &ufid);
        ufidp = &ufid;
    }

    if (ufidp) {

		/*�������ɵ�ufid��flow*/
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
 ��������  :    get_dpif_flow_stats
 ��������  :    emc����ɾ��
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


	/*ʱ���ֱ�Ӹ�ֵ����dpif flow*/
	stats->used = used;
    atomic_read_relaxed(&netdev_flow->stats.tcp_flags, &flags);
    stats->tcp_flags = flags;
}

/*******************************************************************************
 ��������  :    dp_netdev_flow_to_dpif_flow
 ��������  :    
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
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

		/*flow�Ĳ���*/
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

	/*flow���*/
    flow->ufid = netdev_flow->ufid;
    flow->ufid_present = true;
    flow->pmd_id = netdev_flow->pmd_id;

	/*��ȡflow������ͳ��*/
    get_dpif_flow_stats(netdev_flow, &flow->stats);
}

/*******************************************************************************
 ��������  :    dpif_netdev_mask_from_nlattrs
 ��������  :    ������flow ����
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
dpif_netdev_mask_from_nlattrs(const struct nlattr *key, uint32_t key_len,
                              const struct nlattr *mask_key,
                              uint32_t mask_key_len, const struct flow *flow,
                              struct flow_wildcards *wc, bool probe)
{
    enum odp_key_fitness fitness;

	/*������������*/
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
 ��������  :    dpif_netdev_flow_from_nlattrs
 ��������  :    ��key��������match ����flow
 �������  :  	key---flow��match
 				key_len---flow��match����
 				flow---Ҫ�����flow�ṹ
 				
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
dpif_netdev_flow_from_nlattrs(const struct nlattr *key, uint32_t key_len, struct flow *flow, bool probe)
{
	/*��key������match����flow*/
    if (odp_flow_key_to_flow(key, key_len, flow)) 
	{
		/*prob����Ϊ��*/
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

				/*��ʼ��һ����buffer*/
                ds_init(&s);

				/**/
                odp_flow_format(key, key_len, NULL, 0, NULL, &s, true);
                VLOG_ERR("internal error parsing flow key %s", ds_cstr(&s));

				/*�ͷ�s ��buffer*/
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
 ��������  :    emc_cache_slow_sweep
 ��������  :    emc����ɾ��
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
dpif_netdev_flow_get(const struct dpif *dpif, const struct dpif_flow_get *get)
{
	/*��ȡdp*/
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *netdev_flow;
    struct dp_netdev_pmd_thread *pmd;
    struct hmapx to_find = HMAPX_INITIALIZER(&to_find);
    struct hmapx_node *node;
    int error = EINVAL;

	/*δָ��pmd*/
    if (get->pmd_id == PMD_ID_NULL) {

		/*��������pmd*/
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {

			/*�ͷ�pmd*/
            if (dp_netdev_pmd_try_ref(pmd) && !hmapx_add(&to_find, pmd)) {
                dp_netdev_pmd_unref(pmd);
            }
        }
    } else {
    	/*����ָ����core_id ��pmd poll �����ȡ�˶�Ӧpmd*/
        pmd = dp_netdev_get_pmd(dp, get->pmd_id);
        if (!pmd) {
            goto out;
        }

		/*�����ҵ���pmd*/
        hmapx_add(&to_find, pmd);
    }

    if (!hmapx_count(&to_find)) {
        goto out;
    }

	/*�����鵽��pmd*/
    HMAPX_FOR_EACH (node, &to_find) 
	{
        pmd = (struct dp_netdev_pmd_thread *) node->data;

		/*��pmd�ϲ�flow*/
		netdev_flow = dp_netdev_pmd_find_flow(pmd, get->ufid, get->key,
                                              get->key_len);
		/*�鵽��flow*/
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
 ��������  :    dp_netdev_get_mega_ufid
 ��������  :    ����maga ufid
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
dp_netdev_get_mega_ufid(const struct match *match, ovs_u128 *mega_ufid)
{
    struct flow masked_flow;
    size_t i;

    for (i = 0; i < sizeof(struct flow); i++) {

		/*����marked flow*/
        ((uint8_t *)&masked_flow)[i] = ((uint8_t *)&match->flow)[i] &
                                       ((uint8_t *)&match->wc)[i];
    }

	/*����mega flow ufid*/
    dpif_flow_hash(NULL, &masked_flow, sizeof(struct flow), mega_ufid);
}
/*******************************************************************************
 ��������  :    dp_netdev_flow_add
 ��������  :    �������pmd ��Ӧport��dpcls����emc
 �������  :    pmd---pmd
 				match---��ȡ������match����
 				ufid---�����ufid��ָ���Ļ����ɵ�
 				actions---��ȡ����actions
 				actions_len---action�ĸ���
 
 �������  :	
 �� �� ֵ  : 	dp_netdev_flow
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static struct dp_netdev_flow *
dp_netdev_flow_add(struct dp_netdev_pmd_thread *pmd,
                   struct match *match, const ovs_u128 *ufid,
                   const struct nlattr *actions, size_t actions_len)
    OVS_REQUIRES(pmd->flow_mutex)
{
	/*����*/
    struct dp_netdev_flow *flow;

	/*miniflow key ����ṹ*/
	struct netdev_flow_key mask;

	/*port��dpcls*/
    struct dpcls *cls;

	/*ȷ��inport��ȷƥ��*/
    /* Make sure in_port is exact matched before we read it. */
    ovs_assert(match->wc.masks.in_port.odp_port == ODPP_NONE);

	/*�����in_port*/
    odp_port_t in_port = match->flow.in_port.odp_port;

    /* As we select the dpcls based on the port number, each netdev flow
     * belonging to the same dpcls will have the same odp_port value.
     * For performance reasons we wildcard odp_port here in the mask.  In the
     * typical case dp_hash is also wildcarded, and the resulting 8-byte
     * chunk {dp_hash, in_port} will be ignored by netdev_flow_mask_init() and
     * will not be part of the subtable mask.
     * This will speed up the hash computation during dpcls_lookup() because
     * there is one less call to hash_add64() in this case. */

	/*mask��ʼ��*/
	match->wc.masks.in_port.odp_port = 0;

	/*flow �����ʼ������ȡminiflow key������*/
    netdev_flow_mask_init(&mask, match);

	match->wc.masks.in_port.odp_port = ODPP_NONE;

    /* Make sure wc does not have metadata. */
    ovs_assert(!FLOWMAP_HAS_FIELD(&mask.mf.map, metadata)
               && !FLOWMAP_HAS_FIELD(&mask.mf.map, regs));

    /* Do not allocate extra space. */
	/*����flow�ṹ�����*/
    flow = xmalloc(sizeof *flow - sizeof flow->cr.flow.mf + mask.len);

	memset(&flow->stats, 0, sizeof flow->stats);


	/*����״̬*/
	flow->dead = false;
    flow->batch = NULL;

	/*û��markֵ*/
    flow->mark = INVALID_FLOW_MARK;

	/*flow��pmd ufid��*/
    *CONST_CAST(unsigned *, &flow->pmd_id) = pmd->core_id;

	/*����match*/
    *CONST_CAST(struct flow *, &flow->flow) = match->flow;

	/*����ufid*/
	*CONST_CAST(ovs_u128 *, &flow->ufid) = *ufid;

	/*��ʼ��flow���������*/
	ovs_refcount_init(&flow->ref_cnt);

	/*actions ����dp_netdev_flow*/
	ovsrcu_set(&flow->actions, dp_netdev_actions_create(actions, actions_len));

	/*��ȡmega flow ufid*/
    dp_netdev_get_mega_ufid(match, CONST_CAST(ovs_u128 *, &flow->mega_ufid));

	/*��ʼ��miniflow key mask*/
    netdev_flow_key_init_masked(&flow->cr.flow, &match->flow, &mask);

    /* Select dpcls for in_port. Relies on in_port to be exact match. */

	/*��ѯdpcls�Ƿ���ڣ������ڴ���dpcls����pmd->classifiers*/
    cls = dp_netdev_pmd_find_dpcls(pmd, in_port);

	VLOG_DBG("zwl dp_netdev_flow_add find dpcls ok in_port=%u",in_port);

	/*flow��dpcls rule ���룬���������ҵ���Ӧ���ӱ�Ȼ����뵱ǰ������*/
    dpcls_insert(cls, &flow->cr, &mask);

	VLOG_DBG("zwl dp_netdev_flow_add flow insert dpcls");

	/*flow����pmd->flow_table �洢����pmd flow��flow�ڵ����*/
    cmap_insert(&pmd->flow_table, CONST_CAST(struct cmap_node *, &flow->node), dp_netdev_flow_hash(&flow->ufid));

	VLOG_DBG("zwl dp_netdev_flow_add flow insert flow_table");

	/*offload�·�����flow��ӵ�offload item ������offload�߳��·�*/
    queue_netdev_flow_put(pmd, flow, match, actions, actions_len);

	/**/
    if (OVS_UNLIKELY(!VLOG_DROP_DBG((&upcall_rl)))) 
	{
        struct ds ds = DS_EMPTY_INITIALIZER;
        struct ofpbuf key_buf, mask_buf;

		/*����*/
        struct odp_flow_key_parms odp_parms = 
        {
            .flow = &match->flow,				/*match*/
            .mask = &match->wc.masks,			/*����*/
            .support = dp_netdev_support,
        };

		/*key��mask �ڴ��ʼ��*/
        ofpbuf_init(&key_buf, 0);
        ofpbuf_init(&mask_buf, 0);

		/*������key mask*/
        odp_flow_key_from_flow(&odp_parms, &key_buf);
        odp_parms.key_buf = &key_buf;

		/*mask buf*/
        odp_flow_key_from_mask(&odp_parms, &mask_buf);

        ds_put_cstr(&ds, "flow_add: ");

		/*ufid*/
        odp_format_ufid(ufid, &ds);
        ds_put_cstr(&ds, " ");

		/*flow��ʽ��*/
        odp_flow_format(key_buf.data, key_buf.size, mask_buf.data, mask_buf.size, NULL, &ds, false);
        ds_put_cstr(&ds, ", actions:");

		/*flow action ��ʽ��*/
        format_odp_actions(&ds, actions, actions_len, NULL);

        VLOG_DBG("%s", ds_cstr(&ds));

		/*match��key�ڴ�*/
        ofpbuf_uninit(&key_buf);
        ofpbuf_uninit(&mask_buf);

        /* Add a printout of the actual match installed. */
        struct match m;
        ds_clear(&ds);
        ds_put_cstr(&ds, "flow match: ");

		/*mask�� miniflow �ָ�*/
        miniflow_expand(&flow->cr.flow.mf, &m.flow);

		
        miniflow_expand(&flow->cr.mask->mf, &m.wc.masks);

		/*���metadata���*/
        memset(&m.tun_md, 0, sizeof m.tun_md);

		match_format(&m, NULL, &ds, OFP_DEFAULT_PRIORITY);

        VLOG_DBG("%s", ds_cstr(&ds));

        ds_destroy(&ds);
    }

    return flow;
}

/*******************************************************************************
 ��������  :    flow_put_on_pmd
 ��������  :    �����µ�pmd
 �������  :  	pmd---Ҫ�������pmd�߳�
 				key---��ȡ��miniflow key��struct netdev_flow_key key
 				match---match��struct match match ��ȡ��match
 				ufid---flow��ufid
 				put---�����Ҫ�·�������
 				stats---dptctl����ͳ��
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
flow_put_on_pmd(struct dp_netdev_pmd_thread *pmd,
                struct netdev_flow_key *key,
                struct match *match,
                ovs_u128 *ufid,
                const struct dpif_flow_put *put,
                struct dpif_flow_stats *stats)
{
	/*��ʾһ�������������ƥ���򼰶�Ӧ��Actions*/
    struct dp_netdev_flow *netdev_flow;
    int error = 0;

	/*�������ͳ��*/
    if (stats) 
	{
        memset(stats, 0, sizeof *stats);
    }

    ovs_mutex_lock(&pmd->flow_mutex);

	VLOG_DBG("zwl flow_put_on_pmd pmd->core_id=%d, ufid=%lu",pmd->core_id,*ufid);

	/*��pmd��ѯ�����Ƿ���ڣ����ڷ��ر�������dpcls rule��Ӧ��netdev_flows  key Ϊ�洢miniflow��netdev_flow_key*/
    netdev_flow = dp_netdev_pmd_lookup_flow(pmd, key, NULL);
	
	/*��������*/
    if (!netdev_flow) 
	{
		/*������*/
        if (put->flags & DPIF_FP_CREATE) 
		{
			/*pmd����δ��*/
            if (cmap_count(&pmd->flow_table) < MAX_FLOWS) 
			{
				/*�·�����pmd*/
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
	/*�������*/
	else 
	{
    	/*�����Ƿ���mod*/
        if (put->flags & DPIF_FP_MODIFY) 
		{
            struct dp_netdev_actions *new_actions;
            struct dp_netdev_actions *old_actions;

            new_actions = dp_netdev_actions_create(put->actions, put->actions_len);

            old_actions = dp_netdev_flow_get_actions(netdev_flow);
            ovsrcu_set(&netdev_flow->actions, new_actions);

			/*�·�����*/
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
 ��������  :    dpif_netdev_flow_put
 ��������  :    �·�����
 �������  :  	dpif---dp�ӿ������ṹ
 				put---�·�����������
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
dpif_netdev_flow_put(struct dpif *dpif, const struct dpif_flow_put *put)
{
	/*����dp�ӿ������ṹ��ȡ����dp�ṹ*/
    struct dp_netdev *dp = get_dp_netdev(dpif);

	/*miniflow key mask��ȡ��miniflow*/
    struct netdev_flow_key key, mask;

	/*pmd�߳�*/
    struct dp_netdev_pmd_thread *pmd;

	/*match����*/
    struct match match;
    ovs_u128 ufid;
    int error;

	/*������Ϣ*/
    bool probe = put->flags & DPIF_FP_PROBE;

	VLOG_DBG("zwl flow dpif_netdev_flow_put 111");
	
	/*�����������ͳ��*/
    if (put->stats) 
	{
        memset(put->stats, 0, sizeof *put->stats);
    }

	/*����put->key����match����match�� flow�ṹ*/
    error = dpif_netdev_flow_from_nlattrs(put->key, put->key_len, &match.flow, probe);
    if (error) 
	{
        return error;
    }

	/*������flow put->mask���� ����match��mask�ṹ*/
    error = dpif_netdev_mask_from_nlattrs(put->key, put->key_len, put->mask, put->mask_len, &match.flow, &match.wc, probe);
    if (error) 
	{
        return error;
    }

	/*��ȡ����ufid������ָ����ufid*/
    if (put->ufid) 
	{
        ufid = *put->ufid;
    } 
	else 
	{
    	/*key��key������hash ����uufid ����match*/
        dpif_flow_hash(dpif, &match.flow, sizeof match.flow, &ufid);
    }

	VLOG_DBG("zwl flow ufid=%lu",ufid);

    /* The Netlink encoding of datapath flow keys cannot express
     * wildcarding the presence of a VLAN tag. Instead, a missing VLAN
     * tag is interpreted as exact match on the fact that there is no
     * VLAN.  Unless we refactor a lot of code that translates between
     * Netlink and struct flow representations, we have to do the same
     * here.  This must be in sync with 'match' in handle_packet_upcall(). */

	/*vlan�ֶ�*/
	if (!match.wc.masks.vlans[0].tci) 
	{
        match.wc.masks.vlans[0].tci = htons(0xffff);
    }

    /* Must produce a netdev_flow_key for lookup.
     * Use the same method as employed to create the key when adding
     * the flow to the dplcs to make sure they match. */

	/*mask��match �ṹ��ʼ��*/
    netdev_flow_mask_init(&mask, &match);

	/*key ��ȡmatch ����miniflow key�� flow �� match������miniflow ��mask*/
    netdev_flow_key_init_masked(&key, &match.flow, &mask);

	VLOG_DBG("zwl dpif_netdev_flow_put put->pmd_id=%u", put->pmd_id);

	/*����δָ��pmd���·���������pmd*/
    if (put->pmd_id == PMD_ID_NULL) 
	{
		/*pmd�߳���Ϊ0*/
        if (cmap_count(&dp->poll_threads) == 0) 
		{
            return EINVAL;
        }
		
		/*����dp�ϵ�pmd�߳��·�����*/
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) 
        {
            struct dpif_flow_stats pmd_stats;
            int pmd_error;

			/*�����µ�pmd*/
            pmd_error = flow_put_on_pmd(pmd, &key, &match, &ufid, put, &pmd_stats);
            if (pmd_error) 
			{
                error = pmd_error;
            } 
			else if (put->stats) 
            {

				/*��������ͳ��*/
                put->stats->n_packets += pmd_stats.n_packets;
                put->stats->n_bytes += pmd_stats.n_bytes;
                put->stats->used = MAX(put->stats->used, pmd_stats.used);
                put->stats->tcp_flags |= pmd_stats.tcp_flags;
            }
        }
    }
	/*ָ����pmd*/
	else 
	{
    	/*��ȡpmd�߳�*/
        pmd = dp_netdev_get_pmd(dp, put->pmd_id);
        if (!pmd) 
		{
            return EINVAL;
        }

		/*�·�����ָ��pmd*/
        error = flow_put_on_pmd(pmd, &key, &match, &ufid, put, put->stats);

		dp_netdev_pmd_unref(pmd);
    }

    return error;
}

/*******************************************************************************
 ��������  :    flow_del_on_pmd
 ��������  :    ��pmd��ɾ��flow
 �������  :  	pmd---Ҫɾ��flow��pmd
 				stats---Ҫɾ����flow������ͳ��
 				del---Ҫɾ����flow
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
flow_del_on_pmd(struct dp_netdev_pmd_thread *pmd,
                struct dpif_flow_stats *stats,
                const struct dpif_flow_del *del)
{
	/*Ҫɾ����flow*/
    struct dp_netdev_flow *netdev_flow;
    int error = 0;

	/*��ȡ������*/
    ovs_mutex_lock(&pmd->flow_mutex);

	/*pmd���ҵ�flow*/
    netdev_flow = dp_netdev_pmd_find_flow(pmd, del->ufid, del->key,
                                          del->key_len);

	/*�ҵ���Ҫɾ����flow*/
	if (netdev_flow) {
        if (stats) {
            get_dpif_flow_stats(netdev_flow, stats);
        }
		
		/*flow ɾ��*/
        dp_netdev_pmd_remove_flow(pmd, netdev_flow);
    } else {
        error = ENOENT;
    }

	/*�ͷŻ�����*/
    ovs_mutex_unlock(&pmd->flow_mutex);

    return error;
}

/*******************************************************************************
 ��������  :    dpif_netdev_flow_del
 ��������  :    ɾ��flow
 �������  :  	del---Ҫɾ����flow
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
dpif_netdev_flow_del(struct dpif *dpif, const struct dpif_flow_del *del)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;
    int error = 0;

	/*Ҫɾ����flow������ͳ��*/
    if (del->stats) {
        memset(del->stats, 0, sizeof *del->stats);
    }

	/*Ҫɾ����flowû��ָ��pmd*/
    if (del->pmd_id == PMD_ID_NULL) {

		/*poll�ڵ����*/
        if (cmap_count(&dp->poll_threads) == 0) {
            return EINVAL;
        }

		/*poll pmd �ڵ�*/
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
            struct dpif_flow_stats pmd_stats;
            int pmd_error;

			/*ɾ��flow*/
            pmd_error = flow_del_on_pmd(pmd, &pmd_stats, del);
            if (pmd_error) {
                error = pmd_error;
            } 
			/*Ҫɾ����flow��stats ��ֵ*/
			else if (del->stats) {

				/*Ҫɾ����flow��stats*/
                del->stats->n_packets += pmd_stats.n_packets;
                del->stats->n_bytes += pmd_stats.n_bytes;
                del->stats->used = MAX(del->stats->used, pmd_stats.used);
                del->stats->tcp_flags |= pmd_stats.tcp_flags;
            }
        }
    }
	else {

		/*��ȡҪɾ����flow��pmd*/
		pmd = dp_netdev_get_pmd(dp, del->pmd_id);
        if (!pmd) {
            return EINVAL;
        }

		/*��pmd��ɾ��flow*/
        error = flow_del_on_pmd(pmd, del->stats, del);

		/*���*/
		dp_netdev_pmd_unref(pmd);
    }


    return error;
}

/*pmd dump�ṹ������dump����revalidator�̻߳��⣬ֻ���һ��revalidator�̴߳���һ��*/
struct dpif_netdev_flow_dump {
    struct dpif_flow_dump up;						/*dpif�ṹ*/
    struct cmap_position poll_thread_pos;			/*��ʶ���ĸ�pmd�߳�node*/
    struct cmap_position flow_pos;					/*������cmap��λ��*/
    struct dp_netdev_pmd_thread *cur_pmd;			/*��ǰpmd�߳�*/
    int status;										/*״̬*/
    struct ovs_mutex mutex;							/*��revalidator�̻߳���*/
};

static struct dpif_netdev_flow_dump *
dpif_netdev_flow_dump_cast(struct dpif_flow_dump *dump)
{
    return CONTAINER_OF(dump, struct dpif_netdev_flow_dump, up);
}

/*******************************************************************************
 ��������  :    dpif_netdev_flow_dump_create
 ��������  :    ����һ��dump
 �������  :  	terse---true
 				type---NULL
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static struct dpif_flow_dump *
dpif_netdev_flow_dump_create(const struct dpif *dpif_, bool terse,
                             char *type OVS_UNUSED)
{
	/*����һ��dump�ṹ*/
    struct dpif_netdev_flow_dump *dump;

	/*dump flowʹ�õĽṹ*/
    dump = xzalloc(sizeof *dump);
	
    dpif_flow_dump_init(&dump->up, dpif_);

	/*���������Ӧ�ò����ؾ�����Ϣ*/
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

/*dump �߳̽ṹ*/
struct dpif_netdev_flow_dump_thread {
    struct dpif_flow_dump_thread up;						/*dump�߳���up�ṹ*/
    struct dpif_netdev_flow_dump *dump;						/*dump�̶߳�Ӧ��dump�ṹ*/
    struct odputil_keybuf keybuf[FLOW_DUMP_MAX_BATCH];		/*��¼match*/
    struct odputil_keybuf maskbuf[FLOW_DUMP_MAX_BATCH];		/*��¼action*/
};

static struct dpif_netdev_flow_dump_thread *
dpif_netdev_flow_dump_thread_cast(struct dpif_flow_dump_thread *thread)
{
    return CONTAINER_OF(thread, struct dpif_netdev_flow_dump_thread, up);
}

/*******************************************************************************
 ��������  :    dpif_netdev_flow_dump_thread_create
 ��������  :    ����dump�߳̽ṹ
 �������  :  	dump_---
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static struct dpif_flow_dump_thread *
dpif_netdev_flow_dump_thread_create(struct dpif_flow_dump *dump_)
{
	/*��ȡstruct dpif_netdev_flow_dump�ṹ��
	  pmd dump�ṹ������dump����revalidator�̻߳��⣬ֻ���һ��revalidator�̴߳���һ��*/
    struct dpif_netdev_flow_dump *dump = dpif_netdev_flow_dump_cast(dump_);
    struct dpif_netdev_flow_dump_thread *thread;

	/*����dump�߳̽ṹ*/
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
 ��������  :    dpif_netdev_flow_dump_next
 ��������  :    ��dp dump 50��flow
 �������  :  	thread---struct dpif_flow_dump_thread  dump flow�õ����߳�
 				flows---��¼dump����dp flow����ת��Ϊ struct dpif_flow
 				max_flows---ÿ�����dump 50��flow
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
dpif_netdev_flow_dump_next(struct dpif_flow_dump_thread *thread_,
                           struct dpif_flow *flows, int max_flows)
{
	/*��ȡ�߳�dump�ṹ*/
    struct dpif_netdev_flow_dump_thread *thread
        = dpif_netdev_flow_dump_thread_cast(thread_);

	/*��ȡdp��dump�ṹ�����̹߳��ã�ֻ���һ��revalidator����һ��*/
    struct dpif_netdev_flow_dump *dump = thread->dump;

	/*dp��flow���� 50��*/
	struct dp_netdev_flow *netdev_flows[FLOW_DUMP_MAX_BATCH];

	int n_flows = 0;
    int i;

	/*��������ȫ��dump�ṹ*/
    ovs_mutex_lock(&dump->mutex);

	/*�����Ի�ȡpmd ȥdump flow*/
    if (!dump->status) {

		/*��ȡdpif�ṹ*/
		struct dpif_netdev *dpif = dpif_netdev_cast(thread->up.dpif);

		/*��ȡdp_netdev*/
        struct dp_netdev *dp = get_dp_netdev(&dpif->dpif);

		/*��ǰdump���߳�*/
		struct dp_netdev_pmd_thread *pmd = dump->cur_pmd;

		/*ÿ��dump 50��flow*/
		int flow_limit = MIN(max_flows, FLOW_DUMP_MAX_BATCH);

		/*û��ָ��pmd ��ȡpmd*/
        /* First call to dump_next(), extracts the first pmd thread.
         * If there is no pmd thread, returns immediately. */
        if (!pmd) {
			
			/*��ȡ��һ��pmd�߳�*/
            pmd = dp_netdev_pmd_get_next(dp, &dump->poll_thread_pos);
            if (!pmd) {
                ovs_mutex_unlock(&dump->mutex);
                return n_flows;

            }
        }

		/*ִ�гɹ���ִ��һ�� dump 50��flow����pmd��û��flow dump��һ��pmd��50��flow*/
		/*�������ȡ�˻�������ͬʱֻ��һ��revalidator�̷߳���pmd��flow*/
        do {
			/*����pmd�ϵ�flow ÿ������50��*/
            for (n_flows = 0; n_flows < flow_limit; n_flows++) {
                struct cmap_node *node;

				/*����pmd�ϵ�flow table��ÿ��1�����ɹ���ȡ�����λ��*/
                node = cmap_next_position(&pmd->flow_table, &dump->flow_pos);
				/*���ڿսڵ���break*/
				if (!node) {
                    break;
                }

				/*��¼���ص�struct dp_netdev_flow*/
                netdev_flows[n_flows] = CONTAINER_OF(node,
                                                     struct dp_netdev_flow,
                                                     node);
            }

			/*�����pmd û��dump��������һ��pmd*/
            /* When finishing dumping the current pmd thread, moves to
             * the next. */
            if (n_flows < flow_limit) {

				/*û��dump �� 50��*/
                memset(&dump->flow_pos, 0, sizeof dump->flow_pos);
                dp_netdev_pmd_unref(pmd);

				/*��ȡ��һ��pmd�߳�*/
                pmd = dp_netdev_pmd_get_next(dp, &dump->poll_thread_pos);
                if (!pmd) {

					/*��pmd����EOF���*/
                    dump->status = EOF;
                    break;
                }
            }

			/*��¼��ǰdump��pmd�߳�*/
            /* Keeps the reference to next caller. */
            dump->cur_pmd = pmd;

            /* If the current dump is empty, do not exit the loop, since the
             * remaining pmds could have flows to be dumped.  Just dumps again
             * on the new 'pmd'. */
        } while (!n_flows);
    }

	/*����������*/
    ovs_mutex_unlock(&dump->mutex);

	/*50��flow*/
    for (i = 0; i < n_flows; i++) {

		/*match*/
        struct odputil_keybuf *maskbuf = &thread->maskbuf[i];

		/*action*/
		struct odputil_keybuf *keybuf = &thread->keybuf[i];

		/*dp ���flow*/
		struct dp_netdev_flow *netdev_flow = netdev_flows[i];

		/*ת��dpif flow*/
		struct dpif_flow *f = &flows[i];
        struct ofpbuf key, mask;

		/*��0*/
        ofpbuf_use_stack(&key, keybuf, sizeof *keybuf);
        ofpbuf_use_stack(&mask, maskbuf, sizeof *maskbuf);

		/*flowת����struct dpif_flow ����f*/
		dp_netdev_flow_to_dpif_flow(netdev_flow, &key, &mask, f,
                                    dump->up.terse);
    }

    return n_flows;
}

/*******************************************************************************
 ��������  :    dpif_netdev_execute
 ��������  :    ִ��flow��action
 �������  :  	execute---dpifִ�нṹ
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
dpif_netdev_execute(struct dpif *dpif, struct dpif_execute *execute)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
	/*��ȡdp*/
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;

	/*dp����������*/
	struct dp_packet_batch pp;

	/*Ҫ����ı���*/
    if (dp_packet_size(execute->packet) < ETH_HEADER_LEN ||
        dp_packet_size(execute->packet) > UINT16_MAX) {
        return EINVAL;
    }

    /* Tries finding the 'pmd'.  If NULL is returned, that means
     * the current thread is a non-pmd thread and should use
     * dp_netdev_get_pmd(dp, NON_PMD_CORE_ID). */

	/*����dp����pmd���鲻�����pmd�߳�*/
    pmd = ovsthread_getspecific(dp->per_pmd_key);
    if (!pmd) {
		/*���pmd�̣߳��鵽��pmd*/
        pmd = dp_netdev_get_pmd(dp, NON_PMD_CORE_ID);
        if (!pmd) {
            return EBUSY;
        }
    }

	/*ִ��probe����*/
    if (execute->probe) {
        /* If this is part of a probe, Drop the packet, since executing
         * the action may actually cause spurious packets be sent into
         * the network. */

		/*��pmd��*/
        if (pmd->core_id == NON_PMD_CORE_ID) {

			/*�ͷŷ�pmd�߳�*/
            dp_netdev_pmd_unref(pmd);
        }
        
        return 0;
    }

    /* If the current thread is non-pmd thread, acquires
     * the 'non_pmd_mutex'. */

	/*��pmd�߳�*/
    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_lock(&dp->non_pmd_mutex);
    }

	/*���·�pmd�߳�������*/
    /* Update current time in PMD context. */
    pmd_thread_ctx_time_update(pmd);

    /* The action processing expects the RSS hash to be valid, because
     * it's always initialized at the beginning of datapath processing.
     * In this case, though, 'execute->packet' may not have gone through
     * the datapath at all, it may have been generated by the upper layer
     * (OpenFlow packet-out, BFD frame, ...). */

	/*RSS invalid�����*/
	if (!dp_packet_rss_valid(execute->packet)) {

		/*���ñ��ĵ�RSS*/
		dp_packet_set_rss_hash(execute->packet,
                               flow_hash_5tuple(execute->flow, 0));
    }

	/*dp�����������ʼ��*/
    dp_packet_batch_init_packet(&pp, execute->packet);

	/*����������ִ��flow��action*/
	dp_netdev_execute_actions(pmd, &pp, false, execute->flow,
                              execute->actions, execute->actions_len);

	/*pmd flush�����˿�Ҫ��������ȥ�ı���*/
	dp_netdev_pmd_flush_output_packets(pmd, true);

	/*��pmd�߳̽������*/
    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_unlock(&dp->non_pmd_mutex);

		/*�ͷ�pmd��Դ*/
        dp_netdev_pmd_unref(pmd);
    }

    return 0;
}

/*******************************************************************************
 ��������  :    dpif_netdev_operate
 ��������  :    dpif�������Ĳ���
 �������  :  	dpif---dp �ӿ������ṹ
 				ops---dp��������ṹ����
 				n_ops---opҪ�������������
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static void
dpif_netdev_operate(struct dpif *dpif, struct dpif_op **ops, size_t n_ops)
{
    size_t i;

	VLOG_DBG("zwl flow dpif_netdev_operate 111");
	
	/*����������Ĳ���*/
    for (i = 0; i < n_ops; i++) 
	{
		/*��dp�Ĳ�������*/
        struct dpif_op *op = ops[i];

        switch (op->type) 
		{
	        case DPIF_OP_FLOW_PUT:
				/*dpif�������·�*/
	            op->error = dpif_netdev_flow_put(dpif, &op->flow_put);
	            break;

	        case DPIF_OP_FLOW_DEL:
				/*dpif������ɾ��*/
	            op->error = dpif_netdev_flow_del(dpif, &op->flow_del);
	            break;

	        case DPIF_OP_EXECUTE:
				/*ִ��flow��action*/
	            op->error = dpif_netdev_execute(dpif, &op->execute);
	            break;

	        case DPIF_OP_FLOW_GET:
				/*��ȡflow*/
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
 ��������  :    parse_affinity_list
 ��������  :    ��¼�����׺͵�CPU id
 �������  :  	affinity_list---CPU���׺���
 				core_ids---�����׺͵ĺ�id
 				n_rxq---���ն��и���
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
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

		/*���ն���id ת����int*/
        if (! str_to_int(key, 0, &rxq_id) || rxq_id < 0
            || !str_to_int(value, 0, &core_id) || core_id < 0) 
        {
            error = EINVAL;
            break;
        }

		/*���ն���id��¼��Ӧ�׺͵ĺ�id*/
        if (rxq_id < n_rxq) 
		{
            core_ids[rxq_id] = core_id;
        }
    }

    free(copy);
    return error;
}

/*******************************************************************************
 ��������  :    dpif_netdev_port_set_rxq_affinity
 ��������  :    ���ö˿��Ͻ��ն��е��׺��ԣ��˿ڿ����Ƕ����
 �������  :  	port---�˿�
 				affinity_list---�׺͵�CPU list
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
/* Parses 'affinity_list' and applies configuration if it is valid. */
static int
dpif_netdev_port_set_rxq_affinity(struct dp_netdev_port *port, const char *affinity_list)
{
    unsigned *core_ids, i;
    int error = 0;

	/*����˿����ж��� CPU��id*/
    core_ids = xmalloc(port->n_rxq * sizeof *core_ids);

	/*��¼���ն����׺͵��߼���id���������һһ��Ӧ*/
	if (parse_affinity_list(affinity_list, core_ids, port->n_rxq)) 
	{
        error = EINVAL;
        goto exit;
    }

	/*�˿�rxq���ж�Ӧ���߼���id ����*/
    for (i = 0; i < port->n_rxq; i++) 
	{
        port->rxqs[i].core_id = core_ids[i];
    }

exit:
    free(core_ids);
    return error;
}


/*******************************************************************************
 ��������  :    dpif_netdev_port_set_config
 ��������  :    ���ö˿�rx���е��׺���
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
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

	/*�˿��׺�������*/
    const char *affinity_list = smap_get(cfg, "pmd-rxq-affinity");

    ovs_mutex_lock(&dp->port_mutex);
    error = get_port_by_number(dp, port_no, &port);
    if (error || !netdev_is_pmd(port->netdev)
        || nullable_string_is_equal(affinity_list, port->rxq_affinity_list)) {
        goto unlock;
    }

	/*���ö˿�rx���е��׺���*/
    error = dpif_netdev_port_set_rxq_affinity(port, affinity_list);
    if (error) {
        goto unlock;
    }
    free(port->rxq_affinity_list);
	
    port->rxq_affinity_list = nullable_xstrdup(affinity_list);

	/*��������dp*/
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
 ��������  :    dp_netdev_actions_create
 ��������  :    
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
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
 ��������  :    dp_netdev_flow_get_actions
 ��������  :    ��ȡ�����action
 �������  :    
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
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
 ��������  :    dp_netdev_rxq_set_cycles
 ��������  :    ���ն�������ѭ��
 �������  :    rx---���ն���
 			    type---ͳ������---RXQ_CYCLES_PROC_CURR
 			    cycles---����poll�Ĵ���
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static void
dp_netdev_rxq_set_cycles(struct dp_netdev_rxq *rx, enum rxq_cycles_counter_type type, unsigned long long cycles)
{
   /*����poll�Ĵ�����ֵ*/	
   atomic_store_relaxed(&rx->cycles[type], cycles);
}

/*******************************************************************************
 ��������  :  dp_netdev_rxq_add_cycles
 ��������  :  ���ն������ѭ��
 �������  :  rx---���ն���	
 			  type---����ͳ������ RXQ_CYCLES_PROC_CURR
 			  cycles---������ѭ������
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static void
dp_netdev_rxq_add_cycles(struct dp_netdev_rxq *rx, enum rxq_cycles_counter_type type, unsigned long long cycles)
{
	/*����ͳ��*/
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
 ��������  :    dp_netdev_rxq_get_intrvl_cycles
 ��������  :    ��ȡpoll����ʱ�����ݶ�����
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
static uint64_t
dp_netdev_rxq_get_intrvl_cycles(struct dp_netdev_rxq *rx, unsigned idx)
{
    unsigned long long processing_cycles;

	/*��ȡpoll����ʱ�����ݶ����� ����Ϊ6*/
    atomic_read_relaxed(&rx->cycles_intrvl[idx], &processing_cycles);
    return processing_cycles;
}

#if ATOMIC_ALWAYS_LOCK_FREE_8B

/*******************************************************************************
 ��������  :    pmd_perf_metrics_enabled
 ��������  :    ��ȡ����ͳ���Ƿ�������
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
static inline bool
pmd_perf_metrics_enabled(const struct dp_netdev_pmd_thread *pmd)
{
    bool pmd_perf_enabled;

	/*��ȡ����ͳ���Ƿ���*/
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
 ��������  :  dp_netdev_pmd_flush_output_on_port
 ��������  :  pmd���Ͷ˿ڴ����͵��������ķ���ȥ
 �������  :  pmd---pmd�߳�
 			  p---pmd����ķ��˿�
 �������  :  output_cnt---�ɹ����ı���
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
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

	/*ѭ����ʱ������*/
    cycle_timer_start(&pmd->perf_stats, &timer);

	/*�˿�ʹ�ö�̬���Ͷ��п���ʹ��*/
    dynamic_txqs = p->port->dynamic_txqs;
    if (dynamic_txqs) 
	{
		/*�ӷ��Ͷ���ID�ػ�ȡ���Ͷ���ID����̬����*/
        tx_qid = dpif_netdev_xps_get_tx_qid(pmd, p);
    } 
	else 
	{
		/*pmd����ʱָ���ľ�̬������id���Ӷ��г����ҵ�һ�����е�*/
        tx_qid = pmd->static_tx_qid;
    }

	/*�˿ڵȴ�Ҫ�������������ĸ���*/
    output_cnt = dp_packet_batch_size(&p->output_pkts);
    ovs_assert(output_cnt > 0);

	/*�������ķ���ȥ����tx_qid ������*/
    netdev_send(p->port->netdev, tx_qid, &p->output_pkts, dynamic_txqs);

	/*�����������ʼ��*/
	dp_packet_batch_init(&p->output_pkts);

    /* Update time of the next flush. */
	/*��ȡ����ʱ��*/
    atomic_read_relaxed(&pmd->dp->tx_flush_interval, &tx_flush_interval);

	/*�����´η��ͱ���flushʱ��*/
	p->flush_time = pmd->ctx.now + tx_flush_interval;

	/*���걨����ʣ�౨��*/
    ovs_assert(pmd->n_output_batches > 0);

	/*�������������ļ���--*/
	pmd->n_output_batches--;

	/*����ȥ�İ�����ͳ��*/
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_SENT_PKTS, output_cnt);

	/*������������ͳ��*/
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_SENT_BATCHES, 1);

    /* Distribute send cycles evenly among transmitted packets and assign to
     * their respective rx queues. */
    /*ѭ��ʱ�䶨ʱ��ʱ��ֹͣ*/
    cycles = cycle_timer_stop(&pmd->perf_stats, &timer) / output_cnt;

	/*�����˿ڷ���ȥ���������ĸ���*/
	for (i = 0; i < output_cnt; i++) 
	{
		/*��������ָ���������*/
        if (p->output_pkts_rxqs[i]) 
		{
			/*����ͳ��*/
            dp_netdev_rxq_add_cycles(p->output_pkts_rxqs[i], RXQ_CYCLES_PROC_CURR, cycles);
        }
    }

	/*�˿ڷ������ļ���*/
    return output_cnt;
}

/*******************************************************************************
 ��������  :    dp_netdev_pmd_flush_output_packets
 ��������  :    pmd flush�����˿�Ҫ��������ȥ�ı���
 �������  :    pmd---pmd�߳�
 			    force---�Ƿ�ǿ��ˢ����
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
dp_netdev_pmd_flush_output_packets(struct dp_netdev_pmd_thread *pmd, bool force)
{
    struct tx_port *p;
	
    int output_cnt = 0;

	/*���ӿ�����������Ϊ0ֱ�ӷ���*/
    if (!pmd->n_output_batches) 
	{
        return 0;
    }

	/*����pmd����ķ��˿������ѷ��˿��ϴ��������������汨�ķ���*/
    HMAP_FOR_EACH (p, node, &pmd->send_port_cache) 
   	{
		/*�������汨������Ϊ�� �� ������ǿ�Ʒ��Ϳ��� �� ��ǰʱ����ڵ����ϴη���ʱ��*/
        if (!dp_packet_batch_is_empty(&p->output_pkts) && (force || pmd->ctx.now >= p->flush_time)) 
       	{
           	/*����ˢ�����˿�*/ 
            output_cnt += dp_netdev_pmd_flush_output_on_port(pmd, p);
        }
    }

	/*���ط��͵ı�����*/
    return output_cnt;
}

/*******************************************************************************
 ��������  :    dp_netdev_process_rxq_port
 ��������  :    ����netdev���հ����̣�������ձ���
 			    1.���ýӿ�dp_netdev_input�C>dp_netdev_input__������
 			    2.����packet_batch_execute�C>dp_netdev_execute_actionsִ��actions������
 �������  :    pmd---port rx��������pmd�߳̽ṹ
 		        rxq---poll�Ľ��ն���
 		        port_no---poll���հ��˿�
 �������  :	
 �� �� ֵ  : 	����port rx���еı�����
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
dp_netdev_process_rxq_port(struct dp_netdev_pmd_thread *pmd, struct dp_netdev_rxq *rxq, odp_port_t port_no)
{
	/*����ͳ��*/
    struct pmd_perf_stats *s = &pmd->perf_stats;

	/*���б�����������ṹ*/
    struct dp_packet_batch batch;

	/*ѭ����ʱ��*/
	struct cycle_timer timer;

	int error;

	/*�����������汨�ļ���*/
    int batch_cnt = 0;

	/*�����е�ǰ���ĸ���*/
    int rem_qlen = 0, *qlen_p = NULL;
    uint64_t cycles;

    /* Measure duration for polling and processing rx burst. */
	/*ѭ����ʱ����ʼ*/
    cycle_timer_start(&pmd->perf_stats, &timer);

	/*��¼�����ȡ�Ķ���*/
    pmd->ctx.last_rxq = rxq;

	/*����������ṹ��ʼ��*/
    dp_packet_batch_init(&batch);

    /* Fetch the rx queue length only for vhostuser ports. */
	/*��ȡ����ͳ���Ƿ������أ���ȡ���ն��г��ȡ�������������������*/
    if (pmd_perf_metrics_enabled(pmd) && rxq->is_vhost) 
	{
		/*��ǰ���б��ĸ��������г��ȼ�¼*/
        qlen_p = &rem_qlen;
    }

    /*�ӽ��ն����հ�����������ṹ�����б��Ĵ���Ķ���������Ľṹ*/
    error = netdev_rxq_recv(rxq->rx, &batch, qlen_p);
	
	VLOG_DBG("rxq recv ok")

	/*������poll���˱���*/
    if (!error) 
	{
        /* At least one packet received. */
		
        *recirc_depth_get() = 0;

		/*pmd�߳������ĸ���(��ǰʱ��)*/
        pmd_thread_ctx_time_update(pmd);

		/*�����������ļ������Ӷ���poll���ı����ȷ���������*/
		batch_cnt = batch.count;

		/*pmd ����ͳ�ƿ���ʹ��*/
        if (pmd_perf_metrics_enabled(pmd)) 
		{
            /* Update batch histogram. */

			/*��ǰ��������ͳ�ƣ�������������ı���*/
            s->current.batches++;

			/*��������������ͼ���*/
            histogram_add_sample(&s->pkts_per_batch, batch_cnt);

			/* Update the maximum vhost rx queue fill level. */

			/*����Ϊ�����������С���ǰ���б��ĸ��������г��ȼ�¼*/
            if (rxq->is_vhost && rem_qlen >= 0) 
			{
				/*�������뱨����������������*/
                uint32_t qfill = batch_cnt + rem_qlen;

				/*�����б��������ڼ�¼��������������б�����*/
                if (qfill > s->current.max_vhost_qfill) 
				{
					/*�����������б���������*/
                    s->current.max_vhost_qfill = qfill;
                }
            }
        }
		
        /* Process packet batch.*/
        /*��������batch�еİ�ת��datapath ��emc��dpcls�Ȳ���������flow ��action�����ҷ��ͱ��ģ�ǰ���м�ʱ*/
        dp_netdev_input(pmd, &batch, port_no);

        /* Assign processing cycles to rx queue. */
		/*���ն��д���ѭ��ֹͣ*/
        cycles = cycle_timer_stop(&pmd->perf_stats, &timer);

		/*���ն������ѭ��*/
        dp_netdev_rxq_add_cycles(rxq, RXQ_CYCLES_PROC_CURR, cycles);

		/*pmd flush�� pmd output pkt Ҫ���ı���*/
        dp_netdev_pmd_flush_output_packets(pmd, false);
    }
	else 
	{
        /* Discard cycles. */
		/*����ѭ��*/
        cycle_timer_stop(&pmd->perf_stats, &timer);
		
        if (error != EAGAIN && error != EOPNOTSUPP)
		{
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            VLOG_ERR_RL(&rl, "error receiving data from %s: %s", netdev_rxq_get_name(rxq->rx), ovs_strerror(error));
        }
    }

    pmd->ctx.last_rxq = NULL;

	/*����������*/
    return batch_cnt;
}

/*******************************************************************************
 ��������  :  tx_port_lookup
 ��������  :  pmd���Ͷ˿ڵı���
 �������  :  pmd---flow ����pmd
 			  port_no---output�˿�
 			  
 �������  :  
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static struct tx_port *
tx_port_lookup(const struct hmap *hmap, odp_port_t port_no)
{
    struct tx_port *tx;

	/*���з��˿�*/
    HMAP_FOR_EACH_IN_BUCKET (tx, node, hash_port_no(port_no), hmap) 
   	{
   		/*���з��˿�*/
        if (tx->port->port_no == port_no) 
		{
            return tx;
        }
    }

    return NULL;
}

/*******************************************************************************
 ��������  :    port_reconfigure
 ��������  :    �˿���������
 �������  :  	port---�������ö˿�
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
port_reconfigure(struct dp_netdev_port *port)
{
	/*port ��Ӧnet�ṹ*/
    struct netdev *netdev = port->netdev;
    int i, err;

    /* Closes the existing 'rxq's. */

	/*1.�ر��ͷŶ˿������ն���*/
    for (i = 0; i < port->n_rxq; i++) 
	{
        netdev_rxq_close(port->rxqs[i].rx);

		/*���ն��и���*/
        port->rxqs[i].rx = NULL;
    }

	/*�ϴ����õ�port�ն�������port��Ӧ�����*/
    unsigned last_nrxq = port->n_rxq;

	/*�˿ڶ�����0*/
    port->n_rxq = 0;

    /* Allows 'netdev' to apply the pending configuration changes. */

	/*�˿�netdev�����䣬��port��Ҫ��������*/
    if (netdev_is_reconf_required(netdev) || port->need_reconfigure) 
	{
		/*�˿�netdev�������á����������������к�*/
        err = netdev_reconfigure(netdev);
        if (err && (err != EOPNOTSUPP)) 
		{
            VLOG_ERR("Failed to set interface %s new configuration", netdev_get_name(netdev));
            return err;
        }
    }

	/* If the netdev_reconfigure() above succeeds, reopens the 'rxq's. */
	/*��������˿ڽ��ն���*/		  /*�˿��ն��нṹ*/   /*�˿��ն��и���*/
	/*����һ���˿�����4��rx����*/
    port->rxqs = xrealloc(port->rxqs, sizeof *port->rxqs * netdev_n_rxq(netdev));

	/* Realloc 'used' counters for tx queues. */
    free(port->txq_used);

	/*�������뷢�������ô�����¼�ṹ����unsigned�������и��������ô�����¼�ṹ unsigned*/
    port->txq_used = xcalloc(netdev_n_txq(netdev), sizeof *port->txq_used);

	/*�����˿ڽ��ն���*/
    for (i = 0; i < netdev_n_rxq(netdev); i++) 
	{
	    /*�ϴ����õĶ������Ѵ����ϴ����õ��ն�����*/
        bool new_queue = i >= last_nrxq;
		
        if (new_queue) 
		{
            memset(&port->rxqs[i], 0, sizeof port->rxqs[i]);
        }

		/*�˿ڽ��ն��й���port*/
        port->rxqs[i].port = port;

		/*���ն��б���Ƿ���dpdkvhost*/
        port->rxqs[i].is_vhost = !strncmp(port->type, "dpdkvhost", 9);

		/*�򿪶˿ڽ��ն��� ������rxq*/
        err = netdev_rxq_open(netdev, &port->rxqs[i].rx, i);
        if (err) 
		{
            return err;
        }

		/*���ն���++*/
        port->n_rxq++;
    }

    /* Parse affinity list to apply configuration for new queues. */
	/*���ý��ն��е�cpu�׺���*/
    dpif_netdev_port_set_rxq_affinity(port, port->rxq_affinity_list);

    /* If reconfiguration was successful mark it as such, so we can use it */
    port->need_reconfigure = false;

    return 0;
}

/*numa�ڵ�list*/
struct rr_numa_list {
    struct hmap numas;  /* Contains 'struct rr_numa' */
};

/*numa�ڵ�*/
struct rr_numa {
    struct hmap_node node;

    int numa_id;										/*numa id*/

    /* Non isolated pmds on numa node 'numa_id' */
    struct dp_netdev_pmd_thread **pmds;				/*numa�ϷǸ����pmd*/
    int n_pmds;											/*numa��pmd����*/

    int cur_index;
    bool idx_inc;
};

/*******************************************************************************
 ��������  :    rr_numa_list_lookup
 ��������  :    ����numa_id ��numa ������numa�ڵ�
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
static struct rr_numa *
rr_numa_list_lookup(struct rr_numa_list *rr, int numa_id)
{
    struct rr_numa *numa;

	/*����numa_id ��numa ������numa�ڵ�*/
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
 ��������  :    rr_numa_list_next
 ��������  :    ������һ����ѯnuma�ڵ�
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/

/* Returns the next node in numa list following 'numa' in round-robin fashion.
 * Returns first node if 'numa' is a null pointer or the last node in 'rr'.
 * Returns NULL if 'rr' numa list is empty. */
static struct rr_numa *
rr_numa_list_next(struct rr_numa_list *rr, const struct rr_numa *numa)
{
    struct hmap_node *node = NULL;

	/*��ѯnuma�ڵ��������һ��*/
    if (numa) {
        node = hmap_next(&rr->numas, &numa->node);
    }
    if (!node) {
        node = hmap_first(&rr->numas);
    }

    return (node) ? CONTAINER_OF(node, struct rr_numa, node) : NULL;
}

/*******************************************************************************
 ��������  :    rr_numa_list_populate
 ��������  :    numa��ѯ�����ʼ��
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
rr_numa_list_populate(struct dp_netdev *dp, struct rr_numa_list *rr)
{
    struct dp_netdev_pmd_thread *pmd;
    struct rr_numa *numa;

	/*numa��ѯ����*/
    hmap_init(&rr->numas);

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {

		/*�����Ѹ����pmd�ͷ�pmd��*/
        if (pmd->core_id == NON_PMD_CORE_ID || pmd->isolated) {
            continue;
        }

		/*���ݲ�ѯnuma�ڵ�*/
        numa = rr_numa_list_lookup(rr, pmd->numa_id);
        if (!numa) {

			/*���������½���������*/
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
 ��������  :    rr_numa_get_pmd
 ��������  :    ������ݼ�˳����е�numa�ڵ㷵����һ��pmd
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
 ��������  :    rr_numa_list_destroy
 ��������  :    numa ��destroy
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
 ��������  :    compare_rxq_cycles
 ��������  :    �ԱȽ��ն���
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
 ��������  :    rxq_scheduling
 ��������  :    ���а���cpu��������Ӧ��pmd�̱߳��Ϊ����
 				1.port �Ķ���У����ݶ��ж�Ӧ��core id �ָ�ĳ��pmd������ж�Ӧ��pmd
 �������  :  	pinned---�̶���ǣ�true
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
rxq_scheduling(struct dp_netdev *dp, bool pinned) OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;

	/*numa�ڵ�list*/
    struct rr_numa_list rr;

	/*�Ǳ���numa ��ѯ��*/
    struct rr_numa *non_local_numa = NULL;	
    struct dp_netdev_rxq ** rxqs = NULL;
    int n_rxqs = 0;
    struct rr_numa *numa = NULL;
    int numa_id;

	/*����dp�ϵ�port���������˿�rxq*/
    HMAP_FOR_EACH (port, node, &dp->ports) 
	{
		/*port�Ƿ�pmd������*/
        if (!netdev_is_pmd(port->netdev)) 
		{
            continue;
        }

		/*�����˿��ն��У�����ʹ�õ�pmd*/
        for (int qid = 0; qid < port->n_rxq; qid++) 
		{
			/*��ȡ�˿ڽ��ն���*/
            struct dp_netdev_rxq *q = &port->rxqs[qid];

			/*�̶���� �˿�rxq�����Ѱ��߼��ˣ��������׺��ԾͲ���OVS_CORE_UNSPEC*/
            if (pinned && q->core_id != OVS_CORE_UNSPEC) 
			{
                struct dp_netdev_pmd_thread *pmd;

				/*����port rx �����趨��core_id����pmd �����ȡ��Ӧpmd�̣߳�һ��һ��pmd��Ӧһ������*/
                pmd = dp_netdev_get_pmd(dp, q->core_id);
                if (!pmd) 
				{
					/*����û�а�pmd�߳�*/
                    VLOG_WARN("There is no PMD thread on core %d. Queue "
                              "%d on port \'%s\' will not be polled.",
                              q->core_id, qid, netdev_get_name(port->netdev));
                } 
				else 
				{
					/*port rx���й�����pmd����port �����趨��core id�������ĸ�pmd����pmd��Ӧ�����*/
                    q->pmd = pmd;

					/*pmd����Ϊ�����*/
                    pmd->isolated = true;

					/*pmd������δ����*/
                    dp_netdev_pmd_unref(pmd);
                }
            } 

			/*port rx�����߼��˴���δָ���׺��Ե�rxq������˵ȫ�������׺������ﲻӦ���У��ж���δ�����׺���,û�и����а�cpu������ֵķ�������*/
			else if (!pinned && q->core_id == OVS_CORE_UNSPEC) 
			{
                uint64_t cycle_hist = 0;

				/*������ն���*/
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
					/*��ȡpoll����ʱ�����ݶ����� ����*/
                    cycle_hist += dp_netdev_rxq_get_intrvl_cycles(q, i);
                }

				/*���ն�������cycle*/
                dp_netdev_rxq_set_cycles(q, RXQ_CYCLES_PROC_HIST, cycle_hist);

                /* Store the queue. */
				/*��¼���У���Ҫ���ȷ���pmdȥpoll�Ķ���*/
                rxqs[n_rxqs++] = q;
            }
        }
    }

	/*δ�����׺��Ե�rx���в�ֹ1��*/
    if (n_rxqs > 1) 
	{
        /* Sort the queues in order of the processing cycles
         * they consumed during their last pmd interval. */
        /*������������*/
        qsort(rxqs, n_rxqs, sizeof *rxqs, compare_rxq_cycles);
    }

	/*numa��ѯ�����ʼ��*/
    rr_numa_list_populate(dp, &rr);
	
    /* Assign the sorted queues to pmds in round robin. */

	/*����port�Ľ��ն��У���ѭ����ʽ��������Ķ��з����pmds*/
	for (int i = 0; i < n_rxqs; i++) 
	{
		/*��ȡnetdev����numa*/
        numa_id = netdev_get_numa_id(rxqs[i]->port->netdev);

		/*����numa_id ��numa ������numa�ڵ㣬���û�ҵ�˵��numa��û�зǸ����pmd�̣߳�numa��û�����߼���*/
		numa = rr_numa_list_lookup(&rr, numa_id);
        if (!numa) 
		{
			
            /* There are no pmds on the queue's local NUMA node.
               Round robin on the NUMA nodes that do have pmds. */

			/*���еı���NUMA�ڵ���û��PMD�̡߳��ھ���pmd��NUMA�ڵ��Ͻ�����ѯ���ȣ����û���ҵ�������pmd�߳�δ�����numa�ڵ�continue*/
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

			/*������ݼ�˳����е�numa�ڵ㷵����һ��pmd*/
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
			/*������ݼ�˳����е�numa�ڵ㷵����һ��pmd*/
			rxqs[i]->pmd = rr_numa_get_pmd(numa);
	        VLOG_INFO("Core %d on numa node %d assigned port \'%s\' "
	                  "rx queue %d (measured processing cycles %"PRIu64").",
	                  rxqs[i]->pmd->core_id, numa_id,
	                  netdev_rxq_get_name(rxqs[i]->rx),
	                  netdev_rxq_get_queue_id(rxqs[i]->rx),
	                  dp_netdev_rxq_get_cycles(rxqs[i], RXQ_CYCLES_PROC_HIST));
        }
    }


	/*numa ��destroy*/	
    rr_numa_list_destroy(&rr);
    free(rxqs);
}

/*******************************************************************************
 ��������  :    reload_affected_pmds
 ��������  :    ������Ӱ���pmd�߳�=δɾ�����µ�pmd�̣߳���������poll�߳�������Ҫ���ص�pmd�߳�
 				dp������Ҫ���ص�pmd�̣߳������ʣ���pmd���¼��ء�����ɾ������ķ��˿��ϵı���
 �������  :  	dp---������ṹ
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
reload_affected_pmds(struct dp_netdev *dp)
{
    struct dp_netdev_pmd_thread *pmd;

	/*����dp������pmd�߳�������Ҫ���ص�pmd�̣߳�������pmd��Ҫreload*/
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) 
    {
    	/*��������pmd��Ҫreload����������µ�pmd��������pmd��Ҫreload*/
        if (pmd->need_reload) 
		{
			/*ɾ��pmd�ϻ������������*/
            flow_mark_flush(pmd);

			/*����pmd�߳�*/
            dp_netdev_reload_pmd__(pmd);

			/*�������false*/
			pmd->need_reload = false;
        }
    }
}
/*******************************************************************************
 ��������  :    reconfigure_pmd_threads
 ��������  :    ��������pmd�̡߳�ɾ�������ڵ���pmd�������µ�pmd
 				1.dp������Ҫ���ص�pmd�߳�
 				2.����������pmd�̣߳���ʼ������dp poll����
 �������  :  	dp---������
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
reconfigure_pmd_threads(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex)
{
	/*pmd�߳�*/
    struct dp_netdev_pmd_thread *pmd;

	/*pmd�߳�numa��Ϣ ʹ�õ�CPU����Ϣ*/
    struct ovs_numa_dump *pmd_cores;

	/*numa �߼��� id ��*/
    struct ovs_numa_info_core *core;

	/*��ɾ��hmap�ṹ*/
    struct hmapx to_delete = HMAPX_INITIALIZER(&to_delete);

	/*hmap�ڵ� ����ͷ*/
	struct hmapx_node *node;

	bool changed = false;

	/*�Ƿ���Ҫ������̬���Ͷ���ids*/
	bool need_to_adjust_static_tx_qids = false;

    /* The pmd threads should be started only if there's a pmd port in the
     * datapath.  If the user didn't provide any "pmd-cpu-mask", we start
     * NR_PMD_THREADS per numa node. */

	/*ֻ����pmd ���ж˿�ʱ��pmd�̲߳�����������û�û���ṩpmdʹ�õ�cpu���룬������ÿnuma �ڵ�����NR_PMD_THREADS=1 �߳�*/
	

	/*���dp port�����Ƿ��ж˿ڣ����û�ж˿ڣ�pmd_cores Ϊ��*/
    if (!has_pmd_port(dp)) 
	{
		/*pmd��û�ж˿ڣ�ÿ��numa��0��CPU����Ϣ����dump��numaҪ����dump�ĺ���Ϊ0*/
        pmd_cores = ovs_numa_dump_n_cores_per_numa(0);
    }
	/*dp����port��Ȼ���������µ����룬pmdռ��CPU �����ַ���ָ��pmd_cmask��Ϊ�գ�pmd_cmask[0]��Ϊ�գ���ȡ��������numa��Ϣ*/
	else if (dp->pmd_cmask && dp->pmd_cmask[0]) 
	{
		/*��������λ�ĺ�id��������numa�ڵ㣬numa�ڵ���dump*/
        pmd_cores = ovs_numa_dump_cores_with_cmask(dp->pmd_cmask);
    } 
	else 
	{
		/*û����pmd����ÿ��numa��1��CPU ������dump������Ϊ1*/
        pmd_cores = ovs_numa_dump_n_cores_per_numa(NR_PMD_THREADS);
    }

	/* ������������ü�����pmd�̣߳�pmd������ô������Ҫ���������еĸ���*/
    /* We need to adjust 'static_tx_qid's only if we're reducing number of
     * PMD threads. Otherwise, new threads will allocate all the freed ids. */

	/*dump�ϵ�core��С���߳�����������Ҫ������̬�����и�����ǣ�һ�����̶߳�Ӧһ��������*/
	if (ovs_numa_dump_count(pmd_cores) < cmap_count(&dp->poll_threads) - 1) 
	{
        /* Adjustment is required to keep 'static_tx_qid's sequential and
         * avoid possible issues, for example, imbalanced tx queue usage
         * and unnecessary locking caused by remapping on netdev level. */

		/*������Ҫɾ����pmd����Ҫ������̬�����и�����ǣ���Ϊÿ��pmdһ��������*/
        need_to_adjust_static_tx_qids = true;
    }

	/*��������pmd�̣߳�pmd�߳�ʹ�õ�CPU�����������pmd�̼߳���ɾ���У�����pmd�߳�����reload���*/
    /* Check for unwanted pmd threads */
	/*����������Ҫ��pmd�߳�*/
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) 
    {
    	/*��������ʹ��pmd cpu�˵�pmd*/
        if (pmd->core_id == NON_PMD_CORE_ID) 
		{
            continue;
        }

		/*pmd numa id core_id ��Ӧ��cpu���Ѳ���������dump��¼�dump��¼numa��ˣ�numa����to_delete*/
        if (!ovs_numa_dump_contains_core(pmd_cores, pmd->numa_id, pmd->core_id)) 
		{
			/*pmdʹ�õ�CPU�ѱ������ڵ���pmd��ӵ���ɾ��hmapx*/
            hmapx_add(&to_delete, pmd);
        }
		/*������Ҫɾ����pmd����Ҫ������̬�����и�����ǣ���Ϊÿ��pmdһ�������У������µ�pmd����reload���*/
		else if (need_to_adjust_static_tx_qids) 
		{
			/*δɾ����pmd��reload�������true��pmd�������̬������*/
            pmd->need_reload = true;
        }
    }

	/*������ɾ��pmd�ڵ���to_delete��ɾ��pmd�������ڵ���pmd������to_delete����*/
    HMAPX_FOR_EACH (node, &to_delete) 
	{
		/*��ȡpmd�߳�*/
        pmd = (struct dp_netdev_pmd_thread *) node->data;
		
        VLOG_INFO("PMD thread on numa_id: %d, core id: %2d destroyed.", pmd->numa_id, pmd->core_id);

		/*��������ɾ������Ҫ��pmd�̣߳�֮ǰpmdʹ�õ�CPU�ѱ������ڵ���flush�����滺��ı��ġ�����*/
		/* 1.�ͷ�pmd������������
		   2.����pmd�ϻ���ķ��˿ڴ������ı���
 		   3.�ͷŷ�����
 		   4.ɾ��pmd�Ϸ�port��poll������poll�ڵ�
 		*/
		dp_netdev_del_pmd(dp, pmd);
    }

	/*to_delete����Ϊ��*/
    changed = !hmapx_is_empty(&to_delete);

	/*ɾ��to_delete�ṹ*/
	hmapx_destroy(&to_delete);

	/*��Ҫ������̬������*/
    if (need_to_adjust_static_tx_qids) 
	{
        /* 'static_tx_qid's are not sequential now.
         * Reload remaining threads to fix this. */
         
        /*��̬���Ͷ��еĵ�ǰ����˳��ġ����¼���ʣ���߳����޸�������*/

		/*dp������Ҫ���ص�pmd�߳�=��������µ�pmd�������ʣ���pmd���¼��ء�����ɾ������ķ��˿��ϵı���*/
        reload_affected_pmds(dp);
    }

    /* Check for required new pmd threads */
	/*�������������µ�pmd_cores���鿴�����Ƿ��Ѿ���pmd��û���������µ�pmd�߳�*/
    FOR_EACH_CORE_ON_DUMP(core, pmd_cores) 
    {
    	/* ����core_id ��pmd�߳������ȡ�˶�Ӧpmd��һ��pmdռ�ö����*/
		/*�鿴core �Ƿ��Ѿ���pmdռ��*/
        pmd = dp_netdev_get_pmd(dp, core->core_id);

		/*��coreû��pmdռ��*/
        if (!pmd) 
		{
			/*��ȡ��ȥ����һ��pmd*/
            pmd = xzalloc(sizeof *pmd);

			/*�����߼��˸�������pmd�̣߳���ʼ������dp pmd poll�߳�����*/
            dp_netdev_configure_pmd(pmd, dp, core->core_id, core->numa_id);

			/*��������pmd�߳�*/
            pmd->thread = ovs_thread_create("pmd", pmd_thread_main, pmd);
            VLOG_INFO("PMD thread on numa_id: %d, core id: %2d created.", pmd->numa_id, pmd->core_id);
            changed = true;
        } 
		else 
		{
			/*���ѱ�pmd�߳�ռ��*/
            dp_netdev_pmd_unref(pmd);
        }
    }

	/*����и��»���Ҫɾ��pmd��ɾ����������pmd*/
    if (changed) 
	{
        struct ovs_numa_info_numa *numa;

        /* Log the number of pmd threads per numa node. */

		/*��¼ÿ��numa�ڵ��pmd�߳���*/
        FOR_EACH_NUMA_ON_DUMP (numa, pmd_cores) 
        {
        	VLOG_INFO("There are %"PRIuSIZE" pmd threads on numa node %d", numa->n_cores, numa->numa_id);
        }
    }

	/*destroy��������dump�ṹ*/
    ovs_numa_dump_destroy(pmd_cores);
}

/*******************************************************************************
 ��������  :    pmd_remove_stale_ports
 ��������  :    ��pmd�߳���ɾ��������ɾ���Ķ˿ڻ���Ҫ�������õĶ˿�
 �������  :  	dp--������ṹ
 				pmd---������pmd��ȡɾ���ѱ�ɾ���Ķ˿�
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
pmd_remove_stale_ports(struct dp_netdev *dp, struct dp_netdev_pmd_thread *pmd)
    OVS_EXCLUDED(pmd->port_mutex)
    OVS_REQUIRES(dp->port_mutex)
{
    struct rxq_poll *poll, *poll_next;
    struct tx_port *tx, *tx_next;

    ovs_mutex_lock(&pmd->port_mutex);

	/*����pmd poll_list��ȡһ��poll�ṹ�������н��ն���*/
	HMAP_FOR_EACH_SAFE (poll, poll_next, node, &pmd->poll_list) 
	{
		/*poll�ṹ�ڵ��ϵĽ��ն��ж�Ӧ��port*/
        struct dp_netdev_port *port = poll->rxq->port;

		/*�˿���Ҫ�������ã���dp��port��������ɾ����port����poll�ڵ���ɾ��*/
        if (port->need_reconfigure || !hmap_contains(&dp->ports, &port->node)) 
        {
        	/*poll�ṹ�ڵ��pmdɾ��*/
            dp_netdev_del_rxq_from_pmd(pmd, poll);
        }
    }

	/*����pmd���˿�*/
	HMAP_FOR_EACH_SAFE (tx, tx_next, node, &pmd->tx_ports) 
	{
		/*��ȡ�����ж˿�*/
        struct dp_netdev_port *port = tx->port;

		/*�˿���Ҫ�������ã���dp��port��������ɾ����port����poll�ڵ���ɾ��*/
        if (port->need_reconfigure || !hmap_contains(&dp->ports, &port->node)) 
		{
			/*pmdɾ�����˿ڽڵ�*/
            dp_netdev_del_port_tx_from_pmd(pmd, tx);
        }
    }
    ovs_mutex_unlock(&pmd->port_mutex);
}

/* Must be called each time a port is added/removed or the cmask changes.
 * This creates and destroys pmd threads, reconfigures ports, opens their
 * rxqs and assigns all rxqs/txqs to pmd threads. */
 /*******************************************************************************
 ��������  :    reconfigure_datapath
 ��������  :    �˿ڸ��£���������������
 �������  :  	dp---netdev������ṹ
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
reconfigure_datapath(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev_port *port;
    int wanted_txqs;

	/*�ϴ�dp������ż�¼��last_reconfigure_seq*/
    dp->last_reconfigure_seq = seq_read(dp->reconfigure_seq);

    /* Step 1: Adjust the pmd threads based on the datapath ports, the cores
     * on the system and the user configuration. */

	/*����������pmd�߳���������pmd���øı䡢�˿���ɾ */
    reconfigure_pmd_threads(dp);

	/*��Ҫ�ķ��Ͷ�����=����pmd�߳�����ÿ��poll�߳�һ��*/
    wanted_txqs = cmap_count(&dp->poll_threads);

    /* The number of pmd threads might have changed, or a port can be new:
     * adjust the txqs. */

	/*����dp�˿ڽڵ�����������Ͷ�������ÿ���˿����ö෢�Ͷ��С������������poll�߳�����ÿ��poll�߳�һ��������*/
    HMAP_FOR_EACH (port, node, &dp->ports) 
    {
    	/*netdev���ö෢�Ͷ�����=����pmd�߳������˿ڶ�Ӧÿ��pmdһ��������*/
        netdev_set_tx_multiq(port->netdev, wanted_txqs);
    }

    /* Step 2: Remove from the pmd threads ports that have been removed or
     * need reconfiguration. */

    /* Check for all the ports that need reconfiguration.  We cache this in
     * 'port->need_reconfigure', because netdev_is_reconf_required() can
     * change at any time. */

	/*����dp�˿�����ڵ㣬����δɾ����port �������ر��*/
	HMAP_FOR_EACH (port, node, &dp->ports) 
    {
    	/*������ϴ�������Ų�һ�µĶ˿ڶ���Ҫ���䣬�ɶ˿ڡ������˿�*/
        if (netdev_is_reconf_required(port->netdev)) 
		{
			/*�˿���Ҫ��������*/
            port->need_reconfigure = true;
        }
    }

    /* Remove from the pmd threads all the ports that have been deleted or
     * need reconfiguration. */

	/*������pmd�߳���ɾ��������ɾ���Ķ˿���Դ����Ҫ�������õĶ˿�*/
	CMAP_FOR_EACH (pmd, node, &dp->poll_threads) 
    {
        pmd_remove_stale_ports(dp, pmd);
    }

    /* Reload affected pmd threads.  We must wait for the pmd threads before
     * reconfiguring the ports, because a port cannot be reconfigured while
     * it's being used. */

	/*���¼�����Ӱ���pmd�̡߳����Ǳ����ȵȴ�pmd�߳��������ö˿ڣ���Ϊ�������ڱ�ʹ�á��ͷ�port��Ӧ����Դ������*/
	/*���¼���pmd�߳�*/
    reload_affected_pmds(dp);

    /* Step 3: Reconfigure ports. */

    /* We only reconfigure the ports that we determined above, because they're
     * not being used by any pmd thread at the moment.  If a port fails to
     * reconfigure we remove it from the datapath. */

	/*�������ö˿�*/
    struct dp_netdev_port *next_port;

	/*����dp�˿�������dp�ϵ�port*/
	HMAP_FOR_EACH_SAFE (port, next_port, node, &dp->ports) 
	{
        int err;

		/*�˿ڲ���Ҫ����ֱ������*/
        if (!port->need_reconfigure) 
		{
            continue;
        }

		/*�˿����䣬�ͷ�port ��rx���С�������rx���У���port����rx����*/
        err = port_reconfigure(port);
        if (err) 
		{
			/*ɾ���˿�*/
            hmap_remove(&dp->ports, &port->node);

			/*��Ÿı�*/
			seq_change(dp->port_seq);

			/*�˿�destroy*/
			port_destroy(port);
        } 
		else 
		{
			/*�˿ڷ��Ͷ����Ƿ���Ҫ��̬�����У�����˿����õķ�������С��pmd�߳�������ʹ�þ�̬������*/
            /*�������õ�txqС��pmd+��pmd����������̬����txq*/
            port->dynamic_txqs = netdev_n_txq(port->netdev) < wanted_txqs;
        }
    }

    /* Step 4: Compute new rxq scheduling.  We don't touch the pmd threads
     * for now, we just update the 'pmd' pointer in each rxq to point to the
     * wanted thread according to the scheduling policy. */

    /* Reset all the pmd threads to non isolated. */

	/*��������pmd�̷߳ǹ�����*/
	CMAP_FOR_EACH (pmd, node, &dp->poll_threads) 
    {
        pmd->isolated = false;
    }

	/*���ö˿����ж���Ϊδ����pmd*/
    /* Reset all the queues to unassigned */
    HMAP_FOR_EACH (port, node, &dp->ports) 
    {
    	/*�˿ڶ��и�ֵNULL*/
        for (int i = 0; i < port->n_rxq; i++) 
		{
			/*���port ֮ǰ���й�����pmd����������rx ���е�lcore id ���·���*/
            port->rxqs[i].pmd = NULL;
        }
    }

    /* Add pinned queues and mark pmd threads isolated. */
	/*��ӹ̶����в���pmd�̱߳��Ϊ���룬�̶����м�port��rx������ָ����ʹ�õ�lcore��
	  ��pmdʱҲ�ֵ�ʹ����ͬlcore��pmd��pmd�߳�poll��Ӧ����
	*/
    rxq_scheduling(dp, true);

    /* Add non-pinned queues. */
	/*��ӷǹ̶��Ķ���*/
    rxq_scheduling(dp, false);

    /* Step 5: Remove queues not compliant with new scheduling. */
	/*5.ɾ��pmd�߳������µ��Ȳ�һ�µĶ���*/
	/*����dp��pmd�ڵ㣬�鿴pmd��poll�ڵ㣬poll�ڵ��϶��й�����pmd�����Ǳ�pmd����ɾ��poll�ڵ�*/
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) 
    {
        struct rxq_poll *poll, *poll_next;

        ovs_mutex_lock(&pmd->port_mutex);

		/*����pmd��poll����*/
        HMAP_FOR_EACH_SAFE (poll, poll_next, node, &pmd->poll_list) 
		{
			/*poll�ڵ��Ӧport��rx���й�����pmd�Ѳ��Ǳ����У������port��rx qʹ�õ�pmd�����µ���*/
            if (poll->rxq->pmd != pmd) 
			{
				/*��pmd poll����ɾ����pmd���ն���poll�ڵ�*/
                dp_netdev_del_rxq_from_pmd(pmd, poll);
            }
        }
		
        ovs_mutex_unlock(&pmd->port_mutex);
    }

    /* Reload affected pmd threads.  We must wait for the pmd threads to remove
     * the old queues before readding them, otherwise a queue can be polled by
     * two threads at the same time. */

	/*1.pmdɾ���ɵ�port rx q��port ��rx q�ѹ������ȵ�����pmd�����ݸ�port rx q�趨��core id��port rx q��pmd ͬ�߼���*/

	/*���¼�����Ӱ���pmd�̣߳����Ǳ����ھɶ��ж�ȡ����֮ǰ�ȴ�pmd�߳��Ƴ�������rx���п�����ͬʱ�����̶߳�*/
    reload_affected_pmds(dp);

    /* Step 6: Add queues from scheduling, if they're not there already. */

	/*����port ����poll�ڵ��¼port��rx ���� ����pmd��poll����*/
    HMAP_FOR_EACH (port, node, &dp->ports) 
    {
    	/*�˿�δʹ��pmd*/
        if (!netdev_is_pmd(port->netdev)) 
		{
            continue;
        }

		/*����port�Ľ��ն���*/
        for (int qid = 0; qid < port->n_rxq; qid++) 
		{
			/*��ȡ���ն���*/
            struct dp_netdev_rxq *q = &port->rxqs[qid];
			
			/*�����ѹ���pmd*/
            if (q->pmd) 
			{
                ovs_mutex_lock(&q->pmd->port_mutex);

				/*port�Ľ��ն�����ӵ��������ڵ�pmd��һ��pmd�̶߳�Ӧ���port��һ��port��Ӧ�����
				  poll�ڵ��¼port��port��һ��rx���У�����pmd��poll����
				*/
				dp_netdev_add_rxq_to_pmd(q->pmd, q);

				ovs_mutex_unlock(&q->pmd->port_mutex);
            }
        }
    }

    /* Add every port to the tx cache of every pmd thread, if it's not
     * there already and if this pmd has at least one rxq to poll. */

	/*���port��û�pmd�ķ��˿�cache������pmd������һ���Ӷ���ȥpoll����pmd��ÿ��port���pmd�ķ��˿�cache*/

	/*��������pmd�̣߳���pmd��poll����ڵ��ϵķ�port����pmd�ķ���������port tx�ṹ*/
	CMAP_FOR_EACH (pmd, node, &dp->poll_threads) 
    {
        ovs_mutex_lock(&pmd->port_mutex);

		/*pmd��poll����ڵ㲻Ϊ�գ���port�Ķ�����Ҫpoll*/
		if (hmap_count(&pmd->poll_list) || pmd->core_id == NON_PMD_CORE_ID) 
		{
			/*�����������ϵĶ˿ڣ�����tx�ṹ��ӵ�pmd�ķ�port��������*/
            HMAP_FOR_EACH (port, node, &dp->ports) 
            {
            	/* ����port��tx�ṹ������port tx�ṹ����ӵ���pmd���ķ��Ͷ˿ڻ��������������ز�����Ч*/
                dp_netdev_add_port_tx_to_pmd(pmd, port);
            }
        }
        ovs_mutex_unlock(&pmd->port_mutex);
    }

    /* Reload affected pmd threads. */
	/*������Ӱ���pmd�߳�*/
    reload_affected_pmds(dp);
}

/*******************************************************************************
 ��������  :    ports_require_restart
 ��������  :    �˿���Ҫ����
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
/* Returns true if one of the netdevs in 'dp' requires a reconfiguration */
static bool
ports_require_restart(const struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;

	/*�����˿�*/
    HMAP_FOR_EACH (port, node, &dp->ports) 
	{
		/*�����������к�*/
        if (netdev_is_reconf_required(port->netdev)) 
		{
            return true;
        }
    }

    return false;
}

/*******************************************************************************
 ��������  :    dpif_netdev_run
 ��������  :    ��backer�ϵ�dpif�ϵ�pmd�߳̿�ʼ�հ�
 				dp��Ҫreconfig ��reconfig
 �������  :  	dpif---ĳ����backer��Ӧ��dpif
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/

/* Return true if needs to revalidate datapath flows. */
static bool
dpif_netdev_run(struct dpif *dpif)
{
    struct dp_netdev_port *port;

	/*��ȡdp��Ӧ��netdev*/
    struct dp_netdev *dp = get_dp_netdev(dpif);

	/*pmd�߳�*/
    struct dp_netdev_pmd_thread *non_pmd;
    uint64_t new_tnl_seq;
    bool need_to_flush = true;

    ovs_mutex_lock(&dp->port_mutex);

	/*pmd*/
    non_pmd = dp_netdev_get_pmd(dp, NON_PMD_CORE_ID);

	/*pmd�̴߳���*/
	if (non_pmd) 
	{
        ovs_mutex_lock(&dp->non_pmd_mutex);

		/*����dp�ϵ�port*/
        HMAP_FOR_EACH (port, node, &dp->ports) {
        	/*port û����pmd��*/
            if (!netdev_is_pmd(port->netdev)) {
                int i;

				/*����port�ն����հ�������*/
                for (i = 0; i < port->n_rxq; i++) {
                    if (dp_netdev_process_rxq_port(non_pmd,
                                                   &port->rxqs[i],
                                                   port->port_no)) {
                        need_to_flush = false;
                    }
                }
            }
        }

		/*pmd��Ҫ��������*/
        if (need_to_flush) {
            /* We didn't receive anything in the process loop.
             * Check if we need to send something.
             * There was no time updates on current iteration. */
            pmd_thread_ctx_time_update(non_pmd);

			/* pmd flush�����˿�Ҫ��������ȥ�ı���*/
            dp_netdev_pmd_flush_output_packets(non_pmd, false);
        }

		/*��pmd�߳��ͷŷ��Ͷ��е�ID*/
        dpif_netdev_xps_revalidate_pmd(non_pmd, false);
        ovs_mutex_unlock(&dp->non_pmd_mutex);

		/*�߳�destroy*/
        dp_netdev_pmd_unref(non_pmd);
    }

	/*dp��Ҫreconfigure*/
    if (dp_netdev_is_reconf_required(dp) || ports_require_restart(dp)) 
	{
		/*�˿ڸ��£���������������,������pmd�߳̿�ʼ�հ���λ��*/
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
 ��������  :    pmd_free_cached_ports
 ��������  :    ����Ҫɾ����pmd��port�Ĵ����͵ı��ģ��ͷŵ����˿ڻ���ṹ���ͷŶ˿ڷ�����id
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
static void pmd_free_cached_ports(struct dp_netdev_pmd_thread *pmd)
{
    struct tx_port *tx_port_cached;

    /* Flush all the queued packets. */
	/*1.����pmd����ķ��˿������ѷ��˿��ϴ��������������汨�ķ���*/
    dp_netdev_pmd_flush_output_packets(pmd, true);
	
    /* Free all used tx queue ids. */

	/*�ͷ�pmd�϶˿�ʹ�õķ��Ͷ��е�ID*/
    dpif_netdev_xps_revalidate_pmd(pmd, true);

	/*�ͷ�pmd�ϻ����tnl port����ṹ*/
    HMAP_FOR_EACH_POP (tx_port_cached, node, &pmd->tnl_port_cache) 
   	{
        free(tx_port_cached);
    }

	/*���˿�pmd�Ϸ��Ͷ˿ڻ���ṹ*/
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
 ��������  :    pmd_load_cached_ports
 ��������  :    pmd ����ʱ���ػ���ķ��Ͷ˿�
 				1.����pmd����ķ�port�ڵ㻺��ı���
 				2.���뷢�˿ڻ���ṹ����pmd���˿ڻ�������
 �������  :  	pmd--pmd�߳�
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
pmd_load_cached_ports(struct dp_netdev_pmd_thread *pmd)
    OVS_REQUIRES(pmd->port_mutex)
{
    struct tx_port *tx_port, *tx_port_cached;

	/*1.����Ҫɾ����pmd�ϻ���ķ���port�ڵ��ϴ����͵ı���
	  2.�ͷŵ����˿ڻ���ṹ���ͷŶ˿ڷ�����id*/
    pmd_free_cached_ports(pmd);
	
    hmap_shrink(&pmd->send_port_cache);
    hmap_shrink(&pmd->tnl_port_cache);

	/*����pmd�ķ��Ͷ˿����������Ӧtx�ṹtnl�ṹ ����pmd��������*/
    HMAP_FOR_EACH (tx_port, node, &pmd->tx_ports) 
	{
		/*��port netdev���ڵȴ����push pop�Ĳ���������port������ṹ�������������port����*/
        if (netdev_has_tunnel_push_pop(tx_port->port->netdev)) 
		{
			/*����ķ��˿�*/
            tx_port_cached = xmemdup(tx_port, sizeof *tx_port_cached);

			/*���˿ڲ���������Ĳ�������*/
            hmap_insert(&pmd->tnl_port_cache, &tx_port_cached->node, hash_port_no(tx_port_cached->port->port_no));
        }

		/*���˿ڷ��Ͷ��и���*/
        if (netdev_n_txq(tx_port->port->netdev)) 
		{
			/*���뻺��ķ��˿ڽṹ*/
            tx_port_cached = xmemdup(tx_port, sizeof *tx_port_cached);

			/*���˿�д�뷢�˿ڻ���*/
			hmap_insert(&pmd->send_port_cache, &tx_port_cached->node, hash_port_no(tx_port_cached->port->port_no));
        }
    }
}
/*******************************************************************************
 ��������  :    pmd_alloc_static_tx_qid
 ��������  :    �ӷ��Ͷ���ID�����뾲̬���Ͷ���id
 �������  :    pmd---pmd�߳̽ṹ
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
pmd_alloc_static_tx_qid(struct dp_netdev_pmd_thread *pmd)
{
	/*���Ͷ��л�����*/
    ovs_mutex_lock(&pmd->dp->tx_qid_pool_mutex);

	/*id�����뷢�Ͷ���ID����һ�����е�id*/
    if (!id_pool_alloc_id(pmd->dp->tx_qid_pool, &pmd->static_tx_qid)) 
	{
        VLOG_ABORT("static_tx_qid allocation failed for PMD on core %2d" ", numa_id %d.", pmd->core_id, pmd->numa_id);
    }

	/*�����н���*/
    ovs_mutex_unlock(&pmd->dp->tx_qid_pool_mutex);

    VLOG_DBG("static_tx_qid = %d allocated for PMD thread on core %2d" ", numa_id %d.", pmd->static_tx_qid, pmd->core_id, pmd->numa_id);
}

/*******************************************************************************
 ��������  :  pmd_free_static_tx_qid
 ��������  :  �ͷŷ�����id
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
pmd_free_static_tx_qid(struct dp_netdev_pmd_thread *pmd)
{
    ovs_mutex_lock(&pmd->dp->tx_qid_pool_mutex);

	/*�ͷŷ�����id��������id��*/
    id_pool_free_id(pmd->dp->tx_qid_pool, pmd->static_tx_qid);

	ovs_mutex_unlock(&pmd->dp->tx_qid_pool_mutex);
}

/*******************************************************************************
 ��������  :    pmd_load_queues_and_ports
 ��������  :    ��ȡpmdҪpoll�Ķ��кͶ˿ڡ����ظ���
 �������  :    pmd---pmd�߳�
 			    ppoll_list---poll����ָ�����飬����pmd->poll_list�ڵ�����ÿ���ڵ��¼poll�Ķ���ָ��Ͷ�Ӧ�˿ں�
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
pmd_load_queues_and_ports(struct dp_netdev_pmd_thread *pmd, struct polled_queue **ppoll_list)
{
	/*ָ��ĵ�ַ*/
    struct polled_queue *poll_list = *ppoll_list;
    struct rxq_poll *poll;
    int i;

	/*�˿�����*/
    ovs_mutex_lock(&pmd->port_mutex);

	/*�������ָ������ poll_list[i]*/
    poll_list = xrealloc(poll_list, hmap_count(&pmd->poll_list) * sizeof *poll_list);

    i = 0;

	/*��pmd����poll�ڵ����� ����¼���кͶ������ڵĶ˿�*/
    HMAP_FOR_EACH (poll, node, &pmd->poll_list) 
    {
		/*poll����ָ�����飬��¼��pmd poll�Ķ���*/
        poll_list[i].rxq = poll->rxq;

		/*���ж�Ӧ�Ķ˿����*/
		poll_list[i].port_no = poll->rxq->port->port_no;

        i++;
    }

	/*���ض˿ڻ��桢���˿�*/
    pmd_load_cached_ports(pmd);

	/*����*/
    ovs_mutex_unlock(&pmd->port_mutex);

	/*����ָ�����鸳ֵ��pmd->poll_list*/
    *ppoll_list = poll_list;
	
    return i;
}

/*******************************************************************************
 ��������  :    ovs_dp_process_packet
 ��������  :    ÿpmd���Ĵ������̣�ƥ������ִ����Ӧ��action
 				1.���dpdk�˿ڵ�ʱ�򣬻ᴥ������pmd�߳�:
 				dpif_netdev_port_add-->do_add_port-->dp_netdev_set_pmds_on_numa-->pmd_thread_main
 				2.����Ѿ������dpdk�˿ڣ�������ʱ��Ҳ�ᴥ������pmd���߳�
 				dpif_netdev_pmd_set-->dp_netdev_reset_pmd_threads-->dp_netdev_set_pmds_on_numa-->pmd_thread_main	

 				������ѯ�б��г�����ѯ����˿ڣ���ÿһ���˿�������ͬʱ��32������NETDEV_MAX_BURST����
 				���ݼ����������ɽ�ÿһ���հ����з��ࡣ
 				�����Ŀ����Ϊ���ҵ�һ�������Ӷ��԰�����ǡ���Ĵ���
 				�����������з��飬����ÿһ�����齫ִ���ض��Ķ�����

				3.һ��pmd���кܶ�poll�ڵ㣬ÿ��poll�ڵ��Ӧһ���˿ںź�һ���Ӷ��У�һ��port�����ж�����У�
				pmd�̱߳�������poll�ڵ�ȥ�հ�
 				
 �������  :  	f---pmd�߳�
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static void *pmd_thread_main(void *f_)
{
	/*pmd�߳̽ṹ*/
    struct dp_netdev_pmd_thread *pmd = f_;

	/*pmd����ͳ��*/
    struct pmd_perf_stats *s = &pmd->perf_stats;
    unsigned int lc = 0;
    struct polled_queue *poll_list;
    bool exiting;
    int poll_cnt;
    int i;
    int process_packets = 0;

    poll_list = NULL;

	/*per_pmd_key ��¼pmd�߳̽ṹ��ַ*/
    /* Stores the pmd thread's 'pmd' to 'per_pmd_key'. */
    ovsthread_setspecific(pmd->dp->per_pmd_key, pmd);

	/*numa�׺������ã�pmd_thread_setaffinity_cpu�����̰߳󶨵�lcore*/
    ovs_numa_thread_setaffinity_core(pmd->core_id);

	/*pmd���õ��߼��˸�ֵ��¼��dpdk*/
    dpdk_set_lcore_id(pmd->core_id);

	VLOG_DBG("pmd_thread_main pmd->core_id=%u",pmd->core_id);

    /*��ȡpmd��poll�����Ͻڵ㣬Ҫpoll�Ķ��кͶ˿ڣ�����poll_list������pmd���и���*/
	/*һ��pmdҪpoll���port��һ��port���ܶ�Ӧ����ն���*/
    poll_cnt = pmd_load_queues_and_ports(pmd, &poll_list);

	VLOG_DBG("pmd_thread_mainpoll_cnt=%d",poll_cnt);

	/*pmd��Ӧemc��smc���������ʼ��*/
    dfc_cache_init(&pmd->flow_cache);
	
reload:

	/*�ӷ��Ͷ���ID�����뾲̬���Ͷ���id����pmd*/
    pmd_alloc_static_tx_qid(pmd);

    /* List port/core affinity */

	/*����poll����ڵ���ɵ����飬ȥ����poll����*/
    for (i = 0; i < poll_cnt; i++)
	{
	   /*��ȡ����id*/
       VLOG_DBG("Core %d processing port \'%s\' with queue-id %d\n", pmd->core_id, netdev_rxq_get_name(poll_list[i].rxq->rx), netdev_rxq_get_queue_id(poll_list[i].rxq->rx));
	   
       /* Reset the rxq current cycles counter. */

	   /*���ý��ն���poll���ʱ��*/
       dp_netdev_rxq_set_cycles(poll_list[i].rxq, RXQ_CYCLES_PROC_CURR, 0);
    }

	/*�����Ҫpoll�Ķ��и���Ϊ0*/
    if (!poll_cnt) 
	{	
		/*reload���кź��ϴ����к�һ�£�˵��û�ж˿ڱ䶯��pmd�����䶯�ȴ���ֱ����ű䶯����ͬ������*/
        while (seq_read(pmd->reload_seq) == pmd->last_reload_seq) 
		{
            seq_wait(pmd->reload_seq, pmd->last_reload_seq);
            poll_block();
        }
		/*û�ж��У�ѭ��������0*/
        lc = UINT_MAX;
    }

	/*��һ��poll ���ʱ��������0*/
    pmd->intrvl_tsc_prev = 0;

	/*��һ��poll���ʱ����0*/
    atomic_store_relaxed(&pmd->intrvl_cycles, 0);

	/*��һ��tscʱ�����ѭ����������*/
    cycles_counter_update(s);
	
    /* Protect pmd stats from external clearing while polling.*/

	/*��ȡ����ͳ�ƻ�����*/
    ovs_mutex_lock(&pmd->perf_stats.stats_mutex);

	/*forѭ�������˿�(poll�ڵ�)��ִ��dp_netdev_process_rxq_port����˿ڣ�ѭ���м䣬����ݱ䶯���¼���pmd�϶˿ںͶ�����Ϣ*/
    for (;;) 
	{
        uint64_t rx_packets = 0, tx_packets = 0;

		/*pmd����ͳ����������*/
        pmd_perf_start_iteration(s);

		/*����poll�����ϵ�poll�ڵ㣬ȥpoll poll�ڵ��Ӧ port���ն����еı��ġ����Զ���ն��С�һ��poll�ṹһ������*/
        for (i = 0; i < poll_cnt; i++) 
		{
			/*poll��ȡ���ж��б��ķ�������������poll���ı�������poll�ڵ��Ӧ�˿ںźͶ˿ڶ�Ӧ�Ķ��У������Ƕ����*/
            process_packets = dp_netdev_process_rxq_port(pmd, poll_list[i].rxq, poll_list[i].port_no);

			/*����poll�ڵ���ն��У����յı��ļ���*/
            rx_packets += process_packets;

			VLOG_DBG("pmd_thread_main poll_cnt i=%d, process_packets=%d, rx_packets=%u", i, process_packets, rx_packets);
        }

		/*û��poll������*/
        if (!rx_packets) 
		{
            /* We didn't receive anything in the process loop.
             * Check if we need to send something.
             * There was no time updates on current iteration. */
             
			/*�߳�������ʱ�����Ϊ��ǰʱ��*/
            pmd_thread_ctx_time_update(pmd);

			/*pmd flush�����Ͷ˿ڷ����еı��ģ����ط����ı�����*/
            tx_packets = dp_netdev_pmd_flush_output_packets(pmd, false);
			VLOG_DBG("pmd_thread_main pmd flush tx_packets=%u", tx_packets);
        }

		/*1024��û�д��κζ���poll������*/
        if (lc++ > 1024) 
		{
            bool reload;

            lc = 0;

            coverage_try_clear();

			/*ͬ��*/
            dp_netdev_pmd_try_optimize(pmd, poll_list, poll_cnt);

			/*emc��ȷ�����ϻ�*/
            if (!ovsrcu_try_quiesce()) 
			{
				/*emc����ɾ��*/
                emc_cache_slow_sweep(&((pmd->flow_cache).emc_cache));
				VLOG_DBG("pmd_thread_main pmd emc old sweep");
            }

			/*��ȡreload���أ������Ҫreload pmd����break��dp�϶˿���ɾ��pmd����仯ʱ��Ҫreload*/
            atomic_read_relaxed(&pmd->reload, &reload);
            if (reload) 
			{
                break;
            }
        }

		/*pmd��������ͳ��*/
        pmd_perf_end_iteration(s, rx_packets, tx_packets, pmd_perf_metrics_enabled(pmd));
    }
    ovs_mutex_unlock(&pmd->perf_stats.stats_mutex);

	/*reload ������Ҫreload pmd�����¶�ȡpmd��poll�������нڵ���poll�Ķ�����˿�*/
    poll_cnt = pmd_load_queues_and_ports(pmd, &poll_list);

	//������pmd->exit_latch����ô�ս�pmd�߳�
    exiting = latch_is_set(&pmd->exit_latch);
	
    /* Signal here to make sure the pmd finishes
     * reloading the updated configuration. */

	/*���ع�����ɺ�reload�����false����ȡpmd�ϴ�reload�����кż���last_reload_seq*/
    dp_netdev_pmd_reload_done(pmd);

	/*�ͷ�pmd�̷߳�����id*/
    pmd_free_static_tx_qid(pmd);

    if (!exiting) 
	{
        goto reload;
    }

	/*pmd����smc emc �������������*/
    dfc_cache_uninit(&pmd->flow_cache);

	/*�ͷŶ���ָ������*/
	free(poll_list);

	/*�ͷŶ˿�cache*/
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
 ��������  :    dp_netdev_run_meter
 ��������  :    meter ���٣����ٶ�������
 �������  :  	meter_id---������������������meter id
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static void
dp_netdev_run_meter(struct dp_netdev *dp, struct dp_packet_batch *packets_,
                    uint32_t meter_id, long long int now)
{
	/*meter ����*/
    struct dp_meter *meter;
	/*������meter����*/
    struct dp_meter_band *band;

	/*����������*/
    struct dp_packet *packet;

	long long int long_delta_t; /* msec */
    uint32_t delta_t; /* msec */

	/*�������ĸ���*/
    const size_t cnt = dp_packet_batch_size(packets_);
	
    uint32_t bytes, volume;

	/*���������ļ�¼*/
    int exceeded_band[NETDEV_MAX_BURST];

	/*�������ʱ��ļ�¼*/
	uint32_t exceeded_rate[NETDEV_MAX_BURST];

	/*��������ı�����*/
	int exceeded_pkt = cnt; /* First packet that exceeded a band rate. */

	/*meter���65536*/
    if (meter_id >= MAX_METERS) {
        return;
    }

	/*meterid������*/
    meter_lock(dp, meter_id);

	/*���������meter id ��ȡmeter���ýṹ*/
    meter = dp->meters[meter_id];
    if (!meter) {
        goto out;
    }

	/*��ʼ�����������ļ�¼�ṹ*/
    /* Initialize as negative values. */
    memset(exceeded_band, 0xff, cnt * sizeof *exceeded_band);

	/*��ʼ���������ʱ��ļ�¼�ṹ*/
	/* Initialize as zeroes. */
    memset(exceeded_rate, 0, cnt * sizeof *exceeded_rate);

    /* All packets will hit the meter at the same time. */

	/*��ǰʱ��-�ϴ�meterͳ��ʱ��*/
    long_delta_t = (now - meter->used) / 1000; /* msec */

    /* Make sure delta_t will not be too large, so that bucket will not
     * wrap around below. */

	/*��ǰʱ��-�ϴ�meterͳ��ʱ�� ʱ���Ƿ�ʱ����ʱʹ�����ʱ�䣬����ʹ�õ�ǰʱ��-�ϴ�meterͳ��ʱ��*/
    delta_t = (long_delta_t > (long long int)meter->max_delta_t)
        ? meter->max_delta_t : (uint32_t)long_delta_t;

    /* Update meter stats. */
	/*����meterʱ��Ϊ����ʱ��*/
    meter->used = now;

	/*����meter������*/
    meter->packet_count += cnt;
    bytes = 0;

	/*���������������ֽ���*/
    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
        bytes += dp_packet_size(packet);
    }
	
	/*����meter�ֽ�������*/
    meter->byte_count += bytes;

    /* Meters can operate in terms of packets per second or kilobits per
     * second. */

	/*��pps���٣�����pps*/
    if (meter->flags & OFPMF13_PKTPS) {
        /* Rate in packets/second, bucket 1/1000 packets. */
        /* msec * packets/sec = 1/1000 packets. */
        volume = cnt * 1000; /* Take 'cnt' packets from the bucket. */
    } 
	/*��bps���٣�����bps*/
	else {
        /* Rate in kbps, bucket in bits. */
        /* msec * kbps = bits */

        volume = bytes * 8;
    }

    /* Update all bands and find the one hit with the highest rate for each
     * packet (if any). */

	/*����meter�����д�������*/
    for (int m = 0; m < meter->n_bands; ++m) {

		/*��������*/
        band = &meter->bands[m];

        /* Update band's bucket. */

		/*������ʹ��������=ʱ���x����*/
        band->bucket += delta_t * band->up.rate;

		/*�����������ֵ������ʹ��burst_size*/
		if (band->bucket > band->up.burst_size) {
            band->bucket = band->up.burst_size;
        }

        /* Drain the bucket for all the packets, if possible. */

		/*δ����������*/
        if (band->bucket >= volume) {

			/*����ʣ�����*/
            band->bucket -= volume;
        } else {
            int band_exceeded_pkt;

            /* Band limit hit, must process packet-by-packet. */

			/*meter�ǰ�pps����*/
            if (meter->flags & OFPMF13_PKTPS) 
			{

				/*kbps ���ٱ��ĸ���k��λ*/
                band_exceeded_pkt = band->bucket / 1000;

				/*ʣ������Ӧ���ĸ���*/
                band->bucket %= 1000; /* Remainder stays in bucket. */

                /* Update the exceeding band for each exceeding packet.
                 * (Only one band will be fired by a packet, and that
                 * can be different for each packet.) */

				/*���ٱ�����*/
				for (int i = band_exceeded_pkt; i < cnt; i++) 
				{
					/*δ����������*/
                    if (band->up.rate > exceeded_rate[i]) 
					{
						/*����*/
                        exceeded_rate[i] = band->up.rate;

						/*���ٶ�Ӧ�Ĵ�������*/
                        exceeded_band[i] = m;
                    }
                }
            } 
			else 
			{
                /* Packet sizes differ, must process one-by-one. */
                band_exceeded_pkt = cnt;

				/*��������*/
				DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) 
				{
					/*bit*/
                    uint32_t bits = dp_packet_size(packet) * 8;

					/*δ��bps����*/
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

			/*����*/
            /* Remember the first exceeding packet. */
            if (exceeded_pkt > band_exceeded_pkt) 
			{
                exceeded_pkt = band_exceeded_pkt;
            }
        }
    }

    /* Fire the highest rate band exceeded by each packet, and drop
     * packets if needed. */

	/*����ÿ�����ݰ�������������ʴ���Ȼ����*��Ҫʱ�ṩ���ݰ�*/
    size_t j;
    DP_PACKET_BATCH_REFILL_FOR_EACH (j, cnt, packet, packets_) 
	{
        if (exceeded_band[j] >= 0) 
		{
            /* Meter drop packet. */
            band = &meter->bands[exceeded_band[j]];
            band->packet_count += 1;
            band->byte_count += dp_packet_size(packet);

			/*ɾ��packet*/
            dp_packet_delete(packet);
        } 
		else 
		{
            /* Meter accepts packet. */
			/*���batch*/
            dp_packet_batch_refill(packets_, packet, j);
        }
    }
 out:
    meter_unlock(dp, meter_id);
}

/*******************************************************************************
 ��������  :    dpif_netdev_meter_set
 ��������  :    �������meter��Դ������
 �������  :  	meter_id---meter id
 				config---meter��������
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
/* Meter set/get/del processing is still single-threaded. */
static int
dpif_netdev_meter_set(struct dpif *dpif, ofproto_meter_id meter_id,
                      struct ofputil_meter_config *config)
{
	/*��ȡdp*/
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

	/*����dp �����meter �ڴ���Դ*/
    /* Allocate meter */
    meter = xzalloc(sizeof *meter + config->n_bands * sizeof(struct dp_meter_band));
    if (meter) 
	{
		/*meter ���ø�ֵ*/
        meter->flags = config->flags;
        meter->n_bands = config->n_bands;
        meter->max_delta_t = 0;
        meter->used = time_usec();

		/*���ô���*/
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

		/*������ɾ��*/
        dp_delete_meter(dp, mid); /* Free existing meter, if any */


		/*meter dp�����meter��Դ������dp meter*/
		dp->meters[mid] = meter;

#if 1
		/*�·�dp ��ɹ�*/
		VLOG_DBG("zwl:dpif_netdev_meter_set:%s: meter id: %"PRIu32" dp->meters[mid].id: %"PRIu32" ",
						dpif_name(dpif), mid, dp->meters[mid].id);

#endif
		
        meter_unlock(dp, mid);

        return 0;
    }
    return ENOMEM;
}

/*******************************************************************************
 ��������  :    dpif_netdev_meter_get
 ��������  :    ���meter��Դ��ѯ
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
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

	/*����id�ҵ����meter*/
    const struct dp_meter *meter = dp->meters[meter_id];
    if (!meter) {
        retval = ENOENT;
        goto done;
    }

	/*��������*/
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
 ��������  :    dpif_netdev_meter_del
 ��������  :    dpif meterɾ��
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
dpif_netdev_meter_del(struct dpif *dpif,
                      ofproto_meter_id meter_id_,
                      struct ofputil_meter_stats *stats, uint16_t n_bands)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int error;

	/*�Ȳ�ѯdpif�����meter��Դ�Ƿ����*/
    error = dpif_netdev_meter_get(dpif, meter_id_, stats, n_bands);
    if (!error) {
        uint32_t meter_id = meter_id_.uint32;

        meter_lock(dp, meter_id);

#if 1
		VLOG_DBG("zwl-dpif-delmeterflow dpif_netdev_meter_del meter_id=%u.", meter_id);
#endif

		/*����meter id ɾ��meter*/
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
 ��������  :  dp_netdev_pmd_reload_done
 ��������  :  ���ع�����ɺ�reload�����false����ȡpmd�ϴ�reload�����кż���last_reload_seq
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
dp_netdev_pmd_reload_done(struct dp_netdev_pmd_thread *pmd)
{
    ovs_mutex_lock(&pmd->cond_mutex);

	/*reload�����false*/
    atomic_store_relaxed(&pmd->reload, false);

	/*��ȡpmd�ϴ�reload�����кż���last_reload_seq*/
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
 ��������  :    dp_netdev_get_pmd
 ��������  :    ����port ָ����core_id ��pmd poll �����ȡ�˶�Ӧpmd��һ��pmd��Ӧһ������
 �������  :  	core_id---�˿�rxq�󶨵�lcore
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static struct dp_netdev_pmd_thread *dp_netdev_get_pmd(struct dp_netdev *dp, unsigned core_id)
{
    struct dp_netdev_pmd_thread *pmd;
    const struct cmap_node *pnode;

	/*��pmd poll�����̸߳���core_id��ȡһ��pmd�ڵ㣬���ϵ�pmd�߳�*/
    pnode = cmap_find(&dp->poll_threads, hash_int(core_id, 0));
    if (!pnode) 
	{
        return NULL;
    }

	/*�߳̽ڵ��Ӧpmd*/
    pmd = CONTAINER_OF(pnode, struct dp_netdev_pmd_thread, node);

	/*�߳̽ڵ��Ӧpmd*/
    return dp_netdev_pmd_try_ref(pmd) ? pmd : NULL;
}

/*******************************************************************************
 ��������  :    emc_cache_slow_sweep
 ��������  :    emc����ɾ��
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
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
 ��������  :    dp_netdev_pmd_unref
 ��������  :    pmd������δ����
 �������  :  	pmd---pmd�߳�
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
dp_netdev_pmd_unref(struct dp_netdev_pmd_thread *pmd)
{
	/*pmd������δ����*/
    if (pmd && ovs_refcount_unref(&pmd->ref_cnt) == 1) 
	{
		/*�ͷ�pmd�ڵ���ʣ�������Դ*/
        ovsrcu_postpone(dp_netdev_destroy_pmd, pmd);
    }
}

/*******************************************************************************
 ��������  :    dp_netdev_pmd_get_next
 ��������  :    ��dp ��dump 50��flow
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
/* Given cmap position 'pos', tries to ref the next node.  If try_ref()
 * fails, keeps checking for next node until reaching the end of cmap.
 *
 * Caller must unrefs the returned reference. */
static struct dp_netdev_pmd_thread *
dp_netdev_pmd_get_next(struct dp_netdev *dp, struct cmap_position *pos)
{
	/*pmd�߳�*/
    struct dp_netdev_pmd_thread *next;

    do {
        struct cmap_node *node;

		/*pmd�߳̽ڵ�*/
        node = cmap_next_position(&dp->poll_threads, pos);

		/*pmd�߳�*/
		next = node ? CONTAINER_OF(node, struct dp_netdev_pmd_thread, node)
            : NULL;
    } while (next && !dp_netdev_pmd_try_ref(next));

    return next;
}

/*******************************************************************************
 ��������  :    dp_netdev_configure_pmd
 ��������  :    ����������pmd�̣߳���ʼ������dp poll����
 �������  :  	pmd---������pmd�߳�
 				dp---������ṹ
 				core_id---�߼���id
 				numa_id---���ڵ�numa id
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
/* Configures the 'pmd' based on the input argument. */
static void
dp_netdev_configure_pmd(struct dp_netdev_pmd_thread *pmd, struct dp_netdev *dp, unsigned core_id, int numa_id)
{
	/*����pmd��ʼ��*/
    pmd->dp = dp;
    pmd->core_id = core_id;
    pmd->numa_id = numa_id;
	
    pmd->need_reload = false;

	/*���������Ϊ0*/
	pmd->n_output_batches = 0;

	/*δ������*/
    ovs_refcount_init(&pmd->ref_cnt);
	
    latch_init(&pmd->exit_latch);

	/*�����������*/
	pmd->reload_seq = seq_create();

	/*�ϴ�������Ż�ȡ*/
	pmd->last_reload_seq = seq_read(pmd->reload_seq);

	/*reload��Ǹ�ֵ*/
	atomic_init(&pmd->reload, false);
	
    xpthread_cond_init(&pmd->cond, NULL);
    ovs_mutex_init(&pmd->cond_mutex);
    ovs_mutex_init(&pmd->flow_mutex);
    ovs_mutex_init(&pmd->port_mutex);

	/*pmd��������������ʼ��*/
    cmap_init(&pmd->flow_table);

	/*dpcls ��������ʼ��*/
    cmap_init(&pmd->classifiers);

	/*pmd������ ���µĽ��ն��и�ֵNULL*/
    pmd->ctx.last_rxq = NULL;

	/*pmd������ʱ�����Ϊ��ǰʱ��*/
    pmd_thread_ctx_time_update(pmd);
	
    pmd->next_optimization = pmd->ctx.now + DPCLS_OPTIMIZATION_INTERVAL;
    pmd->rxq_next_cycle_store = pmd->ctx.now + PMD_RXQ_INTERVAL_LEN;

	/*��ʼ��poll ��*/
	hmap_init(&pmd->poll_list);

	/*��ʼ�����˿�*/
	hmap_init(&pmd->tx_ports);

	/*��ʼ���������˿�hmap*/
	hmap_init(&pmd->tnl_port_cache);

	/*��ʼ�����淢�˿�hmap*/
	hmap_init(&pmd->send_port_cache);
    /* init the 'flow_cache' since there is no
     * actual thread created for NON_PMD_CORE_ID. */

	/*�߼���id�Ƿ�pmd��*/
	if (core_id == NON_PMD_CORE_ID) 
	{
		/* emc���桢smc�����ʼ��*/
        dfc_cache_init(&pmd->flow_cache);

		/*�ӷ��Ͷ���ID�����뾲̬���Ͷ���id*/
        pmd_alloc_static_tx_qid(pmd);
    }
	
	/*pmd����ͳ�Ƴ�ʼ��*/
    pmd_perf_stats_init(&pmd->perf_stats);

	/*pmd���뵽dp poll�߳�����cmap*/
	cmap_insert(&dp->poll_threads, CONST_CAST(struct cmap_node *, &pmd->node), hash_int(core_id, 0));
}

/*******************************************************************************
 ��������  :    dp_netdev_destroy_pmd
 ��������  :    �ͷ�pmd�ڵ���ʣ�������Դ
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
dp_netdev_destroy_pmd(struct dp_netdev_pmd_thread *pmd)
{
    struct dpcls *cls;

	/*flush��pmd�ϵı���*/
    dp_netdev_pmd_flow_flush(pmd);

	/*�ͷ���Դ*/
    hmap_destroy(&pmd->send_port_cache);
    hmap_destroy(&pmd->tnl_port_cache);
    hmap_destroy(&pmd->tx_ports);
    hmap_destroy(&pmd->poll_list);

	/*����dpcls����dpcls destroy��*/
    /* All flows (including their dpcls_rules) have been deleted already */
    CMAP_FOR_EACH (cls, node, &pmd->classifiers) {
        dpcls_destroy(cls);
        ovsrcu_postpone(free, cls);
    }

	/*�ͷŵ�dpcls�ṹ*/
	cmap_destroy(&pmd->classifiers);

	/*�ͷ�flow table*/
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
 ��������  :    dp_netdev_del_pmd
 ��������  :    ��������ɾ��pmd��pmd�ϵ���Դ��������ñ��
 				1.�ͷ�pmd������������
 				2.����pmd�ϻ���ķ��˿ڴ������ı���
 				3.�ͷŷ�����
 				4.ɾ��pmd�Ϸ�port��poll������poll�ڵ�
 				
 �������  :  	dp---������
 				pmd---��ɾ����pmd�߳�
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
/* Stops the pmd thread, removes it from the 'dp->poll_threads',
 * and unrefs the struct. */
static void
dp_netdev_del_pmd(struct dp_netdev *dp, struct dp_netdev_pmd_thread *pmd)
{
    /* NON_PMD_CORE_ID doesn't have a thread, so we don't have to synchronize,
     * but extra cleanup is necessary */

	/*Ҫɾ����pmd�߳�ʹ�õ��Ƿ�pmd CPU�ˣ�CPU���ѱ������ڵ�*/
	if (pmd->core_id == NON_PMD_CORE_ID) 
	{
		/*��pmd��Դ������*/
        ovs_mutex_lock(&dp->non_pmd_mutex);

		/*�ͷ�pmd��������*/
        dfc_cache_uninit(&pmd->flow_cache);

		/*����pmd�����port�ϴ��������������ġ��ͷ�pmd�ϻ���ports��*/
		pmd_free_cached_ports(pmd);

		/*�ͷ�pmdʹ�õľ�̬���Ͷ���id����pmd���Ͷ���id���ҵ��ڵ㲢�ͷ�*/
		pmd_free_static_tx_qid(pmd);
		
        ovs_mutex_unlock(&dp->non_pmd_mutex);
    } 
	/*Ҫɾ����pmd�߳��õĺ���pmd����ĺ�*/
	else 
	{
		/*pmd �̴߳��Ͻ����̱߳��*/
        latch_set(&pmd->exit_latch);

		/*δ�������ڵ���pmd ����
		  1.����pmd����ķ�port�ڵ㻺��ı���
 		  2.���뷢�˿ڻ���ṹ����pmd���˿ڻ�������
 		*/
        dp_netdev_reload_pmd__(pmd);

		/*������pmd�߳�*/
		xpthread_join(pmd->thread, NULL);
    }

	/*ɾ��pmd�Ϸ�port��poll������poll�ڵ�*/
    dp_netdev_pmd_clear_ports(pmd);

    /* Purges the 'pmd''s flows after stopping the thread, but before
     * destroying the flows, so that the flow stats can be collected. */

	/*ֹͣpmd�߳�ǰ�������*/
    if (dp->dp_purge_cb) 
	{
        dp->dp_purge_cb(dp->dp_purge_aux, pmd->core_id);
    }

	/*��pmd�߳����� ɾ��pmd �߳�*/
	cmap_remove(&pmd->dp->poll_threads, &pmd->node, hash_int(pmd->core_id, 0));

	/*����dp_netdev_destroy_pmd�ͷŶ�pmd��Դ������*/
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
 ��������  :    dp_netdev_pmd_clear_ports
 ��������  :    ɾ��pmd�ӹܵ�port��poll������poll�ڵ�
 �������  :  	pmd---
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
/* Deletes all rx queues from pmd->poll_list and all the ports from
 * pmd->tx_ports. */
static void
dp_netdev_pmd_clear_ports(struct dp_netdev_pmd_thread *pmd)
{
    struct rxq_poll *poll;
    struct tx_port *port;

    ovs_mutex_lock(&pmd->port_mutex);

	/*�ͷ�pmd�ϵ�����poll�ڵ�*/
    HMAP_FOR_EACH_POP (poll, node, &pmd->poll_list) 
    {
        free(poll);
    }

	/*�ͷŷ�port�ϵ�����port*/
    HMAP_FOR_EACH_POP (port, node, &pmd->tx_ports) 
    {
        free(port);
    }
	
    ovs_mutex_unlock(&pmd->port_mutex);
}

/*******************************************************************************
 ��������  :    dp_netdev_add_rxq_to_pmd
 ��������  :    netdev��ӽ��ն��е�pmd
 �������  :  	pmd---���ж�Ӧpmd
 				rxq---port�Ľ��ն���
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
/* Adds rx queue to poll_list of PMD thread, if it's not there already. */
static void
dp_netdev_add_rxq_to_pmd(struct dp_netdev_pmd_thread *pmd, struct dp_netdev_rxq *rxq)
    OVS_REQUIRES(pmd->port_mutex)
{
	/*��ȡ���ն��еĶ���id*/
    int qid = netdev_rxq_get_queue_id(rxq->rx);

	/*���ն���id�������ڵĶ˿�һ�����ϣ*/
    uint32_t hash = hash_2words(odp_to_u32(rxq->port->port_no), qid);
    struct rxq_poll *poll;

	/*����pmd poll����*/
    HMAP_FOR_EACH_WITH_HASH (poll, node, hash, &pmd->poll_list) 
	{
		/*port����ն��ж�Ӧ��poll�ڵ�����pmd��poll�������*/
        if (poll->rxq == rxq) 
		{
            /* 'rxq' is already polled by this thread. Do nothing. */
            return;
        }
    }

	/*����poll�ڵ㣬һ��poll�ڵ��Ӧһ��port�Ľ��ն��У�poll�ڵ��¼port��rx����*/
    poll = xmalloc(sizeof *poll);

	/*poll�ڵ��¼���ն���*/
    poll->rxq = rxq;

	/*poll�ڵ����pmd poll����*/
    hmap_insert(&pmd->poll_list, &poll->node, hash);

	/*pmd���������ر��*/
    pmd->need_reload = true;
}

/*******************************************************************************
 ��������  :    dp_netdev_del_rxq_from_pmd
 ��������  :    ��pmdɾ��poll���ն���
 �������  :  	pmd---�˿�ʹ�õ�pmd
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
/* Delete 'poll' from poll_list of PMD thread. */
static void
dp_netdev_del_rxq_from_pmd(struct dp_netdev_pmd_thread *pmd, struct rxq_poll *poll)
    OVS_REQUIRES(pmd->port_mutex)
{
	/*ɾ�����ն��нڵ�*/
    hmap_remove(&pmd->poll_list, &poll->node);
    free(poll);

    pmd->need_reload = true;
}
/*******************************************************************************
 ��������  :    dp_netdev_add_port_tx_to_pmd
 ��������  :    ����port��tx�ṹ������port tx�ṹ����ӵ���pmd���ķ��Ͷ˿ڻ��������������ز�����Ч
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
/* Add 'port' to the tx port cache of 'pmd', which must be reloaded for the
 * changes to take effect. */
static void
dp_netdev_add_port_tx_to_pmd(struct dp_netdev_pmd_thread *pmd, struct dp_netdev_port *port)
    OVS_REQUIRES(pmd->port_mutex)
{
    struct tx_port *tx;

	/*��ѯport�Ƿ��Ѵ����ڷ��˿ڻ���*/
    tx = tx_port_lookup(&pmd->tx_ports, port->port_no);
    if (tx) 
	{
        /* 'port' is already on this thread tx cache. Do nothing. */
        return;
    }

	/*���˿ڽṹ����*/
    tx = xzalloc(sizeof *tx);

	/*port�ķ��ṹ*/
    tx->port = port;
    tx->qid = -1;
    tx->flush_time = 0LL;

	/*���˿��������ʼ��*/
    dp_packet_batch_init(&tx->output_pkts);

	/*port�ķ��ṹ���뵽hmap*/
    hmap_insert(&pmd->tx_ports, &tx->node, hash_port_no(tx->port->port_no));

	/*����pmd��Ҫ���ر��*/
    pmd->need_reload = true;
}

/*******************************************************************************
 ��������  :    dp_netdev_del_port_tx_from_pmd
 ��������  :    ��pmd ɾ���˿ڷ�����
 �������  :  	pmd---pmd�߳�
 				tx---���Ͷ˿�
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/

/* Del 'tx' from the tx port cache of 'pmd', which must be reloaded for the
 * changes to take effect. */
static void
dp_netdev_del_port_tx_from_pmd(struct dp_netdev_pmd_thread *pmd, struct tx_port *tx)
    OVS_REQUIRES(pmd->port_mutex)
{
	/*��pmd �˿�ɾ�����ڵ�*/
    hmap_remove(&pmd->tx_ports, &tx->node);
    free(tx);

	/*���˿ڴӷ��˿�����ɾ����pmd��Ҫreload��ɾ����Ӧport��������Դ�ȡ�����port�ϵı���*/
    pmd->need_reload = true;
}

static char *
dpif_netdev_get_datapath_version(void)
{
     return xstrdup("<built-in>");
}


/*******************************************************************************
 ��������  :    dp_netdev_flow_used
 ��������  :    emc����ɾ��
 �������  :  	netdev_flow---��ȡÿ�������������Ӧ��flow
 				cnt---ÿ�������������Ӧ�ı�����
 				tcp_flags---��ȡ��miniflow��Ӧ��tcp flag
 				now---pmd�߳����еĵ�ǰʱ��
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
dp_netdev_flow_used(struct dp_netdev_flow *netdev_flow, int cnt, int size, uint16_t tcp_flags, long long now)
{
    uint16_t flags;

	/*pmd���е�ǰʱ��*/
    atomic_store_relaxed(&netdev_flow->stats.used, now);

	/*ÿ����������������*/
    non_atomic_ullong_add(&netdev_flow->stats.packet_count, cnt);

	/*ÿ�������������ֽ���*/
    non_atomic_ullong_add(&netdev_flow->stats.byte_count, size);

	/*ÿ������������tcp flag ��ȡ*/
    atomic_read_relaxed(&netdev_flow->stats.tcp_flags, &flags);
    flags |= tcp_flags;

	/*tcp flag�洢*/
    atomic_store_relaxed(&netdev_flow->stats.tcp_flags, flags);
}
/*******************************************************************************
 ��������  :    dp_netdev_upcall
 ��������  :    ��һ������ȥofproto classifier���Ľӿڣ����ʧ����ɾ������
 �������  :  	
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
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

	/*upcall�ص�����*/
    return dp->upcall_cb(packet_, flow, ufid, pmd->core_id, type, userdata, actions, wc, put_actions, dp->upcall_aux);
}

/*******************************************************************************
 ��������  :    dpif_netdev_packet_get_rss_hash_orig_pkt
 ��������  :    ��dpdk rss �����miniflow��Ԫ�����ϣ
 �������  :  	packet---ÿ������������
 				mf---������ȡ��miniflow
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static inline uint32_t
dpif_netdev_packet_get_rss_hash_orig_pkt(struct dp_packet *packet, const struct miniflow *mf)
{
    uint32_t hash;

    if (OVS_LIKELY(dp_packet_rss_valid(packet))) 
	{
		/*ֱ��ʹ��dpdk rss ��ϣ*/
        hash = dp_packet_get_rss_hash(packet);
    }
	else 
	{	
    	/*miniflow ��Ԫ�����Ĺ�ϣֵ*/
        hash = miniflow_hash_5tuple(mf, 0);

		/*ʹ��miniflow����Ĺ�ϣ����rss ��ϣֵ*/
        dp_packet_set_rss_hash(packet, hash);
    }

    return hash;
}

/*******************************************************************************
 ��������  :    dpif_netdev_packet_get_rss_hash
 ��������  :    ���ݱ��Ļ�ȡrss hash
 �������  :  	packet---����
 				mf---miniflow
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static inline uint32_t
dpif_netdev_packet_get_rss_hash(struct dp_packet *packet, const struct miniflow *mf)
{
    uint32_t hash, recirc_depth;

	/*ֱ�Ӵ�dpdk��ȡ��ϣ*/
    if (OVS_LIKELY(dp_packet_rss_valid(packet))) 
	{
        hash = dp_packet_get_rss_hash(packet);
    } 
	else 
	{
    	/*����miniflow ����Ԫ���ϣ*/
        hash = miniflow_hash_5tuple(mf, 0);

		/*����rss hash*/
        dp_packet_set_rss_hash(packet, hash);
    }

    /* The RSS hash must account for the recirculation depth to avoid
     * collisions in the exact match cache */

	/*RSSɢ�б��뿼��Ҫ�����ѭ����Ⱦ�ȷƥ�仺���еĳ�ͻ*/
    recirc_depth = *recirc_depth_get_unsafe();

	if (OVS_UNLIKELY(recirc_depth)) 
	{
        hash = hash_finish(hash, recirc_depth);

		/*�����ϣ*/
        dp_packet_set_rss_hash(packet, hash);
    }
	
    return hash;
}

/*ÿ����������ṹ�����ڻ���ƥ��ĳ��������Ķ������.��໺��32������ */
struct packet_batch_per_flow {
    unsigned int byte_count;         /* �������б��ĵ����ֽ��� */
    uint16_t tcp_flags;			     /*��miniflow��ȡtcp_flag*/

    struct dp_netdev_flow *flow;   /* ָ����ƥ�����������Ϣ */

    struct dp_packet_batch array;  /*�������Ļ�������*/
								     /*��dpdk�������ձ���ʱ��һ�ο�����������32�����ģ���Щ���ĵ���Ϣ���洢��dp_patch_batch���ݽṹ��*/
};

/*******************************************************************************
 ��������  :    packet_batch_per_flow_update
 ��������  :    �����ÿ������������
 �������  :    batch---ÿ��������ṹ
 			    packet---��ӵı���
 			    tcp_flags---tcp��ǣ���miniflow��ȡtcp_flag
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static inline void
packet_batch_per_flow_update(struct packet_batch_per_flow *batch, struct dp_packet *packet, uint16_t tcp_flags)
{
	/*���������ֽ���*/
    batch->byte_count += dp_packet_size(packet);

	/*tcp���*/
    batch->tcp_flags |= tcp_flags;

	/*��������ÿ������������һ���������Խ���32������ */
	batch->array.packets[batch->array.count++] = packet;
}

/*******************************************************************************
 ��������  :    packet_batch_per_flow_init
 ��������  :    ÿ�������������������ı��ģ�����������
 �������  :    batch---һ��������������ṹ	
 			    flow---�������е���
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static inline void
packet_batch_per_flow_init(struct packet_batch_per_flow *batch, struct dp_netdev_flow *flow)
{
	/*����¼ÿ��������ṹ*/
    flow->batch = batch;

	/*��¼��������*/
    batch->flow = flow;

	/*ÿ������������ṹ��ʼ��*/
    dp_packet_batch_init(&batch->array);

	/*��¼ÿ�������������ֽ���*/
    batch->byte_count = 0;

	/*��ȡ��ÿ������������tcp flag*/
    batch->tcp_flags = 0;
}

/*******************************************************************************
 ��������  :    packet_batch_per_flow_execute
 ��������  :    ÿ������������
 �������  :  	batch---ÿ������������
 				key---skb��ȡ��key
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static inline void
packet_batch_per_flow_execute(struct packet_batch_per_flow *batch, struct dp_netdev_pmd_thread *pmd)
{
    struct dp_netdev_actions *actions;

	/*��ȡÿ�������������Ӧ��flow*/
    struct dp_netdev_flow *flow = batch->flow;

	/*���������ֽ�����bit��*/
    dp_netdev_flow_used(flow, batch->array.count, batch->byte_count, batch->tcp_flags, pmd->ctx.now / 1000);

	/*��ȡflow��Ӧ��actions*/
    actions = dp_netdev_flow_get_actions(flow);

	/*ִ�����е�flow��Ӧ��actions*/
    dp_netdev_execute_actions(pmd, &batch->array, true, &flow->flow, actions->actions, actions->size);
}

/*******************************************************************************
 ��������  :    dp_netdev_queue_batches
 ��������  :    �����ÿ������������
 �������  :    pkt---����emc����ı���
 			    flow---�������е�smc ����Ϣ
 			    tcp_flags---��¼������ȡ��tcp_flags����miniflow��ȡtcp_flag
 			    batches---ÿ������������ṹ���飬֧�ֶ����
 			    n_batches---������index
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static inline void
dp_netdev_queue_batches(struct dp_packet *pkt, struct dp_netdev_flow *flow, uint16_t tcp_flags, struct packet_batch_per_flow *batches, size_t *n_batches)
{
	/*��ȡÿ������������ṹ*/
    struct packet_batch_per_flow *batch = flow->batch;

	/*����Ӧ��������������*/
    if (OVS_UNLIKELY(!batch)) 
	{
		/*��ȡһ������������ṹ*/
        batch = &batches[(*n_batches)++];

		/*ÿ�������������ʼ������¼��Ӧ����*/
        packet_batch_per_flow_init(batch, flow);
    }

	/*ÿ��������������¡���������ÿ��������*/
    packet_batch_per_flow_update(batch, pkt, tcp_flags);
}

/* SMC lookup function for a batch of packets.
 * By doing batching SMC lookup, we can use prefetch
 * to hide memory access latency.
 */

/*******************************************************************************
 ��������  :    smc_lookup_batch
 ��������  :    emc miss�ı��� smc���� �������ѯ������smc ����Ϣ����emc����ͳ������smc��������
 �������  :    pmd---pmd�߳�
 			    keys---miniflow key�ṹ����¼������ȡ��miniflow key��emc�Ѿ�miss�ı��ĵ�miniflow key
 			    missed_keys---δ����emc����ı���
 			    packets_---���б���������ṹ
 			    batches---ÿ������������ṹ��ָ������
 			    n_batches---������ṹ��
 			    cnt---miss�ı�����
 				
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static inline void
smc_lookup_batch(struct dp_netdev_pmd_thread *pmd, struct netdev_flow_key *keys, struct netdev_flow_key **missed_keys,
            struct dp_packet_batch *packets_, struct packet_batch_per_flow batches[],size_t *n_batches, const int cnt)
{
    int i;
    struct dp_packet *packet;
    size_t n_smc_hit = 0, n_missed = 0;

	/*emc��smc*/
    struct dfc_cache *cache = &pmd->flow_cache;

	/*smc*/
	struct smc_cache *smc_cache = &cache->smc_cache;

	const struct cmap_node *flow_node;

    /* Prefetch buckets for all packets */

	/*Ԥȡ*/
    for (i = 0; i < cnt; i++) 
	{
        OVS_PREFETCH(&smc_cache->buckets[keys[i].hash & SMC_MASK]);
    }

	/*�������б����������ģ�ʣ�µ�δ����emc�ı���*/
    DP_PACKET_BATCH_REFILL_FOR_EACH (i, cnt, packet, packets_) 
	{
        struct dp_netdev_flow *flow = NULL;

		/*���ݱ��Ĺ�ϣ��ȡsmc����ڵ�*/
        flow_node = smc_entry_get(pmd, keys[i].hash);

		/*smc ���г�ʼֵfalse*/
        bool hit = false;

		/*��ȡ����smc������ڵ�*/
        if (OVS_LIKELY(flow_node != NULL)) 
		{
			/*smc ����ڵ��µ�flow ����*/
            CMAP_NODE_FOR_EACH (flow, node, flow_node) 
			{
                /* Since we dont have per-port megaflow to check the port
                 * number, we need to  verify that the input ports match. */

				/*dpcls����ƥ��*/											  /*����ƥ��˿����*/
                if (OVS_LIKELY(dpcls_rule_matches_key(&flow->cr, &keys[i]) && flow->flow.in_port.odp_port == packet->md.in_port.odp_port)) 
               	{
                    /* SMC hit and emc miss, we insert into EMC */
					/*��ȡminiflow key��size*/
                    keys[i].len = netdev_flow_key_size(miniflow_n_values(&keys[i].mf));

					/*����smc������emc����*/
                    emc_probabilistic_insert(pmd, &keys[i], flow);

					/*��������ı�������ÿ������������*/
                    dp_netdev_queue_batches(packet, flow, miniflow_get_tcp_flags(&keys[i].mf), batches, n_batches);

					/*smc����++*/
					n_smc_hit++;

					/*smc���б��*/
					hit = true;

					break;
                }
            }
			
			/*����������smc ���������������**/
            if (hit) 
			{
                continue;
            }
        }

        /* SMC missed. Group missed packets together at
         * the beginning of the 'packets' array. */

		/*δ���б�������������б���������*/
        dp_packet_batch_refill(packets_, packet, i);

		/* Put missed keys to the pointer arrays return to the caller */
		/*����smc�ı��ĵ�key ��¼��miss key*/
        missed_keys[n_missed++] = &keys[i];
    }

	/*pmd����smc��������ͳ��*/
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
 ��������  :    dfc_processing
 ��������  :    emc�����ѯ��emc����δ���в�smc��������smc�������emc��������δ���еı��Ķ���������ṹ ȥ��dpcls
 			    1.��dp_packet_batch�е����а�����EMC(pmd->flow_cache)������ȷ����ƥ��
			    2.����Ҫ������fast_path_processing�д���İ���
			    3.ͬʱ��md_is_valid�ú�����������port_no��ʼ��metadata
			    �յ��ļ������Ľ���keyֵ�����Ҵ�cache�в�������ƥ��ı��ķ����������ز�ƥ��ı��ĸ���
 �������  :  	pmd--pmd�߳�
 �������  :	packets_---���б���������ṹ
 				keys---����emc�ı���miniflow key��������¼������ȡ��miniflow key
 				missed_keys---��¼δ����emc�ı���miniflow key��ָ������
 				batches---ÿ������������ṹ���飬֧�ֶ������������ÿ����һ��
 				n_batches---�������ĸ���
 				md_is_valid---false  metadata�Ƿ���Ч
 				port_no---in_port�˿ں�
 				
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static inline size_t
dfc_processing(struct dp_netdev_pmd_thread *pmd, struct dp_packet_batch *packets_, struct netdev_flow_key *keys,
               struct netdev_flow_key **missed_keys, struct packet_batch_per_flow batches[], size_t *n_batches, bool md_is_valid, odp_port_t port_no)
{
	/*miniflow key ��ַ*/
    struct netdev_flow_key *key = &keys[0];

	/*������miss ����*/
    size_t n_missed = 0, n_emc_hit = 0;

	/*pmd�̻߳���������emc cached��ȷ����*/
    struct dfc_cache *cache = &pmd->flow_cache;

	
	struct dp_packet *packet;

	/*��ǰ���б����������汨����*/
    const size_t cnt = dp_packet_batch_size(packets_);
	
    uint32_t cur_min;
    int i;
    uint16_t tcp_flags;

	/*���ݿ��Ƿ���smc����*/
    bool smc_enable_db;

	/*ԭ�Ӷ�ȡsmcʹ�ܿ���*/
    atomic_read_relaxed(&pmd->dp->smc_enable_db, &smc_enable_db);

	/*ԭ�Ӷ���ǰemc������С��*/
    atomic_read_relaxed(&pmd->dp->emc_insert_min, &cur_min);

	/*pmd���±��ļ�������*/
    pmd_perf_update_counter(&pmd->perf_stats, md_is_valid ? PMD_STAT_RECIRC : PMD_STAT_RECV, cnt);
	
    /*����ȡ�������������Ĵ���(�Ӷ���ȡ�����ģ�ÿ�����32��)*/
    DP_PACKET_BATCH_REFILL_FOR_EACH (i, cnt, packet, packets_) 
   	{
   		/*����*/
        struct dp_netdev_flow *flow;

		/*����mark*/
        uint32_t mark;

		/*��packet����С����̫ͷ�ĳ���14 ֱ�Ӷ���*/
        if (OVS_UNLIKELY(dp_packet_size(packet) < ETH_HEADER_LEN)) 
		{
			/*�ͷű���*/
            dp_packet_delete(packet);
			
            continue;
        }

		/*�������ֹ�Ԥȡ�ɼ��ٶ�ȡ�ӳ٣��Ӷ��������*/
        if (i != cnt - 1) 
		{
			/*������������ָ������*/
            struct dp_packet **packets = packets_->packets;
			
            /* Prefetch next packet data and metadata. */
			/*Ԥȡ��������*/
            OVS_PREFETCH(dp_packet_data(packets[i+1]));

			/*Ԫ����Ԥȡ*/
            pkt_metadata_prefetch_init(&packets[i+1]->md);
        }

	   /*metadataû����Ч���ʼ��metadata�����Ƚ�pkt_metadata��flow_in_portǰ���ֽ�ȫ����Ϊ0��Ȼ��in_port.odp_port��Ϊport_no,tunnel.ip_dst��Ϊ0�Ӷ�tunnel�е������ֶ�*/
        if (!md_is_valid) 
		{
			/*����Ԫ���ݳ�ʼ����ֻ����inport*/
            pkt_metadata_init(&packet->md, port_no);
        }

		/*����������Mark��ǣ��Ҳ���recircle���ģ���mark����֮ǰ���й�ĳ��flow��������flow��mark*/
        if ((*recirc_depth_get() == 0) && dp_packet_has_flow_mark(packet, &mark)) 
        {
        	/*���ݶ����������ĵ�markֱ���ҵ����������ڵ�flow*/
            flow = mark_to_flow_find(pmd, mark);
            if (flow) 
			{
				/*�Ӷ�������������ȡtcp ���*/
                tcp_flags = parse_tcp_flags(packet);

				/*����ֱ����������������ӵ�������������������*/
                dp_netdev_queue_batches(packet, flow, tcp_flags, batches, n_batches);

				/*���еı������������������������Ĵ���*/
				continue;
            }
        }

		VLOG_DBG("dp_netdev_input__ miniflow_extract");

		/*�ӱ�����ȡminiflow, �����Ľ�����keyֵ, ����pkt_metadata�е�ֵ�Լ�dp_packet->mbuf��ȡminiflow*/
        miniflow_extract(packet, &key->mf);

		/*miniflow ��������0*/
        key->len = 0; /* Not computed yet. */

		/*���emc��smc���ص�����ȥ�����ϣ*/
        /* If EMC and SMC disabled skip hash computation */

		/*�����뵱ǰdp_packet��Ӧ��miniflow���ڵ�netdev_flow_key�е�hash����hash����emc_lookup��ƥ��entry����hash����NIC��RSS modeʹ��ʱ�����հ�ʱ���㣬������miniflow_hash_5tuple�õ�*/
        if (smc_enable_db == true || cur_min != 0) 
		{
			/*����miniflow���ϣ������emc��metadata δ��Ч��hashΪ�������*/
            if (!md_is_valid) 
			{
				/*��dpdk rss �����miniflow��Ԫ�����ϣ*/
                key->hash = dpif_netdev_packet_get_rss_hash_orig_pkt(packet, &key->mf);
            }
			else 
			{
				/*���ݱ��Ļ�ȡrss hash*/
                key->hash = dpif_netdev_packet_get_rss_hash(packet, &key->mf);
            }
        }

		/*emc����������*/
        if (cur_min) 
		{
			/*emc��ѯ����hash���в��ң����ҽ���keyֵ�Ƚϣ�����key->hash��emc_entry alive, miniflow 3�������õ�dp_netdev_flow*/
            flow = emc_lookup(&cache->emc_cache, key);
			VLOG_DBG("dp_netdev_input__ emc_lookup flow");
        } 
		else 
		{
			/*emcδ�鵽�������ֵ��*/
            flow = NULL;
        }

		/*������emc������*/
		if (OVS_LIKELY(flow)) 
		{
			/*��miniflow��ȡtcp_flags*/
            tcp_flags = miniflow_get_tcp_flags(&key->mf);

			/*���ƥ�䣬����dp_netdev_queue_batches�����������flow->batches�У���ƥ�佫��ƥ��ı��ĵ�ǰ��*/
			/*����dp_netdev_flow��dp_packet���࣬��ͬ�Ը�dp_netdev_flow��Ӧ������dp_packet������ͬ��packet_batch_per_flow*/

			/*����emc����ı������Ӧ�������������棬һ����ִ��action*/
            dp_netdev_queue_batches(packet, flow, tcp_flags, batches, n_batches);

			VLOG_DBG("dp_netdev_input__  flow hit insert queue batches n_emc_hit=%u",n_emc_hit);

			/*emc�������б��ļ���+1*/
            n_emc_hit++;
        } 
		/*δ����*/
		else 
		{
            /* Exact match cache missed. Group missed packets together at
             * the beginning of the 'packets' array. */

			/*δ���б��������������������*/
            dp_packet_batch_refill(packets_, packet, i);
			
            /* 'key[n_missed]' contains the key of the current packet and it
             * will be passed to SMC lookup. The next key should be extracted
             * to 'keys[n_missed + 1]'.
             * We also maintain a pointer array to keys missed both SMC and EMC
             * which will be returned to the caller for future processing. */

			/*��¼δ���еı���key*/
            missed_keys[n_missed] = key;

			/*���еı���ָ�룬Ϊʲô��miss���±�*/
            key = &keys[++n_missed];
        }
    }

	/*emc�������б�������ͳ��*/
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_EXACT_HIT, n_emc_hit);

	/*���ݿ�û�п���smc*/
    if (!smc_enable_db) 
	{
		/*���ض�������������*/
        return dp_packet_batch_size(packets_);
    }

	/*emc��ƥ�䣬ȥsmcƥ��*/
    /* Packets miss EMC will do a batch lookup in SMC if enabled */
    smc_lookup_batch(pmd, keys, missed_keys, packets_, batches, n_batches, n_missed);
	
	VLOG_DBG("dp_netdev_input__  smc_lookup_batch ");

	/*��������Ҫ����� ���б�������������*/
    return dp_packet_batch_size(packets_);
}

/*******************************************************************************
 ��������  :    handle_packet_upcall
 ��������  :    upcall����, ofproto classifier����
 �������  :    key---skb��ȡ��key
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
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

	/*����ͳ��ʱ�����*/
    uint64_t cycles = cycles_counter_update(&pmd->perf_stats);

    match.tun_md.valid = false;

	/*key->mf������match.flow*/
    miniflow_expand(&key->mf, &match.flow);

    ofpbuf_clear(actions);
    ofpbuf_clear(put_actions);

	/*����keyֵ�����hash*/
    dpif_flow_hash(pmd->dp->dpif, &match.flow, sizeof match.flow, &ufid);

	/*��һ������ȥofproto classifier���Ľӿڣ����ʧ����ɾ������*/
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

	/*�����������ʼ��*/
    dp_packet_batch_init_packet(&b, packet);

	/*������ֱ��ִ��action��������Ҫ����Ϊʲô���ܷ���������*/
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

		/*��Ҫ���²���dpcls��û�в��ҵ������dp_netdev_flow_add�������*/
        netdev_flow = dp_netdev_pmd_lookup_flow(pmd, key, NULL);
        if (OVS_LIKELY(!netdev_flow))
		{
			/*�������*/
            netdev_flow = dp_netdev_flow_add(pmd, &match, &ufid, add_actions->data, add_actions->size);
        }
        ovs_mutex_unlock(&pmd->flow_mutex);

		/*ufid��ϣֵ*/
        uint32_t hash = dp_netdev_flow_hash(&netdev_flow->ufid);

		/*��ȷ������룬dpcls���������EMC��*/
        smc_insert(pmd, key, hash);

		/*emc�������*/
        emc_probabilistic_insert(pmd, key, netdev_flow);
    }
	
    if (pmd_perf_metrics_enabled(pmd)) 
	{
        /* Update upcall stats. */

		cycles = cycles_counter_update(&pmd->perf_stats) - cycles;

		/*ÿpmd����ͳ��*/
		struct pmd_perf_stats *s = &pmd->perf_stats;

		s->current.upcalls++;
        s->current.upcall_cycles += cycles;

		/*���*/
        histogram_add_sample(&s->cycles_per_upcall, cycles);
    }
    return error;
}

/*******************************************************************************
 ��������  :  fast_path_processing
 ��������  :  ��ת·������dpcls��ѯ
 			  ������ڲ�ƥ��ı��ģ������fast_path_processing��������ȫ������
			  �ҵ����������cache����ƥ�����ϱ���controller
 �������  :  pmd
              packets_---����ȡ���ı��ģ���������
 			  keys---emc miss�ı���key ָ�������ַ
 			  batches---ÿ�����������飬֧�ֶ����
 			  n_batches---ÿ�������������±�
 			  in_port---���������Ķ˿� 
 				
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static inline void
fast_path_processing(struct dp_netdev_pmd_thread *pmd, struct dp_packet_batch *packets_, struct netdev_flow_key **keys,
					struct packet_batch_per_flow batches[], size_t *n_batches, odp_port_t in_port)
{
	/*ÿ��������������*/
    const size_t cnt = dp_packet_batch_size(packets_);
	
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t PKT_ARRAY_SIZE = cnt;
#else
	/*��������size 32*/
    /* Sparse or MSVC doesn't like variable length array. */
    enum { PKT_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    struct dp_packet *packet;
    struct dpcls *cls;

	/*��¼���ҵ���dpcls rule ����*/
    struct dpcls_rule *rules[PKT_ARRAY_SIZE];

	/*pmd����dp ������ṹ*/
    struct dp_netdev *dp = pmd->dp;

	int upcall_ok_cnt = 0, upcall_fail_cnt = 0;
	
    int lookup_cnt = 0, add_lookup_cnt;

	bool any_miss;

	/*����ÿ��������������*/
    for (size_t i = 0; i < cnt; i++) 
	{
        /* Key length is needed in all the cases, hash computed on demand. */
		/*��ȡ���� miniflow �����ֶ�buf key���ȣ�����miniflow key len*/
        keys[i]->len = netdev_flow_key_size(miniflow_n_values(&keys[i]->mf));
    }
    /* Get the classifier for the in_port */
	/*1.����in_port����hashֵ��Ȼ���ɴ�hashֵ��pmd->classifiers�в���dpcls
       2.ÿ��in_portӵ��һ��dpcls
    */

	/*�˿����е�dpcls*/
    cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    if (OVS_LIKELY(cls)) 
	{
		/*dpcls��ѯ
		1.ͨ��classifier����������������еı��Ķ��ҵ���ƥ������������������emc�����У����ҽ����ļ���flow->batches��
		2.�����ƥ�䣬���ϱ���controller��ûϸ����
		3.ͳ��ƥ�䡢��ƥ��Ͷ�ʧ��
		*/
		/*���ݶ˿����е�dpcls������dpcls rule������miss�ı��ķ���false*/
        any_miss = !dpcls_lookup(cls, (const struct netdev_flow_key **)keys, rules, cnt, &lookup_cnt);
    } 
	/*δ�ҵ�dpcls����*/
	else 
	{
        any_miss = true;
        memset(rules, 0, sizeof(rules));
    }

	/*��rules[i]Ϊ�յ�packets[i]ת��upcall���̴���*/
    if (OVS_UNLIKELY(any_miss) && !fat_rwlock_tryrdlock(&dp->upcall_rwlock)) 
	{
        uint64_t actions_stub[512 / 8], slow_stub[512 / 8];
        struct ofpbuf actions, put_actions;

        ofpbuf_use_stub(&actions, actions_stub, sizeof actions_stub);
        ofpbuf_use_stub(&put_actions, slow_stub, sizeof slow_stub);

		/*������������*/
        DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) 
		{
            struct dp_netdev_flow *netdev_flow;

			/*dpcls�������*/
            if (OVS_LIKELY(rules[i])) 
			{
                continue;
            }

            /* It's possible that an earlier slow path execution installed
             * a rule covering this flow.  In this case, it's a lot cheaper
             * to catch it here than execute a miss. */

			/*����keys�е�miniflow�õ�in_port�����ø�in_port����dpcls�����ҵ��͵���dpcls_lookup�ڽ���һ��rule�Ĳ���*/
            netdev_flow = dp_netdev_pmd_lookup_flow(pmd, keys[i], &add_lookup_cnt);
            if (netdev_flow) 
			{
				/*����dpcls���� ���� ��¼*/
                lookup_cnt += add_lookup_cnt;
                rules[i] = &netdev_flow->cr;
                continue;
            }

			/*����upcall����*/
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

	/*������������*/
    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) 
	{
        struct dp_netdev_flow *flow;

		/*δ����dpcls���� continue*/
        if (OVS_UNLIKELY(!rules[i])) 
		{
            continue;
        }

		 /*����ÿ��������Ӧ��dpcls_rule�õ����Ӧ��miniflow ��󽫸�flow���뵽emc�У�ͬʱ���ݸ�flow��packet�������*/
        flow = dp_netdev_flow_cast(rules[i]);

		
        uint32_t hash = dp_netdev_flow_hash(&flow->ufid);

		/*smc�������*/
        smc_insert(pmd, keys[i], hash);

		/*emc ����*/
        emc_probabilistic_insert(pmd, keys[i], flow);

		/*����������*/
        dp_netdev_queue_batches(packet, flow, miniflow_get_tcp_flags(&keys[i]->mf), batches, n_batches);
    }

	/*���¸�����������ͳ��*/
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
 ��������  :    ovs_dp_process_packet
 ��������  :    ���Ĵ�������(�����ƥ�䣬Ȼ��ִ����Ӧ��action)
 �������  :    key---skb��ȡ��key
 �������  :	pmd---pmd�߳�
			    packets---�����������汨�Ľṹ����ʱ�ṹ���Ӷ���ȡ�ı���
			    md_is_valid---metadata�Ƿ���Ч��recircle����Ϊtrue
 			    port_no---�˿ں�
 			
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static void dp_netdev_input__(struct dp_netdev_pmd_thread *pmd, struct dp_packet_batch *packets, bool md_is_valid, odp_port_t port_no)
{

#if !defined(__CHECKER__) && !defined(_WIN32)

	/*��ǰ��Ҫ����������*/
    const size_t PKT_ARRAY_SIZE = dp_packet_batch_size(packets);
#else
    /* Sparse or MSVC doesn't like variable length array. */
    enum { PKT_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE)

	/*�ӱ�����ȡ��miniflow key*/
	struct netdev_flow_key keys[PKT_ARRAY_SIZE];

	/*δ����emc��dpcls�ı���miniflow key��¼��ָ�����飬����upcall�ϱ�*/
    struct netdev_flow_key *missed_keys[PKT_ARRAY_SIZE];

	/*ÿ������������ṹ���飬��¼����flow�ı���*/
    struct packet_batch_per_flow batches[PKT_ARRAY_SIZE];

	/*������ṹ��*/
    size_t n_batches;
    odp_port_t in_port;

    n_batches = 0;

	VLOG_DBG("dp_netdev_input__ pmd->core_id=%u",pmd->core_id);


	/* 1.��dp_packet_batch�е����а�����EMC(pmd->flow_cache)����IP 5Ԫ��ľ�ȷƥ�䣬����δ����emcҪ������fast_path_processing�д���İ���
       2.ͬʱ��md_is_validΪfalse�ú�����������port_no��ʼ��metadata
    */

	/*1.���յ��ı��Ľ���keyֵ�����Ҳ�emc����cache�У�ƥ��ı��ķ����������������ز�ƥ��ı��ĸ���
	  2.������ڲ�ƥ��ı��ģ�����fast_path_processing���������dpclsȫ������ҵ����������emc cache����ƥ�����ϱ���controller*/
    dfc_processing(pmd, packets, keys, missed_keys, batches, &n_batches, md_is_valid, port_no);

	/*�����������Ĳ�Ϊ��(δ����EMC����ı���)��ȥ��dpcls*/
	if (!dp_packet_batch_is_empty(packets)) 
	{
        /* Get ingress port from first packet's metadata. */
		/*�ӱ���metadata�л�ȡ�����������ĵ�inport*/
        in_port = packets->packets[0]->md.in_port.odp_port;

		/*��ת·������������ڲ�ƥ��ı��ģ������fast_path_processing��������ȫ������ҵ����������cache����ƥ�����ϱ���controller*/
		/*dpcls��ѯ*/
        fast_path_processing(pmd, packets, missed_keys, batches, &n_batches, in_port);
    }

    /* All the flow batches need to be reset before any call to
     * packet_batch_per_flow_execute() as it could potentially trigger
     * recirculation. When a packet matching flow ‘j’ happens to be
     * recirculated, the nested call to dp_netdev_input__() could potentially
     * classify the packet as matching another flow - say 'k'. It could happen
     * that in the previous call to dp_netdev_input__() that same flow 'k' had
     * already its own batches[k] still waiting to be served.  So if its
     * ‘batch’ member is not reset, the recirculated packet would be wrongly
     * appended to batches[k] of the 1st call to dp_netdev_input__(). */
    size_t i;

	/*������ṹ�������ĳ�ʼ��*/
    for (i = 0; i < n_batches; i++) 
	{
		/*ÿ������������ṹ��flow������������ṹ��ֵNULL Ϊɶ*/
        batches[i].flow->batch = NULL;
    }

	/*����packet_batch_execute�����������������ģ�ͳһ���ø��Ե�action*/
    for (i = 0; i < n_batches; i++) 
	{	
		/*ÿ������������ִ�ж�Ӧ����action*/
        packet_batch_per_flow_execute(&batches[i], pmd);
    }
}

/*******************************************************************************
 ��������  :    dp_netdev_input
 ��������  :    pmd����������
 �������  :  	key---skb��ȡ��key
 �������  :	pmd---pmd�߳�
 				packets---�������汨�Ľṹ����ʱ�ṹ
 				port_no---�˿ں�
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static void
dp_netdev_input(struct dp_netdev_pmd_thread *pmd, struct dp_packet_batch *packets, odp_port_t port_no)
{
    dp_netdev_input__(pmd, packets, false, port_no);
}

/*******************************************************************************
 ��������  :    dp_netdev_recirculate
 ��������  :    ��recircle����
 �������  :  	pmd---���ϱ��ĵ�pmd
 				packets---recircle ������ı���
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
dp_netdev_recirculate(struct dp_netdev_pmd_thread *pmd, struct dp_packet_batch *packets)
{
	/*���Ĵ�������(�����ƥ�䣬Ȼ��ִ����Ӧ��action)��������һ��*/
    dp_netdev_input__(pmd, packets, true, 0);
}

/*���е�flow��flow���ڵ�pmd*/
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
 �������� :  dpif_netdev_xps_get_tx_qid
 �������� :  �ͷŷ��Ͷ��е�ID
 ������� :  pmd---pmd�߳�
 		     purge---������Ϊfalse
 ������� :  ��
 ����ֵ�� :  ��
 --------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸����� :  
 �޸�Ŀ�� :  
 �޸����� :  
*******************************************************************************/

static void
dpif_netdev_xps_revalidate_pmd(const struct dp_netdev_pmd_thread *pmd, bool purge)
{
    struct tx_port *tx;
    struct dp_netdev_port *port;
    long long interval;

	/*��������ķ��˿ڡ����ʹ�õķ�����id*/
    HMAP_FOR_EACH (tx, node, &pmd->send_port_cache) 
	{
		/*���˿�ʹ�ö�̬���б��δʹ��*/
        if (!tx->port->dynamic_txqs) 
		{
            continue;
        }

		/*����һ�η��ͼ��ʱ��*/
        interval = pmd->ctx.now - tx->last_used;

		/*������ID���ڣ���purge==false interval < 500000LL, ������ID���*/
		if (tx->qid >= 0 && (purge || interval >= XPS_TIMEOUT)) 
		{
			/*��ȡ�����ж˿�*/
            port = tx->port;
            ovs_mutex_lock(&port->txq_used_mutex);

			/*�˿��·��������ô���--��Ϊʲô*/
            port->txq_used[tx->qid]--;
            ovs_mutex_unlock(&port->txq_used_mutex);

			/*������ʹ�õ�ID���*/
            tx->qid = -1;
        }
    }
}

/*******************************************************************************
 �������� :  dpif_netdev_xps_get_tx_qid
 �������� :  �ӷ�����ID�ض�̬��ȡ���Ͷ��е�ID
 ������� :  pmd---pmd�߳�
 			 p---pmd����ķ��˿�
 ������� :  ��
 ����ֵ�� :  ��
 --------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸����� :  
 �޸�Ŀ�� :  
 �޸����� :  
*******************************************************************************/
static int
dpif_netdev_xps_get_tx_qid(const struct dp_netdev_pmd_thread *pmd, struct tx_port *tx)
{
    struct dp_netdev_port *port;
    long long interval;
    int i, min_cnt, min_qid;

	/*���Ͷ���ʹ��ʱ����*/
    interval = pmd->ctx.now - tx->last_used;

	/*���Ͷ����ϴ�ʹ��ʱ��*/
    tx->last_used = pmd->ctx.now;

	/*���Ͷ���ID���ڣ����ϴη�ʱ�� ���С��500000 ΢��*/
    if (OVS_LIKELY(tx->qid >= 0 && interval < XPS_TIMEOUT)) 
	{
        return tx->qid;
    }

	/*���Ͷ˿�*/
    port = tx->port;

	/*��������ȡ*/
    ovs_mutex_lock(&port->txq_used_mutex);

	/*���Ͷ���ID����*/
    if (tx->qid >= 0) 
	{
		/*���Ͷ������ô�������һ��*/
        port->txq_used[tx->qid]--;

		/*����˿ڷ�����ID*/
        tx->qid = -1;
    }

    min_cnt = -1;
    min_qid = 0;

	/*�����˿��Ϸ����У�ѡ�����ô���С��-1�Ķ���*/
    for (i = 0; i < netdev_n_txq(port->netdev); i++) 
	{
		/*ѡ��������i���ô���С��-1�Ķ��У�*/
        if (port->txq_used[i] < min_cnt || min_cnt == -1) 
		{
			/*��¼����i���ô���*/
            min_cnt = port->txq_used[i];

			/*��¼����id*/
            min_qid = i;
        }
    }

	/*���Ͷ���i���ô�������*/
    port->txq_used[min_qid]++;

	/*������id��ֵ*/
    tx->qid = min_qid;

	/*����������*/
    ovs_mutex_unlock(&port->txq_used_mutex);

	/*ʹ������Ч*/
    dpif_netdev_xps_revalidate_pmd(pmd, false);

    VLOG_DBG("Core %d: New TX queue ID %d for port \'%s\'.", pmd->core_id, tx->qid, netdev_get_name(tx->port->netdev));
	
    return min_qid;
}

/*******************************************************************************
 ��������  :  pmd_tnl_port_cache_lookup
 ��������  :  ���ݶ˿ںŻ�ȡvxlan�˿�
 �������  :  
 			  
 �������  :  
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static struct tx_port *
pmd_tnl_port_cache_lookup(const struct dp_netdev_pmd_thread *pmd, odp_port_t port_no)
{
	/*���ݶ˿ںŲ�ѯvxlan����˿�*/
    return tx_port_lookup(&pmd->tnl_port_cache, port_no);
}

/*******************************************************************************
 ��������  :  pmd_send_port_cache_lookup
 ��������  :  ���ݶ˿ں���pmd->send_port_cache �в鷢�˿�
 �������  :  pmd---flow ����pmd
 			  port_no---output�˿�
 			  
 �������  :  
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static struct tx_port *
pmd_send_port_cache_lookup(const struct dp_netdev_pmd_thread *pmd, odp_port_t port_no)
{
    return tx_port_lookup(&pmd->send_port_cache, port_no);
}

/*******************************************************************************
 ��������  :  dp_netdev_pmd_flush_output_on_port
 ��������  :  ��װvxlan
 �������  :  key---skb��ȡ��key
 			  a---��������
 			  should_steal---�����Ƿ���ȡ
 			  batch---����������
 			  
 �������  :  
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static int
push_tnl_action(const struct dp_netdev_pmd_thread *pmd, const struct nlattr *attr, struct dp_packet_batch *batch)
{
    struct tx_port *tun_port;
    const struct ovs_action_push_tnl *data;
    int err;

	/*�������Ի�ȡvxlan��������*/
    data = nl_attr_get(attr);

	/*����tnl_port�˿ںŴ�pmd->tnl_port_cache�л�ȡvxlan port*/
    tun_port = pmd_tnl_port_cache_lookup(pmd, data->tnl_port);
    if (!tun_port) 
	{
        err = -EINVAL;
        goto error;
    }

	/*��װvxlanͷ*/
    err = netdev_push_header(tun_port->port->netdev, batch, data);
    if (!err) 
	{
        return 0;
    }
error:

	/*��������ɾ�����ͷű����ڴ�*/
    dp_packet_delete_batch(batch, true);
    return err;
}

/*******************************************************************************
 ��������  :    dp_execute_userspace_action
 ��������  :    �ӵ��û�̬
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
dp_execute_userspace_action(struct dp_netdev_pmd_thread *pmd,
                            struct dp_packet *packet, bool should_steal,
                            struct flow *flow, ovs_u128 *ufid,
                            struct ofpbuf *actions,
                            const struct nlattr *userdata)
{
    struct dp_packet_batch b;
    int error;

    ofpbuf_clear(actions);

	/*�ӵ��û�̬*/
    error = dp_netdev_upcall(pmd, packet, flow, NULL, ufid,
                             DPIF_UC_ACTION, userdata, actions,
                             NULL);
    if (!error || error == ENOSPC) {
        dp_packet_batch_init_packet(&b, packet);
        dp_netdev_execute_actions(pmd, &b, should_steal, flow,
                                  actions->data, actions->size);
    } 
	/*������ȡ���*/
	else if (should_steal) {
        dp_packet_delete(packet);
    }
}

/*******************************************************************************
 ��������  :    dp_execute_cb
 ��������  :    ����action�ص�����
 �������  :  	aux_---pmd��flow��Ϣ
 				packets_---����������ṹ
 				key---skb��ȡ��key
 				a---�������ԣ���output�˿ں�
 				should_steal---�����Ƿ���ȡ
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
dp_execute_cb(void *aux_, struct dp_packet_batch *packets_, const struct nlattr *a, bool should_steal)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
	/*pmd��flow��Ϣ*/
    struct dp_netdev_execute_aux *aux = aux_;

	/*�Ѿ�recirc����*/
    uint32_t *depth = recirc_depth_get();

	/*��ȡpmd*/
    struct dp_netdev_pmd_thread *pmd = aux->pmd;

	/*�����������豸�ṹ*/
    struct dp_netdev *dp = pmd->dp;

	/*action ������*/
    int type = nl_attr_type(a);

	/*���Ͷ˿�*/
    struct tx_port *p;

	/*flow�� action ������*/
    switch ((enum ovs_action_attr)type) 
	{
		/*����dp_netdev_lookup_port���Ҷ˿ڣ�Ȼ�����netdev_send���б��ķ���*/
	    case OVS_ACTION_ATTR_OUTPUT:
			
			/*���ݶ˿ں���pmd->send_port_cache�в鷢�˿ڣ�ÿ���˿ڶ������ʱ������һ�����ṹ*/
	        p = pmd_send_port_cache_lookup(pmd, nl_attr_get_odp_port(a));
	        if (OVS_LIKELY(p))
			{
	            struct dp_packet *packet;
	            struct dp_packet_batch out;

				/*��ȡ����δ��*/
	            if (!should_steal) 
				{
					/*�������Ĵ�packets_ cloneһ�ݵ�out�ṹ��ÿ�����Ķ�����buffer*/
	                dp_packet_batch_clone(&out, packets_);

					/*β��Ҫ�����ĳ�������0*/
	                dp_packet_batch_reset_cutlen(packets_);

					/*ʹ��out������ṹ*/
	                packets_ = &out;
	            }

				/*�����趨���ĳ���Ϊcut��ĳ���*/
	            dp_packet_batch_apply_cutlen(packets_);

/*dpdk�Ĵ���*/
#ifdef DPDK_NETDEV
				/*�˿ڷ����ķ���������Ϊ������Ϊ0���Ҵ��ڵı���src��out���µ���������src����ȣ��ȷ����˿����Ѵ��ڵ���������*/
	            if (OVS_UNLIKELY(!dp_packet_batch_is_empty(&p->output_pkts) && packets_->packets[0]->source != p->output_pkts.packets[0]->source)) 
	            {
	                /* XXX: netdev-dpdk assumes that all packets in a single
	                 *      output batch has the same source. Flush here to
	                 *      avoid memory access issues. */

					/*dpdk�ӷ����˿ڱ���������ṹp->output_pkts��������*/
	                dp_netdev_pmd_flush_output_on_port(pmd, p);
	            }
#endif
				/*�µ����������ļ����Ѵ��ڵķ��������ĸ�������32�����ȷ����Ѵ��ڵ���������*/
	            if (dp_packet_batch_size(&p->output_pkts) + dp_packet_batch_size(packets_) > NETDEV_MAX_BURST) 
				{
	                /* Flush here to avoid overflow. */

					/*�����ı������*/
	                dp_netdev_pmd_flush_output_on_port(pmd, p);
	            }

				/*ԭ�����������ĸ���Ϊ��*/
	            if (dp_packet_batch_is_empty(&p->output_pkts)) 
				{
					/*�������������ļ���*/
	                pmd->n_output_batches++;
	            }

				/*������������˿ڷ�������ṹ*/
	            DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) 
				{
					/*��¼pmd�ϴ�ʹ�õķ�����*/
	                p->output_pkts_rxqs[dp_packet_batch_size(&p->output_pkts)] = pmd->ctx.last_rxq;

					/*������ӵ��˿ڷ�������ṹ*/
					dp_packet_batch_add(&p->output_pkts, packet);
	            }
				
	            return;
	        }

			break;

		/*����push_tnl_action����tunnel��װ��Ȼ�����dp_netdev_recirculate�C>dp_netdev_input__���²�����*/
	    case OVS_ACTION_ATTR_TUNNEL_PUSH:
			/*���ı���ȡ*/
	        if (should_steal) 
			{
	            /* We're requested to push tunnel header, but also we need to take
	             * the ownership of these packets. Thus, we can avoid performing
	             * the action, because the caller will not use the result anyway.
	             * Just break to free the batch. */
	            break;
	        }

			/*Ӧ���µı��ĳ���Ϊ��ȡ��ĳ���*/
	        dp_packet_batch_apply_cutlen(packets_);

			/*��vxlan*/
	        push_tnl_action(pmd, a, packets_);
			
	        return;

		/*����netdev_pop_header���װ��Ȼ�����dp_netdev_recirculate�C>dp_netdev_input__���²�����*/
	    case OVS_ACTION_ATTR_TUNNEL_POP:

			/*recircle ���Ϊ6 */
	        if (*depth < MAX_RECIRC_DEPTH) 
			{
	            struct dp_packet_batch *orig_packets_ = packets_;

				/*vxlan�˿ں�*/
	            odp_port_t portno = nl_attr_get_odp_port(a);

				/*���ݶ˿ںŻ�ȡin_port�˿�*/
	            p = pmd_tnl_port_cache_lookup(pmd, portno);
	            if (p)
				{
					/*��vxlan��������ṹ*/
	                struct dp_packet_batch tnl_pkt;

					/*����δ��ȡ*/
	                if (!should_steal) 
					{
						/*���Ŀ�����tnl_pkt��ʱ�ṹ*/
	                    dp_packet_batch_clone(&tnl_pkt, packets_);
						
	                    packets_ = &tnl_pkt;

						/*��������β����Ҫcut���ֽ�����Ϊ0*/
						dp_packet_batch_reset_cutlen(orig_packets_);
	                }

					/*���ĳ�������Ϊcut�󳤶�*/
	                dp_packet_batch_apply_cutlen(packets_);

					/*��vxlanͷ�����걨���������batch*/
	                netdev_pop_header(p->port->netdev, packets_);

					/*�������������Ϊ��*/
					if (dp_packet_batch_is_empty(packets_)) 
					{
	                    return;
	                }

	                struct dp_packet *packet;

					/*����pop��ı���metadata���� in_port*/
					DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) 
					{
						/*port�Ÿ�ֵ������metadata*/
	                    packet->md.in_port.odp_port = portno;
	                }

					/*recircle���+1*/
	                (*depth)++;
					
					/*����vxlan��recircle����ƥ���������Ĵ�������(�����ƥ�䣬Ȼ��ִ����Ӧ��action)*/
	                dp_netdev_recirculate(pmd, packets_);
					
					/*recircle���-1*/
	                (*depth)--;
					
	                return;
	            }
	        }
	        break;

		/*�ӵ��û�̬*/
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

				/*��������upcall �ӵ��û�̬*/
				DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) 
				{
	                flow_extract(packet, &flow);
	                dpif_flow_hash(dp->dpif, &flow, sizeof flow, &ufid);

					/*�ӵ��û�̬*/
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

		/*����recircle����*/
	    case OVS_ACTION_ATTR_RECIRC:

			/*recircle���Ϊ6*/
	        if (*depth < MAX_RECIRC_DEPTH) 
			{
	            struct dp_packet_batch recirc_pkts;

				/*����ȡ���*/
	            if (!should_steal) 
				{
				   /*����clone�����ڴ�*/
	               dp_packet_batch_clone(&recirc_pkts, packets_);
	               packets_ = &recirc_pkts;
	            }

	            struct dp_packet *packet;

				/*�������Ĵ���recircle id*/
	            DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) 
				{
	                packet->md.recirc_id = nl_attr_get_u32(a);
	            }

				/*����ȥ��recircle��ȥƥ��һ��*/
	            (*depth)++;
				
				/*recircle�����������¹�һ������ƥ��*/
	            dp_netdev_recirculate(pmd, packets_);

				(*depth)--;

	            return;
	        }

	        VLOG_WARN("Packet dropped. Max recirculation depth exceeded.");
	        break;

		/*ִ��ct����*/
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

			/*��b����ȡ���ֶ�*/
	        NL_ATTR_FOR_EACH_UNSAFE (b, left, nl_attr_get(a),
	                                 nl_attr_get_size(a)) 
	        {
	        	/**/
	            enum ovs_ct_attr sub_type = nl_attr_type(b);

				/*��������ִ�ж�Ӧ�Ĳ���*/
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

					/*nat����*/
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

			/*ִ�����Ӹ���action������һ��conn*/
	        conntrack_execute(&dp->conntrack, packets_, aux->flow->dl_type, force,
	                          commit, zone, setmark, setlabel, aux->flow->tp_src,
	                          aux->flow->tp_dst, helper, nat_action_info_ref,
	                          pmd->ctx.now / 1000);
	        break;
	    }

		/*ִ��meter action*/
	    case OVS_ACTION_ATTR_METER:

			/*������drop*/
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

	/*δƥ��ı���ɾ��*/
    dp_packet_delete_batch(packets_, should_steal);
}

/*******************************************************************************
 ��������  :  dp_netdev_execute_actions
 ��������  :  ִ�����е�flow��Ӧ��actions
 			  pmd---pmd�߳�
 			  packets--ÿ����������������
 			  should_steal---�Ƿ�steal
 			  flow---����
 			  actions---�����action����
 			  actions_len---����Ӧ��action �ֽڳ���
 			  
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
dp_netdev_execute_actions(struct dp_netdev_pmd_thread *pmd, struct dp_packet_batch *packets, bool should_steal, const struct flow *flow, const struct nlattr *actions, size_t actions_len)
{
    struct dp_netdev_execute_aux aux = { pmd, flow };

	/*�����һЩ���������Ļ������ýӿ�dp_execute_cb*/
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

/*dpdk�õ���netdev���͵�dpif��������ӿڲ�����*/
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

	/*��������Ӷ˿�*/
    dpif_netdev_port_add,
    dpif_netdev_port_del,

	/*���ö˿�rxq���׺���*/
    dpif_netdev_port_set_config,
    dpif_netdev_port_query_by_number,
    dpif_netdev_port_query_by_name,
    NULL,                       /* port_get_pid */
    dpif_netdev_port_dump_start,
    dpif_netdev_port_dump_next,
    dpif_netdev_port_dump_done,
    dpif_netdev_port_poll,
    dpif_netdev_port_poll_wait,

	/*flow�Ĳ���*/
	dpif_netdev_flow_flush,
    dpif_netdev_flow_dump_create,
    dpif_netdev_flow_dump_destroy,
    dpif_netdev_flow_dump_thread_create,
    dpif_netdev_flow_dump_thread_destroy,
    dpif_netdev_flow_dump_next,
    dpif_netdev_operate,								/*����Ĳ���
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

	/*ct����*/
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

	/*meter ����*/
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
/* ����ṹ*/
struct dpcls_subtable 
{
    /* The fields are only used by writers. */
    struct cmap_node cmap_node OVS_GUARDED; /* Within dpcls 'subtables_map'. */

    /* These fields are accessed by readers. */
	/* ÿ���ӱ����԰�������������dpcls����. */
    struct cmap rules;           /* Contains "struct dpcls_rule"s. */         	    /*�����°���������dpcls ����*/

	uint32_t hit_cnt;            /* Number of match hits in subtable in current  	/*���и��ӱ��ͳ�Ƽ���*/
                                 /* optimization interval. */
	
    struct netdev_flow_key mask; /* Wildcards for fields (const). */				/*miniflow key ����*/
    /* 'mask' must be the last field, additional space is allocated here. */
};

/* Initializes 'cls' as a classifier that initially contains no classification
 * rules. */

/*******************************************************************************
 �������� :  dpcls_init
 �������� :  dpcls ��ʼ��
 ������� :  cls---dpcls�ṹ
 
 ������� :  ��
 ����ֵ�� :  ��
 --------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸����� :  
 �޸�Ŀ�� :  
 �޸����� :  
*******************************************************************************/

static void
dpcls_init(struct dpcls *cls)
{
	/*�ӱ�*/
    cmap_init(&cls->subtables_map);

	/*���ȼ��ӱ�*/
    pvector_init(&cls->subtables);
}

/*******************************************************************************
 ��������  :  dpcls_destroy_subtable
 ��������  :  pmd���Ͷ˿ڵı���
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
dpcls_destroy_subtable(struct dpcls *cls, struct dpcls_subtable *subtable)
{
    VLOG_DBG("Destroying subtable %p for in_port %d", subtable, cls->in_port);

	/*ɾ��subtable*/
  	pvector_remove(&cls->subtables, subtable);

	cmap_remove(&cls->subtables_map, &subtable->cmap_node, subtable->mask.hash);
	
    cmap_destroy(&subtable->rules);

	ovsrcu_postpone(free, subtable);
}

/*******************************************************************************
 ��������  :  dpcls_destroy
 ��������  :  
 �������  :  
 			  
 �������  :  
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
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

			/*dpctl ���ѯ*/
            dpcls_destroy_subtable(cls, subtable);
        }
        cmap_destroy(&cls->subtables_map);
        pvector_destroy(&cls->subtables);
    }
}

/*******************************************************************************
 ��������  :    emc_cache_slow_sweep
 ��������  :    emc����ɾ��
 �������  :  	cls---dpcls����
 				mask---����
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static struct dpcls_subtable *
dpcls_create_subtable(struct dpcls *cls, const struct netdev_flow_key *mask)
{
    struct dpcls_subtable *subtable;

    /* Need to add one. */
    subtable = xmalloc(sizeof *subtable - sizeof subtable->mask.mf + mask->len);

	/*��������ʼ��*/
	cmap_init(&subtable->rules);

	/*��������д�����ʼ��0*/
	subtable->hit_cnt = 0;

	/*��������*/
	netdev_flow_key_clone(&subtable->mask, mask);

	/*��������subtables_map*/
	cmap_insert(&cls->subtables_map, &subtable->cmap_node, mask->hash);

	/*����*/
    /* Add the new subtable at the end of the pvector (with no hits yet) */
	pvector_insert(&cls->subtables, subtable, 0);

	VLOG_DBG("Creating %"PRIuSIZE". subtable %p for in_port %d",
             cmap_count(&cls->subtables_map), subtable, cls->in_port);

	pvector_publish(&cls->subtables);

    return subtable;
}

/*******************************************************************************
 ��������  :    dpcls_find_subtable
 ��������  :    ���������
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
static inline struct dpcls_subtable *
dpcls_find_subtable(struct dpcls *cls, const struct netdev_flow_key *mask)
{
    struct dpcls_subtable *subtable;

    CMAP_FOR_EACH_WITH_HASH (subtable, cmap_node, mask->hash, &cls->subtables_map) 
	{
		/*���������*/
        if (netdev_flow_key_equal(&subtable->mask, mask)) {
            return subtable;
        }
    }

	/*���������*/
    return dpcls_create_subtable(cls, mask);
}


/*******************************************************************************
 ��������  :  dpcls_sort_subtable_vector
 ��������  :  dpcls subtable ��������
 �������  :  
 			  
 �������  :  
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
/* Periodically sort the dpcls subtable vectors according to hit counts */
static void
dpcls_sort_subtable_vector(struct dpcls *cls)
{
    struct pvector *pvec = &cls->subtables;
    struct dpcls_subtable *subtable;

    PVECTOR_FOR_EACH (subtable, pvec) 
	{
		/*���ȼ�*/
        pvector_change_priority(pvec, subtable, subtable->hit_cnt);
        subtable->hit_cnt = 0;
    }
	
    pvector_publish(pvec);
}

/*******************************************************************************
 ��������  :  dp_netdev_pmd_try_optimize
 ��������  :  pmd���Ͷ˿ڵı���
 �������  :  
 			  
 �������  :  
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
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
 ��������  :    dpcls_insert
 ��������  :    ���������ҵ���Ӧ���ӱ�Ȼ����뵱ǰ������
 �������  :  	cls---pmd port��Ӧ��dpcls�ṹ
 				rule---flow���ɵ�dpcls rule
 				mask---miniflow key mask
 �������  :	
 �� �� ֵ  : 	��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
/* Insert 'rule' into 'cls'. */
static void
dpcls_insert(struct dpcls *cls, struct dpcls_rule *rule, const struct netdev_flow_key *mask)
{
	/*���������ȡ�����  �ӱ�*/
    struct dpcls_subtable *subtable = dpcls_find_subtable(cls, mask);

    /* Refer to subtable's mask, also for later removal. */
    rule->mask = &subtable->mask;

	/*dpcls������� miniflow��hash ��λcmap��ѯemc*/
    cmap_insert(&subtable->rules, &rule->cmap_node, rule->flow.hash);
}

/*******************************************************************************
 ��������  :    dpcls_remove
 ��������  :    dpcls����ɾ��
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
		/*ɾ���յ������*/
		dpcls_destroy_subtable(cls, subtable);

		/**/
		pvector_publish(&cls->subtables);
    }
}

/* Returns true if 'target' satisfies 'key' in 'mask', that is, if each 1-bit
 * in 'mask' the values in 'key' and 'target' are the same. */
/*******************************************************************************
 ��������  :    dpcls_rule_matches_key
 ��������  :    dpcls �����ѯ
 �������  :    rule---smc�����Ӧdpcls ����
 				target---Ҫƥ��ı��ĵ� miniflow key
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static bool
dpcls_rule_matches_key(const struct dpcls_rule *rule, const struct netdev_flow_key *target)
{
	/*miniflow��ȡ��ֵ*/
    const uint64_t *keyp = miniflow_get_values(&rule->flow.mf);

	/*����ֵ*/
	const uint64_t *maskp = miniflow_get_values(&rule->mask->mf);
    uint64_t value;

	/**/
    NETDEV_FLOW_KEY_FOR_EACH_IN_FLOWMAP(value, target, rule->flow.mf.map) 
	{
		/*�����miniflow ������?*/
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
 ��������  :  dpcls_lookup
 ��������  :  dpcls rule��ѯ
 			  1.ͨ��classifier���������������еı��Ķ��ҵ���ƥ�����������������뻺���У����ҽ����ļ���flow->batches
 			  �����ƥ�䣬���ϱ���controller,ͳ��ƥ�䡢��ƥ��Ͷ�ʧ

 			  dpcls-���->subtables-���->rules��
 			  cmap_find_batch�ڲ���hashֵ��ͬʱ����ÿ��miniflow��Ӧ��rule���и�ֵ

 			  ���ݲ�ͬ����������ӱ�����֣�
 			  Ȼ�����ű��ķֱ�ȥ���е��ӱ���key��mask�����hash���鿴�ӱ�����û����Ӧ��node��
 			  ����еĻ��鿴�Ƿ���hash��ͻ�������ղ鿴�Ƿ���ƥ��keyֵ�ı���

 �������  :  cls---port���ҵ���dpcls�ṹ
 			  keys---����miniflow keyָ�����飬 emc miss�ı���miniflow key
 			  rules---dpcls rule ָ�����飬���ڼ�¼���е�dpcls rule ����
 			  cnt---ÿ��������������
 			  num_lookups_p---dpcls�����ѯ����
 �������  :	
 �� �� ֵ  :  ��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
static bool
dpcls_lookup(struct dpcls *cls, const struct netdev_flow_key *keys[], struct dpcls_rule **rules, const size_t cnt, int *num_lookups_p)
{
    /* The received 'cnt' miniflows are the search-keys that will be processed
     * to find a matching entry into the available subtables.
     * The number of bits in map_type is equal to NETDEV_MAX_BURST. */
    typedef uint32_t map_type;
	
#define MAP_BITS (sizeof(map_type) * CHAR_BIT)
	
	/*bit����32*/
    BUILD_ASSERT_DECL(MAP_BITS >= NETDEV_MAX_BURST);

	/*dpcls �����ӱ�*/
    struct dpcls_subtable *subtable;

	/*keys_map����λ����1*/
    map_type keys_map = TYPE_MAXIMUM(map_type); /* Set all bits. */
    map_type found_map;
	
    uint32_t hashes[MAP_BITS];

	/**/
	const struct cmap_node *nodes[MAP_BITS];

	/*keys_map����1λ��Ϊ�������������ҵ�iλ��Ӧ��i��������������λ��ֻ��¼������һ�����λ*/
    if (cnt != MAP_BITS) 
	{
        keys_map >>= MAP_BITS - cnt; /* Clear extra bits. */
    }
	
	/*���dpcls rule ָ�����飬������й�����������������������*/
    memset(rules, 0, cnt * sizeof *rules);

    int lookups_match = 0, subtable_pos = 1;

    /* The Datapath classifier - aka dpcls - is composed of subtables.
     * Subtables are dynamically created as needed when new rules are inserted.
     * Each subtable collects rules with matches on a specific subset of packet
     * fields as defined by the subtable's mask.  We proceed to process every
     * search-key against each subtable, but when a match is found for a
     * search-key, the search for that key can stop because the rules are
     * non-overlapping. */

	/*dpcls�����ڶ��subtables��ɣ����µĹ������ʱ���ӱ���������̬����*/
    /*ÿ���ӱ��Ǹ������������ֵģ�����ͨ��key���ӱ��������м���*/
    /*�ҵ�ƥ��ı����Ϊ�����ظ�������ֻҪ�ҵ�����ֹͣ*/
    /*���¾���ѭ�������ӱ���в���*/

	/*����ƥ��dpcls�µ����ȼ� subtables �����ӱ�*/
    PVECTOR_FOR_EACH (subtable, &cls->subtables) 
   	{
        int i;

        /* Compute hashes for the remaining keys.  Each search-key is
         * masked with the subtable's mask to avoid hashing the wildcarded
         * bits. */

		/*���ѭ�����ҵ�keys_map��1�����λ�Ƕ��٣�һ��ʼ��ʱ��϶�ȫ��1�����Ǵ�0��ʼ*/
        /*Ȼ����ݱ��ĵ�key��mask�����hash�洢������������һ��1��λ��ֱ����������б���hashֵ�������ȥƥ������
        /*hashֵ�ļ������ͨ��cpu���٣���Ҫcpu֧�֣����ұ���ʱ����"-msse4.2"*/
        ULLONG_FOR_EACH_1(i, keys_map) 
       	{
            /*�Ա��ĵ�miniflow keys[i]����hashֵ*/
            hashes[i] = netdev_flow_key_hash_in_mask(keys[i], &subtable->mask);
        }
		
        /* Lookup. */
		/*keys_map��bitΪ1��λ������hashes��subtable->rules�в���
         *�ҵ��˾ͽ�found_map�и�λ��1��Ȼ����֮��Ӧ��ruleָ�����nodes��*/

		/*���ӱ��н���hashֵ��ƥ�䣬��ƥ�䵽node�ı��ĵ�bit��1��found_map*/
        found_map = cmap_find_batch(&subtable->rules, keys_map, hashes, nodes);
        /* Check results.  When the i-th bit of found_map is set, it means
         * that a set of nodes with a matching hash value was found for the
         * i-th search-key.  Due to possible hash collisions we need to check
         * which of the found rules, if any, really matches our masked
         * search-key. */

		/*���ҵ�ƥ��node�ı��ĵĳ�ͻhash���м�����ϸƥ�䱨��*/
        ULLONG_FOR_EACH_1(i, found_map) 
        {
            struct dpcls_rule *rule;
			
			/*dpcls rule ��ͻ���м������keyֵ�Ƿ�ƥ��*/
            CMAP_NODE_FOR_EACH (rule, cmap_node, nodes[i]) 
            {
				/*dpcls rule�����Ƿ����С�miniflow �� mask�ĶԱ�*/
                if (OVS_LIKELY(dpcls_rule_matches_key(rule, keys[i]))) 
				{
					/*��¼���е�dpcls����*/
                    rules[i] = rule;
                    /* Even at 20 Mpps the 32-bit hit_cnt cannot wrap
                     * within one second optimization interval. */

					/*�����hit�Ĵ���*/
                    subtable->hit_cnt++;

					/*��ѯƥ�����*/
                    lookups_match += subtable_pos;

					goto next;
                }
            }
            /* None of the found rules was a match.  Reset the i-th bit to
             * keep searching this key in the next subtable. */

			/*��ƥ���򽫸�λ����Ϊ0*/
            ULLONG_SET0(found_map, i);  /* Did not match. */
        next:
            ;                     /* Keep Sparse happy. */
        }

		/*����Ѿ�ƥ�������λ*/
        keys_map &= ~found_map;             /* Clear the found rules. */
        if (!keys_map) 
		{
			/*dpcls�����ѯ����*/
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
