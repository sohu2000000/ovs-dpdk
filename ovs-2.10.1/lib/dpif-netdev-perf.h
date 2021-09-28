/*
 * Copyright (c) 2017 Ericsson AB.
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

#ifndef DPIF_NETDEV_PERF_H
#define DPIF_NETDEV_PERF_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#ifdef DPDK_NETDEV
#include <rte_config.h>
#include <rte_cycles.h>
#endif

#include "openvswitch/vlog.h"
#include "ovs-atomic.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* This module encapsulates data structures and functions to maintain basic PMD
 * performance metrics such as packet counters, execution cycles as well as
 * histograms and time series recording for more detailed PMD metrics.
 *
 * It provides a clean API for dpif-netdev to initialize, update and read and
 * reset these metrics.
 *
 * The basic set of PMD counters is implemented as atomic_uint64_t variables
 * to guarantee correct read also in 32-bit systems.
 *
 * The detailed PMD performance metrics are only supported on 64-bit systems
 * with atomic 64-bit read and store semantics for plain uint64_t counters.
 */

/* Set of counter types maintained in pmd_perf_stats. */

/*pmd流量统计类型*/
enum pmd_stat_type {
    PMD_STAT_EXACT_HIT,     /* Packets that had an exact match (emc). */
    PMD_STAT_SMC_HIT,       /* Packets that had a sig match hit (SMC). */
    PMD_STAT_MASKED_HIT,    /* Packets that matched in the flow table. */
    PMD_STAT_MISS,          /* Packets that did not match and upcall was ok. */
    PMD_STAT_LOST,          /* Packets that did not match and upcall failed. */
                            /* The above statistics account for the total
                             * number of packet passes through the datapath
                             * pipeline and should not be overlapping with each
                             * other. */
    PMD_STAT_MASKED_LOOKUP, /* Number of subtable lookups for flow table
                               hits. Each MASKED_HIT hit will have >= 1
                               MASKED_LOOKUP(s). */
    PMD_STAT_RECV,          /* Packets entering the datapath pipeline from an			//从port recv的流量
                             * interface. */
    PMD_STAT_RECIRC,        /* Packets reentering the datapath pipeline due to			//recircle后的流量
                             * recirculation. */
    PMD_STAT_SENT_PKTS,     /* Packets that have been sent. */
    PMD_STAT_SENT_BATCHES,  /* Number of batches sent. */
    PMD_CYCLES_ITER_IDLE,   /* Cycles spent in idle iterations. */
    PMD_CYCLES_ITER_BUSY,   /* Cycles spent in busy iterations. */
    PMD_CYCLES_UPCALL,      /* Cycles spent processing upcalls. */
    PMD_N_STATS
};

/* Array of PMD counters indexed by enum pmd_stat_type.
 * The n[] array contains the actual counter values since initialization
 * of the PMD. Counters are atomically updated from the PMD but are
 * read and cleared also from other processes. To clear the counters at
 * PMD run-time, the current counter values are copied over to the zero[]
 * array. To read counters we subtract zero[] value from n[]. */

struct pmd_counters {
    atomic_uint64_t n[PMD_N_STATS];     /* Value since _init(). */
    uint64_t zero[PMD_N_STATS];         /* Value at last _clear().  */
};

/* Data structure to collect statistical distribution of an integer measurement
 * type in form of a histogram. The wall[] array contains the inclusive
 * upper boundaries of the bins, while the bin[] array contains the actual
 * counters per bin. The histogram walls are typically set automatically
 * using the functions provided below.*/

#define NUM_BINS 32             /* Number of histogram bins. */

/*矩形位图*/
struct histogram {
    uint32_t wall[NUM_BINS];	/*32个u32*/
    uint64_t bin[NUM_BINS];		/*32个u64*/
};

/* Data structure to record details PMD execution metrics per iteration for
 * a history period of up to HISTORY_LEN iterations in circular buffer.
 * Also used to record up to HISTORY_LEN millisecond averages/totals of these
 * metrics.*/

/*迭代流量统计*/
struct iter_stats {
    uint64_t timestamp;         /* Iteration no. or millisecond. */
    uint64_t cycles;            /* Number of TSC cycles spent in it. or ms. */
    uint64_t busy_cycles;       /* Cycles spent in busy iterations or ms. */
    uint32_t iterations;        /* Iterations in ms. */
    uint32_t pkts;              /* Packets processed in iteration or ms. */
    uint32_t upcalls;           /* Number of upcalls in iteration or ms. */
    uint32_t upcall_cycles;     /* Cycles spent in upcalls in it. or ms. */
    uint32_t batches;           /* Number of rx batches in iteration or ms. */	    /*接收队列批处理个数*/
    uint32_t max_vhost_qfill;   /* Maximum fill level in iteration or ms. */		/*迭代最大值*/
};

#define HISTORY_LEN 1000        /* Length of recorded history
                                   (iterations and ms). */
#define DEF_HIST_SHOW 20        /* Default number of history samples to
                                   display. */

struct history {
    size_t idx;                 /* Slot to which next call to history_store()
                                   will write. */
    struct iter_stats sample[HISTORY_LEN];
};

/* Container for all performance metrics of a PMD within the struct
 * dp_netdev_pmd_thread. The metrics must be updated from within the PMD
 * thread but can be read from any thread. The basic PMD counters in
 * struct pmd_counters can be read without protection against concurrent
 * clearing. The other metrics may only be safely read with the clear_mutex
 * held to protect against concurrent clearing. */

/*pmd线程流量统计*/
struct pmd_perf_stats {
    /* Prevents interference between PMD polling and stats clearing. */
    struct ovs_mutex stats_mutex;
    /* Set by CLI thread to order clearing of PMD stats. */
    volatile bool clear;										/*清掉流量统计开关*/
    /* Prevents stats retrieval while clearing is in progress. */
    struct ovs_mutex clear_mutex;
    /* Start of the current performance measurement period. */
    uint64_t start_ms;
    /* Counter for PMD iterations. */
    uint64_t iteration_cnt;
    /* Start of the current iteration. */
    uint64_t start_tsc;
    /* Latest TSC time stamp taken in PMD. */
    uint64_t last_tsc;
    /* Used to space certain checks in time. */
    uint64_t next_check_tsc;
    /* If non-NULL, outermost cycle timer currently running in PMD. */
    struct cycle_timer *cur_timer;
    /* Set of PMD counters with their zero offsets. */
    struct pmd_counters counters;
    /* Statistics of the current iteration. */				
    struct iter_stats current;							/*流量统计*/
    /* Totals for the current millisecond. */
    struct iter_stats totals;
    /* Histograms for the PMD metrics. */
    struct histogram cycles;
    struct histogram pkts;
    struct histogram cycles_per_pkt;
    struct histogram upcalls;
    struct histogram cycles_per_upcall;
    struct histogram pkts_per_batch;
    struct histogram max_vhost_qfill;
    /* Iteration history buffer. */
    struct history iterations;
    /* Millisecond history buffer. */
    struct history milliseconds;
    /* Suspicious iteration log. */
    uint32_t log_susp_it;
    /* Start of iteration range to log. */
    uint32_t log_begin_it;
    /* End of iteration range to log. */
    uint32_t log_end_it;
    /* Reason for logging suspicious iteration. */
    char *log_reason;
};

/* Support for accurate timing of PMD execution on TSC clock cycle level.
 * These functions are intended to be invoked in the context of pmd threads. */

/* Read the TSC cycle register and cache it. Any function not requiring clock
 * cycle accuracy should read the cached value using cycles_counter_get() to
 * avoid the overhead of reading the TSC register. */

/*******************************************************************************
 函数名称  :    cycles_counter_update
 功能描述  :    循环计数更新
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
static inline uint64_t cycles_counter_update(struct pmd_perf_stats *s)
{
#ifdef DPDK_NETDEV
	/*上一次tsc时间戳*/
    return s->last_tsc = rte_get_tsc_cycles();
#else
    return s->last_tsc = 0;
#endif
}

static inline uint64_t
cycles_counter_get(struct pmd_perf_stats *s)
{
    return s->last_tsc;
}

/* A nestable timer for measuring execution time in TSC cycles.
 *
 * Usage:
 * struct cycle_timer timer;
 *
 * cycle_timer_start(pmd, &timer);
 * <Timed execution>
 * uint64_t cycles = cycle_timer_stop(pmd, &timer);
 *
 * The caller must guarantee that a call to cycle_timer_start() is always
 * paired with a call to cycle_stimer_stop().
 *
 * Is is possible to have nested cycles timers within the timed code. The
 * execution time measured by the nested timers is excluded from the time
 * measured by the embracing timer.
 */

/*循环定时器*/
struct cycle_timer {	
    uint64_t start;						/*启动*/
    uint64_t suspended;					/*定时器挂起时间*/
    struct cycle_timer *interrupted;	/*中断回调*/
};

/*******************************************************************************
 函数名称  :    cycle_timer_start
 功能描述  :    循环定时器启动
 输入参数  :    s---pmd 流量统计结构
 			    timer---定时器
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
cycle_timer_start(struct pmd_perf_stats *s, struct cycle_timer *timer)
{
	/*上次流量统计时间戳*/
    struct cycle_timer *cur_timer = s->cur_timer;

	/*更新上次循环时间戳 ?*/
    uint64_t now = cycles_counter_update(s);
    if (cur_timer) 
	{
		/*挂起时间*/
        cur_timer->suspended = now;
    }

	/*上次流量统计时间戳赋值入新定时器，记录上次流量统计时间戳*/
    timer->interrupted = cur_timer;

	/*启动时间为当前时间*/
    timer->start = now;
    timer->suspended = 0;

	/*定时器重新挂入流量统计结构*/
    s->cur_timer = timer;
}

/*******************************************************************************
 函数名称  :    cycle_timer_stop
 功能描述  :    循环定时器停止
 输入参数  :    s---pmd流量统计
 			    timer---定时器
 输出参数  :	
 返 回 值  : 	无
-----------------------------------------------------------------------------
---
 最近一次修改记录 :
 修改作者	:	
 修改目的	: 	
 修改日期	:	
*******************************************************************************/
static inline uint64_t
cycle_timer_stop(struct pmd_perf_stats *s, struct cycle_timer *timer)
{
    /* Assert that this is the current cycle timer. */
    ovs_assert(s->cur_timer == timer);

	/*更新时间*/
    uint64_t now = cycles_counter_update(s);

	/*定时器回调函数*/
    struct cycle_timer *intr_timer = timer->interrupted;

    if (intr_timer) 
	{
        /* Adjust the start offset by the suspended cycles. */
		/*启动时间调整*/
        intr_timer->start += now - intr_timer->suspended;
    }
	
    /* Restore suspended timer, if any. */
	/*挂起定时器*/
    s->cur_timer = intr_timer;

	/*运行时间*/
	return now - timer->start;
}

/* Functions to initialize and reset the PMD performance metrics. */

void pmd_perf_stats_init(struct pmd_perf_stats *s);
void pmd_perf_stats_clear(struct pmd_perf_stats *s);
void pmd_perf_stats_clear_lock(struct pmd_perf_stats *s);

/* Functions to read and update PMD counters. */

void pmd_perf_read_counters(struct pmd_perf_stats *s,
                            uint64_t stats[PMD_N_STATS]);

/* PMD performance counters are updated lock-less. For real PMDs
 * they are only updated from the PMD thread itself. In the case of the
 * NON-PMD they might be updated from multiple threads, but we can live
 * with losing a rare update as 100% accuracy is not required.
 * However, as counters are read for display from outside the PMD thread
 * with e.g. pmd-stats-show, we make sure that the 64-bit read and store
 * operations are atomic also on 32-bit systems so that readers cannot
 * not read garbage. On 64-bit systems this incurs no overhead. */

/*******************************************************************************
 函数名称  :    pmd_perf_update_counter
 功能描述  :    pmd更新不同类型流量统计
 输入参数  :    s---pmd流量统计
 		        counter---流量统计类型，metadata生效则是recircle流量，否则是recv流量
 		        delta---emc流表命中报文计数
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
pmd_perf_update_counter(struct pmd_perf_stats *s, enum pmd_stat_type counter, int delta)
{
    uint64_t tmp;

	/*原子读取计数*/
    atomic_read_relaxed(&s->counters.n[counter], &tmp);

	/*流量统计+*/
    tmp += delta;

	/*原子写*/
	atomic_store_relaxed(&s->counters.n[counter], tmp);
}

/* Functions to manipulate a sample history. */

/*******************************************************************************
 函数名称  :    histogram_add_sample
 功能描述  :    矩形图添加示例
 输入参数  :  	hist---矩形位图
 				val---批处理的报文数，填入矩形位图
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
histogram_add_sample(struct histogram *hist, uint32_t val)
{
    /* TODO: Can do better with binary search? */
	
    for (int i = 0; i < NUM_BINS-1; i++) 
	{
        if (val <= hist->wall[i]) 
		{
            hist->bin[i]++;
			
            return;
        }
    }
    hist->bin[NUM_BINS-1]++;
}

uint64_t histogram_samples(const struct histogram *hist);

/* This function is used to advance the given history index by positive
 * offset in the circular history buffer. */
static inline uint32_t
history_add(uint32_t idx, uint32_t offset)
{
    return (idx + offset) % HISTORY_LEN;
}

/* This function computes the difference between two indices into the
 * circular history buffer. The result is always positive in the range
 * 0 .. HISTORY_LEN-1 and specifies the number of steps to reach idx1
 * starting from idx2. It can also be used to retreat the history index
 * idx1 by idx2 steps. */
static inline uint32_t
history_sub(uint32_t idx1, uint32_t idx2)
{
    return (idx1 + HISTORY_LEN - idx2) % HISTORY_LEN;
}

static inline struct iter_stats *
history_current(struct history *h)
{
    return &h->sample[h->idx];
}

static inline struct iter_stats *
history_next(struct history *h)
{
    size_t next_idx = history_add(h->idx, 1);
    struct iter_stats *next = &h->sample[next_idx];

    memset(next, 0, sizeof(*next));
    h->idx = next_idx;
    return next;
}

static inline struct iter_stats *
history_store(struct history *h, struct iter_stats *is)
{
    if (is) {
        h->sample[h->idx] = *is;
    }
    /* Advance the history pointer */
    return history_next(h);
}

/* Data and function related to logging of suspicious iterations. */

extern bool log_enabled;
extern bool log_extend;
extern uint32_t log_q_thr;
extern uint64_t iter_cycle_threshold;

void pmd_perf_set_log_susp_iteration(struct pmd_perf_stats *s, char *reason);
void pmd_perf_log_susp_iteration_neighborhood(struct pmd_perf_stats *s);

/* Functions recording PMD metrics per iteration. */

void
pmd_perf_start_iteration(struct pmd_perf_stats *s);
void
pmd_perf_end_iteration(struct pmd_perf_stats *s, int rx_packets,
                       int tx_packets, bool full_metrics);

/* Formatting the output of commands. */

struct pmd_perf_params {
    int command_type;
    bool histograms;
    size_t iter_hist_len;
    size_t ms_hist_len;
};

void pmd_perf_format_overall_stats(struct ds *str, struct pmd_perf_stats *s,
                                   double duration);
void pmd_perf_format_histograms(struct ds *str, struct pmd_perf_stats *s);
void pmd_perf_format_iteration_history(struct ds *str,
                                       struct pmd_perf_stats *s,
                                       int n_iter);
void pmd_perf_format_ms_history(struct ds *str, struct pmd_perf_stats *s,
                                int n_ms);
void pmd_perf_log_set_cmd(struct unixctl_conn *conn,
                          int argc, const char *argv[],
                          void *aux OVS_UNUSED);

#ifdef  __cplusplus
}
#endif

#endif /* DPIF_NETDEV_PERF_H */
