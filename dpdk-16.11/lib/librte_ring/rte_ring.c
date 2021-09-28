/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Derived from FreeBSD's bufring.c
 *
 **************************************************************************
 *
 * Copyright (c) 2007,2008 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. The name of Kip Macy nor the names of other
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ***************************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_malloc.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_eal_memconfig.h>
#include <rte_atomic.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_errno.h>
#include <rte_string_fns.h>
#include <rte_spinlock.h>

#include "rte_ring.h"

TAILQ_HEAD(rte_ring_list, rte_tailq_entry);

static struct rte_tailq_elem rte_ring_tailq = {
	.name = RTE_TAILQ_RING_NAME,
};
EAL_REGISTER_TAILQ(rte_ring_tailq)

/* true if x is a power of 2 */
#define POWEROF2(x) ((((x)-1) & (x)) == 0)

/* return the size of memory occupied by a ring */

/*��ȡ����count �ڴ�*/
ssize_t
rte_ring_get_memsize(unsigned count)
{
	ssize_t sz;

	/* count must be a power of 2 */
	if ((!POWEROF2(count)) || (count > RTE_RING_SZ_MASK )) {
		RTE_LOG(ERR, RING,
			"Requested size is invalid, must be power of 2, and "
			"do not exceed the size limit %u\n", RTE_RING_SZ_MASK);
		return -EINVAL;
	}

	sz = sizeof(struct rte_ring) + count * sizeof(void *);
	sz = RTE_ALIGN(sz, RTE_CACHE_LINE_SIZE);
	return sz;
}

/*******************************************************
  ������:	   rte_ring_create
  ��������:    ������
  ��������: 	ring---������ṹ
  				name---��name
				count--��Ԫ�ظ���
				����socketID
				flag---���
  ����ֵ:
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
int rte_ring_init(struct rte_ring *ring, const char *name, unsigned count, unsigned flags)
{
	int ret;

	/* compilation-time checks */
	RTE_BUILD_BUG_ON((sizeof(struct rte_ring) &  RTE_CACHE_LINE_MASK) != 0);
	
#ifdef RTE_RING_SPLIT_PROD_CONS
	RTE_BUILD_BUG_ON((offsetof(struct rte_ring, cons) & RTE_CACHE_LINE_MASK) != 0);
#endif
	RTE_BUILD_BUG_ON((offsetof(struct rte_ring, prod) & RTE_CACHE_LINE_MASK) != 0);
#ifdef RTE_LIBRTE_RING_DEBUG

	RTE_BUILD_BUG_ON((sizeof(struct rte_ring_debug_stats) & RTE_CACHE_LINE_MASK) != 0);

	RTE_BUILD_BUG_ON((offsetof(struct rte_ring, stats) & RTE_CACHE_LINE_MASK) != 0);
	
#endif

	/* init the ring structure */
	/*��ʼ�����ṹ*/
	memset(ring, 0, sizeof(*ring));

	ret = snprintf(ring->name, sizeof(ring->name), "%s", name);
	if (ret < 0 || ret >= (int)sizeof(ring->name))
	{
		return -ENAMETOOLONG;
	}
	
	ring->flags           = flags;

	/*��Ԫ��������ˮ�꣬����Ŀǰ�ж��ٸ�Ԫ��*/
	ring->prod.watermark  = count;

	/*�����߶��е����б��*/
	ring->prod.sp_enqueue = !!(flags & RING_F_SP_ENQ);


	/*�����ߵ����б��*/	
	ring->cons.sc_dequeue = !!(flags & RING_F_SC_DEQ);

	/*����size*/
	ring->prod.size       = ring->cons.size = count;
	ring->prod.mask       = ring->cons.mask = count-1;

	/*����������ͷβindex��Ϊ0*/
	ring->prod.head       = ring->cons.head = 0;
	ring->prod.tail       = ring->cons.tail = 0;

	return 0;
}

/*******************************************************
  ������:	   rte_ring_create
  ��������:    ����������һ�����ʴ�С��memzone����ring
  ��������: 	name---��name
  				count--burst pkt ����
  				����socketID
  				flag---���
  ����ֵ:
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
/* create the ring */
struct rte_ring *rte_ring_create(const char *name, unsigned count, int socket_id, unsigned flags)
{
	char mz_name[RTE_MEMZONE_NAMESIZE];
	struct rte_ring *ring;
	struct rte_tailq_entry *te;
	const struct rte_memzone *memzone;
	ssize_t ring_size;
	int mz_flags = 0;
	struct rte_ring_list* ring_list = NULL;
	int ret;

	/*����ͷ��������ͷ*/
	ring_list = RTE_TAILQ_CAST(rte_ring_tailq.head, rte_ring_list);

	/*��ȡ����С��count ��mbuf��size*/
	/*rte_ring + count*mbuf*/
	ring_size = rte_ring_get_memsize(count);
	if (ring_size < 0) 
	{
		rte_errno = ring_size;

		return NULL;
	}

	/*��name*/
	ret = snprintf(mz_name, sizeof(mz_name), "%s%s", RTE_RING_MZ_PREFIX, name);
	if (ret < 0 || ret >= (int)sizeof(mz_name)) 
	{
		rte_errno = ENAMETOOLONG;
		return NULL;
	}

	/*elem�ڴ�������ڴ�*/
	te = rte_zmalloc("RING_TAILQ_ENTRY", sizeof(*te), 0);
	if (te == NULL) 
	{
		RTE_LOG(ERR, RING, "Cannot reserve memory for tailq\n");
		rte_errno = ENOMEM;
		return NULL;
	}

	rte_rwlock_write_lock(RTE_EAL_TAILQ_RWLOCK);

	/* reserve a memory zone for this ring. If we can't get rte_config or
	 * we are secondary process, the memzone_reserve function will set
	 * rte_errno for us appropriately - hence no check in this this function */

	/*���뻷��С���ڴ����� mzone*/      /*count ��ringԪ�ص�size*/
	memzone = rte_memzone_reserve(mz_name, ring_size, socket_id, mz_flags);
	if (memzone!= NULL) 
	{
		/*mezone��¼��elem��ַ��elem�ڴ��*/
		ring = memzone->addr; /*count ��ringԪ����ʼ��ַ*/
		
		/* no need to check return value here, we already checked the
		 * arguments above */

		/*��ʼ����*/
		rte_ring_init(ring, name, count, flags);

		/*ring ��*/
		te->data = (void *) ring;

		/*��ʹ�õ�memzone���ڴ��zone*/
		ring->memzone = memzone;


		/*ring ������ring����count��ringԪ�أ����ڴ���õ��ڴ�*/
		TAILQ_INSERT_TAIL(ring_list, te, next);
	} 
	else
	{
		ring = NULL;

		RTE_LOG(ERR, RING, "Cannot reserve memory\n");

		rte_free(te);
	}
	
	rte_rwlock_write_unlock(RTE_EAL_TAILQ_RWLOCK);

	return ring;
}

/*******************************************************
  ������:	   rte_ring_free
  ��������:    �ͷŻ�
  ��������: 
  ����ֵ:
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
/* free the ring */
void
rte_ring_free(struct rte_ring *r)
{
	struct rte_ring_list *ring_list = NULL;
	struct rte_tailq_entry *te;

	if (r == NULL)
	{
		return;
	}
	
	/*
	 * Ring was not created with rte_ring_create,
	 * therefore, there is no memzone to free.
	 */

	if (r->memzone == NULL)
	{
		RTE_LOG(ERR, RING, "Cannot free ring (not created with rte_ring_create()");
		return;
	}

	/*�ͷ�memzone*/
	if (rte_memzone_free(r->memzone) != 0) 
	{
		RTE_LOG(ERR, RING, "Cannot free memory\n");
		return;
	}

	/*��ȡring ��*/
	ring_list = RTE_TAILQ_CAST(rte_ring_tailq.head, rte_ring_list);
	rte_rwlock_write_lock(RTE_EAL_TAILQ_RWLOCK);

	/* find out tailq entry */
	/**/
	TAILQ_FOREACH(te, ring_list, next)
	{
		if (te->data == (void *) r)
		{
			break;
		}
	}

	if (te == NULL) 
	{
		rte_rwlock_write_unlock(RTE_EAL_TAILQ_RWLOCK);
		return;
	}

	TAILQ_REMOVE(ring_list, te, next);

	rte_rwlock_write_unlock(RTE_EAL_TAILQ_RWLOCK);

	rte_free(te);
}

/*
 * change the high water mark. If *count* is 0, water marking is
 * disabled
 */

/*******************************************************
  ������:	   rte_ring_set_water_mark
  ��������:    ����ˮ��
  ��������: 	r----��
  				name---��name
				count--��size,�ֽ�
				����socketID
				flag---���
  ����ֵ:
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
int
rte_ring_set_water_mark(struct rte_ring *ring, unsigned count)
{
	/*������õ�ˮ�����ring size*/
	if (count >= r->prod.size)
	{
		return -EINVAL;
	}
	
	/* if count is 0, disable the watermarking */
	/*���count Ϊ0��������ˮ��Ϊcount*/
	if (count == 0)
		count = r->prod.size;

	r->prod.watermark = count;
	
	return 0;
}

/* dump the status of the ring on the console */
/*�Ӵ��ڴ�ӡ����Ϣ*/
void
rte_ring_dump(FILE *f, const struct rte_ring *r)
{
#ifdef RTE_LIBRTE_RING_DEBUG
	struct rte_ring_debug_stats sum;
	unsigned lcore_id;
#endif

	fprintf(f, "ring <%s>@%p\n", r->name, r);
	fprintf(f, "  flags=%x\n", r->flags);
	fprintf(f, "  size=%"PRIu32"\n", r->prod.size);
	fprintf(f, "  ct=%"PRIu32"\n", r->cons.tail);
	fprintf(f, "  ch=%"PRIu32"\n", r->cons.head);
	fprintf(f, "  pt=%"PRIu32"\n", r->prod.tail);
	fprintf(f, "  ph=%"PRIu32"\n", r->prod.head);
	fprintf(f, "  used=%u\n", rte_ring_count(r));
	fprintf(f, "  avail=%u\n", rte_ring_free_count(r));
	if (r->prod.watermark == r->prod.size)
		fprintf(f, "  watermark=0\n");
	else
		fprintf(f, "  watermark=%"PRIu32"\n", r->prod.watermark);

	/* sum and dump statistics */
#ifdef RTE_LIBRTE_RING_DEBUG
	memset(&sum, 0, sizeof(sum));
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		sum.enq_success_bulk += r->stats[lcore_id].enq_success_bulk;
		sum.enq_success_objs += r->stats[lcore_id].enq_success_objs;
		sum.enq_quota_bulk += r->stats[lcore_id].enq_quota_bulk;
		sum.enq_quota_objs += r->stats[lcore_id].enq_quota_objs;
		sum.enq_fail_bulk += r->stats[lcore_id].enq_fail_bulk;
		sum.enq_fail_objs += r->stats[lcore_id].enq_fail_objs;
		sum.deq_success_bulk += r->stats[lcore_id].deq_success_bulk;
		sum.deq_success_objs += r->stats[lcore_id].deq_success_objs;
		sum.deq_fail_bulk += r->stats[lcore_id].deq_fail_bulk;
		sum.deq_fail_objs += r->stats[lcore_id].deq_fail_objs;
	}
	fprintf(f, "  size=%"PRIu32"\n", r->prod.size);
	fprintf(f, "  enq_success_bulk=%"PRIu64"\n", sum.enq_success_bulk);
	fprintf(f, "  enq_success_objs=%"PRIu64"\n", sum.enq_success_objs);
	fprintf(f, "  enq_quota_bulk=%"PRIu64"\n", sum.enq_quota_bulk);
	fprintf(f, "  enq_quota_objs=%"PRIu64"\n", sum.enq_quota_objs);
	fprintf(f, "  enq_fail_bulk=%"PRIu64"\n", sum.enq_fail_bulk);
	fprintf(f, "  enq_fail_objs=%"PRIu64"\n", sum.enq_fail_objs);
	fprintf(f, "  deq_success_bulk=%"PRIu64"\n", sum.deq_success_bulk);
	fprintf(f, "  deq_success_objs=%"PRIu64"\n", sum.deq_success_objs);
	fprintf(f, "  deq_fail_bulk=%"PRIu64"\n", sum.deq_fail_bulk);
	fprintf(f, "  deq_fail_objs=%"PRIu64"\n", sum.deq_fail_objs);
#else
	fprintf(f, "  no statistics available\n");
#endif
}

/* dump the status of all rings on the console */
/**/
void
/*������ӡring ��Ϣ*/
rte_ring_list_dump(FILE *f)
{
	const struct rte_tailq_entry *te;
	struct rte_ring_list *ring_list;

	ring_list = RTE_TAILQ_CAST(rte_ring_tailq.head, rte_ring_list);

	rte_rwlock_read_lock(RTE_EAL_TAILQ_RWLOCK);

	TAILQ_FOREACH(te, ring_list, next)
	{
		rte_ring_dump(f, (struct rte_ring *) te->data);
	}

	rte_rwlock_read_unlock(RTE_EAL_TAILQ_RWLOCK);
}
/*******************************************************
  ������:	   rte_ring_lookup
  ��������:    ����name���һ�
  ��������: 	
				
  ����ֵ:
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
/* search a ring from its name */
struct rte_ring *rte_ring_lookup(const char *name)
{
	struct rte_tailq_entry *te;
	struct rte_ring *r = NULL;
	struct rte_ring_list *ring_list;

	/*������β������*/
	ring_list = RTE_TAILQ_CAST(rte_ring_tailq.head, rte_ring_list);

	rte_rwlock_read_lock(RTE_EAL_TAILQ_RWLOCK);

	/*������β������*/
	TAILQ_FOREACH(te, ring_list, next) 
	{
		/*��ȡring*/
		r = (struct rte_ring *) te->data;

		if (strncmp(name, r->name, RTE_RING_NAMESIZE) == 0)
		{
			break;
		}
	}

	rte_rwlock_read_unlock(RTE_EAL_TAILQ_RWLOCK);

	if (te == NULL) 
	{
		rte_errno = ENOENT;

		return NULL;
	}

	return r;
}
