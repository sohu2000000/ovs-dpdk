/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
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
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/timerfd.h>

#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_interrupts.h>
#include <rte_alarm.h>
#include <rte_common.h>
#include <rte_per_lcore.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>
#include <eal_private.h>

#ifndef	TFD_NONBLOCK
#include <fcntl.h>
#define	TFD_NONBLOCK	O_NONBLOCK
#endif

#define NS_PER_US 1000
#define US_PER_MS 1000
#define MS_PER_S 1000
#define US_PER_S (US_PER_MS * MS_PER_S)

#ifdef CLOCK_MONOTONIC_RAW /* Defined in glibc bits/time.h */
#define CLOCK_TYPE_ID CLOCK_MONOTONIC_RAW
#else
#define CLOCK_TYPE_ID CLOCK_MONOTONIC
#endif

struct alarm_entry {
	LIST_ENTRY(alarm_entry) next;
	struct timeval time;
	rte_eal_alarm_callback cb_fn;
	void *cb_arg;
	volatile uint8_t executing;
	volatile pthread_t executing_id;
};

static LIST_HEAD(alarm_list, alarm_entry) alarm_list = LIST_HEAD_INITIALIZER();
static rte_spinlock_t alarm_list_lk = RTE_SPINLOCK_INITIALIZER;

static struct rte_intr_handle intr_handle = {.fd = -1 };
static int handler_registered = 0;
static void eal_alarm_callback(struct rte_intr_handle *hdl, void *arg);


/*******************************************************
  ??????:		rte_eal_alarm_init
  ????????: 	????????????????
  ????????: 	
  ??????	  :
  ??????????:
  ????????:    2017 -11-15
********************************************************/
int
rte_eal_alarm_init(void)
{
	intr_handle.type = RTE_INTR_HANDLE_ALARM;
	/* create a timerfd file descriptor */

	/*??????????*/
	intr_handle.fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (intr_handle.fd == -1)
	{
		goto error;
	}
	
	return 0;

error:
	rte_errno = errno;
	return -1;
}

static void
eal_alarm_callback(struct rte_intr_handle *hdl __rte_unused,
		void *arg __rte_unused)
{
	struct timespec now;
	struct alarm_entry *ap;

	rte_spinlock_lock(&alarm_list_lk);
	while ((ap = LIST_FIRST(&alarm_list)) !=NULL &&
			clock_gettime(CLOCK_TYPE_ID, &now) == 0 &&
			(ap->time.tv_sec < now.tv_sec || (ap->time.tv_sec == now.tv_sec &&
						(ap->time.tv_usec * NS_PER_US) <= now.tv_nsec))) {
		ap->executing = 1;
		ap->executing_id = pthread_self();
		rte_spinlock_unlock(&alarm_list_lk);

		ap->cb_fn(ap->cb_arg);

		rte_spinlock_lock(&alarm_list_lk);

		LIST_REMOVE(ap, next);
		rte_free(ap);
	}

	if (!LIST_EMPTY(&alarm_list)) {
		struct itimerspec atime = { .it_interval = { 0, 0 } };

		ap = LIST_FIRST(&alarm_list);
		atime.it_value.tv_sec = ap->time.tv_sec;
		atime.it_value.tv_nsec = ap->time.tv_usec * NS_PER_US;
		/* perform borrow for subtraction if necessary */
		if (now.tv_nsec > (ap->time.tv_usec * NS_PER_US))
			atime.it_value.tv_sec--, atime.it_value.tv_nsec += US_PER_S * NS_PER_US;

		atime.it_value.tv_sec -= now.tv_sec;
		atime.it_value.tv_nsec -= now.tv_nsec;
		timerfd_settime(intr_handle.fd, 0, &atime, NULL);
	}
	rte_spinlock_unlock(&alarm_list_lk);
}

int
rte_eal_alarm_set(uint64_t us, rte_eal_alarm_callback cb_fn, void *cb_arg)
{
	struct timespec now;
	int ret = 0;
	struct alarm_entry *ap, *new_alarm;

	/* Check parameters, including that us won't cause a uint64_t overflow */
	if (us < 1 || us > (UINT64_MAX - US_PER_S) || cb_fn == NULL)
		return -EINVAL;

	new_alarm = rte_zmalloc(NULL, sizeof(*new_alarm), 0);
	if (new_alarm == NULL)
		return -ENOMEM;

	/* use current time to calculate absolute time of alarm */
	clock_gettime(CLOCK_TYPE_ID, &now);

	new_alarm->cb_fn = cb_fn;
	new_alarm->cb_arg = cb_arg;
	new_alarm->time.tv_usec = ((now.tv_nsec / NS_PER_US) + us) % US_PER_S;
	new_alarm->time.tv_sec = now.tv_sec + (((now.tv_nsec / NS_PER_US) + us) / US_PER_S);

	rte_spinlock_lock(&alarm_list_lk);
	if (!handler_registered) {
		ret |= rte_intr_callback_register(&intr_handle,
				eal_alarm_callback, NULL);
		handler_registered = (ret == 0) ? 1 : 0;
	}

	if (LIST_EMPTY(&alarm_list))
		LIST_INSERT_HEAD(&alarm_list, new_alarm, next);
	else {
		LIST_FOREACH(ap, &alarm_list, next) {
			if (ap->time.tv_sec > new_alarm->time.tv_sec ||
					(ap->time.tv_sec == new_alarm->time.tv_sec &&
							ap->time.tv_usec > new_alarm->time.tv_usec)){
				LIST_INSERT_BEFORE(ap, new_alarm, next);
				break;
			}
			if (LIST_NEXT(ap, next) == NULL) {
				LIST_INSERT_AFTER(ap, new_alarm, next);
				break;
			}
		}
	}

	if (LIST_FIRST(&alarm_list) == new_alarm) {
		struct itimerspec alarm_time = {
			.it_interval = {0, 0},
			.it_value = {
				.tv_sec = us / US_PER_S,
				.tv_nsec = (us % US_PER_S) * NS_PER_US,
			},
		};
		ret |= timerfd_settime(intr_handle.fd, 0, &alarm_time, NULL);
	}
	rte_spinlock_unlock(&alarm_list_lk);

	return ret;
}

int
rte_eal_alarm_cancel(rte_eal_alarm_callback cb_fn, void *cb_arg)
{
	struct alarm_entry *ap, *ap_prev;
	int count = 0;
	int err = 0;
	int executing;

	if (!cb_fn) {
		rte_errno = EINVAL;
		return -1;
	}

	do {
		executing = 0;
		rte_spinlock_lock(&alarm_list_lk);
		/* remove any matches at the start of the list */
		while ((ap = LIST_FIRST(&alarm_list)) != NULL &&
				cb_fn == ap->cb_fn &&
				(cb_arg == (void *)-1 || cb_arg == ap->cb_arg)) {

			if (ap->executing == 0) {
				LIST_REMOVE(ap, next);
				rte_free(ap);
				count++;
			} else {
				/* If calling from other context, mark that alarm is executing
				 * so loop can spin till it finish. Otherwise we are trying to
				 * cancel our self - mark it by EINPROGRESS */
				if (pthread_equal(ap->executing_id, pthread_self()) == 0)
					executing++;
				else
					err = EINPROGRESS;

				break;
			}
		}
		ap_prev = ap;

		/* now go through list, removing entries not at start */
		LIST_FOREACH(ap, &alarm_list, next) {
			/* this won't be true first time through */
			if (cb_fn == ap->cb_fn &&
					(cb_arg == (void *)-1 || cb_arg == ap->cb_arg)) {

				if (ap->executing == 0) {
					LIST_REMOVE(ap, next);
					rte_free(ap);
					count++;
					ap = ap_prev;
				} else if (pthread_equal(ap->executing_id, pthread_self()) == 0)
					executing++;
				else
					err = EINPROGRESS;
			}
			ap_prev = ap;
		}
		rte_spinlock_unlock(&alarm_list_lk);
	} while (executing != 0);

	if (count == 0 && err == 0)
		rte_errno = ENOENT;
	else if (err)
		rte_errno = err;

	return count;
}
