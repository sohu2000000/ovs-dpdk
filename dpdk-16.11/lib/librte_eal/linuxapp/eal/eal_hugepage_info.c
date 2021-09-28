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

#include <string.h>
#include <sys/types.h>
#include <sys/file.h>
#include <dirent.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <fnmatch.h>
#include <inttypes.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_log.h>
#include <rte_common.h>
#include "rte_string_fns.h"
#include "eal_internal_cfg.h"
#include "eal_hugepages.h"
#include "eal_filesystem.h"

static const char sys_dir_path[] = "/sys/kernel/mm/hugepages";

/* this function is only called from eal_hugepage_info_init which itself
 * is only called from a primary process */

/*******************************************************
  ������:		get_num_hugepages
  ��������: 	��ȡϵͳ�п��ô�ҳ����
  ��������: 	/sys/kernel/mm/hugepages-2048576Ŀ¼
  ����ֵ	  : 
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/

static uint32_t get_num_hugepages(const char *subdir)
{
	char path[PATH_MAX];
	long unsigned resv_pages, pages_num = 0;

	const char *nr_hp_file = "free_hugepages";
	const char *nr_rsvd_file = "resv_hugepages";

	/* first, check how many reserved pages kernel reports */
	/*"/sys/kernel/mm/hugepages-1048576kB/resv_hugepages"*/

	snprintf(path, sizeof(path), "%s/%s/%s", sys_dir_path, subdir, nr_rsvd_file);

	/*��ȡ������ҳ����,ʧ�ܷ���*/
	if (eal_parse_sysfs_value(path, &resv_pages) < 0)
	{
		return 0;
	}
	
	/*��ȡfree_hugepages��ֵ�����ǿ��д�ҳ����*/
	snprintf(path, sizeof(path), "%s/%s/%s", sys_dir_path, subdir, nr_hp_file);

	/*��ȡ�����ڴ�free_hugepages�����*/
	if (eal_parse_sysfs_value(path, &pages_num) < 0)
	{
		return 0;
	}
	
	if (pages_num == 0)
	{
		RTE_LOG(WARNING, EAL, "No free hugepages reported in %s\n",subdir);
	}
	
	/* adjust pages_num */
	/*��Ч��ҳ������ȥ������ҳ*/

	/*free ��ҳ�����˱�����ҳ*/
	if (pages_num >= resv_pages)
	{
		pages_num -= resv_pages;
	}
	else if (resv_pages)
	{
		pages_num = 0;
	}
	
	/* we want to return a uint32_t and more than this looks suspicious
	 * anyway ... */
	 
	if (pages_num > UINT32_MAX)
	{
		pages_num = UINT32_MAX;
	}
	
	return pages_num;
}

/*******************************************************
  ������:		get_default_hp_size
  ��������: 	��ȡ/proc/meminfo��huagepagesize ��ҳsize����
  ��������: 	
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static uint64_t
get_default_hp_size(void)
{
	const char proc_meminfo[] = "/proc/meminfo";
	const char str_hugepagesz[] = "Hugepagesize:";
	unsigned hugepagesz_len = sizeof(str_hugepagesz) - 1;
	char buffer[256];
	unsigned long long size = 0;

	FILE *fd = fopen(proc_meminfo, "r");
	if (fd == NULL)
	{
		rte_panic("Cannot open %s\n", proc_meminfo);
	}

	/*��ȡ/proc/meminfo �µ�Hugepagesize:2048 ��ҳ�ڴ���ڴ�size*/
	/*��ȡHugepagesize: size����*/
	while(fgets(buffer, sizeof(buffer), fd))
	{
		if (strncmp(buffer, str_hugepagesz, hugepagesz_len) == 0)
		{
			size = rte_str_to_size(&buffer[hugepagesz_len]);
			break;
		}
	}
	
	fclose(fd);

	if (size == 0)
		rte_panic("Cannot get default hugepage size from %s\n", proc_meminfo);
	
	return size;
}

/*******************************************************
  ������:		eal_hugepage_info_init
  ��������: 	��ô�ҳ����Ŀ¼ /dev/hugepages����Ŀ¼
  ��������: 	hugepage_sz--��ҳsize���ݣ�����2048��/sys/kernel/mm/hugepages �����
  ����ֵ  :     ��ҳ���ص�Ŀ¼�������ҳ����Ŀ¼��sizeȷʵ��Ŀ¼���sizeһ���򷵻ع���Ŀ¼
  				
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static const char *
get_hugepage_dir(uint64_t hugepage_sz)
{
	enum proc_mount_fieldnames 
	{
		DEVICE = 0,           /*�豸Ŀ¼*/
		MOUNTPT,              /*����Ŀ¼*/
		FSTYPE,               /*�ļ�ϵͳ����*/
		OPTIONS,              /*ѡ��*/
		_FIELDNAME_MAX        
	};
	
	static uint64_t default_size = 0;
	const char proc_mounts[] = "/proc/mounts";
	const char hugetlbfs_str[] = "hugetlbfs";
	const size_t htlbfs_str_len = sizeof(hugetlbfs_str) - 1;
	const char pagesize_opt[] = "pagesize=";
	const size_t pagesize_opt_len = sizeof(pagesize_opt) - 1;
	const char split_tok = ' ';
	char *splitstr[_FIELDNAME_MAX];
	char buf[BUFSIZ];
	char *retval = NULL;

	/*��/proc/mounts*/
	FILE *fd = fopen(proc_mounts, "r");
	if (fd == NULL)
	{
		rte_panic("Cannot open %s\n", proc_mounts);
	}
	
	/*��ȡ/proc/meminfo�� hugepagesize ���� ��ҳ�ڴ�size 2048KB����ΪĬ�ϴ�ҳ�ڴ�size*/
	if (default_size == 0)
	{
		default_size = get_default_hp_size();
	}

	/*��ȡ/proc/mounts���ڴ���ص�Ŀ¼��Ϣ*/
	while (fgets(buf, sizeof(buf), fd))
	{
		/*���ص��ַ����и�*/
		if (rte_strsplit(buf, sizeof(buf), splitstr, _FIELDNAME_MAX, split_tok) != _FIELDNAME_MAX)
		{
			RTE_LOG(ERR, EAL, "Error parsing %s\n", proc_mounts);
			break; /* return NULL */
		}

		/* we have a specified --huge-dir option, only examine that dir */

		/*���internal_config.hugepage_dir �Ƿ� ��/proc/mounts �£����ڴ��Ƿ����*/
		/*/proc/bus/usb--�豸Ŀ¼ /proc/bus/usb--����Ŀ¼ usbfs rw,relatime 0 0*/

		/*��ǰĿ¼�ַ������Ǵ�ҳĿ¼*/

		/*����internal_config.hugepage_dir�Ƿ��Ѿ�����*/
		if (internal_config.hugepage_dir != NULL && strcmp(splitstr[MOUNTPT], internal_config.hugepage_dir) != 0)
		{
			continue;
		}
		
		/*/proc/mounts ��ҳ����Ŀ¼���ܷ��ҵ�"hugetlbfs"�ַ���*/
		if (strncmp(splitstr[FSTYPE], hugetlbfs_str, htlbfs_str_len) == 0)
		{
			/*��ȡ����Ŀ¼�еĴ�ҳsize�ַ���*/
			const char *pagesz_str = strstr(splitstr[OPTIONS], pagesize_opt);

			/* if no explicit page size, the default page size is compared */


			
			/*���ƹ���Ŀ¼��ҳsize��ֵ��Ŀ¼����ҳsizeһ��*/

			/*����Ŀ¼�����ڣ���ҳsize�ַ���*/
			/*Ŀ¼���Ĵ�ҳsize=ϵͳ�Ĵ�ҳsize����ʹ�ù���Ŀ¼�Ĵ�ҳsize*/
			if (pagesz_str == NULL)
			{
				/*/sys/kernel/mm/hugepages ����ҳĿ¼���Ĵ�ҳsize����ϵͳproc/meminfo�µĴ�ҳsize*/
				/*Ŀ¼���Ĵ�ҳsize��ϵͳ�Ĵ�ҳsize����ʹ�ù���Ŀ¼�Ĵ�ҳsize*/
				if (hugepage_sz == default_size)
				{
					retval = strdup(splitstr[MOUNTPT]);  /*dev/hugepages����Ŀ¼*/
					break;
				}
			}
			/* there is an explicit page size, so check it */
			/*����Ŀ¼�д��ڴ�ҳsize�ַ��������Զ���Ĵ�ҳsize�ַ�������Ŀ¼��������ʹ��*/
			else 
			{
				/*����Ŀ¼�л�ȡ�Ĵ�ҳsize*/
				uint64_t pagesz = rte_str_to_size(&pagesz_str[pagesize_opt_len]);
				/*������ص�Ŀ¼�Ĵ�ҳsize����/sys/kernel/mm/hugepages �����Ĵ�ҳ�ڴ�size*/
				/*����Ŀ¼�Ĵ�ҳsize����Ŀ¼���Ĵ�ҳsize����ʹ�ù���Ŀ¼��size*/
				if (pagesz == hugepage_sz) 
				{
					retval = strdup(splitstr[MOUNTPT]);
					break;
				}
			}
		} /* end if strncmp hugetlbfs */
	} /* end while fgets */

	fclose(fd);

	/*dev/hugepages����Ŀ¼*/
	return retval;
}

/*
 * Clear the hugepage directory of whatever hugepage files
 * there are. Checks if the file is locked (i.e.
 * if it's in use by another DPDK process).
 */
	
/*******************************************************
  ������:		clear_hugedir
  ��������: 	�����ҳ���ص��µ��ļ�/dev/hugepages/rte_map0-9
  ��������: 	hugepage_file_dir---��ҳ�ڴ����Ŀ¼,����Ŀ¼/dev/hugepages����Ŀ¼
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static int clear_hugedir(const char * hugepage_file_dir)
{
	DIR *dir;
	struct dirent *dirent;
	int dir_fd, fd, lck_result;
	const char filter[] = "*map_*"; /* matches hugepage files */

	/* open directory */
	/*�򿪴�ҳĿ¼*/
	dir = opendir(hugepage_file_dir);
	if (!dir) 
	{
		RTE_LOG(ERR, EAL, "Unable to open hugepage directory %s\n", hugepage_file_dir);
		goto error;
	}

	dir_fd = dirfd(dir);

	/*��ȡ���صĴ�ҳ��Ŀ¼*/
	dirent = readdir(dir);
	if (!dirent) 
	{
		RTE_LOG(ERR, EAL, "Unable to read hugepage directory %s\n", hugepage_file_dir);
		goto error;
	}

	/*������Ŀ¼��ɾ��rtemap_0-9*/
	while(dirent != NULL)
	{
		/* skip files that don't match the hugepage pattern */
		/*������ƥ��Ĵ�ҳ��ַ,ֱ��ƥ�䵽����map_��Ŀ¼*/
		if (fnmatch(filter, dirent->d_name, 0) > 0) 
		{
			dirent = readdir(dir);
			continue;
		}

		/* try and lock the file */
		/*�򿪴�ҳĿ¼ rtemap_0-9*/
		fd = openat(dir_fd, dirent->d_name, O_RDONLY);

		/* skip to next file */
		if (fd == -1) 
		{
			dirent = readdir(dir);
			continue;
		}

		/* non-blocking lock */
		/*���Ի�ȡ�ļ���*/
		lck_result = flock(fd, LOCK_EX | LOCK_NB);

		/* if lock succeeds, unlock and remove the file */
		/*ɾ��*/
		if (lck_result != -1) 
		{
			flock(fd, LOCK_UN);
			unlinkat(dir_fd, dirent->d_name, 0);
		}
		
		close (fd);

		/*�¸�Ŀ¼*/
		dirent = readdir(dir);
	}

	closedir(dir);
	
	return 0;

error:
	
	if (dir)
	{
		closedir(dir);
	}
	
	RTE_LOG(ERR, EAL, "Error while clearing hugepage dir: %s\n",strerror(errno));

	return -1;
}

static int
compare_hpi(const void *a, const void *b)
{
	const struct hugepage_info *hpi_a = a;
	const struct hugepage_info *hpi_b = b;

	return hpi_b->hugepage_sz - hpi_a->hugepage_sz;
}

/*
 * when we initialize the hugepage info, everything goes
 * to socket 0 by default. it will later get sorted by memory
 * initialization procedure.
 */

/*******************************************************
  ������:		eal_hugepage_info_init
  ��������: 	��ȡϵͳ�и���������ҳ�����ص�Ŀ¼��������¼��internal_config
  ��������: 	
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
int eal_hugepage_info_init(void)
{
	const char dirent_start_text[] = "hugepages-";
	const size_t dirent_start_len = sizeof(dirent_start_text) - 1;
	unsigned i, hugepage_type = 0;
	DIR *dir;
	struct dirent *dirent;

	/*���ļ���/sys/kernel/mm/hugepages*/
	dir = opendir(sys_dir_path);
	if (dir == NULL)
	{
		rte_panic("Cannot open directory %s to read system hugepage " "info\n", sys_dir_path);
	}
	
	/*ѭ����ȡĿ¼�¸�����ҳ��ϢĿ¼������ugepages-1048576kB����ȡĳ���Ĵ�ҳ������Ϣ,ϵͳ���ж��ִ�ҳ*/
	for (dirent = readdir(dir); dirent != NULL; dirent = readdir(dir))
	{
		struct hugepage_info *hugepage_info;

		/*�ҵ���ҳĿ¼��hugepages-xxx*/
		if (strncmp(dirent->d_name, dirent_start_text, dirent_start_len) != 0)
		{
			continue;
		}
		
		/*�����Ҫ3�ֹ���ҳ*/
		if (hugepage_type >= MAX_HUGEPAGE_SIZES)
		{
			break;
		}
		
		/*��ҳ�ڴ���Ϣ�ṹ�������*/
		hugepage_info = &internal_config.hugepage_info[hugepage_type];

		/*��ȡ/sys/kernel/mm/hugepages Ŀ¼�� ������ҳ�ڴ�size, hugepages-2048KB, תΪ�ֽ�2048*/
		hugepage_info->hugepage_sz = rte_str_to_size(&dirent->d_name[dirent_start_len]);

		/*��ҳ���ص�Ŀ¼����ҳsizeΪ�����Ĵ�ҳsize, ����Ŀ¼/dev/hugepages����Ŀ¼*/
		hugepage_info->hugepage_file_dir = get_hugepage_dir(hugepage_info->hugepage_sz);

		/* first, check if we have a mountpoint */

		/*��ҳδ���أ��������ѯ��һ�����Ĵ�ҳ���ص�*/
		if (hugepage_info->hugepage_file_dir == NULL) 
		{
			uint32_t pages_num;

			/*��ȡϵͳ�п��ô�ҳ���� /sys/kernel/mm/hugepages/hugepages-1048576kB/free_hugepages */
			pages_num = get_num_hugepages(dirent->d_name);
			if (pages_num > 0)
			{
				/*��ҳδ������ʾ*/
				RTE_LOG(NOTICE, EAL,
					"%" PRIu32 " hugepages of size "
					"%" PRIu64 " reserved, but no mounted "
					"hugetlbfs found for that size\n",
					pages_num, hugepage_info->hugepage_sz);
			}
			
			continue;
		}

		/* try to obtain a writelock */
		// *�ڶ�ȡhugetlbfs���õ�ʱ����Ҫ��ס����Ŀ¼��������hugepage��mmap��ɺ󣬻����,����Ŀ¼/dev/hugepages����Ŀ¼*/
		hugepage_info->lock_descriptor = open(hugepage_info->hugepage_file_dir, O_RDONLY);

		/* if blocking lock failed */
		/*����ҳĿ¼ʧ������ֹ*/
		if (flock(hugepage_info->lock_descriptor, LOCK_EX) == -1)
		{
			RTE_LOG(CRIT, EAL, "Failed to lock hugepage directory!\n");
			break;
		}
		
		/* clear out the hugepages dir from unused pages */

		/*�����ҳ���ص�ַĿ¼ -r��ʧ������ֹ*/
		/*�����ҳ����Ŀ¼�µ��ļ���/dev/hugepages/rte_map0-9��ҳ�ļ���Ϊ��Ҫɾ��*/
		if (clear_hugedir(hugepage_info->hugepage_file_dir) == -1)
		{
			break;
		}
		
		/* for now, put all pages into socket 0,
		 * later they will be sorted */

		/*/sys/kernel/mm/hugepages-1048576kB ��size����Ч��ҳ����*/
		/* cat /sys/kernel/mm/hugepages/hugepages-1048576kB/free_hugepages */
		/*����¼��0����*/
		/*��ȡϵͳ�������д�ҳ����������64*2M*/
		hugepage_info->pages_num[0] = get_num_hugepages(dirent->d_name);

#ifndef RTE_ARCH_64
		/* for 32-bit systems, limit number of hugepages to
		 * 1GB per page size */

/*64�ܹ���С1G��ҳ����������ҳ���Ŀ¼�Ĺ����ʵ��ҳ��������ʹ���ڴ�����С��1G*/
		/*���ܹ��°�1G�ڴ滮�ִ�ҳ*/
		hugepage_info->pages_num[0] = RTE_MIN(hugepage_info->pages_num[0], RTE_PGSIZE_1G / hugepage_info->hugepage_sz);
#endif

		/*��ҳ������*/
		hugepage_type++;
	}
	closedir(dir);

	/* something went wrong, and we broke from the for loop above */
	if (dirent != NULL)
	{
		return -1;
	}
	
	/*���صĴ�ҳ����������������ֻ��һ�ֹ���ҳ*/
	internal_config.hugepage_type_num = hugepage_type;

	/* sort the page directory entries by size, largest to smallest */
	/*���д�ҳ������࣬���info��Ϣ���Ӵ�Сsize����*/
	qsort(&internal_config.hugepage_info[0], hugepage_type, sizeof(internal_config.hugepage_info[0]), compare_hpi);

	/* now we have all info, check we have at least one valid size */

	/*�������صĴ�ҳ�����������һ�ֹ���ҳ������Ч��ҳ������ҳ������Ϊ0,����64��2M��ҳ*/
	for (i = 0; i < hugepage_type; i++)
	{
		/*�����ҿ��д�ҳ������Ϊ0*/
		if (internal_config.hugepage_info[i].hugepage_file_dir != NULL
		     && internal_config.hugepage_info[i].pages_num[0] > 0)
		{
			return 0;
		}
	}
	
	/* no valid hugepage mounts available, return error */
	/*û�п�ʹ�õĴ�ҳ���*/
	return -1;
}
