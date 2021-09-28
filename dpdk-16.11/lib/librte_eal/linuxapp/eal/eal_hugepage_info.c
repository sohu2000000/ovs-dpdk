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
  函数名:		get_num_hugepages
  功能描述: 	获取系统中可用大页个数
  参数描述: 	/sys/kernel/mm/hugepages-2048576目录
  返回值	  : 
  最后修改人:
  修改日期:    2017 -11-15
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

	/*获取保留大页个数,失败返回*/
	if (eal_parse_sysfs_value(path, &resv_pages) < 0)
	{
		return 0;
	}
	
	/*获取free_hugepages的值，就是空闲大页个数*/
	snprintf(path, sizeof(path), "%s/%s/%s", sys_dir_path, subdir, nr_hp_file);

	/*获取空闲内存free_hugepages大个数*/
	if (eal_parse_sysfs_value(path, &pages_num) < 0)
	{
		return 0;
	}
	
	if (pages_num == 0)
	{
		RTE_LOG(WARNING, EAL, "No free hugepages reported in %s\n",subdir);
	}
	
	/* adjust pages_num */
	/*有效大页个数，去除保留页*/

	/*free 大页包含了保留大页*/
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
  函数名:		get_default_hp_size
  功能描述: 	获取/proc/meminfo下huagepagesize 大页size数字
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
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

	/*获取/proc/meminfo 下的Hugepagesize:2048 大页内存的内存size*/
	/*读取Hugepagesize: size数据*/
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
  函数名:		eal_hugepage_info_init
  功能描述: 	获得大页挂载目录 /dev/hugepages挂载目录
  参数描述: 	hugepage_sz--大页size数据，例如2048，/sys/kernel/mm/hugepages 本规格
  返回值  :     大页挂载的目录，如果大页挂载目录的size确实与目录规格size一致则返回挂载目录
  				
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static const char *
get_hugepage_dir(uint64_t hugepage_sz)
{
	enum proc_mount_fieldnames 
	{
		DEVICE = 0,           /*设备目录*/
		MOUNTPT,              /*挂载目录*/
		FSTYPE,               /*文件系统类型*/
		OPTIONS,              /*选项*/
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

	/*打开/proc/mounts*/
	FILE *fd = fopen(proc_mounts, "r");
	if (fd == NULL)
	{
		rte_panic("Cannot open %s\n", proc_mounts);
	}
	
	/*获取/proc/meminfo下 hugepagesize 数据 大页内存size 2048KB，作为默认大页内存size*/
	if (default_size == 0)
	{
		default_size = get_default_hp_size();
	}

	/*读取/proc/mounts下内存挂载点目录信息*/
	while (fgets(buf, sizeof(buf), fd))
	{
		/*挂载点字符串切割*/
		if (rte_strsplit(buf, sizeof(buf), splitstr, _FIELDNAME_MAX, split_tok) != _FIELDNAME_MAX)
		{
			RTE_LOG(ERR, EAL, "Error parsing %s\n", proc_mounts);
			break; /* return NULL */
		}

		/* we have a specified --huge-dir option, only examine that dir */

		/*检查internal_config.hugepage_dir 是否 在/proc/mounts 下，即内存是否挂载*/
		/*/proc/bus/usb--设备目录 /proc/bus/usb--挂载目录 usbfs rw,relatime 0 0*/

		/*当前目录字符串不是大页目录*/

		/*查找internal_config.hugepage_dir是否已经挂载*/
		if (internal_config.hugepage_dir != NULL && strcmp(splitstr[MOUNTPT], internal_config.hugepage_dir) != 0)
		{
			continue;
		}
		
		/*/proc/mounts 大页挂载目录，能否找到"hugetlbfs"字符串*/
		if (strncmp(splitstr[FSTYPE], hugetlbfs_str, htlbfs_str_len) == 0)
		{
			/*获取挂载目录中的大页size字符串*/
			const char *pagesz_str = strstr(splitstr[OPTIONS], pagesize_opt);

			/* if no explicit page size, the default page size is compared */


			
			/*限制挂载目录大页size的值与目录规格大页size一致*/

			/*挂载目录不存在，大页size字符串*/
			/*目录规格的大页size=系统的大页size，则使用挂载目录的大页size*/
			if (pagesz_str == NULL)
			{
				/*/sys/kernel/mm/hugepages 本大页目录规格的大页size，即系统proc/meminfo下的大页size*/
				/*目录规格的大页size即系统的大页size，则使用挂载目录的大页size*/
				if (hugepage_sz == default_size)
				{
					retval = strdup(splitstr[MOUNTPT]);  /*dev/hugepages挂载目录*/
					break;
				}
			}
			/* there is an explicit page size, so check it */
			/*挂载目录中存在大页size字符串，即自定义的大页size字符串若与目录规格相等则使用*/
			else 
			{
				/*挂载目录中获取的大页size*/
				uint64_t pagesz = rte_str_to_size(&pagesz_str[pagesize_opt_len]);
				/*如果挂载的目录的大页size就是/sys/kernel/mm/hugepages 本规格的大页内存size*/
				/*挂载目录的大页size即是目录规格的大页size，则使用挂载目录的size*/
				if (pagesz == hugepage_sz) 
				{
					retval = strdup(splitstr[MOUNTPT]);
					break;
				}
			}
		} /* end if strncmp hugetlbfs */
	} /* end while fgets */

	fclose(fd);

	/*dev/hugepages挂载目录*/
	return retval;
}

/*
 * Clear the hugepage directory of whatever hugepage files
 * there are. Checks if the file is locked (i.e.
 * if it's in use by another DPDK process).
 */
	
/*******************************************************
  函数名:		clear_hugedir
  功能描述: 	清除大页挂载点下的文件/dev/hugepages/rte_map0-9
  参数描述: 	hugepage_file_dir---大页内存挂载目录,挂载目录/dev/hugepages挂载目录
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static int clear_hugedir(const char * hugepage_file_dir)
{
	DIR *dir;
	struct dirent *dirent;
	int dir_fd, fd, lck_result;
	const char filter[] = "*map_*"; /* matches hugepage files */

	/* open directory */
	/*打开大页目录*/
	dir = opendir(hugepage_file_dir);
	if (!dir) 
	{
		RTE_LOG(ERR, EAL, "Unable to open hugepage directory %s\n", hugepage_file_dir);
		goto error;
	}

	dir_fd = dirfd(dir);

	/*读取挂载的大页子目录*/
	dirent = readdir(dir);
	if (!dirent) 
	{
		RTE_LOG(ERR, EAL, "Unable to read hugepage directory %s\n", hugepage_file_dir);
		goto error;
	}

	/*遍历子目录并删除rtemap_0-9*/
	while(dirent != NULL)
	{
		/* skip files that don't match the hugepage pattern */
		/*跳过不匹配的大页地址,直到匹配到带有map_的目录*/
		if (fnmatch(filter, dirent->d_name, 0) > 0) 
		{
			dirent = readdir(dir);
			continue;
		}

		/* try and lock the file */
		/*打开大页目录 rtemap_0-9*/
		fd = openat(dir_fd, dirent->d_name, O_RDONLY);

		/* skip to next file */
		if (fd == -1) 
		{
			dirent = readdir(dir);
			continue;
		}

		/* non-blocking lock */
		/*可以获取文件锁*/
		lck_result = flock(fd, LOCK_EX | LOCK_NB);

		/* if lock succeeds, unlock and remove the file */
		/*删除*/
		if (lck_result != -1) 
		{
			flock(fd, LOCK_UN);
			unlinkat(dir_fd, dirent->d_name, 0);
		}
		
		close (fd);

		/*下个目录*/
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
  函数名:		eal_hugepage_info_init
  功能描述: 	获取系统中各规格种类大页，挂载点目录及个数记录到internal_config
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
int eal_hugepage_info_init(void)
{
	const char dirent_start_text[] = "hugepages-";
	const size_t dirent_start_len = sizeof(dirent_start_text) - 1;
	unsigned i, hugepage_type = 0;
	DIR *dir;
	struct dirent *dirent;

	/*打开文件夹/sys/kernel/mm/hugepages*/
	dir = opendir(sys_dir_path);
	if (dir == NULL)
	{
		rte_panic("Cannot open directory %s to read system hugepage " "info\n", sys_dir_path);
	}
	
	/*循环读取目录下各规格大页信息目录，例如ugepages-1048576kB，获取某规格的大页数等信息,系统可有多种大页*/
	for (dirent = readdir(dir); dirent != NULL; dirent = readdir(dir))
	{
		struct hugepage_info *hugepage_info;

		/*找到大页目录名hugepages-xxx*/
		if (strncmp(dirent->d_name, dirent_start_text, dirent_start_len) != 0)
		{
			continue;
		}
		
		/*最多需要3种规格大页*/
		if (hugepage_type >= MAX_HUGEPAGE_SIZES)
		{
			break;
		}
		
		/*大页内存信息结构，本规格*/
		hugepage_info = &internal_config.hugepage_info[hugepage_type];

		/*获取/sys/kernel/mm/hugepages 目录下 本规格大页内存size, hugepages-2048KB, 转为字节2048*/
		hugepage_info->hugepage_sz = rte_str_to_size(&dirent->d_name[dirent_start_len]);

		/*大页挂载的目录，大页size为本规格的大页size, 挂载目录/dev/hugepages挂载目录*/
		hugepage_info->hugepage_file_dir = get_hugepage_dir(hugepage_info->hugepage_sz);

		/* first, check if we have a mountpoint */

		/*大页未挂载，则继续查询下一个规格的大页挂载点*/
		if (hugepage_info->hugepage_file_dir == NULL) 
		{
			uint32_t pages_num;

			/*获取系统中可用大页个数 /sys/kernel/mm/hugepages/hugepages-1048576kB/free_hugepages */
			pages_num = get_num_hugepages(dirent->d_name);
			if (pages_num > 0)
			{
				/*大页未挂载提示*/
				RTE_LOG(NOTICE, EAL,
					"%" PRIu32 " hugepages of size "
					"%" PRIu64 " reserved, but no mounted "
					"hugetlbfs found for that size\n",
					pages_num, hugepage_info->hugepage_sz);
			}
			
			continue;
		}

		/* try to obtain a writelock */
		// *在读取hugetlbfs配置的时候，需要锁住整个目录。当所有hugepage都mmap完成后，会解锁,挂载目录/dev/hugepages挂载目录*/
		hugepage_info->lock_descriptor = open(hugepage_info->hugepage_file_dir, O_RDONLY);

		/* if blocking lock failed */
		/*锁大页目录失败则终止*/
		if (flock(hugepage_info->lock_descriptor, LOCK_EX) == -1)
		{
			RTE_LOG(CRIT, EAL, "Failed to lock hugepage directory!\n");
			break;
		}
		
		/* clear out the hugepages dir from unused pages */

		/*清除大页挂载地址目录 -r，失败则终止*/
		/*清除大页挂载目录下的文件，/dev/hugepages/rte_map0-9大页文件，为何要删除*/
		if (clear_hugedir(hugepage_info->hugepage_file_dir) == -1)
		{
			break;
		}
		
		/* for now, put all pages into socket 0,
		 * later they will be sorted */

		/*/sys/kernel/mm/hugepages-1048576kB 本size的有效大页个数*/
		/* cat /sys/kernel/mm/hugepages/hugepages-1048576kB/free_hugepages */
		/*都记录在0格子*/
		/*获取系统本规格空闲大页个数，例如64*2M*/
		hugepage_info->pages_num[0] = get_num_hugepages(dirent->d_name);

#ifndef RTE_ARCH_64
		/* for 32-bit systems, limit number of hugepages to
		 * 1GB per page size */

/*64架构最小1G大页个数，本大页规格目录的规格，真实大页个数，即使用内存限制小于1G*/
		/*本架构下按1G内存划分大页*/
		hugepage_info->pages_num[0] = RTE_MIN(hugepage_info->pages_num[0], RTE_PGSIZE_1G / hugepage_info->hugepage_sz);
#endif

		/*大页规格计数*/
		hugepage_type++;
	}
	closedir(dir);

	/* something went wrong, and we broke from the for loop above */
	if (dirent != NULL)
	{
		return -1;
	}
	
	/*挂载的大页规格种类计数，假设只有一种规格大页*/
	internal_config.hugepage_type_num = hugepage_type;

	/* sort the page directory entries by size, largest to smallest */
	/*所有大页规格种类，规格info信息，从大到小size排序*/
	qsort(&internal_config.hugepage_info[0], hugepage_type, sizeof(internal_config.hugepage_info[0]), compare_hpi);

	/* now we have all info, check we have at least one valid size */

	/*遍历挂载的大页规格中至少有一种规格大页存在有效大页，即大页个数不为0,例如64张2M大页*/
	for (i = 0; i < hugepage_type; i++)
	{
		/*挂载且空闲大页个数不为0*/
		if (internal_config.hugepage_info[i].hugepage_file_dir != NULL
		     && internal_config.hugepage_info[i].pages_num[0] > 0)
		{
			return 0;
		}
	}
	
	/* no valid hugepage mounts available, return error */
	/*没有可使用的大页规格*/
	return -1;
}
