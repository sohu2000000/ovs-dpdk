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

/**
 * @file
 * Stores functions and path defines for files and directories
 * on the filesystem for Linux, that are used by the Linux EAL.
 */

#ifndef EAL_FILESYSTEM_H
#define EAL_FILESYSTEM_H

/** Path of rte config file. */
#define RUNTIME_CONFIG_FMT "%s/.%s_config"

#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>

#include <rte_string_fns.h>
#include "eal_internal_cfg.h"

static const char *default_config_dir = "/var/run";


/*******************************************************
  ������:		eal_runtime_config_path
  ��������: 	�����ļ�·��
  ��������: 	
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static inline const char *
eal_runtime_config_path(void)
{
	static char buffer[PATH_MAX]; /* static so auto-zeroed */

	/*/var/run*/
	const char *directory = default_config_dir;

	/*��ȡhomeĿ¼*/
	const char *home_dir = getenv("HOME");

	if (getuid() != 0 && home_dir != NULL)
	{
		directory = home_dir;
	}
	
	/* /var/run/rte_config*/
	/*��/home/var/runt/rte_configĿ¼*/
	snprintf(buffer, sizeof(buffer) - 1, RUNTIME_CONFIG_FMT, directory, internal_config.hugefile_prefix);
	
	return buffer;
}

/** Path of hugepage info file. */
#define HUGEPAGE_INFO_FMT "%s/.%s_hugepage_info"

/*******************************************************
  ������:		eal_hugepage_info_path
  ��������: 	��ȡ��ҳ����·�� /var/run/rte_hugepage_info
  ��������: 	
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static inline const char *
eal_hugepage_info_path(void)
{
	static char buffer[PATH_MAX]; /* static so auto-zeroed */
	const char *directory = default_config_dir;
	const char *home_dir = getenv("HOME");

	if (getuid() != 0 && home_dir != NULL)
		directory = home_dir;

	/*��ȡ��ҳ����·�� /var/run/rte_hugepage_info*/
	snprintf(buffer, sizeof(buffer) - 1, HUGEPAGE_INFO_FMT, directory, internal_config.hugefile_prefix);

	return buffer;
}

/** String format for hugepage map files. */
#define HUGEFILE_FMT "%s/%smap_%d"
#define TEMP_HUGEFILE_FMT "%s/%smap_temp_%d"


 /*******************************************************
  ������:		eal_get_hugefile_path
  ��������: 	��װ��ҳ·���� /dev/hugepages/rte_smap_1
  ��������: 	buffer---��ҳ·���洢�ڴ�
  				hugepage_file_dir---��ҳ����Ŀ¼ /dev/hugepages
  				f_id---���ƵĴ�ҳID
  ����ֵ  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static inline const char *
eal_get_hugefile_path(char *buffer, size_t buflen, const char *hugepage_file_dir, int f_id)
{
	/*%s/%smap_%d*/
	/*/dev/hugepages/rte_smap_1*/
	snprintf(buffer, buflen, HUGEFILE_FMT, hugepage_file_dir, internal_config.hugefile_prefix, f_id);
	buffer[buflen - 1] = '\0';
	return buffer;
}

/** define the default filename prefix for the %s values above */
#define HUGEFILE_PREFIX_DEFAULT "rte"

/** Function to read a single numeric value from a file on the filesystem.
 * Used to read information from files on /sys */
int eal_parse_sysfs_value(const char *filename, unsigned long *val);

#endif /* EAL_FILESYSTEM_H */
