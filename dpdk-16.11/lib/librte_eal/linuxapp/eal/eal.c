/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
 *   Copyright(c) 2012-2014 6WIND S.A.
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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>
#include <getopt.h>
#include <sys/file.h>
#include <fcntl.h>
#include <stddef.h>
#include <errno.h>
#include <limits.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/stat.h>
#if defined(RTE_ARCH_X86)
#include <sys/io.h>
#endif

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_eal_memconfig.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_random.h>
#include <rte_cycles.h>
#include <rte_string_fns.h>
#include <rte_cpuflags.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_dev.h>
#include <rte_devargs.h>
#include <rte_common.h>
#include <rte_version.h>
#include <rte_atomic.h>
#include <malloc_heap.h>

#include "eal_private.h"
#include "eal_thread.h"
#include "eal_internal_cfg.h"
#include "eal_filesystem.h"
#include "eal_hugepages.h"
#include "eal_options.h"
#include "eal_vfio.h"

#define MEMSIZE_IF_NO_HUGE_PAGE (64ULL * 1024ULL * 1024ULL)

#define SOCKET_MEM_STRLEN (RTE_MAX_NUMA_NODES * 10)

/* Allow the application to print its usage message too if set */
static rte_usage_hook_t	rte_application_usage_hook = NULL;

/*���̵�ַ�ռ��ڴ�����*/
/* early configuration structure, when memory config is not mmapped */
static struct rte_mem_config early_mem_config;                                /*�ڴ�����*/

/* define fd variable here, because file needs to be kept open for the
 * duration of the program, as we hold a write lock on it in the primary proc */
static int mem_cfg_fd = -1;

/*�����ļ�д��*/
static struct flock wr_lock = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start = offsetof(struct rte_mem_config, memseg),
		.l_len = sizeof(early_mem_config.memseg),
};

/* Address of global and public configuration */

/*�ڴ��������Ϣ*/
static struct rte_config rte_config = 
{
		.mem_config = &early_mem_config,     /*�����ڴ����ýṹ*/
};

/* internal configuration (per-core) */
/*128���߼�������*/
struct lcore_config_global lcore_config[RTE_MAX_LCORE];

/* internal configuration */
/*ȫ���ڴ�����*/
struct internal_config_global internal_config;

/* used by rte_rdtsc() */
int rte_cycles_vmware_tsc_map;

/* Return a pointer to the configuration structure */
struct rte_config *
rte_eal_get_configuration(void)
{
	return &rte_config;       /*rteȫ������*/
}

/* parse a sysfs (or other) file containing one integer value */

/*******************************************************
  ������:		eal_parse_sysfs_value
  ��������: 	��ȡCPU��ID
  ��������: 	filename--CPU�ļ���
  ����ֵ	  : val--CPU ֵ
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
int eal_parse_sysfs_value(const char *filename, unsigned long *val)
{
	FILE *f;
	char buf[BUFSIZ];
	char *end = NULL;

	if ((f = fopen(filename, "r")) == NULL)
	{
		RTE_LOG(ERR, EAL, "%s(): cannot open sysfs value %s\n",__func__, filename);
		return -1;
	}

	/*��ȡidֵ*/
	if (fgets(buf, sizeof(buf), f) == NULL) 
	{
		RTE_LOG(ERR, EAL, "%s(): cannot read sysfs value %s\n",__func__, filename);
		fclose(f);
		return -1;
	}

	*val = strtoul(buf, &end, 0);

	if ((buf[0] == '\0') || (end == NULL) || (*end != '\n')) 
	{
		RTE_LOG(ERR, EAL, "%s(): cannot parse sysfs value %s\n",__func__, filename);
		fclose(f);
		
		return -1;
	}
	
	fclose(f);
	
	return 0;
}


/* create memory configuration in shared/mmap memory. Take out
 * a write lock on the memsegs, so we can auto-detect primary/secondary.
 * This means we never close the file while running (auto-close on exit).
 * We also don't lock the whole file, so that in future we can use read-locks
 * on other parts, e.g. memzones, to detect if there are running secondary
 * processes. */

/*******************************************************
  ������:		rte_eal_config_create
  ��������: 	���������ô��������ڹ���
  ��������: 	
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static void
rte_eal_config_create(void)
{
	void *rte_mem_cfg_addr;
	int retval;

	/*��ȡ���������ļ�*/
	/* /var/run/rte_config*/
	/*��/home/var/runt/rte_configĿ¼*/*/
	const char *pathname = eal_runtime_config_path();

	/*����Ϊ�ǹ���ģʽ�򷵻�*/
	if (internal_config.no_shconf)
	{
		return;
	}
	
	/* map the config before hugepage address so that we don't waste a page */
	/*��ҳ����ַӳ�����ýṹ*/
	if (internal_config.base_virtaddr != 0)
	{
		/*��ȡ�ڴ����ýṹ��ַ*/          /*base_addr*/
		/*-----struct rte_mem_config------|----------------------------------------*/
		rte_mem_cfg_addr = (void *) RTE_ALIGN_FLOOR(internal_config.base_virtaddr - sizeof(struct rte_mem_config), sysconf(_SC_PAGE_SIZE));
	}
	else
	{
		/*�״�ӳ��ΪNULL*/
		rte_mem_cfg_addr = NULL;
	}
	
	/*�������ļ����������򴴽�/var/run��*/
	/* /var/run/rte_config*/
	/*�������������ļ����ڴ������ļ�*/
	if (mem_cfg_fd < 0)
	{
		mem_cfg_fd = open(pathname, O_RDWR | O_CREAT, 0660);
		if (mem_cfg_fd < 0)
		{
			rte_panic("Cannot open '%s' for rte_mem_config\n", pathname);
		}
	}

	/*ϵͳ�е������ļ��ı�Ϊ���ýṹ��С*/
	retval = ftruncate(mem_cfg_fd, sizeof(*rte_config.mem_config));
	if (retval < 0)
	{
		close(mem_cfg_fd);
		rte_panic("Cannot resize '%s' for rte_mem_config\n", pathname);
	}

	/*�ļ���*/
	retval = fcntl(mem_cfg_fd, F_SETLK, &wr_lock);
	if (retval < 0)
	{
		close(mem_cfg_fd);
		rte_exit(EXIT_FAILURE, "Cannot create lock on '%s'. Is another primary " "process running?\n", pathname);
	}


	/*�ڴ������ļ�ӳ�䵽��ҳ�ڴ��ļ���ַ��ʼ�ռ�*/
	rte_mem_cfg_addr = mmap(rte_mem_cfg_addr, sizeof(*rte_config.mem_config), PROT_READ | PROT_WRITE, MAP_SHARED, mem_cfg_fd, 0);
	if (rte_mem_cfg_addr == MAP_FAILED)
	{
		rte_panic("Cannot mmap memory for rte_config\n");
	}

	/*�����ڴ����ÿ������ڴ�*/
	memcpy(rte_mem_cfg_addr, &early_mem_config, sizeof(early_mem_config));

	/*�����ļ��ڴ��ַ*/
	/* /var/run/rte_config�������ڴ���Ϣ*/
	rte_config.mem_config = (struct rte_mem_config *) rte_mem_cfg_addr;

	/* store address of the config in the config itself so that secondary
	 * processes could later map the config into this exact location */

	/*�ڴ������ļ���ַ/var/run/rte_config*/
	rte_config.mem_config->mem_cfg_addr = (uintptr_t) rte_mem_cfg_addr;
}

/* attach to an existing shared memory config */

/*******************************************************
  ������:		rte_eal_config_attach
  ��������: 	�����ļ�ӳ�䵽�ڴ�
  ��������: 	
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static void rte_eal_config_attach(void)
{
	struct rte_mem_config *mem_config;

	/* /var/run/rte_config �����ļ���*/
	const char *pathname = eal_runtime_config_path();

	/*��������ǹ���ʽ�򷵻�*/
	if (internal_config.no_shconf)
	{
		return;
	}
	
	if (mem_cfg_fd < 0)
	{
		mem_cfg_fd = open(pathname, O_RDWR);
		
		if (mem_cfg_fd < 0)
		{
			rte_panic("Cannot open '%s' for rte_mem_config\n", pathname);
		}
	}

	/* map it as read-only first */

	/*��������ӳ�䵽�ӽ���*/
	mem_config = (struct rte_mem_config *) mmap(NULL, sizeof(*mem_config), PROT_READ, MAP_SHARED, mem_cfg_fd, 0);
	
	if (mem_config == MAP_FAILED)
	{
		rte_panic("Cannot mmap memory for rte_config! error %i (%s)\n", errno, strerror(errno));
	}

	/*��¼���������ڴ�*/
	rte_config.mem_config = mem_config;
}

/* reattach the shared config at exact memory location primary process has it */
/*******************************************************
  ������:		rte_eal_config_reattach
  ��������: 	�����ļ�����ӳ�䣬Ϊʲô����ӳ��
  ��������: 	
  ����ֵ  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static void
rte_eal_config_reattach(void)
{
	struct rte_mem_config *mem_config;
	void *rte_mem_cfg_addr;

	/*�ڴ�ǹ����򷵻�*/
	if (internal_config.no_shconf)
	{
		return;
	}
	
	/* save the address primary process has mapped shared config to */
	/*��ȡ���õ�ַ/var/run/rte_config*/
	rte_mem_cfg_addr = (void *) (uintptr_t) rte_config.mem_config->mem_cfg_addr;

	/* unmap original config */
	/*��������ڴ�ӳ��*/
	munmap(rte_config.mem_config, sizeof(struct rte_mem_config));

	/* remap the config at proper address */
	/*����ӳ�䵽���ʵĵ�ַ*/
	mem_config = (struct rte_mem_config *) mmap(rte_mem_cfg_addr, sizeof(*mem_config), PROT_READ | PROT_WRITE, MAP_SHARED,mem_cfg_fd, 0);

	if (mem_config == MAP_FAILED || mem_config != rte_mem_cfg_addr)
	{
		if (mem_config != MAP_FAILED)
		{
			/* errno is stale, don't use */
			rte_panic("Cannot mmap memory for rte_config at [%p], got [%p]"
				  " - please use '--base-virtaddr' option\n",
				  rte_mem_cfg_addr, mem_config);
		}
		else
		{
			rte_panic("Cannot mmap memory for rte_config! error %i (%s)\n",
				  errno, strerror(errno));
		}
	}
	
	close(mem_cfg_fd);

	/*/var/run/rte_config*/
	rte_config.mem_config = mem_config;
}

/* Detect if we are a primary or a secondary process */

/*******************************************************
  ������:		eal_proc_type_detect
  ��������: 	���
  ��������: 	
  ����ֵ	:
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
enum rte_proc_type_t
eal_proc_type_detect(void)
{
	enum rte_proc_type_t ptype = RTE_PROC_PRIMARY;

	/*���������ļ�·��/var/run %s/.%s_config*/
	const char *pathname = eal_runtime_config_path();

	/* if we can open the file but not get a write-lock we are a secondary
	 * process. NOTE: if we get a file handle back, we keep that open
	 * and don't close it to prevent a race condition between multiple opens */

	/*�����������ļ�·������ȡ��¼��*/
	if (((mem_cfg_fd = open(pathname, O_RDWR)) >= 0)
		&& (fcntl(mem_cfg_fd, F_SETLK, &wr_lock) < 0))	/*��ȡ��¼��*/
	{
		ptype = RTE_PROC_SECONDARY;
	}
	
	RTE_LOG(INFO, EAL, "Auto-detected process type: %s\n", ptype == RTE_PROC_PRIMARY ? "PRIMARY" : "SECONDARY");

	return ptype;
}

/* Sets up rte_config structure with the pointer to shared memory config.*/
/*******************************************************
  ������:		rte_config_init
  ��������: 	��ҳ�ڴ������ļ�ӳ�䵽�ڴ�
  ��������: 	
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static void rte_config_init(void)
{
	/*��ȡ�������ͣ�dpdk�����������̻�ӽ���*/
	rte_config.process_type = internal_config.process_type;

	switch (rte_config.process_type)
	{
		/*������*/
		case RTE_PROC_PRIMARY:
		{
			/*ӳ�䵽�����̵������ڴ����ýṹ�����������ļ������������ڴ����ã�/var/run/rte_config*/
			rte_eal_config_create();
			break;
		}
		
		/*�ӽ���*/
		case RTE_PROC_SECONDARY:
		{
			/*�����ļ�/var/run/rte_config �ڴ�ӳ�䵽�ӽ���*/
			rte_eal_config_attach();

			/*�ȴ��ڴ�ӳ��������*/
			rte_eal_mcfg_wait_complete(rte_config.mem_config);

			/*�����ڴ�����ӳ�䣬ΪʲôҪ��ӳ��*/
			rte_eal_config_reattach();
			break;
		}

		
		case RTE_PROC_AUTO:
		case RTE_PROC_INVALID:
		{
			rte_panic("Invalid process type\n");
		}
	}
}

/* Unlocks hugepage directories that were locked by eal_hugepage_info_init */
/*******************************************************
  ������:		eal_hugedirs_unlock
  ��������: 	��ҳ������֮ǰ��ס
  ��������: 	
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static void
eal_hugedirs_unlock(void)
{
	int i;

	/*��ҳ����*/
	for (i = 0; i < MAX_HUGEPAGE_SIZES; i++)
	{
		/* skip uninitialized */
		/*��ҳδ��ʼ������*/
		if (internal_config.type_hugepage_info[i].lock_descriptor < 0)
		{
			continue;
		}
		
		/* unlock hugepage file */

		/*�����ļ�*/
		flock(internal_config.type_hugepage_info[i].lock_descriptor, LOCK_UN);

		close(internal_config.type_hugepage_info[i].lock_descriptor);

		/* reset the field */
		internal_config.type_hugepage_info[i].lock_descriptor = -1;
	}
}

/* display usage */
static void
eal_usage(const char *prgname)
{
	printf("\nUsage: %s ", prgname);

	eal_common_usage();
	
	printf("EAL Linux options:\n"
	       "  --"OPT_SOCKET_MEM"        Memory to allocate on sockets (comma separated values)\n"   /*socket���ڴ�����*/
	       "  --"OPT_HUGE_DIR"          Directory where hugetlbfs is mounted\n"                     /*��ҳ����Ŀ¼*/
	       "  --"OPT_FILE_PREFIX"       Prefix for hugepage filenames\n"                            /*��ҳ�ļ�ǰ׺*/
	       "  --"OPT_BASE_VIRTADDR"     Base virtual address\n"                                     /*�������ַ*/
	       "  --"OPT_CREATE_UIO_DEV"    Create /dev/uioX (usually done by hotplug)\n"               /*��������io*/
	       "  --"OPT_VFIO_INTR"         Interrupt mode for VFIO (legacy|msi|msix)\n"                /*����io��ģʽ*/
	       "  --"OPT_XEN_DOM0"          Support running on Xen dom0 without hugetlbfs\n"            /*����֧����xen���޴�ҳģʽ����*/
	       "\n");

	/* Allow the application to print its usage message too if hook is set */
	/*Ӧ�����鷽��*/
	if ( rte_application_usage_hook )
	{
		printf("===== Application Usage =====\n\n");
		rte_application_usage_hook(prgname);
	}
}

/* Set a per-application usage message */
rte_usage_hook_t
rte_set_application_usage_hook( rte_usage_hook_t usage_func )
{
	rte_usage_hook_t	old_func;

	/* Will be NULL on the first call to denote the last usage routine. */
	old_func					= rte_application_usage_hook;
	rte_application_usage_hook	= usage_func;

	return old_func;
}


/*******************************************************
  ������:		eal_parse_socket_mem
  ��������: 	����socket �ڴ����
  ��������: 	socket_mem--socke���ڴ������ַ���
  ����ֵ	:
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static int
eal_parse_socket_mem(char *socket_mem)
{
	char * arg[RTE_MAX_NUMA_NODES];
	char *end;
	int arg_num, i, len;
	uint64_t total_mem = 0;

	/*У�� socket_mem �Ƿ񳬳� 8*10*/
	len = strnlen(socket_mem, SOCKET_MEM_STRLEN);
	if (len == SOCKET_MEM_STRLEN) 
	{
		RTE_LOG(ERR, EAL, "--socket-mem is too long\n");
		return -1;
	}

	/* all other error cases will be caught later */
	/*�ڴ����������*/
	if (!isdigit(socket_mem[len-1]))
	{
		return -1;
	}
	
	/* split the optarg into separate socket values */
	/*�ָ��mem��������*/
	arg_num = rte_strsplit(socket_mem, len, arg, RTE_MAX_NUMA_NODES, ',');

	/* if split failed, or 0 arguments */
	/**/
	if (arg_num <= 0)
	{
		return -1;
	}
	
	internal_config.force_sockets = 1;

	/* parse each defined socket option */
	errno = 0;

	/*����Ҫ�����socket mem*/
	for (i = 0; i < arg_num; i++) 
	{
		end = NULL;

		/*ת��������*/
		internal_config.socket_mem[i] = strtoull(arg[i], &end, 10);

		/* check for invalid input */
		/*���Ƿ�����*/
		if ((errno != 0)  || (arg[i][0] == '\0') || (end == NULL) || (*end != '\0'))
		{
			return -1;
		}

		/*socket�ڴ����*/
		internal_config.socket_mem[i] *= 1024ULL;
		internal_config.socket_mem[i] *= 1024ULL;

		/*socket���ڴ����*/
		total_mem += internal_config.socket_mem[i];
	}

	/* check if we have a positive amount of total memory */
	if (total_mem == 0)
	{
		return -1;
	}
	
	return 0;
}

/*******************************************************
  ������:		eal_parse_base_virtaddr
  ��������: 	���������ַ
  ��������: 	
  ����ֵ	:
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static int
eal_parse_base_virtaddr(const char *arg)
{
	char *end;
	uint64_t addr;

	errno = 0;
	addr = strtoull(arg, &end, 16);

	/* check for errors */
	if ((errno != 0) || (arg[0] == '\0') || end == NULL || (*end != '\0'))
	{
		return -1;
	}
	
	/* make sure we don't exceed 32-bit boundary on 32-bit target */
#ifndef RTE_ARCH_64
	if (addr >= UINTPTR_MAX)
	{
		return -1;
	}
	
#endif

	/* align the addr on 16M boundary, 16MB is the minimum huge page
	 * size on IBM Power architecture. If the addr is aligned to 16MB,
	 * it can align to 2MB for x86. So this alignment can also be used
	 * on x86 */

	/*�������ַ*/
	internal_config.base_virtaddr = RTE_PTR_ALIGN_CEIL((uintptr_t)addr, (size_t)RTE_PGSIZE_16M);

	return 0;
}

/*******************************************************
  ������:		eal_parse_vfio_intr
  ��������: 	����io�жϲ���
  ��������: 	
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static int
eal_parse_vfio_intr(const char *mode)
{
	unsigned i;

	/*ioģʽ*/
	static struct 
	{
		const char *name;
		enum rte_intr_mode value;
	}map[] =
	{
		{ "legacy", RTE_INTR_MODE_LEGACY },
		{ "msi", RTE_INTR_MODE_MSI },
		{ "msix", RTE_INTR_MODE_MSIX },
	};

	/*����ģʽ����������ioģʽ��ֵ*/
	for (i = 0; i < RTE_DIM(map); i++)
	{
		if (!strcmp(mode, map[i].name)) 
		{
			internal_config.vfio_intr_mode = map[i].value;
			
			return 0;
		}
	}
	
	return -1;
}

/*******************************************************
  ������:		eal_log_level_parse
  ��������: 	��־ˮƽ����
  ��������: 	
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
/* Parse the arguments for --log-level only */
static void
eal_log_level_parse(int argc, char **argv)
{
	int opt;
	char **argvopt;
	int option_index;
	const int old_optind    = optind;
	const int old_optopt    = optopt;
	char * const old_optarg = optarg;

	argvopt = argv;
	optind = 1;

	/*��ʼ��internal_config����*/
	eal_reset_internal_config(&internal_config);

	/*��ȡ����*/
	while ((opt = getopt_long(argc, argvopt, eal_short_options, eal_long_options, &option_index)) != EOF)
	{
		int ret;

		/* getopt is not happy, stop right now */
		if (opt == '?')
		{
			break;
		}
		
		/*����eal�Ĳ��������У���־ˮƽ��������*/
		ret = (opt == OPT_LOG_LEVEL_NUM) ? eal_parse_common_option(opt, optarg, &internal_config) : 0;

		/* common parser is not happy */
		if (ret < 0)
		{
			break;
		}
	}

	/* restore getopt lib */
	optind = old_optind;
	optopt = old_optopt;
	optarg = old_optarg;
}

/* Parse the argument given in the command line of the application */

/*******************************************************
  ������:		eal_parse_args
  ��������: 	��������
  ��������: 	argc---��������7
  				argv---����
  ����ֵ	:
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static int eal_parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	const int old_optind = optind;
	const int old_optopt = optopt;
	char * const old_optarg = optarg;

	argvopt = argv;
	optind = 1;

	/*����ѡ�����*/
	while ((opt = getopt_long(argc, argvopt, eal_short_options, eal_long_options, &option_index)) != EOF) 
	{
		/* getopt is not happy, stop right now*/
		/*��������*/
		if (opt == '?')
		{
			eal_usage(prgname);
			ret = -1;
			goto out;
		}

		/*dpdk�����������·�*/
		ret = eal_parse_common_option(opt, optarg, &internal_config);
		/* common parser is not happy */
		if (ret < 0)
		{
			eal_usage(prgname);
			ret = -1;
			goto out;
		}
		
		/*common parser handled this option*/
		if (ret == 0)
		{
			continue;
		}
		
		switch (opt) 
		{
			case 'h':
			{
				eal_usage(prgname);
				exit(EXIT_SUCCESS);
			}
			/* long options */
			/*֧��xen dom0*/
			case OPT_XEN_DOM0_NUM:
			{
#ifdef RTE_LIBRTE_XEN_DOM0
				internal_config.xen_dom0_support = 1;
#else
				RTE_LOG(ERR, EAL, "Can't support DPDK app "
					"running on Dom0, please configure"
					" RTE_LIBRTE_XEN_DOM0=y\n");

				ret = -1;
				goto out;
#endif
				break;
			}
			
			/*��ҳ·��*/
			case OPT_HUGE_DIR_NUM:
			{
				internal_config.hugepage_dir = optarg;
				break;
			}
			/*�ļ�ǰ׺*/
			case OPT_FILE_PREFIX_NUM:
			{
				internal_config.hugefile_prefix = optarg;
				break;
			}
			
			/*socket mem ������socket mem ��ȡ�ڴ��С��ֵ��Internal�ṹ*/
			case OPT_SOCKET_MEM_NUM:
			{
				if (eal_parse_socket_mem(optarg) < 0) 
				{
					RTE_LOG(ERR, EAL, "invalid parameters for --"
							OPT_SOCKET_MEM "\n");
					eal_usage(prgname);
					ret = -1;
					goto out;
				}
				break;
			}
			
			/*�������ַ*/
			case OPT_BASE_VIRTADDR_NUM:
			{
				if (eal_parse_base_virtaddr(optarg) < 0) 
				{
					RTE_LOG(ERR, EAL, "invalid parameter for --" OPT_BASE_VIRTADDR "\n");

					eal_usage(prgname);

					ret = -1;

					goto out;
				}
				
				break;
			}
			
			/*����io����*/
			case OPT_VFIO_INTR_NUM:
			{
				if (eal_parse_vfio_intr(optarg) < 0) 
				{
					RTE_LOG(ERR, EAL, "invalid parameters for --"
							OPT_VFIO_INTR "\n");
					eal_usage(prgname);
					ret = -1;
					goto out;
				}
				break;
			}
			
			/*�豸����*/
			case OPT_CREATE_UIO_DEV_NUM:
			{
				internal_config.create_uio_dev = 1;
				break;

			}
			
			default:
			{
				if (opt < OPT_LONG_MIN_NUM && isprint(opt))
				{
					RTE_LOG(ERR, EAL, "Option %c is not supported " "on Linux\n", opt);
				}
				else if (opt >= OPT_LONG_MIN_NUM
					&& opt < OPT_LONG_MAX_NUM)
				{
					RTE_LOG(ERR, EAL, "Option %s is not supported "
						"on Linux\n",
						eal_long_options[option_index].name);
				} 
				else
				{
					RTE_LOG(ERR, EAL, "Option %d is not supported "
						"on Linux\n", opt);
				}

				eal_usage(prgname);

				ret = -1;

				goto out;
			}
		}
	}

	/*���õ���*/
	if (eal_adjust_config(&internal_config) != 0) 
	{
		ret = -1;
		goto out;
	}

	/* sanity checks */
	/*�Ϸ��Լ��*/
	if (eal_check_common_options(&internal_config) != 0) 
	{
		eal_usage(prgname);
		ret = -1;
		goto out;
	}

	/* --xen-dom0 doesn't make sense with --socket-mem */
	/*�������xen-dom0ģʽȴû��socket*/
	if (internal_config.xen_dom0_support && internal_config.force_sockets == 1) 
	{
		RTE_LOG(ERR, EAL, "Options --"OPT_SOCKET_MEM" cannot be specified " "together with --"OPT_XEN_DOM0"\n");
		eal_usage(prgname);
		ret = -1;
		goto out;
	}

	/*��¼������������Ϊ./dpdk_server*/
	if (optind >= 0)
	{
		argv[optind-1] = prgname;
	}
	
	ret = optind-1;

out:
	
	/* restore getopt lib */
	optind = old_optind;
	optopt = old_optopt;
	optarg = old_optarg;

	return ret;
}

/*******************************************************
  ������:		eal_check_mem_on_local_socket
  ��������: 	����ڱ���socket�ϵ��ڴ棬�����ڴ�
  ��������: 	
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static void
eal_check_mem_on_local_socket(void)
{
	const struct rte_memseg *ms;
	int i, socket_id;

	/*socket id*/
	/*��ȡ���˵�socket id*/
	socket_id = rte_lcore_to_socket_id(rte_config.master_lcore);

	/*��ȡ�ڴ��*/
	ms = rte_eal_get_physmem_layout();

	/*��socket�ڴ�κϷ��Լ��*/
	for (i = 0; i < RTE_MAX_MEMSEG; i++)
	{
		if (ms[i].socket_id == socket_id && ms[i].len > 0)
		{
			return;
		}
	}
	
	RTE_LOG(WARNING, EAL, "WARNING: Master core has no " "memory on local socket!\n");
}

static int
sync_func(__attribute__((unused)) void *arg)
{
	return 0;
}

inline static void
rte_eal_mcfg_complete(void)
{
	/* ALL shared mem_config related INIT DONE */
	/*������*/
	if (rte_config.process_type == RTE_PROC_PRIMARY)
	{
		rte_config.mem_config->magic = RTE_MAGIC;
	}
}

/*
 * Request iopl privilege for all RPL, returns 0 on success
 * iopl() call is mostly for the i386 architecture. For other architectures,
 * return -1 to indicate IO privilege can't be changed in this way.
 */
int
rte_eal_iopl_init(void)
{
#if defined(RTE_ARCH_X86)
	if (iopl(3) != 0)
		return -1;
#endif
	return 0;
}

#ifdef VFIO_PRESENT

/*******************************************************
  ������:		rte_eal_vfio_setup
  ��������: 	
  ��������: 	
  ����ֵ	  :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
static int rte_eal_vfio_setup(void)
{
	int vfio_enabled = 0;

	/*û��pci�豸*/
	if (!internal_config.no_pci)
	{
		/*ʹ������io*/
		pci_vfio_enable();

		/*���io�Ƿ�ʹ��*/
		vfio_enabled |= pci_vfio_is_enabled();
	}

	/*����ioʹ��*/
	if (vfio_enabled) 
	{
		/* if we are primary process, create a thread to communicate with
		 * secondary processes. the thread will use a socket to wait for
		 * requests from secondary process to send open file descriptors,
		 * because VFIO does not allow multiple open descriptors on a group or
		 * VFIO container.
		 */

		/*����Ϊ�����̣�����ioͬ������*/
		if (internal_config.process_type == RTE_PROC_PRIMARY 
			&& vfio_mp_sync_setup() < 0)
		{
			return -1;
		}
	}

	return 0;
	
}
#endif

/* Launch threads, called at application init(). */

/*******************************************************
  ������:		rte_eal_init
  ��������: 	���л�������ʼ�����
  ��������: 	
  ����ֵ    :
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
int rte_eal_init(int argc, char **argv)
{
	int i, fctret, ret;
	pthread_t thread_id;

	/*ִ�д���������int �� int run_once = 0;*/
	static rte_atomic32_t run_once = RTE_ATOMIC32_INIT(0);  /*����������ʼ��Ϊ0*/
	const char *logid;
	
	char cpuset[RTE_CPU_AFFINITY_STR_LEN];          /*cpu��*/
	char thread_name[RTE_MAX_THREAD_NAME_LEN];      /*�߳���*/

	/* checks if the machine is adequate*/
	/*���CPU�ܹ��Ƿ����䣬���ܹ��Ƿ�����dpdk*/
	rte_cpu_check_supported();
	
	/*ֻ��������һ��*/
	if (!rte_atomic32_test_and_set(&run_once))
	{
		return -1;
	}
	
	logid = strrchr(argv[0], '/');
	logid = strdup(logid ? logid + 1: argv[0]);

	/*��ǰ�߳�id*/
	thread_id = pthread_self();

	/*��־ˮƽ����*/
	eal_log_level_parse(argc, argv);

	/* set log level as early as possible*/
	/*������־ˮƽ*/
	rte_set_log_level(internal_config.log_level);

	/*�����߼���, id socketid ��ȡ*/
	if (rte_eal_cpu_init() < 0)
	{
		rte_panic("Cannot detect lcores\n");
	}
	
	/*���������в�����ʼ������*/
	fctret = eal_parse_args(argc, argv);
	if (fctret < 0)
	{
		exit(1);
	}
	
	/*��ʼ����ҳ�����ڴ���Ϣ�����ں����ڴ��ʼ��*/
	if (internal_config.no_hugetlbfs == 0    										/*�����˴�ҳ�ڴ�ģʽ*/
		&& internal_config.process_type != RTE_PROC_SECONDARY 						/*��������Ϊ������*/
		&& internal_config.xen_dom0_support == 0                                    /*app running ģʽ��֧��xen dom0*/
		&& eal_hugepage_info_init() < 0)                                            /*ɨ��ϵͳ��ͬ��������ҳ����Ŀ¼����������¼�����ݽṹ*/
	{
		rte_panic("Cannot get hugepage information\n");
	}
	
	/*��ȡϵͳ������hugepage�ڴ��С�����㷽��*/
	/*δ����ǿ��socket*/
	if (internal_config.memory == 0 && internal_config.force_sockets == 0)
	{
		/*�����˷Ǵ�ҳģʽ�����ڴ�Ϊ64M*/
		if (internal_config.no_hugetlbfs)
		{
			internal_config.memory = MEMSIZE_IF_NO_HUGE_PAGE;
		}
	}

	/*����Ӳ��ӳ��ͼ*/
	if (internal_config.vmware_tsc_map == 1) 
	{
#ifdef RTE_LIBRTE_EAL_VMWARE_TSC_MAP_SUPPORT
		rte_cycles_vmware_tsc_map = 1;
		RTE_LOG (DEBUG, EAL, "Using VMWARE TSC MAP, " "you must have monitor_control.pseudo_perfctr = TRUE\n");
#else
		RTE_LOG (WARNING, EAL, "Ignoring --vmware-tsc-map because " "RTE_LIBRTE_EAL_VMWARE_TSC_MAP_SUPPORT is not set\n");
#endif
	}

	/*dpdk��������ӳ�ʼ��*/
	rte_srand(rte_rdtsc());

	/*�����ļ�ӳ�䵽�ڴ�*/
	rte_config_init();

	/*��ʼ����־��*/
	if (rte_eal_log_init(logid, internal_config.syslog_facility) < 0)
	{
		rte_panic("Cannot init logs\n");
	}

	/*���pci�豸����ȡpci�����Ϣ����������Ӧ��device�ṹ���ӵ�device_list��*/
	/*pci bar�Ĵ�����ַ�ռ�ӳ�䵽�û�̬*/
	/*��ɨ��pci�豸�����豸����pci_device_list*/
	if (rte_eal_pci_init() < 0)
	{
		rte_panic("Cannot init PCI\n");
	}
	
#ifdef VFIO_PRESENT

	/*�����˷�pciģʽ��������pci io����*/
	if (rte_eal_vfio_setup() < 0)
	{
		rte_panic("Cannot init VFIO\n");
	}
	
#endif

	/*ϵͳ��ҳ�ڴ�ӳ�䵽���̵�ַ�ռ䣬��ʼ����memseg�ṹ*/
	if (rte_eal_memory_init() < 0)
	{
		rte_panic("Cannot init memory\n");
	}
	
	/* the directories are locked during eal_hugepage_info_init */

	/*��ҳ����*/
	eal_hugedirs_unlock();

	/*mcfg->memseg[0]������elem���ҵ�socket��Ӧheap�Ķ�Ӧsize������*/
	/*�ڴ������elem������socket��Ӧ��heap����ͬsize�Ĵ�ҳ����heap��ͬ������*/
	if (rte_eal_memzone_init() < 0)
	{
		rte_panic("Cannot init memzone\n");
	}
	
	/*β�����г�ʼ��*/
	if (rte_eal_tailqs_init() < 0)
	{
		rte_panic("Cannot init tail queues for objects\n");
	}
	
	/*��ʱ����ʼ��*/
	if (rte_eal_alarm_init() < 0)
	{
		rte_panic("Cannot init interrupt-handling thread\n");
	}

	/*��ʱ����ʼ��*/
	if (rte_eal_timer_init() < 0)
	{
		rte_panic("Cannot init HPET or TSC timers\n");
	}
	
	/*���socket�ϵ��ڴ��*/
	eal_check_mem_on_local_socket();

	/*�����ʼ��*/
	if (eal_plugins_init() < 0)
	{
		rte_panic("Cannot init plugins\n");
	}
	
	/*�����̳߳�ʼ��*/
	eal_thread_init_master(rte_config.master_lcore);

	/*�߳̽���׺���*/
	ret = eal_thread_dump_affinity(cpuset, RTE_CPU_AFFINITY_STR_LEN);

	RTE_LOG(DEBUG, EAL, "Master lcore %u is ready (tid=%x;cpuset=[%s%s])\n", rte_config.master_lcore, (int)thread_id, cpuset, ret == 0 ? "" : "...");

	/*����������ʼ������������������ʼ������eth_igb_dev_init*/
	if (rte_eal_dev_init() < 0)
	{
		rte_panic("Cannot init pmd devices\n");
	}

	/*��ѯ�жϴ�����*/
	if (rte_eal_intr_init() < 0)
	{
		rte_panic("Cannot init interrupt-handling thread\n");
	}
	
	/*ÿ�߼��˴����߳�*/
	RTE_LCORE_FOREACH_SLAVE(i)
	{
		/*
		 * create communication pipes between master thread
		 * and children
		 */

		/*�����߼���֮�䴴���ܵ�*/
		if (pipe(lcore_config[i].pipe_master2slave) < 0)
		{
			rte_panic("Cannot create pipe\n");
		}
		
		if (pipe(lcore_config[i].pipe_slave2master) < 0)
		{
			rte_panic("Cannot create pipe\n");
		}
		
		lcore_config[i].state = WAIT;

		/* create a thread for each lcore */

		/*ÿ���߼��˴����߳�*/
		ret = pthread_create(&lcore_config[i].thread_id, NULL, eal_thread_loop, NULL);
		if (ret != 0)
		{
			rte_panic("Cannot create thread\n");
		}
		
		/* Set thread_name for aid in debugging. */
		
		/*�����߼����߳�name*/
		snprintf(thread_name, RTE_MAX_THREAD_NAME_LEN, "lcore-slave-%d", i);

		/*���ý���name����id*/
		ret = rte_thread_setname(lcore_config[i].thread_id, thread_name);
		if (ret != 0)
		{
			RTE_LOG(DEBUG, EAL, "Cannot set name for lcore thread\n");
		}
	}

	/*
	 * Launch a dummy function on all slave lcores, so that master lcore
	 * knows they are all ready when this function returns.
	 */


	/*�߼���ע��ص�����*/
	rte_eal_mp_remote_launch(sync_func, NULL, SKIP_MASTER);

	/*�ȴ��߼��˽�������*/
	rte_eal_mp_wait_lcore();

	/* Probe & Initialize PCI devices */
	/*����ʼ��pci�豸*/
	/*��pci��ַ�ռ�ӳ�䵽�û�̬������ӳ���ļ�/dev/uiox/maps
	  �ڵ���pci����probe����
	/* map resources for devices that use igb_uio */

	/*
	  ��pci��Դӳ�䵽uio�û�̬��Ϊ��PCI�豸����map resource�������ɼ�¼�ļ�/dev/uiox/maps
	  ��PCI�豸��PCI����ƥ��󣬵���pci_map_device()����Ϊ��PCI�豸����map resource��
	  ��pci bar�Ĵ����洢��pci�洢�ռ��ַ��ӳ�䵽�ں˵�ַ�ռ䣬�˴���ӳ�䵽�û�̬
	  �ܵ���pci������ʼ������
	*/
	 
	if (rte_eal_pci_probe())
	{
		rte_panic("Cannot probe PCI\n");
	}

	/*�����ս�*/
	rte_eal_mcfg_complete();

	return fctret;
}

/* get core role */
enum rte_lcore_role_t
rte_eal_lcore_role(unsigned lcore_id)
{
	return rte_config.lcore_role[lcore_id];
}

enum rte_proc_type_t
rte_eal_process_type(void)
{
	return rte_config.process_type;
}

/*�Ƿ������˴�ҳ�ڴ�*/
int rte_eal_has_hugepages(void)
{
	return ! internal_config.no_hugetlbfs;
}

/*******************************************************
  ������:		rte_eal_check_module
  ��������: 	ʹ������io
  ��������: 	module_name--����io pciģʽ
  ����ֵ	:
  ����޸���:
  �޸�����:    2017 -11-15
********************************************************/
int
rte_eal_check_module(const char *module_name)
{
	char sysfs_mod_name[PATH_MAX];
	struct stat st;
	int n;

	if (NULL == module_name)
		return -1;

	/* Check if there is sysfs mounted */
	/*���ϵͳ�ļ��Ƿ����*/
	if (stat("/sys/module", &st) != 0)
	{
		RTE_LOG(DEBUG, EAL, "sysfs is not mounted! error %i (%s)\n", errno, strerror(errno));
		return -1;
	}

	/* A module might be built-in, therefore try sysfs */
	/**/
	n = snprintf(sysfs_mod_name, PATH_MAX, "/sys/module/%s", module_name);

	if (n < 0 || n > PATH_MAX) 
	{
		RTE_LOG(DEBUG, EAL, "Could not format module path\n");
		return -1;
	}

	/*�������pci  io �Ƿ���Ч*/
	if (stat(sysfs_mod_name, &st) != 0)
	{
		RTE_LOG(DEBUG, EAL, "Module %s not found! error %i (%s)\n",
		        sysfs_mod_name, errno, strerror(errno));
		return 0;
	}

	/* Module has been found */
	return 1;
}
