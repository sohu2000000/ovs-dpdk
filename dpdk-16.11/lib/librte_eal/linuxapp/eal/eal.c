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

/*进程地址空间内存配置*/
/* early configuration structure, when memory config is not mmapped */
static struct rte_mem_config early_mem_config;                                /*内存配置*/

/* define fd variable here, because file needs to be kept open for the
 * duration of the program, as we hold a write lock on it in the primary proc */
static int mem_cfg_fd = -1;

/*配置文件写锁*/
static struct flock wr_lock = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start = offsetof(struct rte_mem_config, memseg),
		.l_len = sizeof(early_mem_config.memseg),
};

/* Address of global and public configuration */

/*内存的配置信息*/
static struct rte_config rte_config = 
{
		.mem_config = &early_mem_config,     /*早期内存配置结构*/
};

/* internal configuration (per-core) */
/*128个逻辑核配置*/
struct lcore_config_global lcore_config[RTE_MAX_LCORE];

/* internal configuration */
/*全局内存配置*/
struct internal_config_global internal_config;

/* used by rte_rdtsc() */
int rte_cycles_vmware_tsc_map;

/* Return a pointer to the configuration structure */
struct rte_config *
rte_eal_get_configuration(void)
{
	return &rte_config;       /*rte全局配置*/
}

/* parse a sysfs (or other) file containing one integer value */

/*******************************************************
  函数名:		eal_parse_sysfs_value
  功能描述: 	获取CPU核ID
  参数描述: 	filename--CPU文件名
  返回值	  : val--CPU 值
  最后修改人:
  修改日期:    2017 -11-15
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

	/*获取id值*/
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
  函数名:		rte_eal_config_create
  功能描述: 	主进程配置创建，用于共享
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static void
rte_eal_config_create(void)
{
	void *rte_mem_cfg_addr;
	int retval;

	/*获取运行配置文件*/
	/* /var/run/rte_config*/
	/*或/home/var/runt/rte_config目录*/*/
	const char *pathname = eal_runtime_config_path();

	/*配置为非共享模式则返回*/
	if (internal_config.no_shconf)
	{
		return;
	}
	
	/* map the config before hugepage address so that we don't waste a page */
	/*大页基地址映射配置结构*/
	if (internal_config.base_virtaddr != 0)
	{
		/*获取内存配置结构地址*/          /*base_addr*/
		/*-----struct rte_mem_config------|----------------------------------------*/
		rte_mem_cfg_addr = (void *) RTE_ALIGN_FLOOR(internal_config.base_virtaddr - sizeof(struct rte_mem_config), sysconf(_SC_PAGE_SIZE));
	}
	else
	{
		/*首次映射为NULL*/
		rte_mem_cfg_addr = NULL;
	}
	
	/*打开配置文件，不存在则创建/var/run下*/
	/* /var/run/rte_config*/
	/*创建运行配置文件，内存配置文件*/
	if (mem_cfg_fd < 0)
	{
		mem_cfg_fd = open(pathname, O_RDWR | O_CREAT, 0660);
		if (mem_cfg_fd < 0)
		{
			rte_panic("Cannot open '%s' for rte_mem_config\n", pathname);
		}
	}

	/*系统中的配置文件改变为配置结构大小*/
	retval = ftruncate(mem_cfg_fd, sizeof(*rte_config.mem_config));
	if (retval < 0)
	{
		close(mem_cfg_fd);
		rte_panic("Cannot resize '%s' for rte_mem_config\n", pathname);
	}

	/*文件锁*/
	retval = fcntl(mem_cfg_fd, F_SETLK, &wr_lock);
	if (retval < 0)
	{
		close(mem_cfg_fd);
		rte_exit(EXIT_FAILURE, "Cannot create lock on '%s'. Is another primary " "process running?\n", pathname);
	}


	/*内存配置文件映射到大页内存文件地址起始空间*/
	rte_mem_cfg_addr = mmap(rte_mem_cfg_addr, sizeof(*rte_config.mem_config), PROT_READ | PROT_WRITE, MAP_SHARED, mem_cfg_fd, 0);
	if (rte_mem_cfg_addr == MAP_FAILED)
	{
		rte_panic("Cannot mmap memory for rte_config\n");
	}

	/*早期内存配置拷贝到内存*/
	memcpy(rte_mem_cfg_addr, &early_mem_config, sizeof(early_mem_config));

	/*配置文件内存地址*/
	/* /var/run/rte_config，描述内存信息*/
	rte_config.mem_config = (struct rte_mem_config *) rte_mem_cfg_addr;

	/* store address of the config in the config itself so that secondary
	 * processes could later map the config into this exact location */

	/*内存配置文件地址/var/run/rte_config*/
	rte_config.mem_config->mem_cfg_addr = (uintptr_t) rte_mem_cfg_addr;
}

/* attach to an existing shared memory config */

/*******************************************************
  函数名:		rte_eal_config_attach
  功能描述: 	配置文件映射到内存
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static void rte_eal_config_attach(void)
{
	struct rte_mem_config *mem_config;

	/* /var/run/rte_config 配置文件名*/
	const char *pathname = eal_runtime_config_path();

	/*如果开启非共享方式则返回*/
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

	/*运行配置映射到从进程*/
	mem_config = (struct rte_mem_config *) mmap(NULL, sizeof(*mem_config), PROT_READ, MAP_SHARED, mem_cfg_fd, 0);
	
	if (mem_config == MAP_FAILED)
	{
		rte_panic("Cannot mmap memory for rte_config! error %i (%s)\n", errno, strerror(errno));
	}

	/*记录运行配置内存*/
	rte_config.mem_config = mem_config;
}

/* reattach the shared config at exact memory location primary process has it */
/*******************************************************
  函数名:		rte_eal_config_reattach
  功能描述: 	配置文件重新映射，为什么重新映射
  参数描述: 	
  返回值  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static void
rte_eal_config_reattach(void)
{
	struct rte_mem_config *mem_config;
	void *rte_mem_cfg_addr;

	/*内存非共享则返回*/
	if (internal_config.no_shconf)
	{
		return;
	}
	
	/* save the address primary process has mapped shared config to */
	/*获取配置地址/var/run/rte_config*/
	rte_mem_cfg_addr = (void *) (uintptr_t) rte_config.mem_config->mem_cfg_addr;

	/* unmap original config */
	/*清空配置内存映射*/
	munmap(rte_config.mem_config, sizeof(struct rte_mem_config));

	/* remap the config at proper address */
	/*重新映射到合适的地址*/
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
  函数名:		eal_proc_type_detect
  功能描述: 	如果
  参数描述: 	
  返回值	:
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
enum rte_proc_type_t
eal_proc_type_detect(void)
{
	enum rte_proc_type_t ptype = RTE_PROC_PRIMARY;

	/*运行配置文件路径/var/run %s/.%s_config*/
	const char *pathname = eal_runtime_config_path();

	/* if we can open the file but not get a write-lock we are a secondary
	 * process. NOTE: if we get a file handle back, we keep that open
	 * and don't close it to prevent a race condition between multiple opens */

	/*打开运行配置文件路径，获取记录锁*/
	if (((mem_cfg_fd = open(pathname, O_RDWR)) >= 0)
		&& (fcntl(mem_cfg_fd, F_SETLK, &wr_lock) < 0))	/*获取记录锁*/
	{
		ptype = RTE_PROC_SECONDARY;
	}
	
	RTE_LOG(INFO, EAL, "Auto-detected process type: %s\n", ptype == RTE_PROC_PRIMARY ? "PRIMARY" : "SECONDARY");

	return ptype;
}

/* Sets up rte_config structure with the pointer to shared memory config.*/
/*******************************************************
  函数名:		rte_config_init
  功能描述: 	大页内存配置文件映射到内存
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static void rte_config_init(void)
{
	/*获取进程类型，dpdk运行在主进程或从进程*/
	rte_config.process_type = internal_config.process_type;

	switch (rte_config.process_type)
	{
		/*主进程*/
		case RTE_PROC_PRIMARY:
		{
			/*映射到主进程的早期内存配置结构，运行配置文件，描述早期内存配置，/var/run/rte_config*/
			rte_eal_config_create();
			break;
		}
		
		/*从进程*/
		case RTE_PROC_SECONDARY:
		{
			/*配置文件/var/run/rte_config 内存映射到从进程*/
			rte_eal_config_attach();

			/*等待内存映射完成完成*/
			rte_eal_mcfg_wait_complete(rte_config.mem_config);

			/*配置内存重新映射，为什么要重映射*/
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
  函数名:		eal_hugedirs_unlock
  功能描述: 	大页解锁，之前锁住
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static void
eal_hugedirs_unlock(void)
{
	int i;

	/*大页个数*/
	for (i = 0; i < MAX_HUGEPAGE_SIZES; i++)
	{
		/* skip uninitialized */
		/*大页未初始化跳过*/
		if (internal_config.type_hugepage_info[i].lock_descriptor < 0)
		{
			continue;
		}
		
		/* unlock hugepage file */

		/*解锁文件*/
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
	       "  --"OPT_SOCKET_MEM"        Memory to allocate on sockets (comma separated values)\n"   /*socket上内存申请*/
	       "  --"OPT_HUGE_DIR"          Directory where hugetlbfs is mounted\n"                     /*大页挂载目录*/
	       "  --"OPT_FILE_PREFIX"       Prefix for hugepage filenames\n"                            /*大页文件前缀*/
	       "  --"OPT_BASE_VIRTADDR"     Base virtual address\n"                                     /*基虚拟地址*/
	       "  --"OPT_CREATE_UIO_DEV"    Create /dev/uioX (usually done by hotplug)\n"               /*创建虚拟io*/
	       "  --"OPT_VFIO_INTR"         Interrupt mode for VFIO (legacy|msi|msix)\n"                /*虚拟io的模式*/
	       "  --"OPT_XEN_DOM0"          Support running on Xen dom0 without hugetlbfs\n"            /*设置支持在xen上无大页模式运行*/
	       "\n");

	/* Allow the application to print its usage message too if hook is set */
	/*应用试验方法*/
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
  函数名:		eal_parse_socket_mem
  功能描述: 	解析socket 内存参数
  参数描述: 	socket_mem--socke上内存配置字符串
  返回值	:
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static int
eal_parse_socket_mem(char *socket_mem)
{
	char * arg[RTE_MAX_NUMA_NODES];
	char *end;
	int arg_num, i, len;
	uint64_t total_mem = 0;

	/*校验 socket_mem 是否超出 8*10*/
	len = strnlen(socket_mem, SOCKET_MEM_STRLEN);
	if (len == SOCKET_MEM_STRLEN) 
	{
		RTE_LOG(ERR, EAL, "--socket-mem is too long\n");
		return -1;
	}

	/* all other error cases will be caught later */
	/*内存最后是数字*/
	if (!isdigit(socket_mem[len-1]))
	{
		return -1;
	}
	
	/* split the optarg into separate socket values */
	/*分割出mem参数个数*/
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

	/*遍历要处理的socket mem*/
	for (i = 0; i < arg_num; i++) 
	{
		end = NULL;

		/*转换成数据*/
		internal_config.socket_mem[i] = strtoull(arg[i], &end, 10);

		/* check for invalid input */
		/*检查非法输入*/
		if ((errno != 0)  || (arg[i][0] == '\0') || (end == NULL) || (*end != '\0'))
		{
			return -1;
		}

		/*socket内存计算*/
		internal_config.socket_mem[i] *= 1024ULL;
		internal_config.socket_mem[i] *= 1024ULL;

		/*socket总内存计算*/
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
  函数名:		eal_parse_base_virtaddr
  功能描述: 	解析虚拟地址
  参数描述: 	
  返回值	:
  最后修改人:
  修改日期:    2017 -11-15
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

	/*基虚拟地址*/
	internal_config.base_virtaddr = RTE_PTR_ALIGN_CEIL((uintptr_t)addr, (size_t)RTE_PGSIZE_16M);

	return 0;
}

/*******************************************************
  函数名:		eal_parse_vfio_intr
  功能描述: 	虚拟io中断参数
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static int
eal_parse_vfio_intr(const char *mode)
{
	unsigned i;

	/*io模式*/
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

	/*遍历模式个数，虚拟io模式的值*/
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
  函数名:		eal_log_level_parse
  功能描述: 	日志水平解析
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
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

	/*初始化internal_config配置*/
	eal_reset_internal_config(&internal_config);

	/*获取参数*/
	while ((opt = getopt_long(argc, argvopt, eal_short_options, eal_long_options, &option_index)) != EOF)
	{
		int ret;

		/* getopt is not happy, stop right now */
		if (opt == '?')
		{
			break;
		}
		
		/*解析eal的参数命令行，日志水平参数解析*/
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
  函数名:		eal_parse_args
  功能描述: 	解析参数
  参数描述: 	argc---参数个数7
  				argv---参数
  返回值	:
  最后修改人:
  修改日期:    2017 -11-15
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

	/*参数选项解析*/
	while ((opt = getopt_long(argc, argvopt, eal_short_options, eal_long_options, &option_index)) != EOF) 
	{
		/* getopt is not happy, stop right now*/
		/*参数解析*/
		if (opt == '?')
		{
			eal_usage(prgname);
			ret = -1;
			goto out;
		}

		/*dpdk参数解析与下发*/
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
			/*支持xen dom0*/
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
			
			/*大页路径*/
			case OPT_HUGE_DIR_NUM:
			{
				internal_config.hugepage_dir = optarg;
				break;
			}
			/*文件前缀*/
			case OPT_FILE_PREFIX_NUM:
			{
				internal_config.hugefile_prefix = optarg;
				break;
			}
			
			/*socket mem 参数个socket mem 获取内存大小赋值给Internal结构*/
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
			
			/*基虚拟地址*/
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
			
			/*虚拟io个数*/
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
			
			/*设备个数*/
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

	/*配置调整*/
	if (eal_adjust_config(&internal_config) != 0) 
	{
		ret = -1;
		goto out;
	}

	/* sanity checks */
	/*合法性检查*/
	if (eal_check_common_options(&internal_config) != 0) 
	{
		eal_usage(prgname);
		ret = -1;
		goto out;
	}

	/* --xen-dom0 doesn't make sense with --socket-mem */
	/*如果开了xen-dom0模式却没有socket*/
	if (internal_config.xen_dom0_support && internal_config.force_sockets == 1) 
	{
		RTE_LOG(ERR, EAL, "Options --"OPT_SOCKET_MEM" cannot be specified " "together with --"OPT_XEN_DOM0"\n");
		eal_usage(prgname);
		ret = -1;
		goto out;
	}

	/*记录程序名，这里为./dpdk_server*/
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
  函数名:		eal_check_mem_on_local_socket
  功能描述: 	检查在本地socket上的内存，存在内存
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static void
eal_check_mem_on_local_socket(void)
{
	const struct rte_memseg *ms;
	int i, socket_id;

	/*socket id*/
	/*获取主核的socket id*/
	socket_id = rte_lcore_to_socket_id(rte_config.master_lcore);

	/*获取内存段*/
	ms = rte_eal_get_physmem_layout();

	/*本socket内存段合法性检查*/
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
	/*主进程*/
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
  函数名:		rte_eal_vfio_setup
  功能描述: 	
  参数描述: 	
  返回值	  :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
static int rte_eal_vfio_setup(void)
{
	int vfio_enabled = 0;

	/*没有pci设备*/
	if (!internal_config.no_pci)
	{
		/*使能虚拟io*/
		pci_vfio_enable();

		/*检查io是否使能*/
		vfio_enabled |= pci_vfio_is_enabled();
	}

	/*虚拟io使能*/
	if (vfio_enabled) 
	{
		/* if we are primary process, create a thread to communicate with
		 * secondary processes. the thread will use a socket to wait for
		 * requests from secondary process to send open file descriptors,
		 * because VFIO does not allow multiple open descriptors on a group or
		 * VFIO container.
		 */

		/*进程为主进程，虚拟io同步设置*/
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
  函数名:		rte_eal_init
  功能描述: 	运行换环境初始化入口
  参数描述: 	
  返回值    :
  最后修改人:
  修改日期:    2017 -11-15
********************************************************/
int rte_eal_init(int argc, char **argv)
{
	int i, fctret, ret;
	pthread_t thread_id;

	/*执行次数计数，int 型 int run_once = 0;*/
	static rte_atomic32_t run_once = RTE_ATOMIC32_INIT(0);  /*计数变量初始化为0*/
	const char *logid;
	
	char cpuset[RTE_CPU_AFFINITY_STR_LEN];          /*cpu集*/
	char thread_name[RTE_MAX_THREAD_NAME_LEN];      /*线程名*/

	/* checks if the machine is adequate*/
	/*检查CPU架构是否适配，即架构是否适配dpdk*/
	rte_cpu_check_supported();
	
	/*只运行运行一次*/
	if (!rte_atomic32_test_and_set(&run_once))
	{
		return -1;
	}
	
	logid = strrchr(argv[0], '/');
	logid = strdup(logid ? logid + 1: argv[0]);

	/*当前线程id*/
	thread_id = pthread_self();

	/*日志水平解析*/
	eal_log_level_parse(argc, argv);

	/* set log level as early as possible*/
	/*设置日志水平*/
	rte_set_log_level(internal_config.log_level);

	/*可用逻辑核, id socketid 获取*/
	if (rte_eal_cpu_init() < 0)
	{
		rte_panic("Cannot detect lcores\n");
	}
	
	/*根据命令行参数初始化配置*/
	fctret = eal_parse_args(argc, argv);
	if (fctret < 0)
	{
		exit(1);
	}
	
	/*初始化大页种类内存信息，用于后续内存初始化*/
	if (internal_config.no_hugetlbfs == 0    										/*设置了大页内存模式*/
		&& internal_config.process_type != RTE_PROC_SECONDARY 						/*进程类型为主进程*/
		&& internal_config.xen_dom0_support == 0                                    /*app running 模式不支持xen dom0*/
		&& eal_hugepage_info_init() < 0)                                            /*扫描系统不同规格种类大页挂载目录及个数，记录到数据结构*/
	{
		rte_panic("Cannot get hugepage information\n");
	}
	
	/*获取系统中所有hugepage内存大小，计算方法*/
	/*未设置强制socket*/
	if (internal_config.memory == 0 && internal_config.force_sockets == 0)
	{
		/*设置了非大页模式，则内存为64M*/
		if (internal_config.no_hugetlbfs)
		{
			internal_config.memory = MEMSIZE_IF_NO_HUGE_PAGE;
		}
	}

	/*虚拟硬件映射图*/
	if (internal_config.vmware_tsc_map == 1) 
	{
#ifdef RTE_LIBRTE_EAL_VMWARE_TSC_MAP_SUPPORT
		rte_cycles_vmware_tsc_map = 1;
		RTE_LOG (DEBUG, EAL, "Using VMWARE TSC MAP, " "you must have monitor_control.pseudo_perfctr = TRUE\n");
#else
		RTE_LOG (WARNING, EAL, "Ignoring --vmware-tsc-map because " "RTE_LIBRTE_EAL_VMWARE_TSC_MAP_SUPPORT is not set\n");
#endif
	}

	/*dpdk随机数种子初始化*/
	rte_srand(rte_rdtsc());

	/*配置文件映射到内存*/
	rte_config_init();

	/*初始化日志流*/
	if (rte_eal_log_init(logid, internal_config.syslog_facility) < 0)
	{
		rte_panic("Cannot init logs\n");
	}

	/*检测pci设备，获取pci相关信息，并创建对应的device结构链接到device_list中*/
	/*pci bar寄存器地址空间映射到用户态*/
	/*①扫描pci设备，挂设备链，pci_device_list*/
	if (rte_eal_pci_init() < 0)
	{
		rte_panic("Cannot init PCI\n");
	}
	
#ifdef VFIO_PRESENT

	/*设置了非pci模式，则虚拟pci io设置*/
	if (rte_eal_vfio_setup() < 0)
	{
		rte_panic("Cannot init VFIO\n");
	}
	
#endif

	/*系统大页内存映射到进程地址空间，初始化成memseg结构*/
	if (rte_eal_memory_init() < 0)
	{
		rte_panic("Cannot init memory\n");
	}
	
	/* the directories are locked during eal_hugepage_info_init */

	/*大页解锁*/
	eal_hugedirs_unlock();

	/*mcfg->memseg[0]，做成elem，挂到socket对应heap的对应size空闲链*/
	/*内存段做成elem挂链到socket对应的heap，不同size的大页挂入heap不同的链表*/
	if (rte_eal_memzone_init() < 0)
	{
		rte_panic("Cannot init memzone\n");
	}
	
	/*尾部队列初始化*/
	if (rte_eal_tailqs_init() < 0)
	{
		rte_panic("Cannot init tail queues for objects\n");
	}
	
	/*定时器初始化*/
	if (rte_eal_alarm_init() < 0)
	{
		rte_panic("Cannot init interrupt-handling thread\n");
	}

	/*定时器初始化*/
	if (rte_eal_timer_init() < 0)
	{
		rte_panic("Cannot init HPET or TSC timers\n");
	}
	
	/*检查socket上的内存段*/
	eal_check_mem_on_local_socket();

	/*插件初始化*/
	if (eal_plugins_init() < 0)
	{
		rte_panic("Cannot init plugins\n");
	}
	
	/*主核线程初始化*/
	eal_thread_init_master(rte_config.master_lcore);

	/*线程解除亲和性*/
	ret = eal_thread_dump_affinity(cpuset, RTE_CPU_AFFINITY_STR_LEN);

	RTE_LOG(DEBUG, EAL, "Master lcore %u is ready (tid=%x;cpuset=[%s%s])\n", rte_config.master_lcore, (int)thread_id, cpuset, ret == 0 ? "" : "...");

	/*网卡驱动初始化，调用网卡驱动初始化函数eth_igb_dev_init*/
	if (rte_eal_dev_init() < 0)
	{
		rte_panic("Cannot init pmd devices\n");
	}

	/*轮询中断处理函数*/
	if (rte_eal_intr_init() < 0)
	{
		rte_panic("Cannot init interrupt-handling thread\n");
	}
	
	/*每逻辑核创建线程*/
	RTE_LCORE_FOREACH_SLAVE(i)
	{
		/*
		 * create communication pipes between master thread
		 * and children
		 */

		/*主次逻辑核之间创建管道*/
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

		/*每个逻辑核创建线程*/
		ret = pthread_create(&lcore_config[i].thread_id, NULL, eal_thread_loop, NULL);
		if (ret != 0)
		{
			rte_panic("Cannot create thread\n");
		}
		
		/* Set thread_name for aid in debugging. */
		
		/*设置逻辑核线程name*/
		snprintf(thread_name, RTE_MAX_THREAD_NAME_LEN, "lcore-slave-%d", i);

		/*设置进程name进程id*/
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


	/*逻辑核注册回调函数*/
	rte_eal_mp_remote_launch(sync_func, NULL, SKIP_MASTER);

	/*等待逻辑核结束工作*/
	rte_eal_mp_wait_lcore();

	/* Probe & Initialize PCI devices */
	/*检测初始化pci设备*/
	/*①pci地址空间映射到用户态，生成映射文件/dev/uiox/maps
	  ②调用pci驱动probe函数
	/* map resources for devices that use igb_uio */

	/*
	  ①pci资源映射到uio用户态，为该PCI设备创建map resource，并生成记录文件/dev/uiox/maps
	  ②PCI设备和PCI驱动匹配后，调用pci_map_device()函数为该PCI设备创建map resource，
	  ③pci bar寄存器存储的pci存储空间地址已映射到内核地址空间，此次是映射到用户态
	  ④调用pci驱动初始化函数
	*/
	 
	if (rte_eal_pci_probe())
	{
		rte_panic("Cannot probe PCI\n");
	}

	/*配置终结*/
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

/*是否设置了大页内存*/
int rte_eal_has_hugepages(void)
{
	return ! internal_config.no_hugetlbfs;
}

/*******************************************************
  函数名:		rte_eal_check_module
  功能描述: 	使能虚拟io
  参数描述: 	module_name--虚拟io pci模式
  返回值	:
  最后修改人:
  修改日期:    2017 -11-15
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
	/*检查系统文件是否挂载*/
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

	/*检查虚拟pci  io 是否生效*/
	if (stat(sysfs_mod_name, &st) != 0)
	{
		RTE_LOG(DEBUG, EAL, "Module %s not found! error %i (%s)\n",
		        sysfs_mod_name, errno, strerror(errno));
		return 0;
	}

	/* Module has been found */
	return 1;
}
