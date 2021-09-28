/*
 * Copyright (c) 2014 Nicira, Inc.
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
#include "ovs-numa.h"

#include <ctype.h>
#include <errno.h>
#ifdef __linux__
#include <dirent.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#endif /* __linux__ */

#include "hash.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "ovs-thread.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ovs_numa);

/* ovs-numa module
 * ===============
 *
 * This module stores the affinity information of numa nodes and cpu cores.
 * It also provides functions to bookkeep the pin of threads on cpu cores.
 *
 * It is assumed that the numa node ids and cpu core ids all start from 0 and
 * range continuously.  So, for example, if 'ovs_numa_get_n_cores()' returns N,
 * user can assume core ids from 0 to N-1 are all valid and there is a
 * 'struct cpu_core' for each id.
 *
 * NOTE, this module should only be used by the main thread.
 *
 * NOTE, the assumption above will fail when cpu hotplug is used.  In that
 * case ovs-numa will not function correctly.  For now, add a TODO entry
 * for addressing it in the future.
 *
 * TODO: Fix ovs-numa when cpu hotplug is used.
 */

#define MAX_NUMA_NODES 128

/* numa node. */
struct numa_node {
    struct hmap_node hmap_node;     /* In the 'all_numa_nodes'. */
    struct ovs_list cores;          /* List of cpu cores on the numa node. */	/*����˫��*/
    int numa_id;                    /* numa node id. */							/*numa�ڵ�id*/
};

/* Cpu core on a numa node. */
/*ÿnuma�ڵ�CPU��*/
struct cpu_core {
    struct hmap_node hmap_node;/* In the 'all_cpu_cores'. */					/**/
    struct ovs_list list_node; /* In 'numa_node->cores' list. */				/*����˫��*/
    struct numa_node *numa;    /* numa node containing the core. */				/*numa�ڵ������*/
    unsigned core_id;          /* Core id. */
};

/* Contains all 'struct numa_node's. */
/*�������е�numa�ڵ�*/
static struct hmap all_numa_nodes = HMAP_INITIALIZER(&all_numa_nodes);
/* Contains all 'struct cpu_core's. */
static struct hmap all_cpu_cores = HMAP_INITIALIZER(&all_cpu_cores);
/* True if numa node and core info are correctly extracted. */
static bool found_numa_and_core;
/* True if the module was initialized with dummy options. In this case, the
 * module must not interact with the actual cpus/nodes in the system. */
static bool dummy_numa = false;
/* If 'dummy_numa' is true, contains a copy of the dummy numa configuration
 * parameter */
static char *dummy_config;

static struct numa_node *get_numa_by_numa_id(int numa_id);

#ifdef __linux__
/* Returns true if 'str' contains all digits.  Returns false otherwise. */
static bool
contain_all_digits(const char *str)
{
    return str[strspn(str, "0123456789")] == '\0';
}
#endif /* __linux__ */

static struct numa_node *
insert_new_numa_node(int numa_id)
{
    struct numa_node *n = xzalloc(sizeof *n);

    hmap_insert(&all_numa_nodes, &n->hmap_node, hash_int(numa_id, 0));
    ovs_list_init(&n->cores);
    n->numa_id = numa_id;

    return n;
}

static struct cpu_core *
insert_new_cpu_core(struct numa_node *n, unsigned core_id)
{
    struct cpu_core *c = xzalloc(sizeof *c);

    hmap_insert(&all_cpu_cores, &c->hmap_node, hash_int(core_id, 0));
    ovs_list_insert(&n->cores, &c->list_node);
    c->core_id = core_id;
    c->numa = n;

    return c;
}

/* Has the same effect as discover_numa_and_core(), but instead of
 * reading sysfs entries, extracts the info from the global variable
 * 'dummy_config', which is set with ovs_numa_set_dummy().
 *
 * 'dummy_config' lists the numa_ids of each CPU separated by a comma, e.g.
 * - "0,0,0,0": four cores on numa socket 0.
 * - "0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1": 16 cores on two numa sockets.
 * - "0,0,0,0,1,1,1,1": 8 cores on two numa sockets.
 *
 * The different numa ids must be consecutives or the function will abort. */
static void
discover_numa_and_core_dummy(void)
{
    char *conf = xstrdup(dummy_config);
    char *id, *saveptr = NULL;
    unsigned i = 0;
    long max_numa_id = 0;

    for (id = strtok_r(conf, ",", &saveptr); id;
         id = strtok_r(NULL, ",", &saveptr)) {
        struct hmap_node *hnode;
        struct numa_node *n;
        long numa_id;

        numa_id = strtol(id, NULL, 10);
        if (numa_id < 0 || numa_id >= MAX_NUMA_NODES) {
            VLOG_WARN("Invalid numa node %ld", numa_id);
            continue;
        }

        max_numa_id = MAX(max_numa_id, numa_id);

        hnode = hmap_first_with_hash(&all_numa_nodes, hash_int(numa_id, 0));

        if (hnode) {
            n = CONTAINER_OF(hnode, struct numa_node, hmap_node);
        } else {
            n = insert_new_numa_node(numa_id);
        }

        insert_new_cpu_core(n, i);

        i++;
    }

    free(conf);

    if (max_numa_id + 1 != hmap_count(&all_numa_nodes)) {
        ovs_fatal(0, "dummy numa contains non consecutive numa ids");
    }
}

/* Discovers all numa nodes and the corresponding cpu cores.
 * Constructs the 'struct numa_node' and 'struct cpu_core'. */
static void
discover_numa_and_core(void)
{
#ifdef __linux__
    int i;
    DIR *dir;
    bool numa_supported = true;

    /* Check if NUMA supported on this system. */
    dir = opendir("/sys/devices/system/node");

    if (!dir && errno == ENOENT) {
        numa_supported = false;
    }
    if (dir) {
        closedir(dir);
    }

    for (i = 0; i < MAX_NUMA_NODES; i++) {
        char* path;

        if (numa_supported) {
            /* Constructs the path to node /sys/devices/system/nodeX. */
            path = xasprintf("/sys/devices/system/node/node%d", i);
        } else {
            path = xasprintf("/sys/devices/system/cpu/");
        }

        dir = opendir(path);

        /* Creates 'struct numa_node' if the 'dir' is non-null. */
        if (dir) {
            struct numa_node *n;
            struct dirent *subdir;

            n = insert_new_numa_node(i);

            while ((subdir = readdir(dir)) != NULL) {
                if (!strncmp(subdir->d_name, "cpu", 3)
                    && contain_all_digits(subdir->d_name + 3)) {
                    unsigned core_id;

                    core_id = strtoul(subdir->d_name + 3, NULL, 10);
                    insert_new_cpu_core(n, core_id);
                }
            }
            closedir(dir);
        } else if (errno != ENOENT) {
            VLOG_WARN("opendir(%s) failed (%s)", path,
                      ovs_strerror(errno));
        }

        free(path);
        if (!dir || !numa_supported) {
            break;
        }
    }
#endif /* __linux__ */
}

/*******************************************************************************
 ��������  :    get_core_by_core_id
 ��������  :    ����core_id��all_cpu_cores��ȡ����Ϣ
 �������  :  	core_id---
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
/* Gets 'struct cpu_core' by 'core_id'. */
static struct cpu_core*
get_core_by_core_id(unsigned core_id)
{
	/*ÿnuma�ڵ�CPU��*/
    struct cpu_core *core;

	/*��all_cpu_cores�в�ѯcore_id�Ƿ����*/
    HMAP_FOR_EACH_WITH_HASH (core, hmap_node, hash_int(core_id, 0), &all_cpu_cores) 
    {
        if (core->core_id == core_id) 
		{
            return core;
        }
    }

    return NULL;
}

/* Gets 'struct numa_node' by 'numa_id'. */
static struct numa_node*
get_numa_by_numa_id(int numa_id)
{
    struct numa_node *numa;

    HMAP_FOR_EACH_WITH_HASH (numa, hmap_node, hash_int(numa_id, 0),
                             &all_numa_nodes) {
        if (numa->numa_id == numa_id) {
            return numa;
        }
    }

    return NULL;
}


/* Initializes the numa module. */
void
ovs_numa_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        const struct numa_node *n;

        if (dummy_numa) {
            discover_numa_and_core_dummy();
        } else {
            discover_numa_and_core();
        }

        HMAP_FOR_EACH(n, hmap_node, &all_numa_nodes) {
            VLOG_INFO("Discovered %"PRIuSIZE" CPU cores on NUMA node %d",
                      ovs_list_size(&n->cores), n->numa_id);
        }

        VLOG_INFO("Discovered %"PRIuSIZE" NUMA nodes and %"PRIuSIZE" CPU cores",
                   hmap_count(&all_numa_nodes), hmap_count(&all_cpu_cores));

        if (hmap_count(&all_numa_nodes) && hmap_count(&all_cpu_cores)) {
            found_numa_and_core = true;
        }

        ovsthread_once_done(&once);
    }
}

/* Extracts the numa node and core info from the 'config'.  This is useful for
 * testing purposes.  The function must be called once, before ovs_numa_init().
 *
 * The format of 'config' is explained in the comment above
 * discover_numa_and_core_dummy().*/
void
ovs_numa_set_dummy(const char *config)
{
    dummy_numa = true;
    ovs_assert(config);
    free(dummy_config);
    dummy_config = xstrdup(config);
}

bool
ovs_numa_numa_id_is_valid(int numa_id)
{
    return found_numa_and_core && numa_id < ovs_numa_get_n_numas();
}

bool
ovs_numa_core_id_is_valid(unsigned core_id)
{
    return found_numa_and_core && core_id < ovs_numa_get_n_cores();
}

/* Returns the number of numa nodes. */
int
ovs_numa_get_n_numas(void)
{
    return found_numa_and_core ? hmap_count(&all_numa_nodes)
                               : OVS_NUMA_UNSPEC;
}

/* Returns the number of cpu cores. */
int
ovs_numa_get_n_cores(void)
{
    return found_numa_and_core ? hmap_count(&all_cpu_cores)
                               : OVS_CORE_UNSPEC;
}

/* Given 'core_id', returns the corresponding numa node id.  Returns
 * OVS_NUMA_UNSPEC if 'core_id' is invalid. */
int
ovs_numa_get_numa_id(unsigned core_id)
{
    struct cpu_core *core = get_core_by_core_id(core_id);

    if (core) {
        return core->numa->numa_id;
    }

    return OVS_NUMA_UNSPEC;
}

/* Returns the number of cpu cores on numa node.  Returns OVS_CORE_UNSPEC
 * if 'numa_id' is invalid. */
int
ovs_numa_get_n_cores_on_numa(int numa_id)
{
    struct numa_node *numa = get_numa_by_numa_id(numa_id);

    if (numa) {
        return ovs_list_size(&numa->cores);
    }

    return OVS_CORE_UNSPEC;
}

/*******************************************************************************
 ��������  :    ovs_numa_dump_create
 ��������  :    
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
static struct ovs_numa_dump *ovs_numa_dump_create(void)
{
	/*����һ��numa �ṹ*/
    struct ovs_numa_dump *dump = xmalloc(sizeof *dump);

	/*��ʼ��*/
    hmap_init(&dump->cores);
    hmap_init(&dump->numas);

    return dump;
}

/*******************************************************************************
 ��������  :    ovs_numa_dump_add
 ��������  :    �߼���id����numa�ڵ㣬numa�ڵ���Ϊ��������dump��numa����ͼ
 �������  :  	dump---numa dump�ṹ
 				numa_id---numa id
 				core_id---�߼���id
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
ovs_numa_dump_add(struct ovs_numa_dump *dump, int numa_id, int core_id)
{
	/*numa �߼��� id �ԣ���¼��id��numa id*/
    struct ovs_numa_info_core *c = xzalloc(sizeof *c);

	/*һ��numa�ڵ�*/
    struct ovs_numa_info_numa *n;

	/*CPU����Ϣ����¼��id������numa id*/
    c->numa_id = numa_id;
    c->core_id = core_id;

	/*����Ϣ��������numa�ĺ���Ϣ����hmap����*/
    hmap_insert(&dump->cores, &c->hmap_node, hash_2words(numa_id, core_id));

	/*����dump ��¼��numa�ڵ㣬�ҵ�numa_id numa�ڵ�*/
    HMAP_FOR_EACH_WITH_HASH (n, hmap_node, hash_int(numa_id, 0), &dump->numas)
    {
    	/*�ҵ�numa�ڵ�*/
        if (n->numa_id == numa_id) 
		{
			/*numa�˼���+1*/
            n->n_cores++;
            return;
        }
    }

	/*û�ҵ�numa�ڵ㣬��������*/
    n = xzalloc(sizeof *n);

	
    n->numa_id = numa_id;
    n->n_cores = 1;

	/*numa�ڵ����dump��dump��¼����numa�ڵ�*/
    hmap_insert(&dump->numas, &n->hmap_node, hash_int(numa_id, 0));
}

/* Given the 'numa_id', returns dump of all cores on the numa node. */
struct ovs_numa_dump *
ovs_numa_dump_cores_on_numa(int numa_id)
{
    struct ovs_numa_dump *dump = ovs_numa_dump_create();
    struct numa_node *numa = get_numa_by_numa_id(numa_id);

    if (numa) {
        struct cpu_core *core;

        LIST_FOR_EACH (core, list_node, &numa->cores) {
            ovs_numa_dump_add(dump, numa->numa_id, core->core_id);
        }
    }

    return dump;
}

/*******************************************************************************
 ��������  :    ovs_numa_dump_cores_with_cmask
 ��������  :    ��λ����CPU id��������numa��numa�ڵ���dump
 �������  :  	cmask---numa�����ַ���ָ��
 �������  :	
 �� �� ֵ  : 	dump---���������ȡ��λ��CPU��id
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
struct ovs_numa_dump *
ovs_numa_dump_cores_with_cmask(const char *cmask)
{
	/*��¼numa ��id*/
    struct ovs_numa_dump *dump = ovs_numa_dump_create();
    int core_id = 0;
    int end_idx;

    /* Ignore leading 0x. */
    end_idx = 0;

	/*����*/
    if (!strncmp(cmask, "0x", 2) || !strncmp(cmask, "0X", 2)) {
        end_idx = 2;
    }

	/*��������λ*/
    for (int i = strlen(cmask) - 1; i >= end_idx; i--) {

		/*���������λ���ӵ��ֽڵ����ֽڣ�0x800=1000 0000 0000*/
        char hex = cmask[i];
        int bin;

		/*16����תΪ����F->15*/
        bin = hexit_value(hex);
        if (bin == -1) {
            VLOG_WARN("Invalid cpu mask: %c", cmask[i]);
            bin = 0;
        }

		/*һ���ֽڵ�λ�жϣ�1111�ߵ���*/
        for (int j = 0; j < 4; j++) 
		{
			/*λ�����жϣ���λ����λ*/
            if ((bin >> j) & 0x1) 
			{
				/*����core_id��all_cpu_cores��ȡ����Ϣ*/
                struct cpu_core *core = get_core_by_core_id(core_id);

				/*�˴��ڣ�����Ϣ����dump*/
                if (core) 
				{
					/*������λCPU id��������numa��numa�ڵ���dump*/
                    ovs_numa_dump_add(dump, core->numa->numa_id, core->core_id);
                }
            }

			/*��id������������λ��Ӧ*/
            core_id++;
        }
    }

    return dump;
}

/*******************************************************************************
 ��������  :    ovs_numa_dump_n_cores_per_numa
 ��������  :    ����all_numa_nodes������numa�ڵ㣬numa�ڵ��ϵ�cores_per_numa��CPU��id����dump
 �������  :  	cores_per_numa---ÿ��numa��Ҫ��¼��dump�ĺ���
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
struct ovs_numa_dump *ovs_numa_dump_n_cores_per_numa(int cores_per_numa)
{
	/*����һ��numa dump �ṹ����������numa*/
    struct ovs_numa_dump *dump = ovs_numa_dump_create();
    const struct numa_node *n;

	/*����all_numa_nodes������numa�ڵ㣬ʹ��hmap����*/
    HMAP_FOR_EACH (n, hmap_node, &all_numa_nodes) 
	{
		/*ÿnuma�ڵ�CPU��*/
        const struct cpu_core *core;
        int i = 0;

		/*����numa �� �ĺ���Ϣ������dump��Ϣ numa */
        LIST_FOR_EACH (core, list_node, &n->cores) 
		{
			/*numa�Ϻ˴���cores_per_numa*/
            if (i++ >= cores_per_numa) 
			{
                break;
            }

			/*�߼���id����numa�ڵ㣬numa�ڵ���Ϊ��������dump��numa����ͼ*/
            ovs_numa_dump_add(dump, core->numa->numa_id, core->core_id);
        }
    }

    return dump;
}

/*******************************************************************************
 ��������  :    ovs_numa_dump_contains_core
 ��������  :    ��ѯnuma_id��core_id ��dump �ṹ�Ƿ����
 �������  :  	dump---�����CPU��
 			    numa_id---numa id
 			    core_id---�߼���id
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
bool
ovs_numa_dump_contains_core(const struct ovs_numa_dump *dump, int numa_id, unsigned core_id)
{
	/*numa �߼��� id ��*/
    struct ovs_numa_info_core *core;

	/*numa_id, core_id���ϣ������dump ��numa_id��Ӧnuma ��������ѯ��id�Ƿ����*/
    HMAP_FOR_EACH_WITH_HASH (core, hmap_node, hash_2words(numa_id, core_id),&dump->cores) 
	{
		/*У���߼���id �� numa id�Ƿ����*/
        if (core->core_id == core_id && core->numa_id == numa_id) 
		{
            return true;
        }
    }

    return false;
}

/*******************************************************************************
 ��������  :    ovs_numa_dump_count
 ��������  :    
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
size_t
ovs_numa_dump_count(const struct ovs_numa_dump *dump)
{
	/*hmap��CPU�˽ڵ����*/
    return hmap_count(&dump->cores);
}

/*******************************************************************************
 ��������  :    ovs_numa_dump_destroy
 ��������  :    destroy��dump numa ��� �ṹ
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
void
ovs_numa_dump_destroy(struct ovs_numa_dump *dump)
{
    struct ovs_numa_info_core *c;
    struct ovs_numa_info_numa *n;

    if (!dump) {
        return;
    }

	/*�ͷ�dump�ϵ�core �ڵ�*/
    HMAP_FOR_EACH_POP (c, hmap_node, &dump->cores) 
	{
        free(c);
    }

	/*�ͷ�dump�ϵ�numa�ڵ�*/
    HMAP_FOR_EACH_POP (n, hmap_node, &dump->numas) 
	{
        free(n);
    }

	/*���core�ṹ*/
    hmap_destroy(&dump->cores);

	/*���numa�ṹ*/
	hmap_destroy(&dump->numas);

    free(dump);
}

/*******************************************************************************
 ��������  :    ovs_numa_thread_setaffinity_core
 ��������  :    �߳�numa�׺�������,����pmd�׺͵��߼���id
 �������  :    core_id---�߼���ID
 �������  :	
 �� �� ֵ  : 	��
-----------------------------------------------------------------------------
---
 ���һ���޸ļ�¼ :
 �޸�����	:	
 �޸�Ŀ��	: 	
 �޸�����	:	
*******************************************************************************/
int ovs_numa_thread_setaffinity_core(unsigned core_id OVS_UNUSED)
{
    if (dummy_numa) 
	{
        /* Nothing to do */
        return 0;
    }

#ifdef __linux__
    cpu_set_t cpuset;
    int err;

    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

	/*�߳�ʹ�õ�CPU*/
    err = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    if (err) 
	{
        VLOG_ERR("Thread affinity error %d",err);
        return err;
    }

    return 0;
	
#else /* !__linux__ */
    return EOPNOTSUPP;
#endif /* __linux__ */

}
