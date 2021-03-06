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
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <rte_log.h>
#include <rte_memory.h>
#include <rte_eal_memconfig.h>

#include "eal_filesystem.h"
#include "eal_vfio.h"
#include "eal_private.h"

#ifdef VFIO_PRESENT

/* per-process VFIO config */
static struct vfio_config vfio_cfg;

static int vfio_type1_dma_map(int);
static int vfio_noiommu_dma_map(int);

/* IOMMU types we support */

/*????io????????????name????????????*/
static const struct vfio_iommu_type iommu_types[] = 
{
	/* x86 IOMMU, otherwise known as type 1 */
	{ RTE_VFIO_TYPE1, "Type 1", &vfio_type1_dma_map},
	/* IOMMU-less mode */
	{ RTE_VFIO_NOIOMMU, "No-IOMMU", &vfio_noiommu_dma_map},
};

/*******************************************************
  ??????:		vfio_get_group_fd
  ????????: 	????????pci io  ?? id
  ????????: 	
  ??????	  :
  ??????????:
  ????????:    2017 -11-15
********************************************************/
int
vfio_get_group_fd(int iommu_group_no)
{
	int i;
	int vfio_group_fd;
	char filename[PATH_MAX];

	/* check if we already have the group descriptor open */
	/*????pci ?? fd*/
	for (i = 0; i < vfio_cfg.vfio_group_idx; i++)
	{
		if (vfio_cfg.vfio_groups[i].group_no == iommu_group_no)
		{
			return vfio_cfg.vfio_groups[i].fd;
		}
	}
	
	/* if primary, try to open the group */
	/*??????*/
	if (internal_config.process_type == RTE_PROC_PRIMARY) 
	{
		/* try regular group format */
		snprintf(filename, sizeof(filename),
				 VFIO_GROUP_FMT, iommu_group_no);

		/*????????io ??????*/
		vfio_group_fd = open(filename, O_RDWR);
		if (vfio_group_fd < 0)
		{
			/* if file not found, it's not an error */
			if (errno != ENOENT) 
			{
				RTE_LOG(ERR, EAL, "Cannot open %s: %s\n", filename,	strerror(errno));
				return -1;
			}

			/* special case: try no-IOMMU path as well */

			/*????io ?? ????*/
			snprintf(filename, sizeof(filename), VFIO_NOIOMMU_GROUP_FMT, iommu_group_no);
			vfio_group_fd = open(filename, O_RDWR);
			if (vfio_group_fd < 0) 
			{
				if (errno != ENOENT)
				{
					RTE_LOG(ERR, EAL, "Cannot open %s: %s\n", filename,	strerror(errno));
					return -1;
				}
				
				return 0;
			}
			
			/* noiommu group found */
		}

		/* if the fd is valid, create a new group for it */
		/*????????io ?? index ??????*/
		if (vfio_cfg.vfio_group_idx == VFIO_MAX_GROUPS) 
		{
			RTE_LOG(ERR, EAL, "Maximum number of VFIO groups reached!\n");
			close(vfio_group_fd);
			return -1;
		}
		
		vfio_cfg.vfio_groups[vfio_cfg.vfio_group_idx].group_no = iommu_group_no;
		vfio_cfg.vfio_groups[vfio_cfg.vfio_group_idx].fd       = vfio_group_fd;

		return vfio_group_fd;
	}
	/* if we're in a secondary process, request group fd from the primary
	 * process via our socket
	 */
	else
	{
		int socket_fd, ret;

		socket_fd = vfio_mp_sync_connect_to_primary();

		if (socket_fd < 0)
		{
			RTE_LOG(ERR, EAL, "  cannot connect to primary process!\n");
			return -1;
		}

		/*??????????*/
		if (vfio_mp_sync_send_request(socket_fd, SOCKET_REQ_GROUP) < 0) 
		{
			RTE_LOG(ERR, EAL, "  cannot request container fd!\n");
			close(socket_fd);
			return -1;
		}

		/*????*/
		if (vfio_mp_sync_send_request(socket_fd, iommu_group_no) < 0) {
			RTE_LOG(ERR, EAL, "  cannot send group number!\n");
			close(socket_fd);
			return -1;
		}

		/*????????*/
		ret = vfio_mp_sync_receive_request(socket_fd);

		switch (ret) 
		{
			case SOCKET_NO_FD:
			{
				close(socket_fd);
				return 0;
			}

			case SOCKET_OK:
			{
				vfio_group_fd = vfio_mp_sync_receive_fd(socket_fd);

				/* if we got the fd, return it */
				if (vfio_group_fd > 0) 
				{
					close(socket_fd);
					return vfio_group_fd;
				}
			}
				/* fall-through on error */
			default:
			{
				RTE_LOG(ERR, EAL, "  cannot get container fd!\n");
				close(socket_fd);
				return -1;
			}
		}
	}
	return -1;
}

static void
clear_current_group(void)
{
	vfio_cfg.vfio_groups[vfio_cfg.vfio_group_idx].group_no = 0;
	vfio_cfg.vfio_groups[vfio_cfg.vfio_group_idx].fd = -1;
}

int vfio_setup_device(const char *sysfs_base, const char *dev_addr,
		int *vfio_dev_fd, struct vfio_device_info *device_info)
{
	struct vfio_group_status group_status = {
			.argsz = sizeof(group_status)
	};
	int vfio_group_fd;
	int iommu_group_no;
	int ret;

	/* get group number */
	ret = vfio_get_group_no(sysfs_base, dev_addr, &iommu_group_no);
	if (ret == 0) {
		RTE_LOG(WARNING, EAL, "  %s not managed by VFIO driver, skipping\n",
			dev_addr);
		return 1;
	}

	/* if negative, something failed */
	if (ret < 0)
		return -1;

	/* get the actual group fd */
	vfio_group_fd = vfio_get_group_fd(iommu_group_no);
	if (vfio_group_fd < 0)
		return -1;

	/* store group fd */
	vfio_cfg.vfio_groups[vfio_cfg.vfio_group_idx].group_no = iommu_group_no;
	vfio_cfg.vfio_groups[vfio_cfg.vfio_group_idx].fd = vfio_group_fd;

	/* if group_fd == 0, that means the device isn't managed by VFIO */
	if (vfio_group_fd == 0) {
		RTE_LOG(WARNING, EAL, "  %s not managed by VFIO driver, skipping\n",
				dev_addr);
		/* we store 0 as group fd to distinguish between existing but
		 * unbound VFIO groups, and groups that don't exist at all.
		 */
		vfio_cfg.vfio_group_idx++;
		return 1;
	}

	/*
	 * at this point, we know that this group is viable (meaning, all devices
	 * are either bound to VFIO or not bound to anything)
	 */

	/* check if the group is viable */
	ret = ioctl(vfio_group_fd, VFIO_GROUP_GET_STATUS, &group_status);
	if (ret) {
		RTE_LOG(ERR, EAL, "  %s cannot get group status, "
				"error %i (%s)\n", dev_addr, errno, strerror(errno));
		close(vfio_group_fd);
		clear_current_group();
		return -1;
	} else if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		RTE_LOG(ERR, EAL, "  %s VFIO group is not viable!\n", dev_addr);
		close(vfio_group_fd);
		clear_current_group();
		return -1;
	}

	/* check if group does not have a container yet */
	if (!(group_status.flags & VFIO_GROUP_FLAGS_CONTAINER_SET)) {

		/* add group to a container */
		ret = ioctl(vfio_group_fd, VFIO_GROUP_SET_CONTAINER,
				&vfio_cfg.vfio_container_fd);
		if (ret) {
			RTE_LOG(ERR, EAL, "  %s cannot add VFIO group to container, "
					"error %i (%s)\n", dev_addr, errno, strerror(errno));
			close(vfio_group_fd);
			clear_current_group();
			return -1;
		}
		/*
		 * at this point we know that this group has been successfully
		 * initialized, so we increment vfio_group_idx to indicate that we can
		 * add new groups.
		 */
		vfio_cfg.vfio_group_idx++;
	}

	/*
	 * pick an IOMMU type and set up DMA mappings for container
	 *
	 * needs to be done only once, only when at least one group is assigned to
	 * a container and only in primary process
	 */
	if (internal_config.process_type == RTE_PROC_PRIMARY &&
			vfio_cfg.vfio_container_has_dma == 0) {
		/* select an IOMMU type which we will be using */
		const struct vfio_iommu_type *t =
				vfio_set_iommu_type(vfio_cfg.vfio_container_fd);
		if (!t) {
			RTE_LOG(ERR, EAL, "  %s failed to select IOMMU type\n", dev_addr);
			return -1;
		}
		ret = t->dma_map_func(vfio_cfg.vfio_container_fd);
		if (ret) {
			RTE_LOG(ERR, EAL, "  %s DMA remapping failed, "
					"error %i (%s)\n", dev_addr, errno, strerror(errno));
			return -1;
		}
		vfio_cfg.vfio_container_has_dma = 1;
	}

	/* get a file descriptor for the device */
	*vfio_dev_fd = ioctl(vfio_group_fd, VFIO_GROUP_GET_DEVICE_FD, dev_addr);
	if (*vfio_dev_fd < 0) {
		/* if we cannot get a device fd, this simply means that this
		* particular port is not bound to VFIO
		*/
		RTE_LOG(WARNING, EAL, "  %s not managed by VFIO driver, skipping\n",
				dev_addr);
		return 1;
	}

	/* test and setup the device */
	ret = ioctl(*vfio_dev_fd, VFIO_DEVICE_GET_INFO, device_info);
	if (ret) {
		RTE_LOG(ERR, EAL, "  %s cannot get device info, "
				"error %i (%s)\n", dev_addr, errno, strerror(errno));
		close(*vfio_dev_fd);
		return -1;
	}

	return 0;
}

/*******************************************************
  ??????:		vfio_enable
  ????????: 	????????io
  ????????: 	modname--????io pci????
  ??????	  :
  ??????????:
  ????????:    2017 -11-15
********************************************************/
int
vfio_enable(const char *modname)
{
	/* initialize group list */
	int i;
	int vfio_available;


	/*????64??????io????????*/
	for (i = 0; i < VFIO_MAX_GROUPS; i++) 
	{
		vfio_cfg.vfio_groups[i].fd = -1;
		vfio_cfg.vfio_groups[i].group_no = -1;
	}

	/* inform the user that we are probing for VFIO */
	RTE_LOG(INFO, EAL, "Probing VFIO support...\n");

	/* check if vfio-pci module is loaded */
	/*????io pci ????????*/
	vfio_available = rte_eal_check_module(modname);

	/* return error directly */
	if (vfio_available == -1) 
	{
		RTE_LOG(INFO, EAL, "Could not get loaded module details!\n");
		return -1;
	}

	/* return 0 if VFIO modules not loaded */
	/*????????io ????????*/
	if (vfio_available == 0) 
	{
		RTE_LOG(DEBUG, EAL, "VFIO modules not loaded, " "skipping VFIO support...\n");

		return 0;
	}

	/*????io ????????????*/
	vfio_cfg.vfio_container_fd = vfio_get_container_fd();

	/* check if we have VFIO driver enabled */
	/*????????io ????????????*/
	if (vfio_cfg.vfio_container_fd != -1)
	{
		RTE_LOG(NOTICE, EAL, "VFIO support initialized\n");
		vfio_cfg.vfio_enabled = 1;
	}
	else
	{
		RTE_LOG(NOTICE, EAL, "VFIO support could not be initialized\n");
	}

	return 0;
}

int
vfio_is_enabled(const char *modname)
{
	const int mod_available = rte_eal_check_module(modname);
	
	return vfio_cfg.vfio_enabled && mod_available;
}

const struct vfio_iommu_type *
vfio_set_iommu_type(int vfio_container_fd)
{
	unsigned idx;
	for (idx = 0; idx < RTE_DIM(iommu_types); idx++) {
		const struct vfio_iommu_type *t = &iommu_types[idx];

		int ret = ioctl(vfio_container_fd, VFIO_SET_IOMMU,
				t->type_id);
		if (!ret) {
			RTE_LOG(NOTICE, EAL, "  using IOMMU type %d (%s)\n",
					t->type_id, t->name);
			return t;
		}
		/* not an error, there may be more supported IOMMU types */
		RTE_LOG(DEBUG, EAL, "  set IOMMU type %d (%s) failed, "
				"error %i (%s)\n", t->type_id, t->name, errno,
				strerror(errno));
	}
	/* if we didn't find a suitable IOMMU type, fail */
	return NULL;
}

/*******************************************************
  ??????:		vfio_has_supported_extensions
  ????????: 	
  ????????:     vfio_container_fd---????io ???? id	
  ??????	:
  ??????????:
  ????????:    2017 -11-15
********************************************************/
int vfio_has_supported_extensions(int vfio_container_fd)
{
	int ret;
	unsigned idx, n_extensions = 0;

	/*????????io????*/
	for (idx = 0; idx < RTE_DIM(iommu_types); idx++) 
	{
		/*????io????*/
		const struct vfio_iommu_type *t = &iommu_types[idx];


		/*????????io??????????????????????????????*/
		ret = ioctl(vfio_container_fd, VFIO_CHECK_EXTENSION, t->type_id);
		if (ret < 0) 
		{
			RTE_LOG(ERR, EAL, "  could not get IOMMU type, " "error %i (%s)\n", errno, strerror(errno));

			close(vfio_container_fd);

			return -1;
		} 
		else if (ret == 1)
		{
			/* we found a supported extension */
			/*????????*/
			n_extensions++;
		}

		RTE_LOG(DEBUG, EAL, "  IOMMU type %d (%s) is %s\n", t->type_id, t->name, ret ? "supported" : "not supported");
	}

	/*if we didn't find any supported IOMMU types fail*/
	/*??????????iommu*/
	if (!n_extensions)
	{
		close(vfio_container_fd);

		return -1;
	}

	return 0;
}

/*******************************************************
  ??????:		vfio_get_container_fd
  ????????: 	????????fd
  ????????: 	
  ??????	  :
  ??????????:
  ????????:    2017 -11-15
********************************************************/
int
vfio_get_container_fd(void)
{
	int ret, vfio_container_fd;

	/* if we're in a primary process, try to open the container */
	/*??????*/
	if (internal_config.process_type == RTE_PROC_PRIMARY)
	{
		/*????????io????*/
		vfio_container_fd = open(VFIO_CONTAINER_PATH, O_RDWR);
		if (vfio_container_fd < 0) 
		{
			RTE_LOG(ERR, EAL, "  cannot open VFIO container, " "error %i (%s)\n", errno, strerror(errno));
			return -1;
		}

		/* check VFIO API version */
		/*????????io??????*/
		ret = ioctl(vfio_container_fd, VFIO_GET_API_VERSION);
		if (ret != VFIO_API_VERSION)
		{
			if (ret < 0)
			{
				RTE_LOG(ERR, EAL, "  could not get VFIO API version, " "error %i (%s)\n", errno, strerror(errno));
			}
			else
			{
				RTE_LOG(ERR, EAL, "  unsupported VFIO API version!\n");
			}
			
			close(vfio_container_fd);
			return -1;
		}

		/*????????*/
		ret = vfio_has_supported_extensions(vfio_container_fd);
		if (ret) 
		{
			RTE_LOG(ERR, EAL, "  no supported IOMMU " "extensions found!\n");
			return -1;
		}

		return vfio_container_fd;
	} 
	else 
	{
		/*
		 * if we're in a secondary process, request container fd from the
		 * primary process via our socket
		 */
		int socket_fd;

		/*??????socket*/
		socket_fd = vfio_mp_sync_connect_to_primary();
		if (socket_fd < 0) 
		{
			RTE_LOG(ERR, EAL, "  cannot connect to primary process!\n");
			return -1;
		}

		/*????vf io ??socket ???? socket ????*/
		if (vfio_mp_sync_send_request(socket_fd, SOCKET_REQ_CONTAINER) < 0) 
		{
			RTE_LOG(ERR, EAL, "  cannot request container fd!\n");
			close(socket_fd);
			return -1;
		}

		/*??????io socket ????????*/
		vfio_container_fd = vfio_mp_sync_receive_fd(socket_fd);

		if (vfio_container_fd < 0) 
		{
			RTE_LOG(ERR, EAL, "  cannot get container fd!\n");
			close(socket_fd);
			return -1;
		}
		
		close(socket_fd);

		return vfio_container_fd;
	}

	return -1;
}

int
vfio_get_group_no(const char *sysfs_base,
		const char *dev_addr, int *iommu_group_no)
{
	char linkname[PATH_MAX];
	char filename[PATH_MAX];
	char *tok[16], *group_tok, *end;
	int ret;

	memset(linkname, 0, sizeof(linkname));
	memset(filename, 0, sizeof(filename));

	/* try to find out IOMMU group for this device */
	snprintf(linkname, sizeof(linkname),
			 "%s/%s/iommu_group", sysfs_base, dev_addr);

	ret = readlink(linkname, filename, sizeof(filename));

	/* if the link doesn't exist, no VFIO for us */
	if (ret < 0)
		return 0;

	ret = rte_strsplit(filename, sizeof(filename),
			tok, RTE_DIM(tok), '/');

	if (ret <= 0) {
		RTE_LOG(ERR, EAL, "  %s cannot get IOMMU group\n", dev_addr);
		return -1;
	}

	/* IOMMU group is always the last token */
	errno = 0;
	group_tok = tok[ret - 1];
	end = group_tok;
	*iommu_group_no = strtol(group_tok, &end, 10);
	if ((end != group_tok && *end != '\0') || errno != 0) {
		RTE_LOG(ERR, EAL, "  %s error parsing IOMMU number!\n", dev_addr);
		return -1;
	}

	return 1;
}

static int
vfio_type1_dma_map(int vfio_container_fd)
{
	const struct rte_memseg *ms = rte_eal_get_physmem_layout();
	int i, ret;

	/* map all DPDK segments for DMA. use 1:1 PA to IOVA mapping */
	for (i = 0; i < RTE_MAX_MEMSEG; i++) {
		struct vfio_iommu_type1_dma_map dma_map;

		if (ms[i].addr == NULL)
			break;

		memset(&dma_map, 0, sizeof(dma_map));
		dma_map.argsz = sizeof(struct vfio_iommu_type1_dma_map);
		dma_map.vaddr = ms[i].addr_64;
		dma_map.size = ms[i].len;
		dma_map.iova = ms[i].phys_addr;
		dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;

		ret = ioctl(vfio_container_fd, VFIO_IOMMU_MAP_DMA, &dma_map);

		if (ret) {
			RTE_LOG(ERR, EAL, "  cannot set up DMA remapping, "
					"error %i (%s)\n", errno, strerror(errno));
			return -1;
		}
	}

	return 0;
}

static int
vfio_noiommu_dma_map(int __rte_unused vfio_container_fd)
{
	/* No-IOMMU mode does not need DMA mapping */
	return 0;
}

#endif
