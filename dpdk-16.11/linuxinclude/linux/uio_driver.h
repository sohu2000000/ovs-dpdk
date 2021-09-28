/*
 * include/linux/uio_driver.h
 *
 * Copyright(C) 2005, Benedikt Spranger <b.spranger@linutronix.de>
 * Copyright(C) 2005, Thomas Gleixner <tglx@linutronix.de>
 * Copyright(C) 2006, Hans J. Koch <hjk@hansjkoch.de>
 * Copyright(C) 2006, Greg Kroah-Hartman <greg@kroah.com>
 *
 * Userspace IO driver.
 *
 * Licensed under the GPLv2 only.
 */

#ifndef _UIO_DRIVER_H_
#define _UIO_DRIVER_H_

#include <linux/fs.h>
#include <linux/interrupt.h>

struct module;
struct uio_map;

/**
 * struct uio_mem - description of a UIO memory region
 * @name:		name of the memory region for identification
 * @addr:               address of the device's memory rounded to page
 * 			size (phys_addr is used since addr can be
 * 			logical, virtual, or physical & phys_addr_t
 * 			should always be large enough to handle any of
 * 			the address types)
 * @offs:               offset of device memory within the page
 * @size:		size of IO (multiple of page size)
 * @memtype:		type of memory addr points to
 * @internal_addr:	ioremap-ped version of addr, for driver internal use
 * @map:		for use by the UIO core only.
 */
 
/*描述uio内存*/
struct uio_mem {
	const char		*name;                  /*uio 名字，内存映射的名字*/
	phys_addr_t		addr;                   /*物理地址，pci bar寄存器总线地址，内存块的地址*/
	unsigned long		offs;
	resource_size_t		size;               /*内存长度*/
	int			memtype;                    /*内存类型*/
	void __iomem		*internal_addr;     /*物理地址映射到内核虚拟地址*/
	struct uio_map		*map;
};

#define MAX_UIO_MAPS	5

struct uio_portio;

/**
 * struct uio_port - description of a UIO port region
 * @name:		name of the port region for identification
 * @start:		start of port region
 * @size:		size of port region
 * @porttype:		type of port (see UIO_PORT_* below)
 * @portio:		for use by the UIO core only.
 */

/*uio 端口*/
struct uio_port {
	const char		*name;                       /*端口名字*/
	unsigned long		start;                   /*起始位置*/
	unsigned long		size;                    /*size*/
	int			porttype;                        /*类型*/
	struct uio_portio	*portio;                 /*用户态驱动io*/
};

#define MAX_UIO_PORT_REGIONS	5

/*uio设备*/
struct uio_device {
        struct module           *owner;
        struct device           *dev;				//在__uio_register_device中初始化
        int                     minor;				// 次设备id号，uio_get_minor
        atomic_t                event;				//中断事件计数
        struct fasync_struct    *async_queue;		//该设备上的异步等待队列// 
        wait_queue_head_t       wait;				//该设备上的等待队列，在注册设备时(__uio_register_device)初始化
        struct uio_info         *info;				// 指向用户注册的uio_info，在__uio_register_device中被赋值的
        struct kobject          *map_dir;
        struct kobject          *portio_dir;
};

/**
 * struct uio_info - UIO device capabilities
 * @uio_dev:		the UIO device this info belongs to
 * @name:		device name
 * @version:		device driver version
 * @mem:		list of mappable memory regions, size==0 for end of list
 * @port:		list of port regions, size==0 for end of list
 * @irq:		interrupt number or UIO_IRQ_CUSTOM
 * @irq_flags:		flags for request_irq()
 * @priv:		optional private data
 * @handler:		the device's irq handler
 * @mmap:		mmap operation for this uio device
 * @open:		open operation for this uio device
 * @release:		release operation for this uio device
 * @irqcontrol:		disable/enable irqs when 0/1 is written to /dev/uioX
 */
 
 /*uio相关工作*/
struct uio_info {
	struct uio_device	*uio_dev;		                 /*uio设备，在__uio_register_device中初始化*/
	const char		*name;								 /*uio名称*/
	const char		*version;							 /*版本号*/
	struct uio_mem		mem[MAX_UIO_MAPS];               /*可映射的内存区域列表，size==0 列表结束*/
	struct uio_port		port[MAX_UIO_PORT_REGIONS];		//网口区域列表
	long			irq;								//分配给uio设备的中断号，调用__uio_register_device之前必须初始化
	unsigned long		irq_flags;						// 调用__uio_register_device之前必须初始化
	void			*priv;                                          //可选私有数据
	irqreturn_t (*handler)(int irq, struct uio_info *dev_info);		//uio_interrupt中调用，用于中断处理
	int (*mmap)(struct uio_info *info, struct vm_area_struct *vma);	//在uio_mmap中被调用，打开
	int (*open)(struct uio_info *info, struct inode *inode);		//在uio_mmap中被调用，释放
	int (*release)(struct uio_info *info, struct inode *inode);		//在uio_device中被调用，执行设备打开特定操作
	int (*irqcontrol)(struct uio_info *info, s32 irq_on);			//在uio_write方法中被调用，执行用户驱动的中断操作控制，打开关闭 写入/dev/uiox时使用
};

extern int __must_check
	__uio_register_device(struct module *owner,
			      struct device *parent,
			      struct uio_info *info);

/* use a define to avoid include chaining to get THIS_MODULE */
#define uio_register_device(parent, info) \
	__uio_register_device(THIS_MODULE, parent, info)

extern void uio_unregister_device(struct uio_info *info);
extern void uio_event_notify(struct uio_info *info);

/* defines for uio_info->irq */
#define UIO_IRQ_CUSTOM	-1
#define UIO_IRQ_NONE	0

/* defines for uio_mem->memtype */
#define UIO_MEM_NONE	0
#define UIO_MEM_PHYS	1
#define UIO_MEM_LOGICAL	2
#define UIO_MEM_VIRTUAL 3

/* defines for uio_port->porttype */
#define UIO_PORT_NONE	0
#define UIO_PORT_X86	1
#define UIO_PORT_GPIO	2
#define UIO_PORT_OTHER	3

#endif /* _LINUX_UIO_DRIVER_H_ */
