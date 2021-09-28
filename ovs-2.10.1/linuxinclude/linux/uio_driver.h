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
 
/*����uio�ڴ�*/
struct uio_mem {
	const char		*name;                  /*uio ���֣��ڴ�ӳ�������*/
	phys_addr_t		addr;                   /*�����ַ��pci bar�Ĵ������ߵ�ַ���ڴ��ĵ�ַ*/
	unsigned long		offs;
	resource_size_t		size;               /*�ڴ泤��*/
	int			memtype;                    /*�ڴ�����*/
	void __iomem		*internal_addr;     /*�����ַӳ�䵽�ں������ַ*/
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

/*uio �˿�*/
struct uio_port {
	const char		*name;                       /*�˿�����*/
	unsigned long		start;                   /*��ʼλ��*/
	unsigned long		size;                    /*size*/
	int			porttype;                        /*����*/
	struct uio_portio	*portio;                 /*�û�̬����io*/
};

#define MAX_UIO_PORT_REGIONS	5

/*uio�豸*/
struct uio_device {
        struct module           *owner;
        struct device           *dev;				//��__uio_register_device�г�ʼ��
        int                     minor;				// ���豸id�ţ�uio_get_minor
        atomic_t                event;				//�ж��¼�����
        struct fasync_struct    *async_queue;		//���豸�ϵ��첽�ȴ�����// 
        wait_queue_head_t       wait;				//���豸�ϵĵȴ����У���ע���豸ʱ(__uio_register_device)��ʼ��
        struct uio_info         *info;				// ָ���û�ע���uio_info����__uio_register_device�б���ֵ��
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
 
 /*uio��ع���*/
struct uio_info {
	struct uio_device	*uio_dev;		                 /*uio�豸����__uio_register_device�г�ʼ��*/
	const char		*name;								 /*uio����*/
	const char		*version;							 /*�汾��*/
	struct uio_mem		mem[MAX_UIO_MAPS];               /*��ӳ����ڴ������б�size==0 �б����*/
	struct uio_port		port[MAX_UIO_PORT_REGIONS];		//���������б�
	long			irq;								//�����uio�豸���жϺţ�����__uio_register_device֮ǰ�����ʼ��
	unsigned long		irq_flags;						// ����__uio_register_device֮ǰ�����ʼ��
	void			*priv;                                          //��ѡ˽������
	irqreturn_t (*handler)(int irq, struct uio_info *dev_info);		//uio_interrupt�е��ã������жϴ���
	int (*mmap)(struct uio_info *info, struct vm_area_struct *vma);	//��uio_mmap�б����ã���
	int (*open)(struct uio_info *info, struct inode *inode);		//��uio_mmap�б����ã��ͷ�
	int (*release)(struct uio_info *info, struct inode *inode);		//��uio_device�б����ã�ִ���豸���ض�����
	int (*irqcontrol)(struct uio_info *info, s32 irq_on);			//��uio_write�����б����ã�ִ���û��������жϲ������ƣ��򿪹ر� д��/dev/uioxʱʹ��
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
