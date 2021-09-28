#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x14522340, "module_layout" },
	{ 0x33f47eeb, "pci_bus_type" },
	{ 0x60b680f, "pci_enable_sriov" },
	{ 0xaabd532e, "pci_intx_mask_supported" },
	{ 0x7cbc1a65, "pci_block_user_cfg_access" },
	{ 0xd2037915, "dev_set_drvdata" },
	{ 0xd691cba2, "malloc_sizes" },
	{ 0xa30682, "pci_disable_device" },
	{ 0xf417ff07, "pci_disable_msix" },
	{ 0x2bd43d13, "dynamic_debug_enabled2" },
	{ 0xd4a0d60, "pci_disable_sriov" },
	{ 0x2af67760, "uio_unregister_device" },
	{ 0x47024ac3, "sysfs_remove_group" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x41344088, "param_get_charp" },
	{ 0xaf559063, "pci_set_master" },
	{ 0x60ea2d6, "kstrtoull" },
	{ 0x33b5fb2c, "pci_unblock_user_cfg_access" },
	{ 0x9f1019bd, "pci_set_dma_mask" },
	{ 0x7b3d21a1, "pci_enable_msix" },
	{ 0xea147363, "printk" },
	{ 0x2d0bad1c, "sysfs_create_group" },
	{ 0xb4390f9a, "mcount" },
	{ 0x42c8de35, "ioremap_nocache" },
	{ 0x86320d11, "pci_intx" },
	{ 0x9cb480f4, "dynamic_debug_enabled" },
	{ 0xf18b1317, "dev_driver_string" },
	{ 0x68f7c535, "pci_unregister_driver" },
	{ 0x2044fa9e, "kmem_cache_alloc_trace" },
	{ 0x6ad065f4, "param_set_charp" },
	{ 0x37a0cba, "kfree" },
	{ 0x27ece834, "pci_num_vf" },
	{ 0xedc03953, "iounmap" },
	{ 0x5f07b9f3, "__pci_register_driver" },
	{ 0xa385c251, "__uio_register_device" },
	{ 0x9edbecae, "snprintf" },
	{ 0xd6740948, "pci_check_and_mask_intx" },
	{ 0xa12add91, "pci_enable_device" },
	{ 0xb02504d8, "pci_set_consistent_dma_mask" },
	{ 0xa92a43c, "dev_get_drvdata" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=uio";


MODULE_INFO(srcversion, "47AE41AD0F20FAA13A85D76");

static const struct rheldata _rheldata __used
__attribute__((section(".rheldata"))) = {
	.rhel_major = 6,
	.rhel_minor = 5,
};
