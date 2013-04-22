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
};

static const struct modversion_info ____versions[]
__attribute_used__
__attribute__((section("__versions"))) = {
	{ 0x89e24b9c, "struct_module" },
	{ 0xf81ba33d, "iput" },
	{ 0x720a91cc, "unlock_new_inode" },
	{ 0xb8af5873, "iget_locked" },
	{ 0x1bcd461f, "_spin_lock" },
	{ 0x1e6d26a8, "strstr" },
	{ 0xeac28d78, "proc_root" },
	{ 0x98e2f2c2, "filp_close" },
	{ 0xa9399fb9, "filp_open" },
	{ 0x10721aa, "init_task" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "F897AE414383AE64FF46136");
