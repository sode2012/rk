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
	{ 0x4d5503c4, "module_layout" },
	{ 0x1e6d26a8, "strstr" },
	{ 0x6bac55c2, "filp_close" },
	{ 0x47560594, "filp_open" },
	{ 0x1efe283f, "__cap_full_set" },
	{ 0x6c2e3320, "strncmp" },
	{ 0xd0d8621b, "strlen" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x2e60bace, "memcpy" },
	{ 0x970ae4c3, "init_task" },
	{ 0xb85f3bbe, "pv_lock_ops" },
	{ 0x6443d74d, "_raw_spin_lock" },
	{ 0xb65ceea, "dput" },
	{ 0x9a60d038, "iput" },
	{ 0x50eedeb8, "printk" },
	{ 0x75f40144, "d_alloc" },
	{ 0xa9476fb, "d_lookup" },
	{ 0x28171c5b, "current_task" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "78EE35EC3B89BA8C67FF494");
