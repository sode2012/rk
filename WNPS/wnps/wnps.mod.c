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
	{ 0x3ebab4e4, "kobject_put" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xd0d8621b, "strlen" },
	{ 0x77aa43e3, "boot_cpu_data" },
	{ 0x9a5c160b, "sock_release" },
	{ 0x20000329, "simple_strtoul" },
	{ 0x6bac55c2, "filp_close" },
	{ 0x19effc8a, "nf_register_hook" },
	{ 0x3c2c5af5, "sprintf" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x8b18496f, "__copy_to_user_ll" },
	{ 0xc280a525, "__copy_from_user_ll" },
	{ 0x28171c5b, "current_task" },
	{ 0x50eedeb8, "printk" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0xb4390f9a, "mcount" },
	{ 0x1e6d26a8, "strstr" },
	{ 0xc3fa6a59, "memchr" },
	{ 0xd3b5627f, "init_net" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x3cd9c0f6, "pv_cpu_ops" },
	{ 0xbfde8cb5, "nf_unregister_hook" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0x55ae3f7d, "sock_create" },
	{ 0x8235805b, "memmove" },
	{ 0xdbf4b296, "sock_map_fd" },
	{ 0x47560594, "filp_open" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "F052592FCF421BE435793C8");
