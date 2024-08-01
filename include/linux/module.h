#ifndef _LINUX_MODULE_H
#define _LINUX_MODULE_H
/*
 * Dynamic loading of modules into the kernel.
 *
 * Rewritten by Richard Henderson <rth@tamu.edu> Dec 1996
 * Rewritten again by Rusty Russell, 2002
 */
#include <linux/list.h>
#include <linux/stat.h>
#include <linux/compiler.h>
#include <linux/cache.h>
#include <linux/kmod.h>
#include <linux/elf.h>
#include <linux/stringify.h>
#include <linux/kobject.h>
#include <linux/moduleparam.h>
#include <linux/tracepoint.h>

#include <linux/percpu.h>
#include <asm/module.h>

#include <trace/events/module.h>

/* Not Yet Implemented */
#define MODULE_SUPPORTED_DEVICE(name)

/* Some toolchains use a `_' prefix for all user symbols. */
#ifdef CONFIG_SYMBOL_PREFIX
#define MODULE_SYMBOL_PREFIX CONFIG_SYMBOL_PREFIX
#else
#define MODULE_SYMBOL_PREFIX ""
#endif

#define MODULE_NAME_LEN MAX_PARAM_PREFIX_LEN

struct kernel_symbol
{
	unsigned long value;
	const char *name;
};

struct modversion_info
{
	unsigned long crc;
	char name[MODULE_NAME_LEN];
};

struct module;

struct module_attribute {
        struct attribute attr;
        ssize_t (*show)(struct module_attribute *, struct module *, char *);
        ssize_t (*store)(struct module_attribute *, struct module *,
			 const char *, size_t count);
	void (*setup)(struct module *, const char *);
	int (*test)(struct module *);
	void (*free)(struct module *);
};

struct module_kobject
{
	struct kobject kobj;               /* 基本的 kobject 结构体，用于在 sysfs 中管理模块。kobject 是内核对象模型的一部分，用于支持对象和属性的管理。 */
	struct module *mod;               /* 指向关联模块的指针，用于跟踪哪个模块拥有此 kobject。 */
	struct kobject *drivers_dir;      /* 指向驱动程序目录的 kobject 指针，该目录用于组织和管理与模块相关的驱动程序信息。 */
	struct module_param_attrs *mp;    /* 指向模块参数属性的指针，这些属性定义了模块参数的行为和属性。 */
};

/* These are either module local, or the kernel's dummy ones. */
extern int init_module(void);
extern void cleanup_module(void);

/* Archs provide a method of finding the correct exception table. */
struct exception_table_entry;

const struct exception_table_entry *
search_extable(const struct exception_table_entry *first,
	       const struct exception_table_entry *last,
	       unsigned long value);
void sort_extable(struct exception_table_entry *start,
		  struct exception_table_entry *finish);
void sort_main_extable(void);
void trim_init_extable(struct module *m);

#ifdef MODULE
#define MODULE_GENERIC_TABLE(gtype,name)			\
extern const struct gtype##_id __mod_##gtype##_table		\
  __attribute__ ((unused, alias(__stringify(name))))

extern struct module __this_module;
#define THIS_MODULE (&__this_module)
#else  /* !MODULE */
#define MODULE_GENERIC_TABLE(gtype,name)
#define THIS_MODULE ((struct module *)0)
#endif

/* Generic info of form tag = "info" */
#define MODULE_INFO(tag, info) __MODULE_INFO(tag, tag, info)

/* For userspace: you can also call me... */
#define MODULE_ALIAS(_alias) MODULE_INFO(alias, _alias)

/*
 * The following license idents are currently accepted as indicating free
 * software modules
 *
 *	"GPL"				[GNU Public License v2 or later]
 *	"GPL v2"			[GNU Public License v2]
 *	"GPL and additional rights"	[GNU Public License v2 rights and more]
 *	"Dual BSD/GPL"			[GNU Public License v2
 *					 or BSD license choice]
 *	"Dual MIT/GPL"			[GNU Public License v2
 *					 or MIT license choice]
 *	"Dual MPL/GPL"			[GNU Public License v2
 *					 or Mozilla license choice]
 *
 * The following other idents are available
 *
 *	"Proprietary"			[Non free products]
 *
 * There are dual licensed components, but when running with Linux it is the
 * GPL that is relevant so this is a non issue. Similarly LGPL linked with GPL
 * is a GPL combined work.
 *
 * This exists for several reasons
 * 1.	So modinfo can show license info for users wanting to vet their setup 
 *	is free
 * 2.	So the community can ignore bug reports including proprietary modules
 * 3.	So vendors can do likewise based on their own policies
 */
#define MODULE_LICENSE(_license) MODULE_INFO(license, _license)

/*
 * Author(s), use "Name <email>" or just "Name", for multiple
 * authors use multiple MODULE_AUTHOR() statements/lines.
 */
#define MODULE_AUTHOR(_author) MODULE_INFO(author, _author)
  
/* What your module does. */
#define MODULE_DESCRIPTION(_description) MODULE_INFO(description, _description)

/* One for each parameter, describing how to use it.  Some files do
   multiple of these per line, so can't just use MODULE_INFO. */
#define MODULE_PARM_DESC(_parm, desc) \
	__MODULE_INFO(parm, _parm, #_parm ":" desc)

#define MODULE_DEVICE_TABLE(type,name)		\
  MODULE_GENERIC_TABLE(type##_device,name)

/* Version of form [<epoch>:]<version>[-<extra-version>].
   Or for CVS/RCS ID version, everything but the number is stripped.
  <epoch>: A (small) unsigned integer which allows you to start versions
           anew. If not mentioned, it's zero.  eg. "2:1.0" is after
	   "1:2.0".
  <version>: The <version> may contain only alphanumerics and the
           character `.'.  Ordered by numeric sort for numeric parts,
	   ascii sort for ascii parts (as per RPM or DEB algorithm).
  <extraversion>: Like <version>, but inserted for local
           customizations, eg "rh3" or "rusty1".

  Using this automatically adds a checksum of the .c files and the
  local headers in "srcversion".
*/
#define MODULE_VERSION(_version) MODULE_INFO(version, _version)

/* Optional firmware file (or files) needed by the module
 * format is simply firmware file name.  Multiple firmware
 * files require multiple MODULE_FIRMWARE() specifiers */
#define MODULE_FIRMWARE(_firmware) MODULE_INFO(firmware, _firmware)

/* Given an address, look for it in the exception tables */
const struct exception_table_entry *search_exception_tables(unsigned long add);

struct notifier_block;
#ifdef CONFIG_MODULES

extern int modules_disabled; /* for sysctl */
/* Get/put a kernel symbol (calls must be symmetric) */
void *__symbol_get(const char *symbol);
void *__symbol_get_gpl(const char *symbol);
#define symbol_get(x) ((typeof(&x))(__symbol_get(MODULE_SYMBOL_PREFIX #x)))

#ifndef __GENKSYMS__
#ifdef CONFIG_MODVERSIONS
/* Mark the CRC weak since genksyms apparently decides not to
 * generate a checksums for some symbols */
#define __CRC_SYMBOL(sym, sec)					\
	extern void *__crc_##sym __attribute__((weak));		\
	static const unsigned long __kcrctab_##sym		\
	__used							\
	__attribute__((section("__kcrctab" sec), unused))	\
	= (unsigned long) &__crc_##sym;
#else
#define __CRC_SYMBOL(sym, sec)
#endif

/* For every exported symbol, place a struct in the __ksymtab section */
#define __EXPORT_SYMBOL(sym, sec)				\
	extern typeof(sym) sym;					\
	__CRC_SYMBOL(sym, sec)					\
	static const char __kstrtab_##sym[]			\
	__attribute__((section("__ksymtab_strings"), aligned(1))) \
	= MODULE_SYMBOL_PREFIX #sym;                    	\
	static const struct kernel_symbol __ksymtab_##sym	\
	__used							\
	__attribute__((section("__ksymtab" sec), unused))	\
	= { (unsigned long)&sym, __kstrtab_##sym }

#define EXPORT_SYMBOL(sym)					\
	__EXPORT_SYMBOL(sym, "")

#define EXPORT_SYMBOL_GPL(sym)					\
	__EXPORT_SYMBOL(sym, "_gpl")

#define EXPORT_SYMBOL_GPL_FUTURE(sym)				\
	__EXPORT_SYMBOL(sym, "_gpl_future")


#ifdef CONFIG_UNUSED_SYMBOLS
#define EXPORT_UNUSED_SYMBOL(sym) __EXPORT_SYMBOL(sym, "_unused")
#define EXPORT_UNUSED_SYMBOL_GPL(sym) __EXPORT_SYMBOL(sym, "_unused_gpl")
#else
#define EXPORT_UNUSED_SYMBOL(sym)
#define EXPORT_UNUSED_SYMBOL_GPL(sym)
#endif

#endif

enum module_state
{
	MODULE_STATE_LIVE,
	MODULE_STATE_COMING,
	MODULE_STATE_GOING,
};

struct module
{
	enum module_state state;                      /* 模块的状态（加载中、已加载、卸载中等） */

	/* 模块列表中的成员 */
	struct list_head list;                        /* 用于将模块连接到内核模块链表的列表头 */

	/* 模块的唯一标识符 */
	char name[MODULE_NAME_LEN];                    /* 模块的名称，长度由 MODULE_NAME_LEN 定义 */

	/* Sysfs 相关内容 */
	struct module_kobject mkobj;                   /* 模块的 sysfs kobject，用于在 sysfs 中管理模块 */
	struct module_attribute *modinfo_attrs;        /* 模块信息属性，用于向 sysfs 中添加模块属性 */
	const char *version;                          /* 模块的版本信息 */
	const char *srcversion;                       /* 模块的源代码版本信息 */
	struct kobject *holders_dir;                  /* 指向该模块持有者的 sysfs 目录 */

	/* 导出的符号 */
	const struct kernel_symbol *syms;             /* 导出的内核符号表 */
	const unsigned long *crcs;                    /* 导出符号的 CRC 校验和 */
	unsigned int num_syms;                        /* 导出的符号数量 */

	/* 内核参数 */
	struct kernel_param *kp;                      /* 模块的内核参数 */
	unsigned int num_kp;                          /* 内核参数的数量 */

	/* 仅 GPL 的导出符号 */
	unsigned int num_gpl_syms;                    /* 仅 GPL 导出的符号数量 */
	const struct kernel_symbol *gpl_syms;         /* 仅 GPL 导出的符号表 */
	const unsigned long *gpl_crcs;                /* 仅 GPL 导出符号的 CRC 校验和 */

#ifdef CONFIG_UNUSED_SYMBOLS
	/* 未使用的导出符号 */
	const struct kernel_symbol *unused_syms;      /* 未使用的导出符号表 */
	const unsigned long *unused_crcs;             /* 未使用符号的 CRC 校验和 */
	unsigned int num_unused_syms;                 /* 未使用符号的数量 */

	/* 仅 GPL 的未使用导出符号 */
	unsigned int num_unused_gpl_syms;            /* 仅 GPL 未使用符号的数量 */
	const struct kernel_symbol *unused_gpl_syms; /* 仅 GPL 未使用的导出符号表 */
	const unsigned long *unused_gpl_crcs;        /* 仅 GPL 未使用符号的 CRC 校验和 */
#endif

	/* 将来会变为 GPL-only 的符号 */
	const struct kernel_symbol *gpl_future_syms;  /* 将来会变为 GPL-only 的符号表 */
	const unsigned long *gpl_future_crcs;         /* 将来会变为 GPL-only 符号的 CRC 校验和 */
	unsigned int num_gpl_future_syms;             /* 将来会变为 GPL-only 符号的数量 */

	/* 异常表 */
	unsigned int num_exentries;                   /* 异常表中条目的数量 */
	struct exception_table_entry *extable;        /* 异常表 */

	/* 启动函数 */
	int (*init)(void);                            /* 模块的初始化函数 */

	/* 如果非 NULL，init() 返回后会 vfree 这个指针 */
	void *module_init;                           /* 模块初始化后需要释放的内存 */

	/* 实际的代码 + 数据，会在卸载时 vfree */
	void *module_core;                           /* 模块的核心代码和数据 */

	/* 初始化和核心部分的大小 */
	unsigned int init_size, core_size;           /* 初始化和核心部分的大小 */

	/* 执行代码部分的大小 */
	unsigned int init_text_size, core_text_size; /* 初始化和核心部分的代码大小 */

	/* 架构特定的模块值 */
	struct mod_arch_specific arch;               /* 架构特定的模块数据 */

	unsigned int taints;                         /* 内核污染标记（类似于内核的 tainted 标志） */

#ifdef CONFIG_GENERIC_BUG
	/* BUG 支持 */
	unsigned num_bugs;                           /* 记录 BUG 的数量 */
	struct list_head bug_list;                   /* BUG 列表头 */
	struct bug_entry *bug_table;                 /* BUG 表 */
#endif

#ifdef CONFIG_KALLSYMS
	/*
	 * 用于 kallsyms 的符号和字符串表。
	 * core_* 字段是临时的，仅用于加载器（可以在模块初始化后丢弃）。
	 */
	Elf_Sym *symtab, *core_symtab;                /* 符号表和核心符号表 */
	unsigned int num_symtab, core_num_syms;      /* 符号表的数量 */
	char *strtab, *core_strtab;                  /* 字符串表和核心字符串表 */

	/* 节区属性 */
	struct module_sect_attrs *sect_attrs;        /* 模块节区属性 */

	/* 注释属性 */
	struct module_notes_attrs *notes_attrs;      /* 模块注释属性 */
#endif

#ifdef CONFIG_SMP
	/* 每个 CPU 的数据 */
	void __percpu *percpu;                       /* 每个 CPU 数据的指针 */
	unsigned int percpu_size;                   /* 每个 CPU 数据的大小 */
#endif

	/* 命令行参数（可能被篡改） */
	char *args;                                 /* 模块的命令行参数 */

#ifdef CONFIG_TRACEPOINTS
	struct tracepoint *tracepoints;             /* 模块的跟踪点 */
	unsigned int num_tracepoints;               /* 跟踪点的数量 */
#endif

#ifdef CONFIG_TRACING
	const char **trace_bprintk_fmt_start;       /* 追踪 printk 格式的开始 */
	unsigned int num_trace_bprintk_fmt;        /* 追踪 printk 格式的数量 */
#endif

#ifdef CONFIG_EVENT_TRACING
	struct ftrace_event_call *trace_events;     /* 事件跟踪调用 */
	unsigned int num_trace_events;             /* 事件跟踪的数量 */
#endif

#ifdef CONFIG_FTRACE_MCOUNT_RECORD
	unsigned long *ftrace_callsites;            /* ftrace 调用位置 */
	unsigned int num_ftrace_callsites;         /* ftrace 调用位置的数量 */
#endif

#ifdef CONFIG_MODULE_UNLOAD
	/* 依赖于我的模块 */
	struct list_head modules_which_use_me;      /* 依赖于此模块的模块列表 */

	/* 等待我们卸载的任务 */
	struct task_struct *waiter;                 /* 等待模块卸载的任务 */

	/* 卸载函数 */
	void (*exit)(void);                        /* 模块的卸载函数 */

	struct module_ref {
		unsigned int incs;                      /* 引用计数增加 */
		unsigned int decs;                      /* 引用计数减少 */
	} __percpu *refptr;                         /* 模块的每个 CPU 引用计数 */
#endif

#ifdef CONFIG_CONSTRUCTORS
	/* 构造函数 */
	ctor_fn_t *ctors;                          /* 构造函数的列表 */
	unsigned int num_ctors;                    /* 构造函数的数量 */
#endif
};

#ifndef MODULE_ARCH_INIT
#define MODULE_ARCH_INIT {}
#endif

extern struct mutex module_mutex;

/* FIXME: It'd be nice to isolate modules during init, too, so they
   aren't used before they (may) fail.  But presently too much code
   (IDE & SCSI) require entry into the module during init.*/
static inline int module_is_live(struct module *mod)
{
	return mod->state != MODULE_STATE_GOING;
}

struct module *__module_text_address(unsigned long addr);
struct module *__module_address(unsigned long addr);
bool is_module_address(unsigned long addr);
bool is_module_percpu_address(unsigned long addr);
bool is_module_text_address(unsigned long addr);

static inline int within_module_core(unsigned long addr, struct module *mod)
{
	return (unsigned long)mod->module_core <= addr &&
	       addr < (unsigned long)mod->module_core + mod->core_size;
}

static inline int within_module_init(unsigned long addr, struct module *mod)
{
	return (unsigned long)mod->module_init <= addr &&
	       addr < (unsigned long)mod->module_init + mod->init_size;
}

/* Search for module by name: must hold module_mutex. */
struct module *find_module(const char *name);

struct symsearch {
	const struct kernel_symbol *start, *stop;
	const unsigned long *crcs;
	enum {
		NOT_GPL_ONLY,
		GPL_ONLY,
		WILL_BE_GPL_ONLY,
	} licence;
	bool unused;
};

/* Search for an exported symbol by name. */
const struct kernel_symbol *find_symbol(const char *name,
					struct module **owner,
					const unsigned long **crc,
					bool gplok,
					bool warn);

/* Walk the exported symbol table */
bool each_symbol(bool (*fn)(const struct symsearch *arr, struct module *owner,
			    unsigned int symnum, void *data), void *data);

/* Returns 0 and fills in value, defined and namebuf, or -ERANGE if
   symnum out of range. */
int module_get_kallsym(unsigned int symnum, unsigned long *value, char *type,
			char *name, char *module_name, int *exported);

/* Look for this name: can be of form module:name. */
unsigned long module_kallsyms_lookup_name(const char *name);

int module_kallsyms_on_each_symbol(int (*fn)(void *, const char *,
					     struct module *, unsigned long),
				   void *data);

extern void __module_put_and_exit(struct module *mod, long code)
	__attribute__((noreturn));
#define module_put_and_exit(code) __module_put_and_exit(THIS_MODULE, code);

#ifdef CONFIG_MODULE_UNLOAD
unsigned int module_refcount(struct module *mod);
void __symbol_put(const char *symbol);
#define symbol_put(x) __symbol_put(MODULE_SYMBOL_PREFIX #x)
void symbol_put_addr(void *addr);

/* Sometimes we know we already have a refcount, and it's easier not
   to handle the error case (which only happens with rmmod --wait). */
static inline void __module_get(struct module *module)
{
	if (module) {
		preempt_disable();
		__this_cpu_inc(module->refptr->incs);
		trace_module_get(module, _THIS_IP_,
				 __this_cpu_read(module->refptr->incs));
		preempt_enable();
	}
}

static inline int try_module_get(struct module *module)
{
	int ret = 1;

	if (module) {
		preempt_disable();

		if (likely(module_is_live(module))) {
			__this_cpu_inc(module->refptr->incs);
			trace_module_get(module, _THIS_IP_,
				__this_cpu_read(module->refptr->incs));
		} else
			ret = 0;

		preempt_enable();
	}
	return ret;
}

extern void module_put(struct module *module);

#else /*!CONFIG_MODULE_UNLOAD*/
static inline int try_module_get(struct module *module)
{
	return !module || module_is_live(module);
}
static inline void module_put(struct module *module)
{
}
static inline void __module_get(struct module *module)
{
}
#define symbol_put(x) do { } while(0)
#define symbol_put_addr(p) do { } while(0)

#endif /* CONFIG_MODULE_UNLOAD */
int use_module(struct module *a, struct module *b);

/* This is a #define so the string doesn't get put in every .o file */
#define module_name(mod)			\
({						\
	struct module *__mod = (mod);		\
	__mod ? __mod->name : "kernel";		\
})

/* For kallsyms to ask for address resolution.  namebuf should be at
 * least KSYM_NAME_LEN long: a pointer to namebuf is returned if
 * found, otherwise NULL. */
const char *module_address_lookup(unsigned long addr,
			    unsigned long *symbolsize,
			    unsigned long *offset,
			    char **modname,
			    char *namebuf);
int lookup_module_symbol_name(unsigned long addr, char *symname);
int lookup_module_symbol_attrs(unsigned long addr, unsigned long *size, unsigned long *offset, char *modname, char *name);

/* For extable.c to search modules' exception tables. */
const struct exception_table_entry *search_module_extables(unsigned long addr);

int register_module_notifier(struct notifier_block * nb);
int unregister_module_notifier(struct notifier_block * nb);

extern void print_modules(void);

extern void module_update_tracepoints(void);
extern int module_get_iter_tracepoints(struct tracepoint_iter *iter);

#else /* !CONFIG_MODULES... */
#define EXPORT_SYMBOL(sym)
#define EXPORT_SYMBOL_GPL(sym)
#define EXPORT_SYMBOL_GPL_FUTURE(sym)
#define EXPORT_UNUSED_SYMBOL(sym)
#define EXPORT_UNUSED_SYMBOL_GPL(sym)

/* Given an address, look for it in the exception tables. */
static inline const struct exception_table_entry *
search_module_extables(unsigned long addr)
{
	return NULL;
}

static inline struct module *__module_address(unsigned long addr)
{
	return NULL;
}

static inline struct module *__module_text_address(unsigned long addr)
{
	return NULL;
}

static inline bool is_module_address(unsigned long addr)
{
	return false;
}

static inline bool is_module_percpu_address(unsigned long addr)
{
	return false;
}

static inline bool is_module_text_address(unsigned long addr)
{
	return false;
}

/* Get/put a kernel symbol (calls should be symmetric) */
#define symbol_get(x) ({ extern typeof(x) x __attribute__((weak)); &(x); })
#define symbol_put(x) do { } while(0)
#define symbol_put_addr(x) do { } while(0)

static inline void __module_get(struct module *module)
{
}

static inline int try_module_get(struct module *module)
{
	return 1;
}

static inline void module_put(struct module *module)
{
}

#define module_name(mod) "kernel"

/* For kallsyms to ask for address resolution.  NULL means not found. */
static inline const char *module_address_lookup(unsigned long addr,
					  unsigned long *symbolsize,
					  unsigned long *offset,
					  char **modname,
					  char *namebuf)
{
	return NULL;
}

static inline int lookup_module_symbol_name(unsigned long addr, char *symname)
{
	return -ERANGE;
}

static inline int lookup_module_symbol_attrs(unsigned long addr, unsigned long *size, unsigned long *offset, char *modname, char *name)
{
	return -ERANGE;
}

static inline int module_get_kallsym(unsigned int symnum, unsigned long *value,
					char *type, char *name,
					char *module_name, int *exported)
{
	return -ERANGE;
}

static inline unsigned long module_kallsyms_lookup_name(const char *name)
{
	return 0;
}

static inline int module_kallsyms_on_each_symbol(int (*fn)(void *, const char *,
							   struct module *,
							   unsigned long),
						 void *data)
{
	return 0;
}

static inline int register_module_notifier(struct notifier_block * nb)
{
	/* no events will happen anyway, so this can always succeed */
	return 0;
}

static inline int unregister_module_notifier(struct notifier_block * nb)
{
	return 0;
}

#define module_put_and_exit(code) do_exit(code)

static inline void print_modules(void)
{
}

static inline void module_update_tracepoints(void)
{
}

static inline int module_get_iter_tracepoints(struct tracepoint_iter *iter)
{
	return 0;
}

#endif /* CONFIG_MODULES */

struct device_driver;
#ifdef CONFIG_SYSFS
struct module;

extern struct kset *module_kset;
extern struct kobj_type module_ktype;
extern int module_sysfs_initialized;

int mod_sysfs_init(struct module *mod);
int mod_sysfs_setup(struct module *mod,
			   struct kernel_param *kparam,
			   unsigned int num_params);
int module_add_modinfo_attrs(struct module *mod);
void module_remove_modinfo_attrs(struct module *mod);

#else /* !CONFIG_SYSFS */

static inline int mod_sysfs_init(struct module *mod)
{
	return 0;
}

static inline int mod_sysfs_setup(struct module *mod,
			   struct kernel_param *kparam,
			   unsigned int num_params)
{
	return 0;
}

static inline int module_add_modinfo_attrs(struct module *mod)
{
	return 0;
}

static inline void module_remove_modinfo_attrs(struct module *mod)
{ }

#endif /* CONFIG_SYSFS */

#define symbol_request(x) try_then_request_module(symbol_get(x), "symbol:" #x)

/* BELOW HERE ALL THESE ARE OBSOLETE AND WILL VANISH */

#define __MODULE_STRING(x) __stringify(x)


#ifdef CONFIG_GENERIC_BUG
int  module_bug_finalize(const Elf_Ehdr *, const Elf_Shdr *,
			 struct module *);
void module_bug_cleanup(struct module *);

#else	/* !CONFIG_GENERIC_BUG */

static inline int  module_bug_finalize(const Elf_Ehdr *hdr,
					const Elf_Shdr *sechdrs,
					struct module *mod)
{
	return 0;
}
static inline void module_bug_cleanup(struct module *mod) {}
#endif	/* CONFIG_GENERIC_BUG */

#endif /* _LINUX_MODULE_H */
