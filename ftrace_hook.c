/*
 * Hooking kernel functions using ftrace framework
 *
 * Copyright (c) 2018 ilammy
 */

#define pr_fmt(fmt) "ftrace_hook: " fmt

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>

MODULE_DESCRIPTION("Example module hooking clone() and execve() via ftrace");
MODULE_AUTHOR("ilammy <a.lozovsky@gmail.com>");
MODULE_LICENSE("GPL");

#define MAX_TASKS 8

/*
 * struct fh_hook - describes a single hook to install
 * @name: name of the function to hook
 * @func: pointer to the function to execute instead
 * @orig: pointer to the location where to save a pointer
 *        to the original function
 * @addr: kernel address of the function entry
 * @ops:  ftrace_ops state for this function hook
 * @task_lock:    protects &active_tasks
 * @active_tasks: list of tasks currently executing our trace function
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct fh_hook {
	const char *name;
	void *func;
	void *orig;

	unsigned long addr;
	struct ftrace_ops ops;

	spinlock_t task_lock;
	struct task_struct *active_tasks[MAX_TASKS];
};

static void fh_init_active_tasks(struct fh_hook *hook)
{
	spin_lock_init(&hook->task_lock);

	memset(hook->active_tasks, 0, sizeof(hook->active_tasks));
}

static bool __fh_can_switch_rip(struct fh_hook *hook)
{
	size_t i;

	/*
	 * If the current task is already on the list then this
	 * is a recursive activation of the original function
	 * made the hook function.
	 *
	 * Remove the current task from the list to allow further
	 * calls and deny hook function execution.
	 */
	for (i = 0; i < MAX_TASKS; i++) {
		if (hook->active_tasks[i] == current) {
			hook->active_tasks[i] = NULL;
			return false;
		}
	}

	/*
	 * If the current task is not on the list then this
	 * is the first activation of the ftrace function for
	 * this task (initial entry).
	 *
	 * In this case add the current task to the active list.
	 * Then allow the hook function to execute.
	 */
	for (i = 0; i < MAX_TASKS; i++) {
		if (hook->active_tasks[i] == NULL) {
			hook->active_tasks[i] = current;
			return true;
		}
	}

	/*
	 * If the task list is already full then deny hook execution
	 * for this particular activation. The hooked function will
	 * execute unmodified. Drop a warning to the log so that
	 * we know that the task list is probably too small.
	 */
	pr_notice("task limit overflow for '%s'\n", hook->name);

	return false;
}

/**
 * fh_can_switch_rip() - check the tick-tock status of the hook
 * @hook: hook to check
 *
 * Returns: permission to reset %rip to the hook function.
 */
static bool fh_can_switch_rip(struct fh_hook *hook)
{
	bool permit = true;

	/*
	 * Note the non-irq spinlocks which means that you should not
	 * hook functions which may be called from interrupt context.
	 */

	spin_lock(&hook->task_lock);

	permit = __fh_can_switch_rip(hook);

	spin_unlock(&hook->task_lock);

	return permit;
}

/**
 * fh_reset_hook() - allow the next hook call
 * @hook: hook to reset
 *
 * You should call this function from the hook function which does not
 * call the original implementation. It is necessary to allow the next
 * call to be hooked.
 */
void fh_reset_hook(struct fh_hook *hook)
{
	size_t i;

	spin_lock(&hook->task_lock);

	for (i = 0; i < MAX_TASKS; i++) {
		if (hook->active_tasks[i] == current) {
			hook->active_tasks[i] = NULL;
			break;
		}
	}

	spin_unlock(&hook->task_lock);
}

static int fh_resolve_hook_address(struct fh_hook *hook)
{
	hook->addr = kallsyms_lookup_name(hook->name);

	if (!hook->addr) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

	*((unsigned long*) hook->orig) = hook->addr;

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct pt_regs *regs)
{
	struct fh_hook *hook = container_of(ops, struct fh_hook, ops);

	if (fh_can_switch_rip(hook))
		regs->ip = (unsigned long) hook->func;
}

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct fh_hook *hook)
{
	int err;

	fh_init_active_tasks(hook);

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION_SAFE.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION_SAFE
	                | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->addr, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->addr, 1, 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct fh_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->addr, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct fh_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct fh_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

static asmlinkage long (*real_sys_clone)(unsigned long clone_flags,
		unsigned long newsp, int __user *parent_tidptr,
		int __user *child_tidptr, unsigned long tls);

static asmlinkage long fh_sys_clone(unsigned long clone_flags,
		unsigned long newsp, int __user *parent_tidptr,
		int __user *child_tidptr, unsigned long tls)
{
	long ret;

	pr_info("clone() before\n");

	ret = real_sys_clone(clone_flags, newsp, parent_tidptr,
		child_tidptr, tls);

	pr_info("clone() after: %ld\n", ret);

	return ret;
}

static char *duplicate_filename(const char __user *filename)
{
	char *kernel_filename;

	kernel_filename = kmalloc(4096, GFP_KERNEL);
	if (!kernel_filename)
		return NULL;

	if (strncpy_from_user(kernel_filename, filename, 4096) < 0) {
		kfree(kernel_filename);
		return NULL;
	}

	return kernel_filename;
}

static asmlinkage long (*real_sys_execve)(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp);

static asmlinkage long fh_sys_execve(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp)
{
	long ret;
	char *kernel_filename;

	kernel_filename = duplicate_filename(filename);

	pr_info("execve() before: %s\n", kernel_filename);

	kfree(kernel_filename);

	ret = real_sys_execve(filename, argv, envp);

	pr_info("execve() after: %ld\n", ret);

	return ret;
}

static struct fh_hook demo_hooks[] = {
	{
		.name = "sys_clone",
		.func = fh_sys_clone,
		.orig = &real_sys_clone,
	},
	{
		.name = "sys_execve",
		.func = fh_sys_execve,
		.orig = &real_sys_execve,
	},
};

static int fh_init(void)
{
	int err;

	err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (err)
		return err;

	pr_info("module loaded\n");

	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));

	pr_info("module unloaded\n");
}
module_exit(fh_exit);
