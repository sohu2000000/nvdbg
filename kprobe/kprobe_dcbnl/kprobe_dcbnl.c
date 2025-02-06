/*
 * Kprobe for virtio net cvq
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/pci.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#define TRACE_SYMBOL "dcbnl_ieee_set"

void get_process_name(pid_t pid) {
	struct task_struct *task;

	// 使用 find_vpid 获取与 PID 对应的 pid 结构
	struct pid *pid_struct = find_vpid(pid);
	if (!pid_struct) {
		printk(KERN_ERR "无法找到 PID: %d 对应的 vpid\n", pid);
		return;
	}

	// 使用 pid_task 获取 task_struct
	rcu_read_lock(); // 进入 RCU 临界区
	task = pid_task(pid_struct, PIDTYPE_PID);
	if (task) {
		printk(KERN_INFO "进程名称: %s\n", task->comm);
	} else {
		printk(KERN_ERR "PID: %d 找不到对应的任务\n", pid);
	}
	rcu_read_unlock(); // 离开 RCU 临界区
}

/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp = {
	.symbol_name	= TRACE_SYMBOL,
};

/* x86_64中寄存器中参数的顺序: rdi rsi rdx rcx r8 r9*/
/* aarch64: x0-x7 对应参数 */
/* kprobe pre_handler: called just before the probed instruction is executed */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	pid_t pid = current->pid; // 获取当前进程 ID

	printk(KERN_INFO "Process %d triggered dcbnl_ieee_set\n", pid);
	get_process_name(pid); // 获取当前进程名称
	return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
/* x86_64中寄存器中返回值存储在: rax*/
static void handler_post(struct kprobe *p, struct pt_regs *regs,
			 unsigned long flags)
{
}

static int __init kprobe_init(void)
{
	int ret;
	kp.pre_handler = handler_pre;
	kp.post_handler = handler_post;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		printk(KERN_INFO "register_kprobe failed, returned %d\n", ret);
		return ret;
	}
	printk(KERN_INFO "Planted kprobe at %p\n", kp.addr);
	return 0;
}

static void __exit kprobe_exit(void)
{
	unregister_kprobe(&kp);
	printk(KERN_INFO "kprobe at %p unregistered\n", kp.addr);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");

