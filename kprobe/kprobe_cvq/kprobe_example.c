/*
 * Kprobe for virtio net cvq
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/virtio_net.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include <linux/pci.h>

#define VIRTIO_NET_RSS_MAX_KEY_SIZE     40
#define VIRTIO_NET_RSS_MAX_TABLE_LEN    128
struct virtio_net_ctrl_rss {
	u32 hash_types;
	u16 indirection_table_mask;
	u16 unclassified_queue;
	u16 indirection_table[VIRTIO_NET_RSS_MAX_TABLE_LEN];
	u16 max_tx_vq;
	u8 hash_key_length;
	u8 key[VIRTIO_NET_RSS_MAX_KEY_SIZE];
};

struct virtnet_interrupt_coalesce {
	u32 max_packets;
	u32 max_usecs;
};

struct virtnet_info {
	struct virtio_device *vdev;
	struct virtqueue *cvq;
	struct net_device *dev;
	struct send_queue *sq;
	struct receive_queue *rq;
	unsigned int status;

	/* Max # of queue pairs supported by the device */
	u16 max_queue_pairs;

	/* # of queue pairs currently used by the driver */
	u16 curr_queue_pairs;

	/* # of XDP queue pairs currently used by the driver */
	u16 xdp_queue_pairs;

	/* xdp_queue_pairs may be 0, when xdp is already loaded. So add this. */
	bool xdp_enabled;

	/* I like... big packets and I cannot lie! */
	bool big_packets;

	/* number of sg entries allocated for big packets */
	unsigned int big_packets_num_skbfrags;

	/* Host will merge rx buffers for big packets (shake it! shake it!) */
	bool mergeable_rx_bufs;

	/* Host supports rss and/or hash report */
	bool has_rss;
	bool has_rss_hash_report;
	u8 rss_key_size;
	u16 rss_indir_table_size;
	u32 rss_hash_types_supported;
	u32 rss_hash_types_saved;
	struct virtio_net_ctrl_rss rss;

	/* Has control virtqueue */
	bool has_cvq;

	/* Lock to protect the control VQ */
	struct mutex cvq_lock;

	/* Host can handle any s/g split between our header and packet data */
	bool any_header_sg;

	/* Packet virtio header size */
	u8 hdr_len;

	/* Work struct for delayed refilling if we run low on memory. */
	struct delayed_work refill;

	/* Is delayed refill enabled? */
	bool refill_enabled;

	/* The lock to synchronize the access to refill_enabled */
	spinlock_t refill_lock;

	/* Work struct for config space updates */
	struct work_struct config_work;

	/* Work struct for setting rx mode */
	struct work_struct rx_mode_work;

	/* OK to queue work setting RX mode? */
	bool rx_mode_work_enabled;

	/* Does the affinity hint is set for virtqueues? */
	bool affinity_hint_set;

	/* CPU hotplug instances for online & dead */
	struct hlist_node node;
	struct hlist_node node_dead;

	struct control_buf *ctrl;

	/* Ethtool settings */
	u8 duplex;
	u32 speed;

	/* Is rx dynamic interrupt moderation enabled? */
	bool rx_dim_enabled;

	/* Interrupt coalescing settings */
	struct virtnet_interrupt_coalesce intr_coal_tx;
	struct virtnet_interrupt_coalesce intr_coal_rx;

	unsigned long guest_offloads;
	unsigned long guest_offloads_capable;

	/* failover when STANDBY feature enabled */
	struct failover *failover;

	u64 device_stats_cap;
};

// 定义哈希表，大小为 2^4 = 16 个桶
DEFINE_HASHTABLE(dev_call_count, 4);
// 定义一个 spinlock 用于保护哈希表
static DEFINE_SPINLOCK(hash_table_lock);

// 定义哈希表条目结构
struct dev_counter {
	char dev_name[IFNAMSIZ]; // 设备名称
	u8 bus; // BDF: 总线号
	u8 device; // BDF: 设备号
	u8 function; // BDF: 功能号
	u8 devfn; // 编码后的设备和功能号 (pci_dev->devfn)
	u64 counter; // 调用次数
	u64 ok_ret; // 调用次数
	u64 err_ret; // 调用次数
	struct hlist_node node; // 哈希链表节点
};

//#define TRACE_SYMBOL "virtnet_send_command"
//#define TRACE_SYMBOL "virtnet_set_rx_mode"
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6, 10, 0)
	#define TRACE_SYMBOL "virtnet_send_command"
#else
	#define TRACE_SYMBOL "virtnet_send_command_reply"
#endif


// 查找或创建条目
static struct dev_counter *
find_or_create_entry(const char *dev_name, u8 bus, u8 device, u8 function,
		     u8 devfn)
{
	struct dev_counter *entry;
	u32 key = jhash(dev_name, strlen(dev_name), 0); // 根据设备名称生成哈希值
	unsigned long flags;

	spin_lock_irqsave(&hash_table_lock, flags);

	// 遍历哈希桶，查找是否已经存在对应条目
	hash_for_each_possible(dev_call_count, entry, node, key) {
		if (strcmp(entry->dev_name, dev_name) == 0) {
			spin_unlock_irqrestore(&hash_table_lock, flags);
			return entry; // 找到条目，返回
		}
	}

	// 如果未找到，分配新的条目并初始化
	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		spin_unlock_irqrestore(&hash_table_lock, flags);
		return NULL;
	}

	strncpy(entry->dev_name, dev_name, IFNAMSIZ);
	entry->bus = bus;
	entry->device = device;
	entry->function = function;
	entry->devfn = devfn;
	entry->counter = 0;
	entry->ok_ret = 0;
	entry->err_ret = 0;

	// 添加到哈希表中
	hash_add(dev_call_count, &entry->node, key);

	// 解锁
	spin_unlock_irqrestore(&hash_table_lock, flags);
	return entry;
}

static struct dev_counter *find_entry(const char *dev_name)
{
	struct dev_counter *entry;
	u32 key = jhash(dev_name, strlen(dev_name), 0); // 根据设备名称生成哈希值
	unsigned long flags;

	spin_lock_irqsave(&hash_table_lock, flags);

	// 遍历哈希桶，查找是否已经存在对应条目
	hash_for_each_possible(dev_call_count, entry, node, key) {
		if (strcmp(entry->dev_name, dev_name) == 0) {
			spin_unlock_irqrestore(&hash_table_lock, flags);
			return entry; // 找到条目，返回
		}
	}

	spin_unlock_irqrestore(&hash_table_lock, flags);
	return NULL;
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
/*
 	int dfd = -1;
	struct filename *filename = NULL;
#ifdef CONFIG_X86
	dfd = regs->di;
    filename = (struct filename *) regs->si;
#endif

#ifdef CONFIG_ARM64
  	dfd = regs->regs[0];
    filename = (struct filename *) regs->regs[1];
#endif

 	if (filename && !(strcmp(filename->name, "testfile")))
        printk(KERN_INFO "handler_pre:%s: dfd=%d, name=%s\n", p->symbol_name, dfd, filename->name);

*/
	struct virtnet_info *vi = (struct virtnet_info *)regs->di; // 获取第一个参数 dev
	struct virtio_device *vdev = vi->vdev;
	struct net_device *dev = vi->dev;
	struct dev_counter *entry;
	u8 bus, device, function;
	struct pci_dev *pci_dev; // 用于存储 PCI 设备信息
	u8 class = (u8)regs->si;
	u8 cmd = (u8)regs->dx;
	unsigned long flags;

	pr_info("kprobe pre %s Device: %s cmd %#x, cmd %#x\n", TRACE_SYMBOL, dev->name, class, cmd);

	if (class == VIRTIO_NET_CTRL_RX &&
	    (cmd == VIRTIO_NET_CTRL_RX_PROMISC ||
	     cmd == VIRTIO_NET_CTRL_RX_ALLMULTI)) {
		// 将网络设备的父设备转换为 PCI 设备
		pci_dev = to_pci_dev(vdev->dev.parent);
		if (!pci_dev) {
			pr_warn("No PCI device found for net_device: %s\n", dev->name);
			return 0;
		}
		// 提取 BDF 信息
		bus = pci_dev->bus->number;
		device = PCI_SLOT(pci_dev->devfn);
		function = PCI_FUNC(pci_dev->devfn);
		// pr_info("Device: %s, BDF: %02x:%02x.%x devfn %#x bus %p \n", dev->name, bus, device, function, pci_dev->devfn, pci_dev->bus);

		entry = find_or_create_entry(dev->name, bus, device, function, pci_dev->devfn);
		if (entry) {
			spin_lock_irqsave(&hash_table_lock, flags);
			entry->counter++; // 增加调用次数
			spin_unlock_irqrestore(&hash_table_lock, flags);
		}
	}

	return 0;

}

/* kprobe post_handler: called after the probed instruction is executed */
/* x86_64中寄存器中返回值存储在: rax*/
static void handler_post(struct kprobe *p, struct pt_regs *regs,
			 unsigned long flags)
{
	struct virtnet_info *vi = (struct virtnet_info *)regs->di; // 获取第一个参数 dev
	struct virtio_device *vdev = vi->vdev;
	struct net_device *dev = vi->dev;
	struct dev_counter *entry;
	struct pci_dev *pci_dev; // 用于存储 PCI 设备信息
	u8 class = (u8)regs->si;
	u8 cmd = (u8)regs->dx;
	unsigned long flag;
	bool retval;

	pr_info("kprobe post %s Device: %s cmd %#x, cmd %#x\n", TRACE_SYMBOL, dev->name, class, cmd);

#ifdef CONFIG_X86_64
	retval = (bool)regs->ax; // Access RAX register for x86_64
#elif defined(CONFIG_ARM64)
	retval = (bool)regs->regs[0]; // Access X0 register for ARM64
#else
#error "Unsupported architecture"
#endif

	if (class == VIRTIO_NET_CTRL_RX &&
	    (cmd == VIRTIO_NET_CTRL_RX_PROMISC ||
	     cmd == VIRTIO_NET_CTRL_RX_ALLMULTI)) {
		// 将网络设备的父设备转换为 PCI 设备
		pci_dev = to_pci_dev(vdev->dev.parent);
		if (!pci_dev) {
			pr_warn("No PCI device found for net_device: %s\n", dev->name);
			return;
		}

		entry = find_entry(dev->name);
		if (entry) {
			spin_lock_irqsave(&hash_table_lock, flag);
			if (retval)
				entry->ok_ret++;
			else
				entry->err_ret++;
			spin_unlock_irqrestore(&hash_table_lock, flag);
		}
	}
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 11, 0)
/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	/*printk(KERN_INFO "fault_handler: p->addr = 0x%p, trap #%dn",
		p->addr, trapnr);*/
	/* Return 0 because we don't handle the fault. */
	return 0;
}
#endif

// 打印并清理哈希表内容
static void print_and_cleanup_hash_table(void)
{
	struct dev_counter *entry;
	struct hlist_node *tmp;
	unsigned long flags;
	int bkt;

	pr_info("Final Hash Table Contents:\n");
	pr_info("====================================\n");

	spin_lock_irqsave(&hash_table_lock, flags);
	hash_for_each_safe(dev_call_count, bkt, tmp, entry, node) {
		pr_info("Device: %s BDF %02x:%02x.%x Send: %llu OkRet: %llu ErrRet: %llu \n",
			 entry->dev_name,
			 entry->bus,
			 entry->device,
			 entry->function,
			 entry->counter,
			 entry->ok_ret,
			 entry->err_ret);
		hash_del(&entry->node); // 从哈希表中删除条目
		kfree(entry); // 释放内存
	}
	spin_unlock_irqrestore(&hash_table_lock, flags);
	pr_info("====================================\n");
	pr_info("Hash table cleared\n");
}

static int __init kprobe_init(void)
{
	int ret;
	kp.pre_handler = handler_pre;
	kp.post_handler = handler_post;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 11, 0)
	kp.fault_handler = handler_fault;
#endif

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
	print_and_cleanup_hash_table();
	unregister_kprobe(&kp);
	printk(KERN_INFO "kprobe at %p unregistered\n", kp.addr);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");

