#ifdef CONFIG_SANITIZER_COVERAGE

#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>

struct dentry *root_dentry, *enable_dentry, *dump_dentry, *stats_dentry;
struct task_struct *enabled_coverage_task = NULL;

static inline bool coverage_enabled_for_thread() {
	if (!current)
  		return false;
	return current->sanitizer_coverage.enabled;
}

void __sanitizer_cov_with_check(int *unused_guard);

static void enable_coverage_for_thread() {
	if (coverage_enabled_for_thread()) return;
	// allocate memory for the buffer.
	current->sanitizer_coverage.counter = 0;
	current->sanitizer_coverage.pc_max = __sanitizer_cov_with_check;
	current->sanitizer_coverage.pc_min = __sanitizer_cov_with_check;
	pr_err("__sanitizer_cov_with_check: %p\n", __sanitizer_cov_with_check);
	current->sanitizer_coverage.pc_hash = NULL;  // unused
	current->sanitizer_coverage.pcs_size = 20480;
	current->sanitizer_coverage.pcs = kcalloc(current->sanitizer_coverage.pcs_size, sizeof(void*), GFP_KERNEL);  // leaked
	pr_err("enabled coverage for thread %p, pid %d. pcs: %p\n", current, current->pid, current->sanitizer_coverage.pcs);
	enabled_coverage_task = current;
	current->sanitizer_coverage.enabled = true;
}

static inline void disable_coverage_for_thread() {
	if (!current)
  		return;
	current->sanitizer_coverage.enabled = false;
}


void __sanitizer_cov_module_init(void) {
  // Do nothing here for now.
}
EXPORT_SYMBOL(__sanitizer_cov_module_init);

void __sanitizer_cov_with_check(int *unused_guard)
{
	if (!current || !coverage_enabled_for_thread()) {
  		// TODO(glider): need to return here.
	  	return;
  		///enable_coverage_for_thread();
	}
	void *caller = __builtin_return_address(0);
	if (caller > current->sanitizer_coverage.pc_max)
		current->sanitizer_coverage.pc_max = caller;
	else if (caller < current->sanitizer_coverage.pc_min)
		current->sanitizer_coverage.pc_min = caller;
	
	//current->sanitizer_coverage.enabled = false;
	//pr_err("about to write %p to pcs: %p at index %d\n", caller, current->sanitizer_coverage.pcs, current->sanitizer_coverage.counter % current->sanitizer_coverage.pcs_size);
	//current->sanitizer_coverage.enabled = true;
	current->sanitizer_coverage.pcs[current->sanitizer_coverage.counter % current->sanitizer_coverage.pcs_size] = caller;
	current->sanitizer_coverage.counter++;
}
EXPORT_SYMBOL(__sanitizer_cov_with_check);

static ssize_t enable_write(struct file *file, const char __user *addr,
			   size_t len, loff_t *pos)
{
	enable_coverage_for_thread();
	return len;
}

/* read() implementation for enable file. Unused. */
static ssize_t enable_read(struct file *file, char __user *addr, size_t len,
			  loff_t *pos)
{
	// TODO(glider) remove
	/* Allow read operation so that a recursive copy won't fail. */
	return 0;
}
static const struct file_operations sancov_enable_fops = {
	.write	= enable_write,
	.read	= enable_read,
	.llseek	= noop_llseek,
};

static ssize_t stats_read(struct file *file, char __user *addr, size_t len,
			  loff_t *pos)
{
	pr_err("dumping stats for thread %p, pid %d\n", current, current->pid);
	if (!coverage_enabled_for_thread()) {
		pr_err("Coverage disabled for thread %p, pid %d!\n", current, current->pid);
		return 0;
	}
	struct sanitizer_coverage_info coverage;
	// Prevent functions called from stats_read() from messing up the coverage.
	memcpy(&coverage, &current->sanitizer_coverage, sizeof(struct sanitizer_coverage_info));

	char out_buf[1024], *p = out_buf;
	pr_err("Number of coverage hits (incl. duplicates): %d\n", coverage.counter);
	p += scnprintf(p, sizeof(out_buf) + out_buf - p,
		       "Number of coverage hits (incl. duplicates): %d\n",
		       coverage.counter);
	p += scnprintf(p, sizeof(out_buf) + out_buf - p,
		       "Min covered PC: %p\n", coverage.pc_min);
	p += scnprintf(p, sizeof(out_buf) + out_buf - p,
		       "Max covered PC: %p\n", coverage.pc_max);
	return simple_read_from_buffer(addr, len, pos, out_buf, p - out_buf);
}


static const struct file_operations sancov_stats_fops = {
	.read	= stats_read,
	.llseek	= generic_file_llseek,
	.open	= simple_open,
};

static ssize_t dump_read(struct file *file, char __user *addr, size_t len,
			  loff_t *pos)
{
	pr_err("dumping coverage for thread %p, pid %d\n", current, current->pid);
	if (!coverage_enabled_for_thread()) {
		pr_err("Coverage disabled for thread %p, pid %d!\n", current, current->pid);
		return 0;
	}
	struct sanitizer_coverage_info coverage;
	// Prevent functions called from dump_read() from messing up the coverage.
	memcpy(&coverage, &current->sanitizer_coverage, sizeof(struct sanitizer_coverage_info));
	size_t out_buf_size = 20 * coverage.pcs_size;
	char *out_buf = kcalloc(out_buf_size, 1, GFP_KERNEL);
	char *p = out_buf;
	pr_err("%p\n", coverage.counter);
	p += scnprintf(p, out_buf_size + out_buf - p,
		       "%p\n",
		       coverage.counter);
	#if 1
	for (int i = 0; i < min(coverage.counter, coverage.pcs_size); i++) {
		p += scnprintf(p, out_buf_size + out_buf - p,
			       "%p\n",
			       coverage.pcs[i]);

	}
	#endif
	int ret = simple_read_from_buffer(addr, len, pos, out_buf, p - out_buf);
	kfree(out_buf);
	return ret;
}

static const struct file_operations sancov_dump_fops = {
	.read	= dump_read,
	.llseek	= generic_file_llseek,
	.open	= simple_open,
};

static __init int sanitizer_coverage_fs_init(void)
{
	int rc = -EIO;
	root_dentry = debugfs_create_dir("sancov", NULL);
	if (!root_dentry)
		goto err_remove;
	enable_dentry = debugfs_create_file("enable", 0600, root_dentry,
					    NULL, &sancov_enable_fops);
	if (!enable_dentry)
		goto err_remove;
	dump_dentry = debugfs_create_file("dump", 0600, root_dentry,
					  NULL, &sancov_dump_fops);
	if (!dump_dentry)
		goto err_remove;
	stats_dentry = debugfs_create_file("stats", 0600, root_dentry,
					  NULL, &sancov_stats_fops);
	if (!stats_dentry)
		goto err_remove;
	return 0;
err_remove:
	pr_err("sanitizer_coverage_fs_init failed\n");
	if (root_dentry)
		debugfs_remove(root_dentry);
}

device_initcall(sanitizer_coverage_fs_init);
#endif  // CONFIG_SANITIZER_COVERAGE
