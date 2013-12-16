/**
 * bnotify - Notify the userspace that the process is blocked.
 * Copyright (C) 2013 Changli Gao <xiaosuo@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <bnotify.h>

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/poll.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Changli Gao <xiaosuo@gmail.com>");
MODULE_DESCRIPTION("Notify the userspace that the process is blocked");

struct bnotify_file {
	struct list_head	entry_list;
	struct list_head	block_list;
	struct list_head	wake_list;
	wait_queue_head_t	wq;
};

struct bnotify_entry {
	union {
		struct {
			pid_t			pid;
			struct rb_node		node;
			struct list_head	link;
			struct list_head	block_link;
			struct bnotify_file	*file;
		};
		struct rcu_head			rcu;
	};
	struct preempt_notifier			notifier;
	struct module				*module;
};

struct bnotify_wake {
	struct preempt_notifier			notifier;
	union {
		struct {
			struct bnotify_file	*file;
			struct list_head	link;
		};
		struct work_struct		work;
	};
	struct module				*module;
};

static DEFINE_SPINLOCK(bnotify_lock);
static struct rb_root		*bnotify_hash_table;
static u32			bnotify_hash_table_size;
static struct workqueue_struct	*bnotify_wq;

static struct rb_root *bnotify_alloc_hash_table(u32 *psize)
{
	unsigned long size;
	struct rb_root *hash_table;

	*psize = roundup(*psize, PAGE_SIZE / sizeof(*hash_table));
	size = *psize * sizeof(*hash_table);
	hash_table = (void *)__get_free_pages(GFP_KERNEL | __GFP_NOWARN |
			__GFP_ZERO, get_order(size));
	if (!hash_table) {
		pr_warn("Falling back to vzalloc\n");
		hash_table = vzalloc(size);
	}

	return hash_table;
}

static void bnotify_free_hash_table(struct rb_root *hash_table,
		unsigned int size)
{
	if (is_vmalloc_addr(hash_table))
		vfree(hash_table);
	else
		free_pages((unsigned long)hash_table,
				get_order(sizeof(*hash_table) * size));
}

static struct bnotify_entry *____bnotify_insert_entry(
		struct bnotify_entry *entry, struct rb_root *hash_table,
		unsigned int hash_table_size)
{
	struct rb_node **new, *parent = NULL;
	struct rb_root *root;

	root = &hash_table[entry->pid % hash_table_size];
	new = &root->rb_node;
	while (*new) {
		struct bnotify_entry *this;

		parent = *new;
		this = rb_entry(parent, struct bnotify_entry, node);
		if (entry->pid < this->pid)
			new = &parent->rb_left;
		else if (entry->pid > this->pid)
			new = &parent->rb_right;
		else
			return this;
	}

	rb_link_node(&entry->node, parent, new);
	rb_insert_color(&entry->node, root);

	return NULL;
}

static struct bnotify_entry *__bnotify_insert_entry(struct bnotify_entry *entry)
{
	return ____bnotify_insert_entry(entry, bnotify_hash_table,
			bnotify_hash_table_size);
}

static int bnotify_set_hash_table_size(const char *val, struct kernel_param *kp)
{
	unsigned int hash_table_size, i;
	struct rb_root *hash_table;
	int rc;

	if (!bnotify_hash_table_size)
		return param_set_uint(val, kp);
	rc = kstrtouint(val, 0, &hash_table_size);
	if (rc)
		return rc;
	if (!hash_table_size)
		return -EINVAL;

	hash_table = bnotify_alloc_hash_table(&hash_table_size);
	if (!hash_table)
		return -ENOMEM;

	spin_lock(&bnotify_lock);
	if (hash_table_size != bnotify_hash_table_size) {
		struct bnotify_entry *entry;

		for (i = 0; i < bnotify_hash_table_size; i++) {
#ifdef rbtree_postorder_for_each_entry_safe
			struct bnotify_entry *next;

			rbtree_postorder_for_each_entry_safe(entry, next,
					&bnotify_hash_table[i], node) {
#else
			struct rb_node *node, *next;

			for (node = rb_first(&bnotify_hash_table[i]);
			     node; node = next) {
				entry = rb_entry(node, struct bnotify_entry,
						node);
				next = rb_next(node);
				rb_erase(&entry->node, &bnotify_hash_table[i]);
#endif
				____bnotify_insert_entry(entry, hash_table,
						hash_table_size);
			}
		}
		swap(hash_table, bnotify_hash_table);
		swap(hash_table_size, bnotify_hash_table_size);
		pr_info("set the size of the hash table to %u\n",
				bnotify_hash_table_size);
	}
	spin_unlock(&bnotify_lock);

	bnotify_free_hash_table(hash_table, hash_table_size);

	return 0;
}

module_param_call(hash_table_size, bnotify_set_hash_table_size,
		param_get_uint, &bnotify_hash_table_size, 0644);
MODULE_PARM_DESC(hash_table_size,
		"size of the hash table for bnotify entries");

static struct bnotify_entry *____bnotify_find_entry(void)
{
	struct rb_root *root;
	struct rb_node *node;
	struct bnotify_entry *entry;
	pid_t pid = current->pid;

	root = &bnotify_hash_table[pid % bnotify_hash_table_size];
	node = root->rb_node;
	while (node) {
		entry = rb_entry(node, struct bnotify_entry, node);
		if (pid < entry->pid)
			node = node->rb_left;
		else if (pid > entry->pid)
			node = node->rb_right;
		else
			return entry;
	}

	return NULL;
}

static void bnotify_gc(struct rcu_head *rcu)
{
	struct bnotify_entry *entry;

	entry = container_of(rcu, struct bnotify_entry, rcu);
	module_put(entry->module);
	kfree(entry);
}

static void __bnotify_remove_entry(struct bnotify_entry *entry)
{
	struct rb_root *root;

	root = &bnotify_hash_table[entry->pid % bnotify_hash_table_size];
	rb_erase(&entry->node, root);
	__hlist_del(&entry->notifier.link);
	call_rcu_sched(&entry->rcu, bnotify_gc);
}

static struct bnotify_entry *__bnotify_find_entry(void)
{
	struct bnotify_entry *entry = ____bnotify_find_entry();

	if (entry && !entry->file) {
		__bnotify_remove_entry(entry);
		entry = NULL;
	}

	return entry;
}

static void bnotify_free_wake(struct work_struct *work)
{
	struct bnotify_wake *wake;

	wake = container_of(work, struct bnotify_wake, work);
	module_put(wake->module);
	kfree(wake);
}

/**
 * Since sched_out is called with the rq locked and sched_in isn't called
 * with rq locked, we postphone the waking up to the next's sched_in.
 */
static void bnotify_sched_in_wake(struct preempt_notifier *notifier, int cpu)
{
	struct bnotify_wake *wake;

	wake = container_of(notifier, struct bnotify_wake, notifier);
	spin_lock(&bnotify_lock);
	if (wake->file) {
		wake_up_interruptible(&wake->file->wq);
		list_del_init(&wake->link);
	}
	spin_unlock(&bnotify_lock);
	__hlist_del(&wake->notifier.link);
	INIT_WORK(&wake->work, bnotify_free_wake);
	queue_work_on(raw_smp_processor_id(), bnotify_wq, &wake->work);
}

static void bnotify_sched_out_wake(struct preempt_notifier *notifier,
		struct task_struct *next)
{
	BUG_ON(true);
}

static struct preempt_ops bnotify_preempt_wake_ops = {
	.sched_in	= bnotify_sched_in_wake,
	.sched_out	= bnotify_sched_out_wake,
};

static void __bnotify_insert_wake(struct task_struct *next,
		struct bnotify_file *f)
{
	struct bnotify_wake *wake;

	wake = kmalloc(sizeof(*wake), GFP_ATOMIC | GFP_TEMPORARY);
	if (!wake)
		goto err;
	wake->module = THIS_MODULE;
	if (!try_module_get(wake->module))
		goto err2;
	preempt_notifier_init(&wake->notifier, &bnotify_preempt_wake_ops);
	hlist_add_head(&wake->notifier.link, &next->preempt_notifiers);
	wake->file = f;
	list_add(&wake->link, &f->wake_list);

	return;
err2:
	kfree(wake);
err:
	return;
}

static void bnotify_sched_in(struct preempt_notifier *notifier, int cpu)
{
	struct bnotify_entry *entry;

	spin_lock(&bnotify_lock);
	entry = __bnotify_find_entry();
	if (entry && !list_empty(&entry->block_link))
		list_del_init(&entry->block_link);
	spin_unlock(&bnotify_lock);
}

static void bnotify_sched_out(struct preempt_notifier *notifier,
		struct task_struct *next)
{
	struct bnotify_entry *entry;

	spin_lock(&bnotify_lock);
	entry = __bnotify_find_entry();
	if (entry) {
		switch (current->state) {
		case TASK_DEAD:
			list_del_init(&entry->link);
			list_del_init(&entry->block_link);
			__bnotify_remove_entry(entry);
			break;
		case TASK_INTERRUPTIBLE:
		case TASK_UNINTERRUPTIBLE:
			if (list_empty(&entry->block_link)) {
				struct bnotify_file *f = entry->file;

				list_add(&entry->block_link, &f->block_list);
				if (f->block_list.prev == &entry->block_link)
					__bnotify_insert_wake(next, f);
			}
			break;
		}
	}
	spin_unlock(&bnotify_lock);
}

static struct preempt_ops bnotify_preempt_ops = {
	.sched_in	= bnotify_sched_in,
	.sched_out	= bnotify_sched_out,
};

static ssize_t bnotify_read(struct file *f, char __user *buf, size_t size,
		loff_t *ppos)
{
	struct bnotify_file *bf = f->private_data;
	DEFINE_WAIT(wait);
	int rc , limit, written = 0;
	struct bnotify_entry *entry;
	bool nonblock = f->f_flags & O_NONBLOCK, checked = false;
	u32 *pids;
	LIST_HEAD(block_list);

	if (!access_ok(VERIFY_WRITE, buf, size))
		return -EFAULT;
	pids = (void *)__get_free_page(GFP_KERNEL | __GFP_NOWARN |
			GFP_TEMPORARY);
	if (!pids)
		return -ENOMEM;
	limit = size;
again:
	rc = 0;
	if (limit > PAGE_SIZE)
		limit = PAGE_SIZE;
	limit /= sizeof(*pids);
	if (limit == 0) {
		rc = -EINVAL;
		goto out;
	}
	spin_lock(&bnotify_lock);
	if (!checked) {
		entry = __bnotify_find_entry();
		if (entry && entry->file == bf) {
			rc = -EINVAL;
			goto out;
		}
		checked = true;
	}
	for (;;) {
		prepare_to_wait(&bf->wq, &wait, TASK_INTERRUPTIBLE);
		if (!list_empty(&bf->block_list)) {
			struct bnotify_entry *next;

			list_for_each_entry_safe(entry, next, &bf->block_list,
					block_link) {
				pids[rc++] = entry->pid;
				list_move(&entry->block_link, &block_list);
				if (rc >= limit)
					break;
			}
			break;
		}
		if (nonblock) {
			rc = -EAGAIN;
			break;
		}
		if (signal_pending(current)) {
			rc = -EINTR;
			break;
		}
		spin_unlock(&bnotify_lock);
		schedule();
		spin_lock(&bnotify_lock);
	}
	finish_wait(&bf->wq, &wait);
out:
	spin_unlock(&bnotify_lock);
	if (rc > 0) {
		if (__copy_to_user(buf + written, pids, rc * sizeof(*pids))) {
			rc = -EFAULT;
			spin_lock(&bnotify_lock);
			list_splice_init(&block_list, &bf->block_list);
			spin_unlock(&bnotify_lock);
		} else {
			struct bnotify_entry *next;

			spin_lock(&bnotify_lock);
			list_for_each_entry_safe(entry, next, &block_list,
					block_link)
				list_del_init(&entry->block_link);
			spin_unlock(&bnotify_lock);
			written += rc * sizeof(*pids);
			if (rc == PAGE_SIZE / sizeof(*pids) &&
			    written < size) {
				limit = size - written;
				goto again;
			}
		}
	}
	free_page((unsigned long)pids);

	return written > 0 ? written : rc;
}

static ssize_t bnotify_write(struct file *f, const char __user *buf,
		size_t size, loff_t *ppos)
{
	return -EINVAL;
}

static unsigned int bnotify_poll(struct file *f, struct poll_table_struct *pt)
{
	struct bnotify_file *bf = f->private_data;
	unsigned int events = 0;

	poll_wait(f, &bf->wq, pt);
	spin_lock(&bnotify_lock);
	if (!list_empty(&bf->block_list))
		events = POLLIN | POLLRDNORM;
	spin_unlock(&bnotify_lock);

	return events;
}

static long bnotify_add_entry(struct bnotify_file *f)
{
	struct bnotify_entry *entry;
	int rc;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		rc = -ENOMEM;
		goto err;
	}
	entry->module = THIS_MODULE;
	if (!try_module_get(entry->module)) {
		rc = -EBUSY;
		goto err2;
	}
	INIT_LIST_HEAD(&entry->block_link);
	preempt_notifier_init(&entry->notifier,  &bnotify_preempt_ops);
	spin_lock(&bnotify_lock);
	entry->pid = current->pid;
	if (__bnotify_insert_entry(entry)) {
		rc = -EEXIST;
		goto err3;;
	}
	list_add(&entry->link, &f->entry_list);
	entry->file = f;
	preempt_notifier_register(&entry->notifier);
	spin_unlock(&bnotify_lock);

	return 0;
err3:
	spin_unlock(&bnotify_lock);
	module_put(entry->module);
err2:
	kfree(entry);
err:
	return rc;
}

static long bnotify_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	int rc;
	struct bnotify_file *bf = f->private_data;

	switch (cmd) {
	case BNOTIFY_IOCADD:
		rc = bnotify_add_entry(bf);
		break;
	default:
		rc = -EINVAL;
	}

	return rc;
}

static int bnotify_open(struct inode *inode, struct file *f)
{
	struct bnotify_file *bf = kmalloc(sizeof(*bf), GFP_KERNEL);

	if (!bf)
		return -ENOMEM;
	INIT_LIST_HEAD(&bf->entry_list);
	INIT_LIST_HEAD(&bf->block_list);
	INIT_LIST_HEAD(&bf->wake_list);
	init_waitqueue_head(&bf->wq);
	f->private_data = bf;

	return 0;
}

static int bnotify_release(struct inode *inode, struct file *f)
{
	struct bnotify_file *bf = f->private_data;
	struct bnotify_entry *entry, *next;
	struct bnotify_wake *wake, *wake_next;

	spin_lock(&bnotify_lock);
	list_for_each_entry_safe(entry, next, &bf->entry_list, link) {
		list_del_init(&entry->link);
		list_del_init(&entry->block_link);
		entry->file = NULL;
	}
	list_for_each_entry_safe(wake, wake_next, &bf->wake_list, link) {
		list_del_init(&wake->link);
		wake->file = NULL;
	}
	spin_unlock(&bnotify_lock);
	synchronize_sched();
	kfree(bf);

	return 0;
}

static const struct file_operations bnotify_fops = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.read		= bnotify_read,
	.write		= bnotify_write,
	.poll		= bnotify_poll,
	.unlocked_ioctl	= bnotify_ioctl,
	.compat_ioctl	= bnotify_ioctl,
	.open		= bnotify_open,
	.release	= bnotify_release,
};

static struct miscdevice bnotify_miscdev = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "bnotify",
	.fops		= &bnotify_fops,
	.mode		= 0666,
};

static int __init init(void)
{
	int retval = -ENOMEM;

	if (!bnotify_hash_table_size)
		bnotify_hash_table_size = PAGE_SIZE /
			sizeof(*bnotify_hash_table);
	bnotify_hash_table = bnotify_alloc_hash_table(&bnotify_hash_table_size);
	if (!bnotify_hash_table_size)
		goto err;

	bnotify_wq = alloc_workqueue("bnotify_wq", 0, 0);
	if (!bnotify_wq)
		goto err2;

	retval = misc_register(&bnotify_miscdev);
	if (retval)
		goto err3;

	return 0;
err3:
	destroy_workqueue(bnotify_wq);
err2:
	bnotify_free_hash_table(bnotify_hash_table, bnotify_hash_table_size);
err:
	return retval;
}
module_init(init);

static void __exit fini(void)
{
	misc_deregister(&bnotify_miscdev);
	destroy_workqueue(bnotify_wq);
	synchronize_sched();
	bnotify_free_hash_table(bnotify_hash_table, bnotify_hash_table_size);
}
module_exit(fini);
