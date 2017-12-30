/*
 * Copyright (C) 2017 jianhui zhao <jianhuizhao329@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/inet.h>
#include "tip.h"

#define TIP_HASH_SIZE 128

static rwlock_t tip_lock;
static struct hlist_head tip_hash_table[TIP_HASH_SIZE];
static struct kmem_cache *tip_cache __read_mostly;

static inline u32 tip_hash_func(u32 addr)
{
	return addr & (TIP_HASH_SIZE - 1);
}

static struct tip_entry *tip_alloc(__be32 addr)
{
	struct tip_entry *tip = NULL;
	
	tip = kmem_cache_zalloc(tip_cache, GFP_ATOMIC);
	if (tip == NULL) {
		pr_err("tip_cache: alloc failed\n");
		return NULL;
	}
	
	INIT_HLIST_NODE(&tip->hlist);
	tip->addr = addr;
	
	return tip;
}

static inline struct tip_entry *tip_find(__be32 addr, struct hlist_head *head)
{
	struct tip_entry *pos;

	hlist_for_each_entry(pos, head, hlist) {
		if (addr == pos->addr)
			return pos;
	}
	
	return NULL;
}

static void del_tip(__be32 addr)
{
	u32 hash;
	struct tip_entry *tip;
	
	hash = tip_hash_func(addr);
	
	write_lock_bh(&tip_lock);
	tip = tip_find(addr, &tip_hash_table[hash]);
	if(tip) {
		hlist_del(&tip->hlist);
		kmem_cache_free(tip_cache, tip);
	}
	write_unlock_bh(&tip_lock);
}

static void tip_clear(void)
{
	int i;
	struct hlist_head *chain;
	struct hlist_node *next;
	struct tip_entry *pos;
	
	if (!tip_cache)
		return;
	
	write_lock_bh(&tip_lock);
	for (i = 0; i != TIP_HASH_SIZE; i++) {
		chain = &tip_hash_table[i];
		hlist_for_each_entry_safe(pos, next, chain, hlist) {
			hlist_del(&pos->hlist);
			kmem_cache_free(tip_cache, pos);
		}

	}
	write_unlock_bh(&tip_lock);
}

int trusted_ip(__be32 addr)
{
	int ret = 0;
	u32 hash = tip_hash_func(addr);
	
	read_lock_bh(&tip_lock);
	if(tip_find(addr, &tip_hash_table[hash]))
		ret = 1;
	
	read_unlock_bh(&tip_lock);
	return ret;
}

int add_tip(__be32 addr)
{
	u32 hash;
	struct tip_entry *tip;
	
	hash = tip_hash_func(addr);
	
	read_lock_bh(&tip_lock);
	if(tip_find(addr, &tip_hash_table[hash])) {
		read_unlock_bh(&tip_lock);
	} else {
		read_unlock_bh(&tip_lock);
		
		tip = tip_alloc(addr);
		if (!tip)
			return -ENOMEM;
		
		write_lock_bh(&tip_lock);
		hlist_add_head(&tip->hlist, &tip_hash_table[hash]);
		write_unlock_bh(&tip_lock);
	}
	
	return 0;
}

static void *trusted_ip_seq_start(struct seq_file *s, loff_t *pos)
{
	read_lock_bh(&tip_lock);

	if (*pos == 0)
		return SEQ_START_TOKEN;
	
	if (*pos >= TIP_HASH_SIZE)
		return NULL;

	return &tip_hash_table[*pos];
}

static void *trusted_ip_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	if (v == SEQ_START_TOKEN)
		(*pos) = 0;
	else
		(*pos)++;

	if (*pos >= TIP_HASH_SIZE) {
		return NULL;
	}

	return &tip_hash_table[*pos];
}

static void trusted_ip_seq_stop(struct seq_file *s, void *v)
{
	read_unlock_bh(&tip_lock);
}

static int trusted_ip_seq_show(struct seq_file *s, void *v)
{
	struct hlist_head *head = v;
	struct tip_entry *pos;
	
	if (v == SEQ_START_TOKEN) {
		seq_printf(s, "--------------Trusted IP Address-------------\n");
	} else {
		hlist_for_each_entry(pos, head, hlist) {
			seq_printf(s, "\t%pI4\t\n", &(pos->addr));
		}
	}

	return 0;
}

static struct seq_operations trusted_ip_seq_ops = {
	.start = trusted_ip_seq_start,
	.next = trusted_ip_seq_next,
	.stop = trusted_ip_seq_stop,
	.show = trusted_ip_seq_show
};

static int proc_trusted_ip_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &trusted_ip_seq_ops);
}

static ssize_t proc_trusted_ip_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
{
	char data[128];
	
	if (size == 0)
		return -EINVAL;

	if (size > sizeof(data))
		size = sizeof(data);
	
	if (copy_from_user(data, buf, size))
		return -EFAULT;
	
	data[size - 1] = 0;

	if (!strncmp(data, "clear", 5))
		tip_clear();
	else {
		__be32 addr;
		char op;
		
		if (!in4_pton(data + 1, -1, (u8 *)&addr, -1, NULL)) {
			pr_err("invalid format: %s\n", data);
			goto QUIT;
		}
		
		op = data[0];
		
		if (op == '+')
			add_tip(addr);
		else if (op == '-')
			del_tip(addr);
		else
			pr_err("invalid format: %s\n", data);
	}

QUIT:			
	return size;
}							

static const struct file_operations proc_trusted_ip_ops = {
	.owner 		= THIS_MODULE,
	.open  		= proc_trusted_ip_open,
	.read   	= seq_read,
	.write 		= proc_trusted_ip_write,
	.llseek 	= seq_lseek,
	.release 	= seq_release
};

int tip_init(struct proc_dir_entry *proc)
{
	int ret;
	int i = 0;
	
	tip_cache = kmem_cache_create("tip_cache", sizeof(struct tip_entry), 0, 0, NULL);
	if (!tip_cache)
		return -ENOMEM;
	
	rwlock_init(&tip_lock);
	
	for (i = 0; i < TIP_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&tip_hash_table[i]);

	if (!proc_create("trusted_ip", 0644, proc, &proc_trusted_ip_ops)) {
		pr_err("can't create file /proc/wifidog/trusted_ip\n");
		ret = -EINVAL;
		goto free_cache;
	}
	
	return 0;
	
free_cache:
	kmem_cache_destroy(tip_cache);
	return ret;
}

void tip_free(struct proc_dir_entry *proc)
{
	tip_clear();
	remove_proc_entry("trusted_ip", proc);
	kmem_cache_destroy(tip_cache);
}
