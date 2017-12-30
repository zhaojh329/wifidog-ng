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
#include <linux/etherdevice.h>
#include <linux/inet.h>
#include <linux/jhash.h>
#include "terminal.h"

#define TERM_TTL					60
#define TERM_HASH_SIZE 				(1 << 8)

static u32 hash_rnd __read_mostly;
static rwlock_t term_ip_lock;
static struct hlist_head term_ip_hash_table[TERM_HASH_SIZE];
static struct kmem_cache *term_cache __read_mostly;

static inline u32 term_ip_hash4(__be32 ip)
{
	return jhash_1word((__force u32)ip, hash_rnd) & (TERM_HASH_SIZE - 1);
}

static int term_mark_authed(__be32 ip)
{
	struct terminal *term;
	u32 hash = term_ip_hash4(ip);

	read_lock_bh(&term_ip_lock);
	hlist_for_each_entry(term, &term_ip_hash_table[hash], node) {
		if (term->ip == ip) {
			term->flags |= TERM_AUTHED;
			read_unlock_bh(&term_ip_lock);
			return 0;
		}
	}
	read_unlock_bh(&term_ip_lock);
	return -1;
}

static int term_mark_denied(__be32 ip)
{
	struct terminal *term;
	u32 hash = term_ip_hash4(ip);

	read_lock_bh(&term_ip_lock);
	hlist_for_each_entry(term, &term_ip_hash_table[hash], node) {
		if (term->ip == ip) {
			term->flags &= ~TERM_AUTHED;
			read_unlock_bh(&term_ip_lock);
			return 0;
		}
	}
	read_unlock_bh(&term_ip_lock);
	return -1;
}

int term_is_authd(__be32 ip)
{
	struct terminal *term = find_term_by_ip(ip);
	if (term && (term->flags & TERM_AUTHED))
		return 1;
	return 0;
}

static void term_clear(void)
{
	int i;
	struct hlist_head *chain;
	struct hlist_node *next;
	struct terminal *pos;
	
	if (!term_cache)
		return;
	
	write_lock_bh(&term_ip_lock);
	for (i = 0; i != TERM_HASH_SIZE; i++) {
		chain = &term_ip_hash_table[i];
		hlist_for_each_entry_safe(pos, next, chain, node) {
			hlist_del(&pos->node);
			del_timer(&pos->expires);
			kmem_cache_free(term_cache, pos);
		}

	}
	write_unlock_bh(&term_ip_lock);
}

static void *term_seq_start(struct seq_file *s, loff_t *pos)
{
	read_lock_bh(&term_ip_lock);

	if (*pos == 0)
		return SEQ_START_TOKEN;
	
	if (*pos >= TERM_HASH_SIZE)
		return NULL;

	return &term_ip_hash_table[*pos];
}

static void *term_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	if (v == SEQ_START_TOKEN)
		(*pos) = 0;
	else
		(*pos)++;

	if (*pos >= TERM_HASH_SIZE) {
		return NULL;
	}

	return &term_ip_hash_table[*pos];
}

static void term_seq_stop(struct seq_file *s, void *v)
{
	read_unlock_bh(&term_ip_lock);
}

static int term_seq_show(struct seq_file *s, void *v)
{
	struct hlist_head *head = v;
	struct terminal *term;
	struct timeval tv;
	u8 authed = 0;
	
	if (v == SEQ_START_TOKEN) {
		seq_printf(s, "%-17s  %-16s  %-16s  %-16s  %-14s  %-7s\n", "MAC", "IP", "Rx", "Tx", "Time", "Authed");
	} else {
		hlist_for_each_entry(term, head, node) {
			jiffies_to_timeval(jiffies - term->j, &tv);
			if (term->flags & TERM_AUTHED)
				authed = 1;
			seq_printf(s, "%pM  %-16pI4  %-16llu  %-16llu  %-14ld  %-7d\n", 
				term->mac, &(term->ip), term->flow.rx, term->flow.tx, tv.tv_sec, authed);
		}
	}

	return 0;
}

static struct seq_operations term_seq_ops = {
	.start = term_seq_start,
	.next = term_seq_next,
	.stop = term_seq_stop,
	.show = term_seq_show
};

static int proc_term_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &term_seq_ops);
}

static ssize_t proc_term_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
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
		term_clear();
	else {
		__be32 addr;
		char op;
		
		if (!in4_pton(data + 1, -1, (u8 *)&addr, -1, NULL)) {
			pr_err("invalid format: %s\n", data);
			goto QUIT;
		}
		
		op = data[0];
		
		if (op == '+')
			term_mark_authed(addr);
		else if (op == '-')
			term_mark_denied(addr);
		else
			pr_err("invalid format: %s\n", data);
	}

QUIT:			
	return size;
}	

static const struct file_operations proc_term_ops = {
	.owner 		= THIS_MODULE,
	.open  		= proc_term_open,
	.read   	= seq_read,
	.write 		= proc_term_write,
	.llseek 	= seq_lseek,
	.release 	= seq_release
};

static inline void term_timer_refresh(struct terminal *term, u32 timeout)
{
	mod_timer(&term->expires, jiffies + timeout * HZ);
}

static void term_timer_timeout(unsigned long ptr)
{
	struct terminal *term = (struct terminal *)ptr;

	if (!(term->flags & TERM_ACTIVE)) {
		write_lock_bh(&term_ip_lock);
		hlist_del(&term->node);
		write_unlock_bh(&term_ip_lock);		
		kmem_cache_free(term_cache, term);
	} else {
		term->active &= ~TERM_ACTIVE;
		term_timer_refresh(term, TERM_TTL);
	}
}

static struct terminal *term_alloc(void)
{
	struct terminal *term = NULL;
	
	term = kmem_cache_zalloc(term_cache, GFP_ATOMIC);
	if (term == NULL) {
		pr_err("term_cache: alloc failed\n");
		return NULL;
	}
	
	return term;
}

struct terminal *find_term_by_ip(__be32 ip)
{
	struct terminal *term;
	u32 hash = term_ip_hash4(ip);

	read_lock_bh(&term_ip_lock);
	hlist_for_each_entry(term, &term_ip_hash_table[hash], node) {
		if (term->ip == ip) {
			read_unlock_bh(&term_ip_lock);
			return term;
		}
	}
	read_unlock_bh(&term_ip_lock);
	return NULL;
}

int add_term(u8 *mac, __be32 ip)
{
	struct terminal *term = NULL;
	u32 hash = term_ip_hash4(ip);
	
	term = term_alloc();
	if (!term)
		return -ENOMEM;

	term->j = jiffies;
	term->ip = ip;
	memcpy(term->mac, mac, ETH_ALEN);

	setup_timer(&term->expires, term_timer_timeout, (unsigned long)term);
	
	write_lock_bh(&term_ip_lock);
	hlist_add_head(&term->node, &term_ip_hash_table[hash]);
	write_unlock_bh(&term_ip_lock);

	term_timer_refresh(term, TERM_TTL);
	
	return 0;
}

int term_init(struct proc_dir_entry *proc)
{
	int ret, i;

	net_get_random_once(&hash_rnd, sizeof(hash_rnd));

	rwlock_init(&term_ip_lock);

	for (i = 0; i < TERM_HASH_SIZE; i++) {
		INIT_HLIST_HEAD(&term_ip_hash_table[i]);
	}
	
	term_cache = kmem_cache_create("term_cache", sizeof(struct terminal), 0, 0, NULL);
	if (!term_cache)
		return -ENOMEM;

	if (!proc_create("term", 0644, proc, &proc_term_ops)) {
		pr_err("can't create file /proc/wifidog/term\n");
		ret = -EINVAL;
		goto free_cache;
	}
	
	return 0;

free_cache:
	kmem_cache_destroy(term_cache);
	return ret;
}

void term_free(struct proc_dir_entry *proc)
{
	term_clear();
	remove_proc_entry("term", proc);
	kmem_cache_destroy(term_cache);
}

