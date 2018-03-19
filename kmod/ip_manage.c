/*
 *  Copyright (C) 2017 jianhui zhao <jianhuizhao329@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/inet.h>

#include "config.h"
#include "ip_manage.h"

#define TIP_HASH_SIZE 128

static rwlock_t ip_lock;
static struct hlist_head ipe_hash_table[TIP_HASH_SIZE];
static struct kmem_cache *ipe_cache __read_mostly;

static inline u32 ip_hash_func(u32 addr)
{
    return addr & (TIP_HASH_SIZE - 1);
}

static struct ip_entry *ipe_alloc(__be32 addr)
{
    struct ip_entry *e = NULL;

    e = kmem_cache_zalloc(ipe_cache, GFP_ATOMIC);
    if (e == NULL) {
        pr_err("ipe_cache: alloc failed\n");
        return NULL;
    }

    INIT_HLIST_NODE(&e->hlist);
    e->addr = addr;

    return e;
}

static inline struct ip_entry *ipe_find(__be32 addr, struct hlist_head *head)
{
    struct ip_entry *pos;

    hlist_for_each_entry(pos, head, hlist) {
        if (addr == pos->addr)
            return pos;
    }

    return NULL;
}

static void del_ipe(__be32 addr)
{
    u32 hash;
    struct ip_entry *e;

    hash = ip_hash_func(addr);

    write_lock_bh(&ip_lock);
    e = ipe_find(addr, &ipe_hash_table[hash]);
    if(e) {
        hlist_del(&e->hlist);
        kmem_cache_free(ipe_cache, e);
    }
    write_unlock_bh(&ip_lock);
}

static void ipe_clear(void)
{
    int i;
    struct hlist_head *chain;
    struct hlist_node *next;
    struct ip_entry *pos;

    if (!ipe_cache)
        return;

    write_lock_bh(&ip_lock);
    for (i = 0; i != TIP_HASH_SIZE; i++) {
        chain = &ipe_hash_table[i];
        hlist_for_each_entry_safe(pos, next, chain, hlist) {
            hlist_del(&pos->hlist);
            kmem_cache_free(ipe_cache, pos);
        }
    }
    write_unlock_bh(&ip_lock);
}

int allowed_dest_ip(__be32 addr)
{
    int ret = 0;
    u32 hash = ip_hash_func(addr);

    read_lock_bh(&ip_lock);
    if(ipe_find(addr, &ipe_hash_table[hash]))
        ret = 1;

    read_unlock_bh(&ip_lock);
    return ret;
}

int allow_dest_ip(__be32 addr)
{
    u32 hash;
    struct ip_entry *e;

    hash = ip_hash_func(addr);

    read_lock_bh(&ip_lock);
    if(ipe_find(addr, &ipe_hash_table[hash])) {
        read_unlock_bh(&ip_lock);
    } else {
        read_unlock_bh(&ip_lock);

        e = ipe_alloc(addr);
        if (!e)
            return -ENOMEM;

        write_lock_bh(&ip_lock);
        hlist_add_head(&e->hlist, &ipe_hash_table[hash]);
        write_unlock_bh(&ip_lock);
    }

    return 0;
}

static void *ip_seq_start(struct seq_file *s, loff_t *pos)
{
    read_lock_bh(&ip_lock);

    if (*pos == 0)
        return SEQ_START_TOKEN;

    if (*pos >= TIP_HASH_SIZE)
        return NULL;

    return &ipe_hash_table[*pos];
}

static void *ip_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
    if (v == SEQ_START_TOKEN)
        (*pos) = 0;
    else
        (*pos)++;

    if (*pos >= TIP_HASH_SIZE) {
        return NULL;
    }

    return &ipe_hash_table[*pos];
}

static void ip_seq_stop(struct seq_file *s, void *v)
{
    read_unlock_bh(&ip_lock);
}

static int ip_seq_show(struct seq_file *s, void *v)
{
    struct hlist_head *head = v;
    struct ip_entry *pos;

    if (v == SEQ_START_TOKEN) {
        seq_printf(s, "--------------Allowed IP Address To-------------\n");
    } else {
        hlist_for_each_entry(pos, head, hlist) {
            seq_printf(s, "\t%pI4\t\n", &(pos->addr));
        }
    }

    return 0;
}

static struct seq_operations allowed_dest_ip_seq_ops = {
    .start = ip_seq_start,
    .next = ip_seq_next,
    .stop = ip_seq_stop,
    .show = ip_seq_show
};

static int proc_ip_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &allowed_dest_ip_seq_ops);
}

static ssize_t proc_ip_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
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
        ipe_clear();
    else {
        __be32 addr;
        char op;

        if (!in4_pton(data + 1, -1, (u8 *)&addr, -1, NULL)) {
            pr_err("invalid format: %s\n", data);
            goto QUIT;
        }

        op = data[0];

        if (op == '+')
            allow_dest_ip(addr);
        else if (op == '-')
            del_ipe(addr);
        else
            pr_err("invalid format: %s\n", data);
    }

QUIT:
    return size;
}

static const struct file_operations proc_ops = {
    .owner      = THIS_MODULE,
    .open       = proc_ip_open,
    .read       = seq_read,
    .write      = proc_ip_write,
    .llseek     = seq_lseek,
    .release    = seq_release
};

int ip_manage_init(struct proc_dir_entry *proc)
{
    int ret;
    int i = 0;

    ipe_cache = kmem_cache_create("ipe_cache", sizeof(struct ip_entry), 0, 0, NULL);
    if (!ipe_cache)
        return -ENOMEM;

    rwlock_init(&ip_lock);

    for (i = 0; i < TIP_HASH_SIZE; i++)
        INIT_HLIST_HEAD(&ipe_hash_table[i]);

    if (!proc_create("ip", 0644, proc, &proc_ops)) {
        pr_err("can't create file /proc/"PROC_DIR_NAME"/ip\n");
        ret = -EINVAL;
        goto free_cache;
    }

    return 0;

free_cache:
    kmem_cache_destroy(ipe_cache);
    return ret;
}

void ip_manage_free(struct proc_dir_entry *proc)
{
    ipe_clear();
    remove_proc_entry("ip", proc);
    kmem_cache_destroy(ipe_cache);
}
