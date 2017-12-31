/*
 *	Copyright (C) 2017 jianhui zhao <jianhuizhao329@gmail.com>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2 as
 *	published by the Free Software Foundation.
 */
 
#ifndef __IP_MANAGE_
#define __IP_MANAGE_

#include <linux/types.h>

struct ip_entry {
	struct hlist_node	hlist;
	__be32	addr;
};

int ip_manage_init(struct proc_dir_entry *proc);
void ip_manage_free(struct proc_dir_entry *proc);
int allow_dest_ip(__be32 addr);
int allowed_dest_ip(__be32 addr);

#endif
