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
 
#ifndef __TERMINAL_
#define __TERMINAL_

#include <linux/types.h>
#include <linux/if_ether.h>

#define TERM_ACTIVE		(1 << 0)
#define TERM_AUTHED		(1 << 1)

struct term_flow {
	u64 tx;
	u64 rx;
};

struct terminal {
	struct hlist_node node;
	__be32 ip;
	u8 mac[ETH_ALEN];
	u8 active;
	u32 j;
	u8 flags;
	struct term_flow flow;
	struct timer_list expires;
};

int term_init(struct proc_dir_entry *proc);
void term_free(struct proc_dir_entry *proc);

struct terminal *find_term_by_ip(__be32 ip);
int add_term(u8 *mac, __be32 ip);
int term_is_authd(__be32 ip);

#endif

