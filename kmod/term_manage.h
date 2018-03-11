/*
 *  Copyright (C) 2017 jianhui zhao <jianhuizhao329@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */
 
#ifndef __TERM_MANAGE_
#define __TERM_MANAGE_

#include <linux/types.h>
#include <linux/if_ether.h>

enum term_state {
    TERM_STATE_UNKNOWN,
    TERM_STATE_TEMPPASS,
    TERM_STATE_AUTHED,
    TERM_STATE_TIMEOUT
};

struct term_flow {
    u64 tx;
    u64 rx;
};

struct terminal {
    struct hlist_node node;
    __be32 ip;
    u8 mac[ETH_ALEN];
    u8 token[33];
    enum term_state state;
    u32 auth_time;
    struct term_flow flow;
    struct timer_list timer;
};

int term_init(struct proc_dir_entry *proc);
void term_free(struct proc_dir_entry *proc);

struct terminal *find_term_by_mac(const u8 *mac);
int add_term(u8 *mac, __be32 ip);
void update_term(struct terminal *term);
int term_is_allowed(const u8 *mac);

#endif

