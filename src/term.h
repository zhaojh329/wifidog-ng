/*
 * Copyright (C) 2017 Jianhui Zhao <jianhuizhao329@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 * USA
 */

#ifndef _TERM_H
#define _TERM_H

#include <avl.h>
#include <libubox/uloop.h>

#define IPSET_PERMANENT_TIME    (100 * 24 * 60 * 60)
#define IPSET_MAC               "wifidog-ng-mac"
#define IPSET_IP                "wifidog-ng-ip"

enum {
    TERM_FLAG_AUTHED = (1 << 0),
    TERM_FLAG_TIMEOUT = (1 << 1),
    TERM_FLAG_WISPR = (1 << 2),
};

struct terminal {
    uint8_t flag;
    char mac[18];
    char ip[16];
    char token[33];
    uint32_t tx;    /* outgoing */
    uint32_t rx;    /* incoming */
    time_t auth_time;
    struct avl_node avl;
    struct uloop_timeout timeout;
};

extern struct avl_tree term_tree;

int term_init();
void term_deinit();

void allow_term(const char *mac, bool temporary);
void deny_term(const char *mac);

struct terminal *term_new(const char *mac, const char *ip);
struct terminal *find_term(const char *mac);
void del_term(struct terminal *term);
void del_term_by_mac(const char *mac);
void auth_term_by_mac(const char *mac, const char *token);

#endif
