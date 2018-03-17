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

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <avl.h>
#include <string.h>
#include <stdlib.h>

struct auth_server {
    int port;
    char *host;
    char *path;
    char *login_path;
    char *portal_path;
    char *msg_path;
    char *ping_path;
    char *auth_path;
};

struct popular_server {
    struct avl_node avl;
    char host[0];
};

struct whitelist_domain {
    struct avl_node avl;
    char domain[0];
};

struct config {
    const char *gw_interface;
    const char *gw_address;
    const char *gw_id;
    const char *ssid;
    int gw_port;
    int gw_ssl_port;
    int checkinterval;
    int clienttimeout;
    int temppass_time;

    struct auth_server authserver;
    struct avl_tree popular_servers;
    struct avl_tree whitelist_domains;

    char *login_url;
    char *auth_url;
    char *portal_url;
    char *ping_url;
    char *msg_url;
};

int parse_config();

struct config *get_config();
int init_authserver_url();

static inline void alloc_authserver_option(char **option, const char *value)
{
    free(*option);
    *option = strdup(value);
}

#endif
