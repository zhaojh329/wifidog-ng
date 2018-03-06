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

#ifndef _UTILS_H
#define _UTILS_H

#include <stdbool.h>

int get_iface_ip(const char *ifname, char *dst, int len);
int get_iface_mac(const char *ifname, char *dst, int len);
int arp_get(const char *ifname, const char *ip, char *dst, int len);

int allow_destip(const char *ip);
int allow_domain(const char *domain);

int urlencode(char *buf, int blen, const char *src, int slen);

void wifidog_runqueue_init();
void wifidog_runqueue_finish();

int enable_kmod(const char *interface, int port, int ssl_port);
int disable_kmod();

#endif
