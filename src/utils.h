/*
 * Copyright (C) 2017 Jianhui Zhao <jianhuizhao329@gmail.com>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _UTILS_H
#define _UTILS_H

#include <stdbool.h>

int get_iface_ip(const char *ifname, char *dst, int len);
int get_iface_mac(const char *ifname, char *dst, int len);
int arp_get(const char *ifname, const char *ip, char *dst, int len);

int enable_kmod(bool enable, const char *interface, int port, int ssl_port);
int allow_termianl(const char *mac, const char *token, bool temporary);
void termianl_temppass_init();
int deny_termianl(const char *mac);
int allow_destip(const char *ip);

#endif
