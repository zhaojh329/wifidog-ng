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

#ifndef _TEMPPASS_H
#define _TEMPPASS_H

#include <stdbool.h>
#include <netinet/in.h>
#include <libubox/avl.h>
#include <libubox/uloop.h>

struct termianl {
	bool authed;
	char token[32];
	char mac[18];
	uint64_t last_rx;
	uint64_t last_tx;
	time_t last_update;
	struct avl_node node;
	struct uloop_timeout timer;
};

void termianl_init();
int allow_termianl(const char *mac, const char *token, bool temporary);
int deny_termianl(const char *mac);
struct termianl *find_element(const  char *mac);

#endif
