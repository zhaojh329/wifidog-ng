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

#ifndef _HTTP_H
#define _HTTP_H

#include <stdlib.h>
#include <uhttpd/uhttpd.h>
#include <libubox/uclient.h>

typedef void (*http_cb)(void *data, char *content);

int httppost(http_cb cb, void *data, const char *post_data, const char *url, ...);

#define httpget(cb, data, url...) httppost(cb, data, NULL, url)

#endif

