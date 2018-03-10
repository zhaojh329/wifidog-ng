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

#include <libubox/ulog.h>
#include <libubus.h>
#include "utils.h"
#include "config.h"
#include "counters.h"

static struct ubus_context *ctx;

enum {
    STATUS_INTERNET,
    __STATUS_MAX
};

static const struct blobmsg_policy status_policy[] = {
    [STATUS_INTERNET] = { .name = "internet", .type = BLOBMSG_TYPE_BOOL },
};

static int server_status(struct ubus_context *ctx, struct ubus_object *obj,
             struct ubus_request_data *req, const char *method,
             struct blob_attr *msg)
{

    return 0;
}

static const struct ubus_method wifidog_methods[] = {
    UBUS_METHOD("status", server_status, status_policy)
};

static struct ubus_object_type wifidog_object_type =
    UBUS_OBJECT_TYPE("wifidog", wifidog_methods);

static struct ubus_object server_object = {
    .name = "wifidog",
    .type = &wifidog_object_type,
    .methods = wifidog_methods,
    .n_methods = ARRAY_SIZE(wifidog_methods),
};

int wifidog_ubus_init()
{
    int ret;

    ctx = ubus_connect(NULL);
    if (!ctx) {
        ULOG_ERR("Failed to connect to ubus\n");
        return -1;
    }

    ubus_add_uloop(ctx);

    ret = ubus_add_object(ctx, &server_object);
    if (ret) {
        ULOG_ERR("Failed to add server object: %s\n", ubus_strerror(ret));
        return -1;
    }
    return 0;
}
