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
#include <libubox/uloop.h>

#include "heartbeat.h"
#include "utils.h"
#include "config.h"
#include "resolv.h"
#include "counters.h"

static int offline_time = -1;

static void check_internet_available_cb(struct hostent *he, void *data)
{
    struct config *conf = get_config();

    if (he) {
        ULOG_INFO("Internet is available\n");

        if (offline_time == -1 || offline_time > 0) {
            offline_time = 0;

            start_heartbeat();
            start_counters();
            allow_domain(conf->authserver.host);
            enable_kmod(conf->gw_interface);
        }
    } else {
        struct popular_server *popular_server = data;

        ULOG_INFO("Internet is not available\n");

        if (popular_server->next) {
            resolv_start(popular_server->next->hostname, check_internet_available_cb, popular_server->next);
            return;
        }

        offline_time += conf->checkinterval;

        if (offline_time / conf->checkinterval > 2) {
            stop_heartbeat();
            stop_counters();
            disable_kmod();

            ULOG_INFO("Internet not available too long\n");
        }
    }
}

static void check_internet(struct uloop_timeout *t)
{
    struct config *conf = get_config();

    uloop_timeout_set(t, 1000 * conf->checkinterval);

    resolv_start(conf->popular_servers->hostname, check_internet_available_cb, conf->popular_servers);
}

static struct uloop_timeout timeout = {
    .cb = check_internet
};

void start_check_internet()
{
    /* Wait for network interface to be created */
    uloop_timeout_set(&timeout, 10000);
}
