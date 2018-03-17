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

static void parse_whitelist_domain()
{
    struct config *conf = get_config();
    struct whitelist_domain *d;
    static bool parsed;

    if (parsed)
        return;

    avl_for_each_element(&conf->whitelist_domains, d, avl) {
        allow_domain(d->domain);
    }

    allow_domain(conf->authserver.host);
}

static void check_internet_available_cb(struct hostent *he, void *data)
{
    struct config *conf = get_config();

    if (he) {
        if (offline_time == -1 || offline_time > 0) {
            ULOG_INFO("Internet became available\n");

            offline_time = 0;

            start_heartbeat();
            start_counters();
            parse_whitelist_domain();
            enable_kmod(conf->gw_interface);
        }
    } else {
        struct popular_server *p = data;

        ULOG_INFO("Internet became not available\n");

        if (avl_is_last(&conf->popular_servers, &p->avl)) {
            offline_time += conf->checkinterval;

            if (offline_time / conf->checkinterval > 2) {
                stop_heartbeat();
                stop_counters();
                disable_kmod();

                ULOG_INFO("Internet not available too long\n");
            }
        } else {
            p = avl_next_element(p, avl);
            resolv_start(p->host, check_internet_available_cb, p);
        }
    }
}

static void check_internet(struct uloop_timeout *t)
{
    struct config *conf = get_config();
    struct popular_server *p;

    uloop_timeout_set(t, 1000 * conf->checkinterval);

    p = avl_first_element(&conf->popular_servers, p, avl);
    resolv_start(p->host, check_internet_available_cb, p);
}

static struct uloop_timeout timeout = {
    .cb = check_internet
};

void start_check_internet()
{
    check_internet(&timeout);
}
