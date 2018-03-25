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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libubox/ulog.h>
#include <uhttpd/uhttpd.h>

#include "version.h"
#include "ubus.h"
#include "auth.h"
#include "utils.h"
#include "resolv.h"
#include "config.h"
#include "ipset.h"
#include "term.h"
#include "bwmon.h"
#include "check_internet.h"

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [option]\n"
        "      -v           # verbose\n"
        , prog);
    exit(1);
}

int main(int argc, char **argv)
{
    int opt;
    bool verbose = false;
    struct config *conf = get_config();

    while ((opt = getopt(argc, argv, "v")) != -1) {
        switch (opt) {
        case 'v':
            verbose = true;
            break;
        default: /* '?' */
            usage(argv[0]);
        }
    }

    if (!verbose)
        ulog_threshold(LOG_ERR);

    ULOG_INFO("wifidog-ng version %s\n", WIFIDOG_NG_VERSION_STRING);

    if (parse_config())
        return -1;
    
    if (ipset_init() < 0)
        return -1;

    uloop_init();

    term_init();

    ipset_create("wifidog-ng-mac", "hash:mac", 86400);
    ipset_create("wifidog-ng-ip", "hash:ip", 0);

    ipset_flush("wifidog-ng-mac");
    ipset_flush("wifidog-ng-ip");

    resolv_init();

    if (auth_init() < 0)
        goto EXIT;

    wifidog_ubus_init();
    start_check_internet();
    bwmon_init(conf->gw_interface);

    uloop_run();

EXIT:
    bwmon_deinit();
    term_deinit();
    resolv_shutdown();
    ipset_destroy("wifidog-ng-mac");
    ipset_destroy("wifidog-ng-ip");
    ipset_deinit();
    uloop_done();
    ULOG_INFO("wifidog-ng exit.\n");
    
    return 0;
}
