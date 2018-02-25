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

#include <sys/sysinfo.h>
#include <uhttpd/uhttpd.h>
#include <libubox/ulog.h>

#include "http.h"
#include "config.h"

static time_t start_time;

static void ping_cb(void *data, char *body)
{
    if (!body || strcmp(body, "Pong"))
        ULOG_INFO("Auth server did NOT say Pong\n");
}

static void ping(struct uloop_timeout *t)
{
    struct config *conf = get_config();
    struct sysinfo info;

    uloop_timeout_set(t, 1000 * conf->checkinterval);

    memset(&info, 0, sizeof(info));
    
    if (sysinfo(&info) < 0) {
        ULOG_ERR("sysinfo:%s\n", strerror(errno));
        return;
    }

    httpget(ping_cb, NULL, "http://%s:%d%s%sgw_id=%s&sys_uptime=%ld&sys_memfree=%lu&sys_load=%lu&wifidog_uptime=%lu",
        conf->authserver.host, conf->authserver.port, conf->authserver.path, conf->authserver.ping_path,
        conf->gw_id, info.uptime, info.freeram * info.mem_unit, info.loads[0], time(NULL) - start_time);
}

void start_heartbeat()
{
    static struct uloop_timeout timeout = {
        .cb = ping
    };

    time(&start_time);
    
    uloop_timeout_set(&timeout, 0);
}

