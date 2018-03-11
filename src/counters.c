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

#include <sys/sysinfo.h>
#include <uhttpd/uhttpd.h>
#include <libubox/ulog.h>
#include <libubox/utils.h>
#include <libubox/blobmsg_json.h>

#include "auth.h"
#include "http.h"
#include "auth.h"
#include "utils.h"
#include "config.h"

enum {
    COUNTERS_RESP,
    _COUNTERS_MAX
};

static const struct blobmsg_policy counters_pol[] = {
    [COUNTERS_RESP] = {
        .name = "resp",
        .type = BLOBMSG_TYPE_ARRAY
    }
};

enum {
    COUNTERS_RESP_MAC,
    COUNTERS_RESP_AUTH,
    _COUNTERS_RESP_MAX
};

static const struct blobmsg_policy resp_pol[] = {
   [COUNTERS_RESP_MAC] = {
       .name = "mac",
       .type = BLOBMSG_TYPE_STRING
   },
   [COUNTERS_RESP_AUTH] = {
       .name = "auth",
       .type = BLOBMSG_TYPE_INT32
   }
};

static void counters_cb(void *data, char *body)
{
    static struct blob_buf b;
    struct blob_attr *tb[_COUNTERS_RESP_MAX];

    if (!body)
        return;

    blobmsg_buf_init(&b);

    if (!blobmsg_add_json_from_string(&b, body)) {
        ULOG_ERR("counters: invalid resp format\n");
        blob_buf_free(&b);
        return;
    }

    blobmsg_parse(counters_pol, _COUNTERS_MAX, tb, blob_data(b.head), blob_len(b.head));

    if (tb[COUNTERS_RESP]) {
        int rem;
        struct blob_attr *item;

        blobmsg_for_each_attr(item, blobmsg_data(tb[COUNTERS_RESP]), rem) {
            blobmsg_parse(resp_pol, _COUNTERS_RESP_MAX, tb, blobmsg_data(item), blobmsg_data_len(item));

            if (tb[COUNTERS_RESP_MAC]) {
                if (tb[COUNTERS_RESP_AUTH] && blobmsg_get_u32(tb[COUNTERS_RESP_AUTH])) {
                    deny_termianl(blobmsg_data(tb[COUNTERS_RESP_MAC]));
                }
            }
        }
    }

    blob_buf_free(&b);
}

static void counters(struct uloop_timeout *t)
{
    FILE *fp = NULL;
    char buf[1024], *p, *mac, *ip, *rx, *tx, *uptime, *state, *token;
    struct config *conf = get_config();
    struct blob_buf b;
    void *tbl, *array;

    uloop_timeout_set(t, 1000 * conf->checkinterval);

    fp = fopen("/proc/wifidog-ng/term", "r");
    if (!fp) {
        ULOG_ERR("fopen:%s\n", strerror(errno));
        return;
    }

    memset(&b, 0, sizeof(b));
    blobmsg_buf_init(&b);

    array = blobmsg_open_array(&b, "counters");

    while (1) {
        if (!fgets(buf, sizeof(buf), fp))
            break;

        if (buf[0] == 'M')
            continue;

        p = buf;

        mac = strtok(p, " ");
        ip = strtok(NULL, " ");
        rx = strtok(NULL, " ");
        tx = strtok(NULL, " ");
        uptime = strtok(NULL, " ");
        state = strtok(NULL, " ");
        token = strtok(NULL, " ");

        if (!token || *token == 0)
            continue;

        p = strrchr(token, '\n');
        if (p)
            *p = 0;

        if (state[0] == '3') {
            ULOG_INFO("Client(%s) timeout\n", mac);
            authserver_request(NULL, "logout", ip, mac, token);
            deny_termianl(mac);
            continue;
        }

        if (state[0] == '2') {
            tbl = blobmsg_open_table(&b, "");
            blobmsg_add_string(&b, "ip", ip);
            blobmsg_add_string(&b, "mac", mac);
            blobmsg_add_string(&b, "token", token);
            blobmsg_add_string(&b, "uptime", uptime);
            blobmsg_add_u64(&b, "incoming", atoll(rx));
            blobmsg_add_u64(&b, "outgoing", atoll(tx));
            blobmsg_close_table(&b, tbl);
        }
    }

    blobmsg_close_table(&b, array);
    p = blobmsg_format_json(b.head, true);
    httppost(counters_cb, NULL, p, "%s&stage=counters", conf->auth_url);

    free(p);
    blob_buf_free(&b);
}

static struct uloop_timeout timeout = {
    .cb = counters
};

void start_counters()
{
    uloop_timeout_set(&timeout, 0);
}

void stop_counters()
{
    uloop_timeout_cancel(&timeout);
}
