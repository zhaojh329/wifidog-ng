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

#include "http.h"
#include "config.h"
#include "auth.h"
#include "termianl.h"

enum {
    COUNTERS_RESP
};

static const struct blobmsg_policy pol[] = {
    [COUNTERS_RESP] = {
        .name = "resp",
        .type = BLOBMSG_TYPE_ARRAY
    }
};

static void counters_cb(void *data, char *body)
{
    static struct blob_buf b;
    struct blob_attr *tb[ARRAY_SIZE(pol)];

    if (!body)
        return;

    blobmsg_buf_init(&b);

    if (!blobmsg_add_json_from_string(&b, body))
        return;

    if (blobmsg_parse(pol, ARRAY_SIZE(pol), tb, blob_data(b.head), blob_len(b.head)) != 0) {
        ULOG_ERR("Parse counters resp failed:%s\n", body);
        goto err;
    }

    if (tb[COUNTERS_RESP]) {
        struct blob_attr *attr;
        struct blob_attr *data = blobmsg_data(tb[COUNTERS_RESP]);
        int len = blobmsg_data_len(tb[COUNTERS_RESP]);

         __blob_for_each_attr(attr, data, len) {
             struct blob_attr *attr2;
             struct blob_attr *data2 = blobmsg_data(attr);
             int len2 = blobmsg_data_len(attr);
                const char *mac = NULL;
                int auth = 1;

             __blob_for_each_attr(attr2, data2, len2) {
                struct blobmsg_hdr *hdr = blob_data(attr2);

                if (!strcmp((const char *)hdr->name, "mac")) {
                    mac = blobmsg_get_string(attr2);
                } else {
                    auth = blobmsg_get_u32(attr2);
                }
             }

             if (mac && auth == 0) {
               deny_termianl(mac);
             }
         }
    }

err:
    blob_buf_free(&b);
}

static void counters(struct uloop_timeout *t)
{
    FILE *fp = NULL;
    char buf[1024], *p, *mac, *ip, *rx, *tx, *authed, *token;
    struct config *conf = get_config();
    struct blob_buf b;
    void *tbl, *array;

    uloop_timeout_set(t, 1000 * conf->checkinterval);

    fp = fopen("/proc/wifidog/term", "r");
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
        strtok(NULL, " ");
        authed = strtok(NULL, " ");
        token = strtok(NULL, " ");

        if (*authed != '1' || !token)
            continue;

        p = strrchr(token, '\n');
        if (p)
            *p = 0;

        tbl = blobmsg_open_table(&b, "");
        blobmsg_add_string(&b, "ip", ip);
        blobmsg_add_string(&b, "mac", mac);
        blobmsg_add_string(&b, "token", token);
        blobmsg_add_u64(&b, "incoming", atoll(rx));
        blobmsg_add_u64(&b, "outgoing", atoll(tx));
        blobmsg_close_table(&b, tbl);
    }

    blobmsg_close_table(&b, array);
    p = blobmsg_format_json(b.head, true);

    httppost(counters_cb, NULL, p, "http://%s:%d%s%sstage=counters&gw_id=%s",
            conf->authserver.host, conf->authserver.port, conf->authserver.path, 
            conf->authserver.auth_path, conf->gw_id);

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
