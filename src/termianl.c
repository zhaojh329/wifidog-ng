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
#include <string.h>
#include <errno.h>
#include <libubox/uloop.h>
#include <libubox/ulog.h>
#include <libubox/avl-cmp.h>
#include <libubox/avl.h>
#include "utils.h"
#include "config.h"

struct termianl_temppass {
    char mac[18];
    struct avl_node node;
    struct uloop_timeout timer;
};

static struct avl_tree temppass_tree;

void termianl_init()
{
	avl_init(&temppass_tree, avl_strcmp, false, NULL);
}

int deny_termianl(const char *mac)
{
    FILE *fp = fopen("/proc/wifidog/term", "w");
    if (!fp) {
        ULOG_ERR("fopen:%s\n", strerror(errno));
        return -1;
    }

    fprintf(fp, "-%s\n", mac);
    fclose(fp);

    ULOG_INFO("deny termianl: %s\n", mac);
    return 0;
}

static void temppass_timer_cb(struct uloop_timeout *t)
{
    struct termianl_temppass *termianl = container_of(t, struct termianl_temppass, timer);

    deny_termianl(termianl->mac);
    avl_delete(&temppass_tree, &termianl->node);
    free(termianl);
}

int allow_termianl(const char *mac, const char *token, bool temporary)
{
    struct termianl_temppass *termianl;
    struct config *conf = get_config();

    FILE *fp = fopen("/proc/wifidog/term", "w");
    if (!fp) {
        ULOG_ERR("fopen:%s\n", strerror(errno));
        return -1;
    }

    fprintf(fp, "+%s %s\n", mac, token ? token : "");
    fclose(fp);

    ULOG_INFO("allow termianl %s: %s\n", temporary ? "temporary" : "", mac);

    termianl = avl_find_element(&temppass_tree, mac, termianl, node);
    if (termianl) {
        if (temporary) {
            uloop_timeout_set(&termianl->timer, conf->temppass_time * 1000);
            return 0;
        }
        uloop_timeout_cancel(&termianl->timer);
        avl_delete(&temppass_tree, &termianl->node);
        free(termianl);
    } else if (temporary) {
        termianl = calloc(1, sizeof(struct termianl_temppass));
        if (!termianl) {
            ULOG_ERR("allow_termianl temporary FAILED: No mem\n");
            return -1;
        }

        termianl->node.key = strcpy(termianl->mac, mac);
        termianl->timer.cb = temppass_timer_cb;
        uloop_timeout_set(&termianl->timer, conf->temppass_time * 1000);
        avl_insert(&temppass_tree, &termianl->node);
    }
    return 0;
}
