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
#include <libubox/ulog.h>
#include <libubox/avl-cmp.h>

#include "utils.h"
#include "config.h"
#include "termianl.h"

static struct avl_tree term_tree;

void termianl_init()
{
    avl_init(&term_tree, avl_strcmp, false, NULL);
}

int deny_termianl(const char *mac)
{
    struct termianl *term;
    FILE *fp;

    fp = fopen("/proc/wifidog/term", "w");
    if (!fp) {
        ULOG_ERR("Kernel module is not loaded\n");
        return -1;
    }

    fprintf(fp, "-%s\n", mac);
    fclose(fp);

    term = avl_find_element(&term_tree, mac, term, node);
    if (term) {
        avl_delete(&term_tree, &term->node);
        free(term);
    }

    ULOG_INFO("deny termianl: %s\n", mac);
    return 0;
}

static void temppass_timer_cb(struct uloop_timeout *t)
{
    struct termianl *term = container_of(t, struct termianl, timer);

    deny_termianl(term->mac);
}

int allow_termianl(const char *mac, const char *token, bool temporary)
{
    struct termianl *term;
    struct config *conf = get_config();
    FILE *fp;

    fp = fopen("/proc/wifidog/term", "w");
    if (!fp) {
        ULOG_ERR("fopen:%s\n", strerror(errno));
        return -1;
    }

    fprintf(fp, "+%s %s\n", mac, token ? token : "");
    fclose(fp);

    ULOG_INFO("allow termianl %s: %s\n", temporary ? "temporary" : "", mac);

    term = avl_find_element(&term_tree, mac, term, node);
    if (!term) {
        term = calloc(1, sizeof(struct termianl));
        if (!term) {
            ULOG_ERR("allow_termianl calloc FAILED: No mem\n");
            return -1;
        }

        term->node.key = strcpy(term->mac, mac);
        term->timer.cb = temppass_timer_cb;
        avl_insert(&term_tree, &term->node);
    }

    if (temporary) {
        uloop_timeout_set(&term->timer, conf->temppass_time * 1000);
    } else {
        uloop_timeout_cancel(&term->timer);

        if (token)
            strncpy(term->token, token, sizeof(term->token) - 1);
    }
    return 0;
}

struct termianl *find_element(const  char *mac)
{
    struct termianl *term;

    return avl_find_element(&term_tree, mac, term, node);
}
