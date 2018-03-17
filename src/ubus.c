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

#include <inttypes.h>
#include <libgen.h>
#include <libubox/ulog.h>
#include <libubus.h>
#include "utils.h"
#include "config.h"
#include "counters.h"
#include "uci.h"

static struct ubus_context *ctx;
static struct blob_buf b;

enum {
    TERM_ACTION,
    TERM_MAC,
    __TERM_MAX
};

static const struct blobmsg_policy term_policy[] = {
    [TERM_ACTION] = { .name = "action", .type = BLOBMSG_TYPE_STRING },
    [TERM_MAC] = { .name = "mac", .type = BLOBMSG_TYPE_STRING },
};

static int serve_term(struct ubus_context *ctx, struct ubus_object *obj,
             struct ubus_request_data *req, const char *method,
             struct blob_attr *msg)
{
    struct blob_attr *tb[__TERM_MAX];
    const char *action, *mac;

    blobmsg_parse(term_policy, __TERM_MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[TERM_ACTION] || !tb[TERM_MAC])
        return UBUS_STATUS_INVALID_ARGUMENT;

    action = blobmsg_data(tb[TERM_ACTION]);
    mac = blobmsg_data(tb[TERM_MAC]);

    if (!strcmp(action, "add"))
        allow_termianl(mac, NULL, false);
    else if (!strcmp(action, "del"))
        deny_termianl(mac);
    else
        return UBUS_STATUS_NOT_SUPPORTED;

    return 0;
}

enum {
    WHITELIST_ACTION,
    WHITELIST_DOMAIN,
    WHITELIST_MAC,
    __WHITELIST_MAX
};

static const struct blobmsg_policy whitelist_policy[] = {
    [WHITELIST_ACTION] = { .name = "action", .type = BLOBMSG_TYPE_STRING },
    [WHITELIST_DOMAIN] = { .name = "domain", .type = BLOBMSG_TYPE_STRING },
    [WHITELIST_MAC] = { .name = "mac", .type = BLOBMSG_TYPE_STRING },
};

static int save_whitelist(const char *action, const char *option, const char *value)
{
    struct uci_context *cursor = uci_alloc_context();
    struct uci_ptr ptr = {
        .package = "wifidog-ng"
    };
    struct uci_package *p = NULL;
    struct uci_section *s;
    struct uci_element *e;

    if (uci_load(cursor, ptr.package, &p)) {
        uci_perror(cursor, "");
        return cursor->err;
    }

    uci_foreach_element(&p->sections, e) {
        s = uci_to_section(e);

        if (!strcmp(s->type, "whitelist"))
            break;
        s = NULL;
    }

    if (!s)
        uci_add_section(cursor, p, "whitelist", &s);

    ptr.s = s;
    ptr.option = option;
    ptr.value = value;

    if (!strcmp(action, "add")) {
        ptr.o = uci_lookup_option(cursor, s, ptr.option);
        if (ptr.o) {
            uci_foreach_element(&ptr.o->v.list, e) {
                if (!strcmp(uci_to_option(e)->e.name, value))
                    goto RET;
            }
        }
        uci_add_list(cursor, &ptr);
    } else {
        uci_del_list(cursor, &ptr);
    }

    uci_save(cursor, p);
    uci_commit(cursor, &p, false);

RET:
    uci_unload(cursor, p);
    return 0;
}

static int serve_whitelist(struct ubus_context *ctx, struct ubus_object *obj,
             struct ubus_request_data *req, const char *method,
             struct blob_attr *msg)
{
    struct blob_attr *tb[__WHITELIST_MAX];
    const char *action, *domain = NULL, *mac = NULL;

    blobmsg_parse(whitelist_policy, __WHITELIST_MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[WHITELIST_ACTION])
        return UBUS_STATUS_INVALID_ARGUMENT;

    action = blobmsg_data(tb[WHITELIST_ACTION]);

    if (tb[WHITELIST_DOMAIN])
        domain = blobmsg_data(tb[WHITELIST_DOMAIN]);

    if (tb[WHITELIST_MAC])
        mac = blobmsg_data(tb[WHITELIST_MAC]);

    if (!strcmp(action, "add")) {
        if (domain) {
            allow_domain(domain);
            save_whitelist("add", "domain", domain);
        }

        if (mac) {
            whitelist_termianl(mac);
            save_whitelist("add", "mac", mac);
        }
    } else if (!strcmp(action, "del")) {
        if (domain) {
            deny_domain(domain);
            save_whitelist("del", "domain", domain);
        }
        if (mac) {
            deny_termianl(mac);
            save_whitelist("del", "mac", mac);
        }
    } else {
        return UBUS_STATUS_NOT_SUPPORTED;
    }

    return 0;
}

enum {
    AUTHSERVER_OPTIONS,
    __AUTHSERVER_MAX
};

static const struct blobmsg_policy authserver_policy[] = {
    [AUTHSERVER_OPTIONS] = { .name = "options", .type = BLOBMSG_TYPE_TABLE }
};

/*
 * Format applicable blob value as string and place a pointer to the string
 * buffer in "p". Uses a static string buffer.
 */
static bool uci_format_blob(struct blob_attr *v, const char **p)
{
    static char buf[21];

    *p = NULL;

    switch (blobmsg_type(v))
    {
    case BLOBMSG_TYPE_STRING:
        *p = blobmsg_data(v);
        break;

    case BLOBMSG_TYPE_INT64:
        snprintf(buf, sizeof(buf), "%"PRIu64, blobmsg_get_u64(v));
        *p = buf;
        break;

    case BLOBMSG_TYPE_INT32:
        snprintf(buf, sizeof(buf), "%u", blobmsg_get_u32(v));
        *p = buf;
        break;

    case BLOBMSG_TYPE_INT16:
        snprintf(buf, sizeof(buf), "%u", blobmsg_get_u16(v));
        *p = buf;
        break;

    case BLOBMSG_TYPE_INT8:
        snprintf(buf, sizeof(buf), "%u", !!blobmsg_get_u8(v));
        *p = buf;
        break;

    default:
        break;
    }

    return !!*p;
}

static int save_authserver(struct blob_attr *options)
{
    struct uci_context *cursor = uci_alloc_context();
    struct uci_ptr ptr = {
        .package = "wifidog-ng"
    };
    struct uci_package *p = NULL;
    struct uci_section *s;
    struct uci_element *e;

    struct blob_attr *cur;
    int rem;

    if (uci_load(cursor, ptr.package, &p)) {
        uci_perror(cursor, "");
        return cursor->err;
    }

    uci_foreach_element(&p->sections, e) {
        s = uci_to_section(e);

        if (!strcmp(s->type, "authserver"))
            break;
        s = NULL;
    }

    if (!s)
        uci_add_section(cursor, p, "authserver", &s);

    ptr.s = s;

    if (options) {
        blobmsg_for_each_attr(cur, options, rem) {
            if (!uci_format_blob(cur, &ptr.value))
                continue;

            ptr.o = NULL;
            ptr.option = blobmsg_name(cur);
            uci_set(cursor, &ptr);
        }
    }

    uci_foreach_element(&s->options, e){
        struct uci_option *o = uci_to_option(e);
        if (o->type == UCI_TYPE_STRING)
            blobmsg_add_string(&b, o->e.name, o->v.string);
    }

    uci_save(cursor, p);
    uci_commit(cursor, &p, false);

    uci_unload(cursor, p);
    return 0;
}

static int serve_authserver(struct ubus_context *ctx, struct ubus_object *obj,
             struct ubus_request_data *req, const char *method,
             struct blob_attr *msg)
{
    struct blob_attr *tb[__AUTHSERVER_MAX];

    blobmsg_parse(authserver_policy, __AUTHSERVER_MAX, tb, blob_data(msg), blob_len(msg));

    blob_buf_init(&b, 0);
    save_authserver(tb[AUTHSERVER_OPTIONS]);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    return 0;
}

static const struct ubus_method wifidog_methods[] = {
    UBUS_METHOD("term", serve_term, term_policy),
    UBUS_METHOD("whitelist", serve_whitelist, whitelist_policy),
    UBUS_METHOD("authserver", serve_authserver, authserver_policy),
};

static struct ubus_object_type wifidog_object_type =
    UBUS_OBJECT_TYPE("wifidog", wifidog_methods);

static struct ubus_object server_object = {
    .name = "wifidog-ng",
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
