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

#include "config.h"
#include "utils.h"
#include <uci_blob.h>
#include <libubox/ulog.h>
#include <uhttpd/uhttpd.h>
#include <libubox/avl-cmp.h>

static struct blob_buf b;

static struct config conf = {
    .gw_interface = "br-lan",
    .gw_port = 2060,
    .gw_ssl_port = 8443,
    .checkinterval = 30,
    .clienttimeout = 5,
    .temppass_time = 30,
    .authserver = {
        .port = 80,
        .path = "/wifidog/",
        .login_path = "login",
        .portal_path = "portal",
        .msg_path = "gw_message.php",
        .ping_path = "ping",
        .auth_path = "auth",
    }
};

enum {
    GATEWAY_ATTR_ENABLED,
    GATEWAY_ATTR_IFNAME,
    GATEWAY_ATTR_ADDRESS,
    GATEWAY_ATTR_ID,
    GATEWAY_ATTR_SSID,
    GATEWAY_ATTR_PORT,
    GATEWAY_ATTR_SSL_PORT,
    GATEWAY_ATTR_CHECKINTERVAL,
    GATEWAY_ATTR_CLIENTTIMEOUT,
    GATEWAY_ATTR_TEMPPASS_TIME,
    GATEWAY_ATTR_MAX
};

static const struct blobmsg_policy gateway_attrs[GATEWAY_ATTR_MAX] = {
    [GATEWAY_ATTR_ENABLED] = { .name = "enabled", .type = BLOBMSG_TYPE_BOOL },
    [GATEWAY_ATTR_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
    [GATEWAY_ATTR_ADDRESS] = { .name = "address", .type = BLOBMSG_TYPE_STRING },
    [GATEWAY_ATTR_ID] = { .name = "id", .type = BLOBMSG_TYPE_STRING },
    [GATEWAY_ATTR_SSID] = { .name = "ssid", .type = BLOBMSG_TYPE_STRING },
    [GATEWAY_ATTR_PORT] = { .name = "port", .type = BLOBMSG_TYPE_INT32 },
    [GATEWAY_ATTR_SSL_PORT] = { .name = "ssl_port", .type = BLOBMSG_TYPE_INT32 },
    [GATEWAY_ATTR_CHECKINTERVAL] = { .name = "checkinterval", .type = BLOBMSG_TYPE_INT32 },
    [GATEWAY_ATTR_CLIENTTIMEOUT] = { .name = "client_timeout", .type = BLOBMSG_TYPE_INT32 },
    [GATEWAY_ATTR_TEMPPASS_TIME] = { .name = "temppass_time", .type = BLOBMSG_TYPE_INT32 }
};

static const struct uci_blob_param_list gateway_attr_list = {
    .n_params = GATEWAY_ATTR_MAX,
    .params = gateway_attrs,
};

static void parse_gateway(struct uci_section *s)
{    
    struct blob_attr *tb[GATEWAY_ATTR_MAX];
    
    blob_buf_init(&b, 0);

    uci_to_blob(&b, s, &gateway_attr_list);
    blobmsg_parse(gateway_attrs, GATEWAY_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

    if (tb[GATEWAY_ATTR_ENABLED] && !blobmsg_get_bool(tb[GATEWAY_ATTR_ENABLED])) {
        ULOG_INFO("wifidog-ng not enabled\n");
        exit(0);
    }

    if (tb[GATEWAY_ATTR_IFNAME])
        conf.gw_interface = strdup(blobmsg_data(tb[GATEWAY_ATTR_IFNAME]));

    if (tb[GATEWAY_ATTR_ADDRESS])
        conf.gw_address = strdup(blobmsg_data(tb[GATEWAY_ATTR_ADDRESS]));
    
    if (tb[GATEWAY_ATTR_ID])
        conf.gw_id = strdup(blobmsg_data(tb[GATEWAY_ATTR_ID]));

    if (tb[GATEWAY_ATTR_SSID]) {
        const char *ssid = blobmsg_data(tb[GATEWAY_ATTR_SSID]);
        conf.ssid = calloc(1, strlen(ssid) * 4);
        urlencode((char *)conf.ssid, strlen(ssid) * 4, ssid, strlen(ssid));
    }

    if (tb[GATEWAY_ATTR_PORT])
        conf.gw_port = blobmsg_get_u32(tb[GATEWAY_ATTR_PORT]);

    if (tb[GATEWAY_ATTR_SSL_PORT])
        conf.gw_ssl_port = blobmsg_get_u32(tb[GATEWAY_ATTR_SSL_PORT]);

    if (tb[GATEWAY_ATTR_CHECKINTERVAL])
        conf.checkinterval = blobmsg_get_u32(tb[GATEWAY_ATTR_CHECKINTERVAL]);

    if (tb[GATEWAY_ATTR_CLIENTTIMEOUT])
        conf.clienttimeout = blobmsg_get_u32(tb[GATEWAY_ATTR_CLIENTTIMEOUT]);

    if (tb[GATEWAY_ATTR_TEMPPASS_TIME])
        conf.temppass_time = blobmsg_get_u32(tb[GATEWAY_ATTR_TEMPPASS_TIME]);
}

enum {
    AUTHSERVER_ATTR_HOST,
    AUTHSERVER_ATTR_PORT,
    AUTHSERVER_ATTR_PATH,
    AUTHSERVER_ATTR_LOGIN_PATH,
    AUTHSERVER_ATTR_PORTAL_PATH,
    AUTHSERVER_ATTR_MSG_PATH,
    AUTHSERVER_ATTR_PING_PATH,
    AUTHSERVER_ATTR_AUTH_PATH,
    AUTHSERVER_ATTR_MAX
};

static const struct blobmsg_policy authserver_attrs[AUTHSERVER_ATTR_MAX] = {
    [AUTHSERVER_ATTR_HOST] = { .name = "host", .type = BLOBMSG_TYPE_STRING },
    [AUTHSERVER_ATTR_PORT] = { .name = "port", .type = BLOBMSG_TYPE_INT32 },
    [AUTHSERVER_ATTR_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
    [AUTHSERVER_ATTR_LOGIN_PATH] = { .name = "login_path", .type = BLOBMSG_TYPE_STRING },
    [AUTHSERVER_ATTR_PORTAL_PATH] = { .name = "portal_path", .type = BLOBMSG_TYPE_STRING },
    [AUTHSERVER_ATTR_MSG_PATH] = { .name = "msg_path", .type = BLOBMSG_TYPE_STRING },
    [AUTHSERVER_ATTR_PING_PATH] = { .name = "ping_path", .type = BLOBMSG_TYPE_STRING },
    [AUTHSERVER_ATTR_AUTH_PATH] = { .name = "auth_path", .type = BLOBMSG_TYPE_STRING },
};

const struct uci_blob_param_list authserver_attr_list = {
    .n_params = AUTHSERVER_ATTR_MAX,
    .params = authserver_attrs,
};

static void parse_authserver(struct uci_section *s)
{
    struct blob_attr *tb[AUTHSERVER_ATTR_MAX];
    struct auth_server *authserver = &conf.authserver;
    
    blob_buf_init(&b, 0);

    uci_to_blob(&b, s, &authserver_attr_list);
    blobmsg_parse(authserver_attrs, AUTHSERVER_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

    if (tb[AUTHSERVER_ATTR_HOST])
        authserver->host = strdup(blobmsg_data(tb[AUTHSERVER_ATTR_HOST]));
    
    if (tb[AUTHSERVER_ATTR_PORT])
        authserver->port = blobmsg_get_u32(tb[AUTHSERVER_ATTR_PORT]);

    if (tb[AUTHSERVER_ATTR_PATH])
        authserver->path = strdup(blobmsg_data(tb[AUTHSERVER_ATTR_PATH]));

    if (tb[AUTHSERVER_ATTR_LOGIN_PATH])
        authserver->login_path = strdup(blobmsg_data(tb[AUTHSERVER_ATTR_LOGIN_PATH]));

    if (tb[AUTHSERVER_ATTR_PORTAL_PATH])
        authserver->portal_path = strdup(blobmsg_data(tb[AUTHSERVER_ATTR_PORTAL_PATH]));

    if (tb[AUTHSERVER_ATTR_MSG_PATH])
        authserver->msg_path = strdup(blobmsg_data(tb[AUTHSERVER_ATTR_MSG_PATH]));

    if (tb[AUTHSERVER_ATTR_PING_PATH])
        authserver->ping_path = strdup(blobmsg_data(tb[AUTHSERVER_ATTR_PING_PATH]));

    if (tb[AUTHSERVER_ATTR_AUTH_PATH])
        authserver->auth_path = strdup(blobmsg_data(tb[AUTHSERVER_ATTR_AUTH_PATH]));
}

enum {
    POPULAR_SERVER_ATTR_SERVER,
    POPULAR_SERVER_ATTR_MAX
};

static const struct blobmsg_policy popular_server_attrs[POPULAR_SERVER_ATTR_MAX] = {
    [POPULAR_SERVER_ATTR_SERVER] = { .name = "server", .type = BLOBMSG_TYPE_ARRAY },
};

const struct uci_blob_param_list popular_server_attr_list = {
    .n_params = POPULAR_SERVER_ATTR_MAX,
    .params = popular_server_attrs,
};

int add_popular_server(const char *host)
{
    struct popular_server *p = calloc(1, sizeof(struct popular_server) + strlen(host) + 1);
    if (!p) {
        ULOG_ERR("add_popular_server failed:%s\n", strerror(errno));
        return -1;
    }
    p->avl.key = strcpy(p->host, host);
    avl_insert(&conf.popular_servers, &p->avl);
    return 0;
}
static void parse_popular_server(struct uci_section *s)
{
    struct blob_attr *tb[POPULAR_SERVER_ATTR_MAX];

    blob_buf_init(&b, 0);

    uci_to_blob(&b, s, &popular_server_attr_list);
    blobmsg_parse(popular_server_attrs, POPULAR_SERVER_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

    if (tb[POPULAR_SERVER_ATTR_SERVER]) {
        int rem;
        struct blob_attr *cur;

        blobmsg_for_each_attr(cur, tb[POPULAR_SERVER_ATTR_SERVER], rem) {
            if (blobmsg_type(cur) == BLOBMSG_TYPE_STRING) {
                if (add_popular_server(blobmsg_data(cur)) < 0) {
                    ULOG_ERR("parse_popular_server failed\n");
                    return;
                }
            }
        }
    }
}

enum {
    WHITELIST_ATTR_DOMAIN,
    WHITELIST_ATTR_MAX
};

static const struct blobmsg_policy whitelist_attrs[WHITELIST_ATTR_MAX] = {
    [WHITELIST_ATTR_DOMAIN] = { .name = "domain", .type = BLOBMSG_TYPE_ARRAY },
};

const struct uci_blob_param_list whitelist_attr_list = {
    .n_params = WHITELIST_ATTR_MAX,
    .params = whitelist_attrs,
};

static void parse_whitelist(struct uci_section *s)
{
    struct blob_attr *tb[WHITELIST_ATTR_MAX];

    blob_buf_init(&b, 0);

    uci_to_blob(&b, s, &whitelist_attr_list);
    blobmsg_parse(whitelist_attrs, WHITELIST_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

    if (tb[WHITELIST_ATTR_DOMAIN]) {
        int rem;
        struct blob_attr *cur;

        blobmsg_for_each_attr(cur, tb[WHITELIST_ATTR_DOMAIN], rem) {
            if (blobmsg_type(cur) == BLOBMSG_TYPE_STRING) {
                const char *domain = blobmsg_data(cur);
                struct whitelist_domain *d = calloc(1, sizeof(struct whitelist_domain) + strlen(domain) + 1);
                if (!d) {
                    ULOG_ERR("parse_whitelist failed:%s\n", strerror(errno));
                    return;
                }
                d->avl.key = strcpy(d->domain, domain);
                avl_insert(&conf.whitelist_domains, &d->avl);
            }
        }
    }
}

static int config_kmod()
{
    FILE *fp = fopen("/proc/wifidog-ng/config", "w");
    if (!fp) {
        ULOG_ERR("Kernel module is not loaded\n");
        return -1;
    }

    fprintf(fp, "port=%d\n", conf.gw_port);
    fprintf(fp, "ssl_port=%d\n", conf.gw_ssl_port);
    fprintf(fp, "client_timeout=%d\n", conf.checkinterval * conf.clienttimeout);
    fprintf(fp, "temppass_time=%d\n", conf.temppass_time);
    fclose(fp);

    ULOG_INFO("Config kmod OK\n");
    return 0;
}

static int init_authserver_url()
{
    struct auth_server *authserver = &conf.authserver;
    char port[10] = "";

    if (authserver->port != 80)
        sprintf(port, ":%d", authserver->port);

    free(conf.login_url);
    if (asprintf(&conf.login_url, "http://%s%s%s%s?gw_address=%s&gw_port=%d&gw_id=%s&ssid=%s",
        authserver->host, port, authserver->path, authserver->login_path,
        conf.gw_address, conf.gw_port, conf.gw_id, conf.ssid ? conf.ssid : "") < 0)
        goto err;

    free(conf.auth_url);
    if (asprintf(&conf.auth_url, "http://%s%s%s%s?gw_id=%s",
        authserver->host, port, authserver->path, authserver->auth_path, conf.gw_id) < 0)
        goto err;

    free(conf.ping_url);
    if (asprintf(&conf.ping_url, "http://%s%s%s%s?gw_id=%s",
        authserver->host, port, authserver->path, authserver->ping_path, conf.gw_id) < 0)
        goto err;

    free(conf.portal_url);
    if (asprintf(&conf.portal_url, "http://%s%s%s%s?gw_id=%s",
        authserver->host, port, authserver->path, authserver->portal_path, conf.gw_id) < 0)
        goto err;

    free(conf.msg_url);
    if (asprintf(&conf.msg_url, "http://%s%s%s%s?gw_id=%s",
        authserver->host, port, authserver->path, authserver->msg_path, conf.gw_id) < 0)
        goto err;

    return 0;
err:
    ULOG_ERR("asprintf: %s\n", strerror(errno));
    return -1;
}

int parse_config()
{
    struct uci_context *ctx = uci_alloc_context();
    struct uci_package *p = NULL;
    struct uci_element *e;
    char buf[128];
    
    if (uci_load(ctx, "wifidog-ng", &p) || !p) {
        ULOG_ERR("Load uci config 'wifidog-ng' failed\n");
        uci_free_context(ctx);
        return -1;
    }

    avl_init(&conf.popular_servers, avl_strcmp, false, NULL);
    avl_init(&conf.whitelist_domains, avl_strcmp, false, NULL);

    uci_foreach_element(&p->sections, e) {
        struct uci_section *s = uci_to_section(e);
        if (!strcmp(s->type, "gateway"))
            parse_gateway(s);
        else if (!strcmp(s->type, "authserver"))
            parse_authserver(s);
        else if (!strcmp(s->type, "popularserver"))
            parse_popular_server(s);
        else if (!strcmp(s->type, "whitelist"))
            parse_whitelist(s);
    }

    if (avl_is_empty(&conf.popular_servers)) {
        add_popular_server("www.baidu.com");
        add_popular_server("www.qq.com");
    }

    blob_buf_free(&b);
    uci_free_context(ctx);
    
    if (!conf.gw_id) {
        if (get_iface_mac(conf.gw_interface, buf, sizeof(buf)) < 0)
            return -1;
        conf.gw_id = strdup(buf);
    }

    if (!conf.gw_address) {
        if (get_iface_ip(conf.gw_interface, buf, sizeof(buf)) < 0)
            return -1;
        conf.gw_address = strdup(buf);
    }
    
    if (init_authserver_url() < 0)
        return -1;

    return config_kmod();
}

struct config *get_config()
{
    return &conf;
}

static inline void alloc_authserver_option(char **option, const char *value)
{
    free(*option);
    *option = strdup(value);
}

void reinit_config(const char *type, const char *option, const char *value)
{
    if (!strcmp(type, "authserver")) {
        struct auth_server *authserver = &conf.authserver;

        if (!strcmp(option, "host")) {
            deny_domain(authserver->host);
            alloc_authserver_option(&authserver->host, value);
            allow_domain(authserver->host);
        }
        else if (!strcmp(option, "port"))
            authserver->port = atoi(value);
        else if (!strcmp(option, "path"))
            alloc_authserver_option(&authserver->path, value);
        else if (!strcmp(option, "login_path"))
            alloc_authserver_option(&authserver->login_path, value);
        else if (!strcmp(option, "portal_path"))
            alloc_authserver_option(&authserver->portal_path, value);
        else if (!strcmp(option, "msg_path"))
            alloc_authserver_option(&authserver->msg_path, value);
        else if (!strcmp(option, "ping_path"))
            alloc_authserver_option(&authserver->ping_path, value);
        else if (!strcmp(option, "auth_path"))
            alloc_authserver_option(&authserver->auth_path, value);

        init_authserver_url();
    } else if (!strcmp(type, "gateway")) {
        if (!strcmp(option, "checkinterval"))
            conf.checkinterval = atoi(value);
        else if (!strcmp(option, "temppass_time"))
            conf.temppass_time = atoi(value);
        else if (!strcmp(option, "client_timeout"))
            conf.clienttimeout = atoi(value);
    }
}
