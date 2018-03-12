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

#include "auth.h"
#include "utils.h"
#include "config.h"
#include "http.h"

struct authserver_request_param {
    bool login;
    struct uh_client *cl;
    char token[33];
};

static void authserver_request_cb(void *data, char *content)
{
    struct config *conf = get_config();
    struct authserver_request_param *param = data;
    struct uh_client *cl;
    const char *remote_addr;
    char mac[18] = "";
    int code = -1;

    if (!param) /* For logout */
        return;

    cl = param->cl;
    remote_addr = cl->get_peer_addr(cl);

    if (arp_get(conf->gw_interface, remote_addr, mac, sizeof(mac)) < 0) {
        ULOG_ERR("arp_get failed for %s\n", remote_addr);
        cl->request_done(cl);
        return;
    }
    
    ULOG_INFO("auth for %s: %s\n", mac, content);

    if (!content)
        goto deny;
    
    sscanf(content, "Auth: %d", &code);

    if (code == 1) {
        allow_termianl(mac, param->token, false);
        cl->redirect(cl, 302, conf->portal_url);
        free(param);
        return;
    } else {
        cl->redirect(cl, 302, conf->msg_url);
        free(param);
        return;
    }

deny:
    deny_termianl(mac);
    free(param);
}

void authserver_request(void *data, const char *type, const char *ip, const char *mac, const char *token)
{
    struct config *conf = get_config();
    struct authserver_request_param *param = NULL;

    if (!strcmp(type, "login")) {
        param = calloc(1, sizeof(struct authserver_request_param));
        strcpy(param->token, token);
        param->cl = data;
    }

    httpget(authserver_request_cb, param, "%s&stage=%s&ip=%s&mac=%s&token=%s", conf->auth_url, type, ip, mac, token);
}

static void http_callback_404(struct uh_client *cl)
{
    struct config *conf = get_config();
    const char *remote_addr = cl->get_peer_addr(cl);
    char mac[18] = "";
    static char tmpurl[2048] = "", url[8192] = "";
    static char *redirect_html = "<!doctype html><html><body><script type=\"text/javascript\">"
                "setTimeout(function() {location.href = '%s&ip=%s&mac=%s&url=%s';}, 1);</script></body></html>";

    if (cl->request.method != UH_HTTP_MSG_GET) {
        cl->request_done(cl);
        return;
    }

    if (arp_get(conf->gw_interface, remote_addr, mac, sizeof(mac)) < 0) {
        ULOG_ERR("arp_get failed for %s\n", remote_addr);
        cl->request_done(cl);
        return;
    }
    
    snprintf(tmpurl, (sizeof(tmpurl) - 1), "http://%s%s", cl->get_header(cl, "host"), cl->get_url(cl));
    urlencode(url, sizeof(url), tmpurl, strlen(tmpurl));

    cl->send_header(cl, 200, "OK", -1);
    cl->header_end(cl);
    cl->chunk_printf(cl, redirect_html, conf->login_url, remote_addr, mac, url);
    cl->request_done(cl);
}

static void http_callback_auth(struct uh_client *cl)
{
    struct config *conf = get_config();
    const char *token = cl->get_var(cl, "token");
    const char *remote_addr = cl->get_peer_addr(cl);
    char mac[18] = "";

    if (arp_get(conf->gw_interface, remote_addr, mac, sizeof(mac)) < 0) {
        cl->send_header(cl, 200, "OK", -1);
        cl->header_end(cl);
        cl->chunk_printf(cl, "<h1>Failed to retrieve your MAC address</h1>");
        cl->request_done(cl);
        ULOG_ERR("Failed to retrieve MAC address for ip %s\n", remote_addr);
        return;
    }

    if (token && *token) {
        const char *logout = cl->get_var(cl, "logout");
        if (logout)
            authserver_request(cl, "logout", remote_addr, mac, token);
        else
            authserver_request(cl, "login", remote_addr, mac, token);
    } else {
        cl->send_header(cl, 200, "OK", -1);
        cl->header_end(cl);
        cl->chunk_printf(cl, "<h1>Invalid token</h1>");
        cl->request_done(cl);

        /* cancel possible temppass */
        deny_termianl(mac);
    }
}

static void http_callback_temppass(struct uh_client *cl)
{
    char mac[18] = "";
    struct config *conf = get_config();
    const char *remote_addr = cl->get_peer_addr(cl);
    const char *script = cl->get_var(cl, "script");

    if (arp_get(conf->gw_interface, remote_addr, mac, sizeof(mac)) < 0) {
        cl->send_header(cl, 200, "OK", -1);
        cl->header_end(cl);
        cl->chunk_printf(cl, "<h1>Failed to retrieve your MAC address</h1>");
        cl->request_done(cl);
        ULOG_ERR("Failed to retrieve MAC address for ip %s\n", remote_addr);
        return;
    }

    allow_termianl(mac, NULL, true);

    cl->send_header(cl, 200, "OK", -1);
    cl->header_end(cl);
    cl->chunk_printf(cl, "%s", script ? script : "");
    cl->request_done(cl);
}

static int http_init(int port, bool ssl)
{
    struct uh_server *srv = NULL;
    
    srv = uh_server_new("0.0.0.0", port);
    if (!srv)
        return -1;
    
    ULOG_INFO("Listen on: *:%d\n", port);

#if (UHTTPD_SSL_SUPPORT)
    if (ssl && srv->ssl_init(srv, "/etc/wifidog-ng/wifidog-ng.key", "/etc/wifidog-ng/wifidog-ng.crt"))
        goto err;
#endif

    srv->error404_cb = http_callback_404;

    uh_add_action(srv, "/wifidog/auth", http_callback_auth);
    uh_add_action(srv, "/wifidog/temppass", http_callback_temppass);

    return 0;

#if (UHTTPD_SSL_SUPPORT)
err:
     srv->free(srv);
     return -1;
#endif
}

int auth_init()
{
    struct config *conf = get_config();
    
    if (http_init(conf->gw_port, false))
        return -1;

#if (UHTTPD_SSL_SUPPORT)
    if (http_init(conf->gw_ssl_port, true))
        return -1;
#endif

    return 0;
}
