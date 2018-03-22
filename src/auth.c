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
#include "term.h"

static inline void simple_http_send(struct uh_client *cl, const char *str)
{
    cl->send_header(cl, 200, "OK", -1);
    cl->header_end(cl);
    cl->chunk_printf(cl, str);
    cl->request_done(cl);
}

static void authserver_request_login_cb(void *data, char *content)
{
    struct config *conf = get_config();
    struct uh_client *cl = data;
    const char *remote_addr;
    char mac[18] = "";
    int code = -1;

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
        auth_term_by_mac(mac);
        cl->redirect(cl, 302, conf->portal_url);
        return;
    } else {
        cl->redirect(cl, 302, conf->msg_url);
        return;
    }

deny:
    del_term_by_mac(mac);
}

void authserver_request(void *data, int type, const char *ip, const char *mac, const char *token)
{
    struct config *conf = get_config();

    if (type == AUTH_REQUEST_TYPE_LOGIN)
        httpget(authserver_request_login_cb, data, "%s&stage=login&ip=%s&mac=%s&token=%s",
            conf->auth_url, ip, mac, token);
    else if (type == AUTH_REQUEST_TYPE_LOGOUT)
        httpget(NULL, NULL, "%s&stage=logout&ip=%s&mac=%s&token=%s", conf->auth_url, ip, mac, token);
}

static void http_callback_404(struct uh_client *cl)
{
    struct config *conf = get_config();
    const char *remote_addr = cl->get_peer_addr(cl);
    char mac[18] = "";
    static char *redirect_html = "<!doctype html><html><body><script type=\"text/javascript\">"
                "setTimeout(function() {location.href = '%s&ip=%s&mac=%s';}, 1);</script></body></html>";

    if (cl->request.method != UH_HTTP_MSG_GET)
        goto done;

    if (arp_get(conf->gw_interface, remote_addr, mac, sizeof(mac)) < 0) {
        ULOG_ERR("arp_get failed for %s\n", remote_addr);
        goto done;
    }
    
    cl->send_header(cl, 200, "OK", -1);
    cl->header_end(cl);
    cl->chunk_printf(cl, redirect_html, conf->login_url, remote_addr, mac);

done:
    cl->request_done(cl);
}

static void http_callback_auth(struct uh_client *cl)
{
    struct config *conf = get_config();
    const char *token = cl->get_var(cl, "token");
    const char *remote_addr = cl->get_peer_addr(cl);
    char mac[18] = "";

    if (arp_get(conf->gw_interface, remote_addr, mac, sizeof(mac)) < 0) {
        simple_http_send(cl, "<h1>Failed to retrieve your MAC address</h1>");
        ULOG_ERR("Failed to retrieve MAC address for ip %s\n", remote_addr);
        return;
    }

    if (token && *token) {
        const char *logout = cl->get_var(cl, "logout");
        if (logout) {
            authserver_request(NULL, AUTH_REQUEST_TYPE_LOGOUT, remote_addr, mac, token);
        } else {
            struct terminal *term = term_new(mac, remote_addr, token);
            if (!term) {
                simple_http_send(cl, "<h1>System error</h1>");
                return;
            }
            authserver_request(cl, AUTH_REQUEST_TYPE_LOGIN, remote_addr, mac, token);
        }
    } else {
        simple_http_send(cl, "<h1>Invalid token</h1>");
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

    cl->send_header(cl, 200, "OK", -1);
    cl->header_end(cl);

    if (arp_get(conf->gw_interface, remote_addr, mac, sizeof(mac)) < 0) {
        cl->chunk_printf(cl, "<h1>Failed to retrieve your MAC address</h1>");
        ULOG_ERR("Failed to retrieve MAC address for ip %s\n", remote_addr);
        goto done;
    }

    allow_termianl(mac, true);
    cl->chunk_printf(cl, "%s", script ? script : "");

done:
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
