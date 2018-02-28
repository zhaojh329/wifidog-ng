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

#include <libubox/ulog.h>

#include "auth.h"
#include "utils.h"
#include "ping.h"
#include "config.h"
#include "http.h"
#include "counters.h"

struct authserver_request_param {
    struct uh_client *cl;
    char token[33];
};

static void authserver_request_cb(void *data, char *content)
{
    struct authserver_request_param *param = data;
    struct uh_client *cl = param->cl;
    struct config *conf = get_config();
    const char *remote_addr = cl->get_peer_addr(cl);
    char mac[18] = "";
    int code = -1;
    
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
        
        cl->redirect(cl, 302, "http://%s:%d%s%sgw_id=%s", conf->authserver.host, conf->authserver.port, conf->authserver.path,
            conf->authserver.portal_path, conf->gw_id);
        free(param);
        return;
    }

deny:
    deny_termianl(mac);
    free(param);
}

static void authserver_request(struct uh_client *cl, const char *type, const char *ip, const char *mac, const char *token)
{
    struct config *conf = get_config();
    struct authserver_request_param *param = calloc(1, sizeof(struct authserver_request_param));

    param->cl = cl;
    strcpy(param->token, token);

    httpget(authserver_request_cb, param, "http://%s:%d%s%sstage=%s&ip=%s&mac=%s&token=%s",
                        conf->authserver.host, conf->authserver.port, conf->authserver.path,
                        conf->authserver.auth_path, type, ip, mac, token);
}

static void http_callback_404(struct uh_client *cl)
{
    struct config *conf = get_config();
    const char *remote_addr = cl->get_peer_addr(cl);
    char mac[18] = "";
    
    if (cl->request.method != UH_HTTP_MSG_GET) {
        cl->request_done(cl);
        return;
    }

    if (arp_get(conf->gw_interface, remote_addr, mac, sizeof(mac)) < 0) {
        ULOG_ERR("arp_get failed for %s\n", remote_addr);
        cl->request_done(cl);
        return;
    }
    
    cl->redirect(cl, 302, "http://%s:%d%s%sgw_address=%s&gw_port=%d&ip=%s&mac=%s&ssid=%s",
        conf->authserver.host, conf->authserver.port, conf->authserver.path, conf->authserver.login_path,
        conf->gw_address, conf->gw_port, remote_addr, mac, conf->ssid ? conf->ssid : "");
}

static void http_callback_auth(struct uh_client *cl)
{
    const char *token = cl->get_var(cl, "token");
    struct config *conf = get_config();

    if (token) {
        const char *remote_addr = cl->get_peer_addr(cl);
        const char *logout = cl->get_var(cl, "logout");
        char mac[18] = "";

        if (arp_get(conf->gw_interface, remote_addr, mac, sizeof(mac)) < 0) {
            cl->send_header(cl, 200, "OK", -1);
            cl->header_end(cl);
            cl->chunk_printf(cl, "<h1>Failed to retrieve your MAC address</h1>");
            cl->request_done(cl);
            ULOG_ERR("Failed to retrieve MAC address for ip %s\n", remote_addr);
            return;
        }

        if (logout)
            authserver_request(cl, "logout", remote_addr, mac, token);
        else
            authserver_request(cl, "login", remote_addr, mac, token);
    } else {
        cl->send_header(cl, 200, "OK", -1);
        cl->header_end(cl);
        cl->chunk_printf(cl, "<h1>Invalid token</h1>");
        cl->request_done(cl);
    }
}

static void http_callback_temppass(struct uh_client *cl)
{
    char mac[18] = "";
    struct config *conf = get_config();
    const char *remote_addr = cl->get_peer_addr(cl);

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
    cl->append_header(cl, "Access-Control-Allow-Origin", "*");
    cl->append_header(cl, "Access-Control-Allow-Method", "GET");
    cl->header_end(cl);
    cl->chunk_printf(cl, "<h1>OK</h1>");
    cl->request_done(cl);
}

static int http_init(int port, bool ssl)
{
    struct uh_server *srv = NULL;
    
    srv = uh_server_new("0.0.0.0", port);
    if (!srv)
        goto err;
    
    ULOG_INFO("Listen on: *:%d\n", port);

#if (UHTTPD_SSL_SUPPORT)
    if (ssl && srv->ssl_init(srv, "/etc/wifidog/wifidog.key", "/etc/wifidog/wifidog.crt"))
        goto err;
#endif

    srv->error404_cb = http_callback_404;

    uh_add_action(srv, "/wifidog/auth", http_callback_auth);
    uh_add_action(srv, "/wifidog/temppass", http_callback_temppass);

    return 0;
err:
     srv->free(srv);
     return -1;
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
    termianl_temppass_init();
    allow_destip(conf->authserver.host);
    start_heartbeat();
    start_counters();
    enable_kmod(true, conf->gw_interface, conf->gw_port, conf->gw_ssl_port);

    return 0;
}

