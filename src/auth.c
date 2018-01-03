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

#include "auth.h"
#include "utils.h"
#include "ping.h"
#include "config.h"
#include "httpget.h"

static void authserver_request_cb(void *data, char *content)
{
    struct uh_client *cl = data;
    struct config *conf = get_config();
    const char *remote_addr = cl->get_peer_addr(cl);
    char mac[13] = "";
    int code = -1;
    
    if (arp_get(conf->gw_interface, remote_addr, mac, sizeof(mac)) < 0) {
        uh_log_err("arp_get failed for %s", remote_addr);
        cl->request_done(cl);
        return;
    }
    
    uh_log_debug("auth cb:%s", content);

    if (!content)
        goto deny;
    
    sscanf(content, "Auth: %d", &code);

    if (code == 1) {
        allow_termianl(mac);
        
        cl->redirect(cl, 302, "http://%s:%d%s%sgw_id=%s", conf->authserver.host, conf->authserver.port, conf->authserver.path,
            conf->authserver.portal_path, conf->gw_id);
        return;
    }

deny:
    deny_termianl(mac);
}

static void authserver_request(struct uh_client *cl, const char *type, const char *ip, const char *mac, const char *token)
{
    struct config *conf = get_config();
    
    httpget(authserver_request_cb, cl, "http://%s:%d%s%sstage=%s&ip%s&mac=%s&token=%s",
                        conf->authserver.host, conf->authserver.port, conf->authserver.path,
                        conf->authserver.auth_path, type, ip, mac, token);
}

static void http_callback_404(struct uh_client *cl)
{
    struct config *conf = get_config();
    const char *remote_addr = cl->get_peer_addr(cl);
    char mac[13] = "";
    
    if (cl->request.method != UH_HTTP_MSG_GET) {
        cl->request_done(cl);
        return;
    }

    if (arp_get(conf->gw_interface, remote_addr, mac, sizeof(mac)) < 0) {
        uh_log_err("arp_get failed for %s", remote_addr);
        cl->request_done(cl);
        return;
    }
    
    cl->redirect(cl, 302, "http://%s:%d%s%sgw_address=%s&gw_port=%d&ip=%s&mac=%s",
        conf->authserver.host, conf->authserver.port, conf->authserver.path, conf->authserver.login_path,
        conf->gw_address, conf->gw_port, remote_addr, mac);
}

static void http_callback_auth(struct uh_client *cl)
{
    const char *token = cl->get_var(cl, "token");
    struct config *conf = get_config();
    
    if (token) {
        const char *remote_addr = cl->get_peer_addr(cl);
        const char *logout = cl->get_var(cl, "logout");
        char mac[13] = "";

        if (arp_get(conf->gw_interface, remote_addr, mac, sizeof(mac)) < 0) {
            cl->send_header(cl, 200, "OK", -1);
            cl->header_end(cl);
            cl->chunk_printf(cl, "<h1>Failed to retrieve your MAC address</h1>");
            cl->request_done(cl);
            uh_log_err("Failed to retrieve MAC address for ip %s", remote_addr);
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

static int http_init(int port, bool ssl)
{
    char buf[128];
    struct uh_server *srv = NULL;

    sprintf(buf, "%d", port);
    
    srv = uh_server_new("0.0.0.0", buf);
    if (!srv)
        goto err;
    
    uh_log_debug("Listen on: *:%s", buf);

    if (ssl && srv->ssl_init(srv, "/etc/wifidog/wifidog.key", "/etc/wifidog/wifidog.crt"))
        goto err;
    
    srv->error404_cb = http_callback_404;

    uh_add_action(srv, "/wifidog/auth", http_callback_auth);

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

    allow_destip(conf->authserver.host);
    start_heartbeat();
    enable_kmod(true);

    return 0;
}

