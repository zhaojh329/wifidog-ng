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

#include "http.h"
#include "euci.h"
#include "utils.h"
#include "config.h"
#include "httpget.h"

void logout_client(char *mac)
{
}

static void error404_cb(struct uh_client *cl)
{
    struct config *conf = get_config();
    const char *remote_addr = cl->get_peer_addr(cl);
    char *mac = arp_get(conf->gw_interface, remote_addr);
    
    if (cl->request.method != UH_HTTP_MSG_GET) {
        cl->request_done(cl);
        return;
    }
    
    cl->redirect(cl, 302, "http://%s:%d%s%sgw_address=%s&gw_port=%d&ip=%s&mac=%s",
        conf->authserver.host, conf->authserver.port, conf->authserver.path, conf->authserver.login_path,
        conf->gw_address, conf->gw_port, remote_addr, mac);

    free(mac);
}

static void wifidog_auth_cb(void *data, char *body)
{
    struct uh_client *cl = data;
    const char *remote_addr = cl->get_peer_addr(cl);
    struct config *conf = get_config();
    char *mac = arp_get(conf->gw_interface, remote_addr);
    
    printf("auth cb:%s\n", body);

    allow_termianl(mac);
    
    cl->redirect(cl, 302, "http://www.baidu.com");
}

static void wifidog_auth(struct uh_client *cl)
{
    const char *token = cl->get_var(cl, "token");
    struct config *conf = get_config();
    
    if (token) {
        const char *remote_addr = cl->get_peer_addr(cl);
        const char *logout = cl->get_var(cl, "logout");
        char *mac = arp_get(conf->gw_interface, remote_addr);
    

        if (!mac) {
            cl->send_header(cl, 200, "OK", -1);
            cl->header_end(cl);
            cl->chunk_printf(cl, "<h1>Failed to retrieve your MAC address</h1>");
            cl->request_done(cl);
            uh_log_err("Failed to retrieve MAC address for ip %s", remote_addr);
        } else {
            if (logout)
                logout_client(mac);
            else {
                httpget(wifidog_auth_cb, cl, "http://%s:%d%s%sstage=login&ip%s&mac=%s",
                    conf->authserver.host, conf->authserver.port, conf->authserver.path, conf->authserver.auth_path,
                    remote_addr, mac);
            }
            free(mac);
        }
    } else {
        cl->send_header(cl, 200, "OK", -1);
        cl->header_end(cl);
        cl->chunk_printf(cl, "<h1>Invalid token</h1>");
        cl->request_done(cl);
    }
}

int http_init(const char *port, bool ssl)
{
    struct uh_server *srv = NULL;
    
    srv = uh_server_new("0.0.0.0", port);
    if (!srv)
        goto err;
    
    uh_log_debug("Listen on: *:%s", port);

    if (ssl) {
        if (srv->ssl_init(srv, "/etc/wifidog/wifidog.key", "/etc/wifidog/wifidog.crt") < 0)
        goto err;
    }
    
    srv->error404_cb = error404_cb;

    uh_add_action(srv, "/wifidog/auth", wifidog_auth);

    return 0;
err:
     srv->free(srv);
     return -1;
}

