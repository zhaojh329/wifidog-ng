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

#include <uhttpd/uhttpd.h>
#include <string.h>
#include <stdio.h>
#include "http.h"
#include "utils.h"
#include "config.h"

int main(int argc, char **argv)
{
    char buf[128] = "";
    struct config *conf = get_config();
    
    uh_log_debug("libuhttpd version: %s", UHTTPD_VERSION_STRING);

    parse_config();

    uloop_init();

    sprintf(buf, "%d", conf->gw_port);
    http_init(buf, false);
    
#if (UHTTPD_SSL_SUPPORT)
    sprintf(buf, "%d", conf->gw_ssl_port);
    http_init(buf, true);
#endif

    allow_destip(conf->authserver.host);

    start_heartbeat();

    enable_kmod(true);
    
    uloop_run();

    uloop_done();
    
    return 0;
}
