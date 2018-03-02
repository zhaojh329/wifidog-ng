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

#ifndef _CONFIG_H_
#define _CONFIG_H_

struct config {
    const char *gw_interface;
    const char *gw_address;
    const char *gw_id;
    const char *ssid;
    int gw_port;
    int gw_ssl_port;
    int checkinterval;

    struct {
        int port;
        const char *host;
        const char *path;
        const char *login_path;
        const char *portal_path;
        const char *msg_path;
        const char *ping_path;
        const char *auth_path;
    } authserver;
};

int parse_config();

struct config *get_config();

#endif
