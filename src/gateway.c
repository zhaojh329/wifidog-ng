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
#include <uhttpd/uhttpd.h>

#include "config.h"
#include "termianl.h"
#include "ubus.h"
#include "auth.h"

int main(int argc, char **argv)
{
    if (parse_config())
        return -1;
    
    uloop_init();

    if (auth_init() < 0)
        goto EXIT;

    ubus_init();
    termianl_init();
    
    uloop_run();

EXIT:
    uloop_done();
    ULOG_INFO("wifidog-ng exit.\n");
    
    return 0;
}
