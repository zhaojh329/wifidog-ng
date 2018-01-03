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

#include <signal.h>
#include <uhttpd/uhttpd.h>

#include "config.h"
#include "auth.h"

static void signal_handle(int sig)
{
	if (sig == SIGINT) {
		uloop_done();
    }
}

int main(int argc, char **argv)
{
    if (parse_config())
        return -1;

    signal(SIGINT, signal_handle);
    
    uloop_init();

    auth_init();
    
    uloop_run();

    uh_log_debug("wifidog-ng exit.");
    
    return 0;
}
