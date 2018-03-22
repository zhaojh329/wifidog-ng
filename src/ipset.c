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
#include <libipset/session.h>
#include <libipset/types.h>

static struct ipset_session *session;

int ipset_init()
{
	/* Load set types */
    ipset_load_types();

    /* Initialize session */
    session = ipset_session_init(NULL);
    if (!session) {
        ULOG_ERR("Cannot initialize ipset session, aborting.\n");
        return -1;
    }
    return 0;
}

void ipset_deinit()
{
	ipset_session_fini(session);
}

static void ipset_add_del(const char *setname, const char *value, int timeout, bool add)
{
	int cmd = add ? IPSET_CMD_ADD : IPSET_CMD_DEL;
	const struct ipset_type *type;
    static char buf[128];

    ipset_envopt_parse(session, IPSET_ENV_EXIST, NULL);

	ipset_parse_setname(session, IPSET_SETNAME, setname);
    type = ipset_type_get(session, cmd);
    ipset_parse_elem(session, type->last_elem_optional, value);

    if (add && timeout > 0) {
    	sprintf(buf, "%d", timeout);
    	ipset_parse_timeout(session, IPSET_OPT_TIMEOUT, buf);
    }
	
	ipset_cmd(session, cmd, 0);
}

void ipset_add(const char *setname, const char *value, int timeout)
{
	ipset_add_del(setname, value, timeout, true);
}

void ipset_del(const char *setname, const char *value)
{
	ipset_add_del(setname, value, 0, false);
}
