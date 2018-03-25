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

#include "utils.h"

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

static int handle_error(const char *tag)
{
    ULOG_ERR("%s: %s\n", tag, ipset_session_error(session));
    return -1;
}

int ipset_create(const char *setname, const char *typename, int timeout)
{
    int cmd = IPSET_CMD_CREATE;
    const struct ipset_type *type;

    ipset_envopt_parse(session, IPSET_ENV_EXIST, NULL);

    if (ipset_parse_setname(session, IPSET_SETNAME, setname))
        return handle_error("ipset_parse_setname");

    if (ipset_parse_typename(session, IPSET_OPT_TYPENAME, typename) < 0)
        return handle_error("ipset_parse_typename");

    type = ipset_type_get(session, cmd);
    if (!type)
        return handle_error("ipset_type_get");

    if (timeout > 0)
        ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout);

    if (ipset_cmd(session, cmd, 0) < 0)
        return handle_error("ipset_cmd");

    return 0;
}

static int ipset_easy_cmd(const char *setname, int cmd)
{
    if (ipset_parse_setname(session, IPSET_SETNAME, setname))
        return handle_error("ipset_parse_setname");

    if (ipset_cmd(session, cmd, 0) < 0)
        return handle_error("ipset_cmd");

    return 0;
}

int ipset_flush(const char *setname)
{
    return ipset_easy_cmd(setname, IPSET_CMD_FLUSH);
}

int ipset_destroy(const char *setname)
{
    return ipset_easy_cmd(setname, IPSET_CMD_DESTROY);
}

static int ipset_add_del(const char *setname, const char *value, int timeout, bool add)
{
	int cmd = add ? IPSET_CMD_ADD : IPSET_CMD_DEL;
	const struct ipset_type *type;

    ipset_envopt_parse(session, IPSET_ENV_EXIST, NULL);

	if (ipset_parse_setname(session, IPSET_SETNAME, setname))
        return handle_error("ipset_parse_setname");

    type = ipset_type_get(session, cmd);
    if (!type)
        return handle_error("ipset_type_get");

    if (ipset_parse_elem(session, type->last_elem_optional, value) < 0)
        return handle_error("ipset_parse_elem");

    if (add && timeout > 0)
        ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout);
	
	if (ipset_cmd(session, cmd, 0) < 0)
        return handle_error("ipset_cmd");

    return 0;
}

int ipset_add(const char *setname, const char *value, int timeout)
{
	return ipset_add_del(setname, value, timeout, true);
}

int ipset_del(const char *setname, const char *value)
{
	return ipset_add_del(setname, value, 0, false);
}
