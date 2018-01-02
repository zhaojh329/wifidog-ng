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

#include "httpget.h"

struct uclient_param {
    httpget_cb cb;
    void *data;
    char body[256];
};

static void _uclient_free(struct uclient *cl)
{
    free(cl->priv);
    uclient_free(cl);
}

static void header_done_cb(struct uclient *cl)
{
	printf("status_code = %d\n", cl->status_code);
}

static void read_data_cb(struct uclient *cl)
{
	struct uclient_param *param = cl->priv;
	int len;

	while (1) {
		len = uclient_read(cl, param->body, sizeof(param->body));
		if (len <= 0)
			return;
	}
}

static void eof_cb(struct uclient *cl)
{
	if (!cl->data_eof) {
		uh_log_err("Connection reset prematurely");
	} else {
        struct uclient_param *param = cl->priv;

        if (param->cb)
            param->cb(param->data, param->body);
    }
	_uclient_free(cl);
}

static void handle_uclient_error(struct uclient *cl, int code)
{
    const char *type = "Unknown error";

	switch(code) {
	case UCLIENT_ERROR_CONNECT:
		type = "Connection failed";
		break;
	case UCLIENT_ERROR_TIMEDOUT:
		type = "Connection timed out";
		break;
	default:
		break;
	}

	uh_log_err("Connection error: %s", type);
	_uclient_free(cl);
}

static const struct uclient_cb _cb = {
	.header_done = header_done_cb,
	.data_read = read_data_cb,
	.data_eof = eof_cb,
	.error = handle_uclient_error
};

int httpget(httpget_cb cb, void *data, const char *url, ...)
{
    static char buf[1024];
    struct uclient *cl;
    va_list ap;
    struct uclient_param *param = NULL;

    va_start(ap, url);
    vsnprintf(buf, sizeof(buf), url, ap);
    va_end(ap);
    
    cl = uclient_new(buf, NULL, &_cb);
	if (!cl) {
		uh_log_err("Failed to allocate uclient context");
		return -1;
	}

    param = calloc(1, sizeof(struct uclient_param));
    param->cb = cb;
    param->data = data;
    
    cl->timeout_msecs = 1000;
    cl->priv = param;
    
    if (uclient_connect(cl)) {
        uh_log_err("Failed to establish connection");
        goto err;
    }

    if (uclient_request(cl)) {
        uh_log_err("Failed to request");
        goto err;
    }

    return 0;
    
err:
    if (cl)
        uclient_free(cl);

    if (param)
        free(param);
        
    return -1;
}

