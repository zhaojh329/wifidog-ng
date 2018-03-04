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
#include "http.h"

#define MAX_CONTENT_SIZE    1024

struct uclient_param {
    http_cb cb;
    void *data;
    int content_len;
    char *content;
};

static void _uclient_free(struct uclient *cl)
{
    struct uclient_param *param = cl->priv;
    if (param)
        free(param->content);
    free(param);
    uclient_free(cl);
}

static void header_done_cb(struct uclient *cl)
{
    struct uclient_param *param = cl->priv;

    param->content = calloc(1, MAX_CONTENT_SIZE + 1);
    if (param->content)
        return;
    ULOG_ERR("calloc:%s\n", strerror(errno));
}

static void read_data_cb(struct uclient *cl)
{
    static char buf[1024];
    struct uclient_param *param = cl->priv;
    int len;

    while (1) {
        if (param->content_len < MAX_CONTENT_SIZE && param->content) {
            len = uclient_read(cl, param->content + param->content_len, MAX_CONTENT_SIZE - param->content_len);
            if (len > 0)
                param->content_len += len;
        } else {
            len = uclient_read(cl, buf, sizeof(buf));
        }

        if (len <= 0)
            break;
    }
}

static void eof_cb(struct uclient *cl)
{
    if (!cl->data_eof) {
        ULOG_ERR("Connection reset prematurely\n");
    } else {
        struct uclient_param *param = cl->priv;

        if (param->cb)
            param->cb(param->data, param->content);
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

    ULOG_ERR("httpget \"%s\" error: %s\n", cl->url->location, type);
    _uclient_free(cl);
}

static const struct uclient_cb _cb = {
    .header_done = header_done_cb,
    .data_read = read_data_cb,
    .data_eof = eof_cb,
    .error = handle_uclient_error
};

int httppost(http_cb cb, void *data, const char *post_data, const char *url, ...)
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
        ULOG_ERR("Failed to allocate uclient context\n");
        return -1;
    }

    param = calloc(1, sizeof(struct uclient_param));
    param->cb = cb;
    param->data = data;
    
    cl->timeout_msecs = 1000;
    cl->priv = param;
    
    if (uclient_connect(cl)) {
        ULOG_ERR("Failed to establish connection\n");
        goto err;
    }

    if (post_data) {
        uclient_http_set_request_type(cl, "POST");
        uclient_http_set_header(cl, "Content-Type", "application/json");
        uclient_write(cl, post_data, strlen(post_data));
    }

    if (uclient_request(cl)) {
        ULOG_ERR("Failed to request\n");
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

