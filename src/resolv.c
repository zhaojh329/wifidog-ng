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

#include <ares.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <ares.h>
#include <arpa/inet.h>
#include <libubox/ulog.h>
#include <libubox/uloop.h>

#include "resolv.h"

struct resolv_ctx {
    struct uloop_fd ufd;
    struct uloop_timeout ut;

    ares_channel channel;
    struct ares_options options;
};

static struct resolv_ctx default_ctx;

static void reset_timer()
{
	float repeat;
    struct timeval tvout;
    struct timeval *tv;

    tv = ares_timeout(default_ctx.channel, NULL, &tvout);
    if (tv == NULL)
        return;

    repeat = tv->tv_sec + tv->tv_usec / 1000000. + 1e-9;

    uloop_timeout_set(&default_ctx.ut, repeat * 1000);
}

/* Handle c-ares events */
static void resolv_sock_state_cb(void *data, int s, int read, int write)
{
    struct resolv_ctx *ctx = (struct resolv_ctx *)data;

    if (read || write) {
        if (ctx->ufd.fd != s)
            uloop_fd_delete(&ctx->ufd);

        ctx->ufd.fd = s;
        uloop_fd_add(&ctx->ufd, (read ? ULOOP_READ : 0) | (write ? ULOOP_WRITE : 0));
    } else {
        ctx->ufd.fd = -1;
        uloop_fd_delete(&ctx->ufd);
    }
}

/* DNS UDP socket activity callback */
static void resolv_sock_cb(struct uloop_fd *ufd, unsigned int events)
{
    struct resolv_ctx *ctx = (struct resolv_ctx *)ufd;
    ares_socket_t rfd = ARES_SOCKET_BAD;
    ares_socket_t wfd = ARES_SOCKET_BAD;

    if (events & ULOOP_READ)
        rfd = ufd->fd;
    if (events & ULOOP_WRITE)
        wfd = ufd->fd;

    ares_process_fd(ctx->channel, rfd, wfd);

    reset_timer();
}

/* DNS timeout callback */
static void resolv_timeout_cb(struct uloop_timeout *ut)
{
    struct resolv_ctx *ctx = container_of(ut, struct resolv_ctx, ut);

    ares_process_fd(ctx->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);

    reset_timer();
}

int resolv_init()
{
	int status;

    if ((status = ares_library_init(ARES_LIB_INIT_ALL)) != ARES_SUCCESS) {
        ULOG_ERR("c-ares error: %s\n", ares_strerror(status));
        return -1;
    }

    memset(&default_ctx, 0, sizeof(struct resolv_ctx));

    default_ctx.options.sock_state_cb_data = &default_ctx;
    default_ctx.options.sock_state_cb      = resolv_sock_state_cb;
    default_ctx.options.timeout            = 3000;
    default_ctx.options.tries              = 2;

    status = ares_init_options(&default_ctx.channel, &default_ctx.options,
#if ARES_VERSION_MAJOR >= 1 && ARES_VERSION_MINOR >= 12
                               ARES_OPT_NOROTATE |
#endif
                               ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_SOCK_STATE_CB);

    if (status != ARES_SUCCESS) {
        ULOG_ERR("failed to initialize c-ares\n");
        return -1;
    }

    default_ctx.ufd.cb = resolv_sock_cb;
    default_ctx.ut.cb = resolv_timeout_cb;

    return 0;
}

void resolv_shutdown()
{
    ares_cancel(default_ctx.channel);
    ares_destroy(default_ctx.channel);
    ares_library_cleanup();
}

/* Wrapper for client callback we provide to c-ares */
static void dns_query_v4_cb(void *arg, int status, int timeouts, struct hostent *he)
{
    struct resolv_query *query = (struct resolv_query *)arg;

    if (status == ARES_EDESTRUCTION)
        return;

    if (!he || status != ARES_SUCCESS) {
    	he = NULL;
		ULOG_ERR("failed to lookup v4 address %s\n", ares_strerror(status));
        goto CLEANUP;
    }

CLEANUP:
	query->resolv_cb(he, query->data);

    if (query->free_cb)
        query->free_cb(query->data);
    else
        free(query->data);

    free(query);
}

void resolv_start(const char *hostname, void (*resolv_cb)(struct hostent *he, void *data),
             void (*free_cb)(void *data), void *data)
{
    /* Wrap c-ares's call back in our own */
    struct resolv_query *query = calloc(1, sizeof(struct resolv_query));

    query->resolv_cb      = resolv_cb;
    query->data           = data;
    query->free_cb        = free_cb;

    ares_gethostbyname(default_ctx.channel, hostname, AF_INET, dns_query_v4_cb, query);
    reset_timer();
}
