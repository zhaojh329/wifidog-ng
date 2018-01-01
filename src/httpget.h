#ifndef _HTTPGET_H
#define _HTTPGET_H

#include <uhttpd/uhttpd.h>
#include <libubox/uclient.h>

typedef void (*httpget_cb)(void *data, char *body);

int httpget(httpget_cb cb, void *data, const char *url, ...);

#endif
